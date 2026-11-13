"""Run within the test Remnanode's private network namespace."""
import hashlib
import http.client
import http.server
import json
from pathlib import Path
import secrets
import select
import socketserver
import sys
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import tomllib
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack

from test_interop import BODY, Origin, XRAY, wait_port

LAB = Path("/lab")
TAG = "rust-test"
WS_TAG = "rust-mux-test"
TCP = (18480, 18481, 18483, 18484, 18488)
UDP = (53, 18486, 18487, 18496, 18497, 18498)
CORE_PORT = 18443
WS_PORT = 18444
TEST_ID = "20001"
ADDED_ID = "20002"
MUX_TEST_ID = "20003"
ECHO_PORT = 18482
SECRET = (LAB / "token").read_text()
CONTEXT = ssl.create_default_context(cafile=str(LAB / "ca.crt"))
CONTEXT.load_cert_chain(LAB / "panel.crt", LAB / "panel.key")


def api(path, body=None, token=SECRET):
    connection = http.client.HTTPSConnection("127.0.0.1", 13001, context=CONTEXT, timeout=25)
    try:
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        connection.request("GET" if body is None else "POST", f"/node/{path}",
                           body=None if body is None else json.dumps(body), headers=headers)
        response = connection.getresponse()
        data = json.loads(response.read())
        if response.status >= 300:
            raise RuntimeError(f"{path} returned HTTP {response.status}: {data.get('message')}")
        return data["response"]
    finally:
        connection.close()


def wait_api():
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            api("xray/healthcheck")
            return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("test Remnanode did not start")


class Site(Origin):
    def end_headers(self):
        self.send_header("Strict-Transport-Security", "max-age=86400")
        super().end_headers()


class TcpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        with self.request:
            while data := self.request.recv(65536):
                self.request.sendall(data)


def check_mux_accounting(stack, socks_port):
    server = stack.enter_context(socketserver.ThreadingTCPServer(("127.0.0.1", ECHO_PORT), TcpEcho))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    stack.callback(server.shutdown)

    def traffic(reset):
        users = api("stats/get-users-stats", {"reset": reset})["users"]
        user = next((user for user in users if user["username"] == MUX_TEST_ID), {})
        return user.get("uplink", 0), user.get("downlink", 0)

    traffic(True)
    assert traffic(False) == (0, 0)
    connections, rounds = 8, 16
    first_round = threading.Barrier(connections + 1, timeout=10)
    payload = bytes(range(256)) * 256

    def echo(index):
        with socket.create_connection(("127.0.0.1", socks_port), timeout=10) as sock, sock.makefile("rb") as reader:
            sock.sendall(b"\x05\x01\x00")
            assert reader.read(2) == b"\x05\x00"
            sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", ECHO_PORT))
            assert reader.read(10)[:4] == b"\x05\x00\x00\x01"
            for round_index in range(rounds):
                data = struct.pack("!II", index, round_index) + payload[8:]
                sock.sendall(data)
                assert reader.read(len(data)) == data
                if round_index == 0:
                    first_round.wait()

    with ThreadPoolExecutor(max_workers=connections) as workers:
        streams = [workers.submit(echo, index) for index in range(connections)]
        first_round.wait()
        snapshots = [traffic(True)]
        while any(not stream.done() for stream in streams):
            time.sleep(0.005)
            snapshots.append(traffic(True))
        for stream in streams:
            stream.result()
    snapshots.append(traffic(True))
    expected = connections * rounds * len(payload)
    assert tuple(map(sum, zip(*snapshots))) == (expected, expected), snapshots
    assert traffic(False) == (0, 0)
    print(f"PASS Remnanode Mux accounting through concurrent resets: {expected} bytes per direction")


class HttpRelay(socketserver.StreamRequestHandler):
    def handle(self):
        if not self.rfile.readline(4096).startswith(b"CONNECT "):
            return
        headers = []
        while (header := self.rfile.readline(4096)) not in (b"\r\n", b""):
            headers.append(header.lower())
        if not any(header.startswith(b"proxy-authorization: basic ") for header in headers):
            self.wfile.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            return
        with socket.create_connection(("127.0.0.1", 18480), timeout=4) as origin:
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            while readable := select.select((self.connection, origin), (), (), 4)[0]:
                for source in readable:
                    chunk = source.recv(65536)
                    if not chunk:
                        return
                    target = origin if source is self.connection else self.connection
                    target.sendall(chunk)


def serve(stack, companion):
    if companion:
        server = stack.enter_context(socketserver.ThreadingTCPServer(("127.0.0.1", 18489), HttpRelay))
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        stack.callback(server.shutdown)
    for port in TCP:
        origin = stack.enter_context(http.server.ThreadingHTTPServer(("127.0.0.1", port), Site))
        if port in (18481, 18483, 18488):
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            version = ssl.TLSVersion.TLSv1_2 if port == 18481 else ssl.TLSVersion.TLSv1_3
            if port != 18488:
                tls.minimum_version = version
                tls.maximum_version = version
            tls.load_cert_chain(LAB / "site.crt", LAB / "site.key")
            origin.socket = tls.wrap_socket(origin.socket, server_side=True)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        stack.callback(origin.shutdown)

    def echo(listener):
        while True:
            try:
                payload, address = listener.recvfrom(65507)
                listener.sendto(payload, address)
            except OSError:
                return
    for port in UDP:
        sock = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        sock.bind(("127.0.0.1", port))
        threading.Thread(target=echo, args=(sock,), daemon=True).start()


def cascade_fixture(stack, stage):
    identity = str(uuid.uuid4())
    cert = LAB / "site.crt"
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"listen": "127.0.0.1", "port": 18490, "protocol": "socks", "settings": {"udp": True}},
            {"listen": "127.0.0.1", "port": 18491, "protocol": "vless",
             "settings": {"clients": [{"id": identity}], "decryption": "none"},
             "streamSettings": {"network": "raw", "security": "tls", "tlsSettings": {
                 "certificates": [{"certificateFile": str(cert), "keyFile": str(LAB / "site.key")}]
             }}},
            {"listen": "127.0.0.1", "port": 18493, "protocol": "vless",
             "settings": {"clients": [{"id": identity, "flow": "xtls-rprx-vision"}], "decryption": "none"},
             "streamSettings": {"network": "raw", "security": "tls", "tlsSettings": {
                 "certificates": [{"certificateFile": str(cert), "keyFile": str(LAB / "site.key")}]
             }}},
            {"listen": "127.0.0.1", "port": 18494, "protocol": "vless",
             "settings": {"clients": [{"id": identity}], "decryption": "none"},
             "streamSettings": {"network": "raw"}},
        ],
        "outbounds": [
            {"tag": "echo", "protocol": "freedom", "settings": {
                "redirect": "127.0.0.1:18480",
                "finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"], "port": "18480"}],
            }},
            {"tag": "direct", "protocol": "freedom", "settings": {
                "finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"], "port": "18483,18486,18496-18498"}]
            }},
        ],
        "routing": {"rules": [{"type": "field", "port": "18483,18486,18496-18498", "outboundTag": "direct"}]},
    }
    path = stage / "cascade.json"
    path.write_text(json.dumps(config))
    log = stack.enter_context(open(stage / "cascade.log", "w+"))
    process = stack.enter_context(subprocess.Popen([XRAY, "run", "-c", path], stdout=log, stderr=log))
    stack.callback(process.terminate)
    for port in (18490, 18491, 18493, 18494):
        wait_port(port, process)
    outbounds = [
        {"tag": "SOCKS-TEST", "protocol": "socks", "settings": {
            "servers": [{"address": "127.0.0.1", "port": 18490}]
        }},
        {"tag": "VLESS-TEST", "protocol": "vless", "settings": {"vnext": [{
            "address": "127.0.0.1", "port": 18491, "users": [{"id": identity, "encryption": "none"}],
        }]}, "streamSettings": {"network": "raw", "security": "tls", "tlsSettings": {
            "serverName": "example.test", "pinnedPeerCertSha256": pin,
        }}},
    ]
    vision = json.loads(json.dumps(outbounds[1]))
    vision["tag"] = "VISION-TEST"
    vision["settings"]["vnext"][0]["port"] = 18493
    vision["settings"]["vnext"][0]["users"][0]["flow"] = "xtls-rprx-vision"
    bad_pin = json.loads(json.dumps(vision))
    bad_pin["tag"] = "PIN-MISMATCH-TEST"
    bad_pin["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"] = "0" * 64
    plain = {
        "tag": "VLESS-PLAIN-TEST", "protocol": "vless", "settings": {"vnext": [{
            "address": "127.0.0.1", "port": 18494,
            "users": [{"id": identity, "level": 0, "encryption": "none"}],
        }]}, "streamSettings": {"network": "raw", "sockopt": {
            "domainStrategy": "ForceIPv4", "tcpNoDelay": True, "tcpFastOpen": True,
            "tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": 15,
        }},
    }
    return outbounds + [vision, bad_pin, plain]


def xray_client(stack, stage, account, flow, public, short_id, port, source=None):
    return start_xray_client(stack, stage, port, {
        "protocol": "vless", **({"sendThrough": source} if source else {}),
        "settings": {"vnext": [{"address": "127.0.0.1", "port": CORE_PORT,
                     "users": [{"id": account, "flow": flow, "encryption": "none"}]}]},
        "streamSettings": {"network": "raw", "security": "reality",
                           "realitySettings": {"serverName": "example.test", "fingerprint": "chrome",
                                               "password": public, "shortId": short_id}},
    })


def start_xray_client(stack, stage, port, outbound):
    path = stage / f"client-{port}.json"
    path.write_text(json.dumps({
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                      "settings": {"udp": True}}],
        "outbounds": [outbound],
    }))
    log = stack.enter_context(open(stage / f"client-{port}.log", "w+"))
    process = stack.enter_context(subprocess.Popen([XRAY, "run", "-c", path], stdout=log, stderr=log))
    def cleanup():
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
    stack.callback(cleanup)
    wait_port(port, process)


def request_through(port, url, *, ok=True, upload=False, host=None):
    result = subprocess.run(
        ["curl", "-fkSs", "--max-time", "4", "--socks5-hostname", f"127.0.0.1:{port}",
         *(["--data-binary", "@-"] if upload else []), *(["-H", f"Host: {host}"] if host else []), url],
        input=BODY if upload else None, capture_output=True,
    )
    assert (result.returncode == 0 and result.stdout == BODY) if ok else (result.returncode != 0 and not result.stdout), (
        url, result.returncode, len(result.stdout), result.stderr.decode()
    )


def read_exact(stream, size):
    data = b""
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise RuntimeError("short SOCKS reply")
        data += part
    return data


def datagrams(port, origin, *, blocked=False, payloads=None):
    if payloads is None:
        payload = b"nightvpn-udp-" + secrets.token_bytes(41)
        payloads = [payload] * (1 if blocked else 3)
    with socket.create_connection(("127.0.0.1", port), timeout=3) as control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        control.sendall(b"\x05\x01\x00")
        assert read_exact(control, 2) == b"\x05\x00"
        control.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
        response = read_exact(control, 10)
        assert response[:4] == b"\x05\x00\x00\x01", response.hex()
        relay = socket.inet_ntoa(response[4:8]), struct.unpack("!H", response[8:])[0]
        prefix = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", origin)
        for index, payload in enumerate(payloads):
            should_drop = blocked and index == len(payloads) - 1
            client.settimeout(1.5 if should_drop else 4)
            client.sendto(prefix + payload, relay)
            try:
                result, _ = client.recvfrom(65535)
            except TimeoutError:
                if should_drop:
                    return
                raise
            assert not should_drop and result == prefix + payload, result.hex()
    return sum(map(len, payloads))


def check_shadowsocks():
    tag, inbound_port = "shadowsocks-test", 19999
    first_user, added_user = "20004", "20005"
    first_password, added_password = secrets.token_hex(24), secrets.token_hex(24)
    method = "chacha20-ietf-poly1305"
    profile = {
        "inbounds": [{
            "tag": tag, "protocol": "shadowsocks", "listen": "0.0.0.0", "port": inbound_port,
            "settings": {"network": "tcp,udp", "clients": [{
                "id": str(uuid.uuid4()), "email": first_user,
                "password": first_password, "method": method,
            }]},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
        }],
        "outbounds": [{"tag": "BLOCK", "protocol": "blackhole"},
                      {"tag": "DIRECT", "protocol": "freedom", "settings": {
                          "finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"], "port": "18480,18486"}],
                      }}],
        "routing": {"rules": [
            {"type": "field", "domain": ["full:blocked.example.test"], "outboundTag": "BLOCK"},
            {"type": "field", "inboundTag": [tag], "port": "18480,18486", "outboundTag": "DIRECT"},
        ]},
    }

    def client(stack, stage, socks_port, password):
        start_xray_client(stack, stage, socks_port, {
            "protocol": "shadowsocks", "settings": {"servers": [{
                "address": "127.0.0.1", "port": inbound_port,
                "method": method, "password": password,
            }]},
        })

    def counters(reset):
        return {entry["username"]: (entry["uplink"], entry["downlink"])
                for entry in api("stats/get-users-stats", {"reset": reset})["users"]}

    with ExitStack() as stack:
        stage = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        serve(stack, False)
        wait_api()
        status = api("xray/start", {
            "internals": {"hashes": {"emptyConfig": "ss-test", "inbounds": [
                {"usersCount": 1, "tag": tag, "hash": "ss-test"},
            ]}, "forceRestart": True},
            "xrayConfig": profile,
        })
        assert status["isStarted"], status
        client(stack, stage, 11080, first_password)
        client(stack, stage, 11081, added_password)
        url = "http://127.0.0.1:18480/"
        request_through(11080, url, upload=True)
        tcp = counters(True)[first_user]
        assert all(total >= len(BODY) for total in tcp), tcp
        request_through(11080, url, ok=False, host="blocked.example.test")
        request_through(11081, url, ok=False)
        payload = datagrams(11080, 18486)
        udp = counters(True)[first_user]
        assert udp == (payload, payload), udp
        user_id = str(uuid.uuid4())
        result = api("handler/add-users", {"affectedInboundTags": [tag], "users": [{
            "inboundData": [{"type": "shadowsocks", "tag": tag}],
            "userData": {"userId": added_user, "hashUuid": user_id, "vlessUuid": user_id,
                         "trojanPassword": "", "ssPassword": added_password},
        }]})
        assert result["success"], result
        request_through(11081, url)
        assert counters(True)[added_user][1] >= len(BODY)
        result = api("handler/remove-users", {"users": [{"userId": added_user, "hashUuid": user_id}]})
        assert result["success"], result
        request_through(11081, url, ok=False)
        request_through(11080, url)
        api("xray/stop")
        print("PASS Shadowsocks Go-client TCP, UDP, sniffing block, counters and dynamic users")


def torrent_check(stack, stage, original, public, short_id, plugin):
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(read_exact(self.request, 68))

    echo = stack.enter_context(socketserver.ThreadingTCPServer(("127.0.0.1", 18492), Echo))
    echo.daemon_threads = True
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    stack.callback(echo.shutdown)

    payload = b"\x13BitTorrent protocol" + bytes(8) + secrets.token_bytes(40)

    def probe(port):
        with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
            client.sendall(b"\x05\x01\x00")
            assert read_exact(client, 2) == b"\x05\x00"
            client.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 18492))
            assert read_exact(client, 10)[:2] == b"\x05\x00"
            client.sendall(payload)
            if not client.recv(1, socket.MSG_PEEK):
                raise EOFError("handshake was blocked")
            return read_exact(client, len(payload))

    source = "127.0.0.2"
    xray_client(stack, stage, original, "xtls-rprx-vision", public, short_id, 11081, source=source)
    try:
        probe(11081)
    except (EOFError, OSError):
        pass
    else:
        raise AssertionError("Torrent Blocker let the handshake reach the origin")

    def wait_for_report(address, account_id):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            reports = api("plugin/torrent-blocker/collect", {})["reports"]
            for report in reports:
                action = report["actionReport"]
                if action["ip"] == address and str(action["userId"]) == account_id:
                    assert action["blocked"] is True and report["xrayReport"]["protocol"] == "bittorrent", report
                    print("PASS Remnanode Torrent Blocker detected the BitTorrent handshake, received the webhook and banned the original IP via nftables")
                    return
            time.sleep(0.1)
        raise RuntimeError("Torrent Blocker did not report the BitTorrent handshake")

    wait_for_report(source, TEST_ID)
    if "--native" in sys.argv:
        dht_ping = b"d1:ad2:id20:01234567890123456789e1:q4:ping1:t2:aa1:y1:qe"
        utp_syn = b"\x41\x00" + bytes(14) + b"\x00\x01\x00\x00"
        for index, (kind, payloads) in enumerate((
            ("DHT ping", [dht_ping]),
            ("uTP SYN after an allowed datagram", [b"ordinary UDP test", utp_syn]),
        ), start=3):
            address = f"127.0.0.{index}"
            account_id = str(20100 + index)
            account = str(uuid.uuid4())
            result = api("handler/add-users", {"affectedInboundTags": [TAG], "users": [{
                "inboundData": [{"type": "vless", "tag": TAG, "flow": "xtls-rprx-vision"}],
                "userData": {"userId": account_id, "hashUuid": account, "vlessUuid": account,
                             "trojanPassword": "", "ssPassword": ""},
            }]})
            assert result["success"], result
            port = 11088 + index
            xray_client(stack, stage, account, "xtls-rprx-vision", public, short_id, port, source=address)
            datagrams(port, 18486, blocked=True, payloads=payloads)
            wait_for_report(address, account_id)
            print(f"PASS Torrent Blocker rejected UDP {kind}")
    before = api("stats/get-system-stats")["xrayInfo"]["uptime"]
    plugin["config"]["torrentBlocker"]["enabled"] = False
    result = api("plugin/sync", {"plugin": plugin})
    assert result["accepted"], result
    assert probe(11080) == payload
    assert api("stats/get-system-stats")["xrayInfo"]["uptime"] >= before
    print("PASS disabling Torrent Blocker through Remnanode let the handshake reach the origin without restarting the core")


def stop_core():
    api("xray/stop")
    try:
        with socket.create_connection(("127.0.0.1", CORE_PORT), timeout=1):
            raise AssertionError("core listener still accepts after Remnanode stop")
    except ConnectionRefusedError:
        pass


def main():
    with ExitStack() as stack:
        stage = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        companion = "--companion" in sys.argv
        features = companion or "--native" in sys.argv
        serve(stack, features)
        wait_api()
        keys = subprocess.check_output([XRAY, "x25519"], text=True)
        keys = dict(line.split(": ", 1) for line in keys.splitlines() if ": " in line)
        private, public = keys["PrivateKey"], keys["Password (PublicKey)"]
        short_id, short_id_alt = secrets.token_hex(8), secrets.token_hex(8)
        original, added = str(uuid.uuid4()), str(uuid.uuid4())
        profile = {
            "inbounds": [{
                "tag": TAG, "listen": "0.0.0.0", "port": CORE_PORT, "protocol": "vless",
                "settings": {"decryption": "none", "flow": "xtls-rprx-vision",
                             "clients": [{"id": original, "email": TEST_ID}]},
                "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                    "serverNames": ["example.test"], "privateKey": private,
                    "shortIds": [short_id, short_id_alt], "target": "localhost:18488",
                    "minClientVer": "26.1.0", "maxClientVer": "26.12.31",
                }},
            }],
            "outbounds": [{"tag": "BLOCK", "protocol": "blackhole"}, {"tag": "DIRECT", "protocol": "freedom", "settings": {
                "finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"], "port": "53,18480-18488"}]
            }}],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
                {"type": "field", "domain": ["full:localhost"], "port": 18480, "outboundTag": "BLOCK"},
                {"type": "field", "ip": ["127.0.0.0/8"], "port": "18480-18483",
                 "network": "tcp", "inboundTag": [TAG], "outboundTag": "DIRECT"},
                {"type": "field", "network": "udp", "port": "53,18486", "outboundTag": "DIRECT"},
            ]},
        }
        if features and "--live-profile" not in sys.argv:
            profile["outbounds"].extend(cascade_fixture(stack, stage))
            if companion:
                profile["dns"] = {"hosts": {"localhost": "127.0.0.1"}, "servers": ["localhost"]}
            profile["outbounds"][1]["settings"] = {"targetStrategy": "ForceIPv4", "finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"], "port": "53,18480-18488"}]}
            profile["inbounds"][0]["sniffing"] = {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}
            profile["inbounds"][0]["streamSettings"]["sockopt"] = {
                "tcpNoDelay": True, "tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": 15, "tcpFastOpen": True,
            }
            profile["outbounds"].append({"tag": "HTTP-TEST", "protocol": "http", "settings": {
                "servers": [{"address": "127.0.0.1", "port": 18489, "users": [{"user": "lab", "pass": "test"}]}],
            }})
            profile["routing"]["rules"][0:0] = [
                {"type": "field", "domain": ["full:blocked.example.test"], "outboundTag": "BLOCK"},
                {"type": "field", "domain": ["geosite:category-ads-all"], "port": 18480, "outboundTag": "HTTP-TEST"},
                {"type": "field", "ip": ["geoip:private"], "port": 18480, "network": "tcp",
                 "inboundTag": [TAG], "user": [TEST_ID, ADDED_ID], "outboundTag": "HTTP-TEST"},
            ]
            # Preserve precedence of the localhost rule over the GeoIP route.
            rules = profile["routing"]["rules"]
            rules.insert(0, rules.pop(3))
            rules[0:0] = [
                {"type": "field", "domain": ["full:lab-socks.example.test"], "outboundTag": "SOCKS-TEST"},
                {"type": "field", "domain": ["full:lab-vless.example.test"], "outboundTag": "VLESS-TEST"},
                {"type": "field", "domain": ["full:plain.example.test"], "outboundTag": "VLESS-PLAIN-TEST"},
                {"type": "field", "domain": ["full:vision.example.test"], "outboundTag": "VISION-TEST"},
                {"type": "field", "domain": ["full:pin-mismatch.example.test"], "outboundTag": "PIN-MISMATCH-TEST"},
                {"type": "field", "network": "udp", "port": 18496, "outboundTag": "VISION-TEST"},
                {"type": "field", "network": "udp", "port": 18497, "outboundTag": "SOCKS-TEST"},
                {"type": "field", "network": "udp", "port": 18498, "outboundTag": "VLESS-PLAIN-TEST"},
            ]
        shadow = "--live-profile" in sys.argv
        tag = TAG
        if shadow:
            profile = json.loads((LAB / "shadow-profile.json").read_text())
            inbound = profile["inbounds"][0]
            tag = inbound["tag"]
            inbound["settings"]["clients"] = [{"id": original, "email": TEST_ID}]
            inbound["streamSettings"]["realitySettings"].update({
                "target": "127.0.0.1:18488", "serverNames": ["example.test"],
                "privateKey": private, "shortIds": [short_id, short_id_alt],
            })
            # Route the lab request to a local test proxy. The live DIRECT security policy stays in place.
            original_outbounds = len(profile["outbounds"])
            profile["outbounds"].append({"tag": "LAB-HTTP", "protocol": "http", "settings": {
                "servers": [{"address": "127.0.0.1", "port": 18489, "users": [{"user": "lab", "pass": "test"}]}],
            }})
            profile["routing"]["rules"].insert(0, {
                "type": "field", "network": "tcp", "port": 18480, "outboundTag": "LAB-HTTP"
            })
        torrent = "--torrent" in sys.argv
        test_mux = "--native" in sys.argv and not shadow and not torrent
        inbounds = [{"usersCount": 1, "tag": tag, "hash": "test"}]
        if "--xhttp" in sys.argv:
            xhttp_tag, xhttp_port, xhttp_path = "lab-xhttp", 18454, "/api/v2/sync"
            xhttp_account = str(uuid.uuid4())
            xhttp_email = "lab-xhttp-user"
            profile["inbounds"].append({
                "tag": xhttp_tag, "listen": "127.0.0.1", "port": xhttp_port, "protocol": "vless",
                "settings": {"decryption": "none", "clients": [{"id": xhttp_account, "email": xhttp_email}]},
                "streamSettings": {
                    "network": "xhttp", "security": "reality",
                    "xhttpSettings": {"path": xhttp_path, "mode": "stream-one"},
                    "realitySettings": profile["inbounds"][0]["streamSettings"]["realitySettings"],
                },
            })
            profile["routing"]["rules"].insert(0, {
                "type": "field", "inboundTag": [xhttp_tag], "network": "tcp",
                "ip": ["127.0.0.0/8"], "port": "18483", "outboundTag": "DIRECT",
            })
            inbounds.append({"usersCount": 1, "tag": xhttp_tag, "hash": "xhttp-test"})
        if test_mux:
            mux_account = str(uuid.uuid4())
            profile["inbounds"].append({
                "tag": WS_TAG, "listen": "127.0.0.1", "port": WS_PORT, "protocol": "vless",
                "settings": {"decryption": "none", "clients": [{"id": mux_account, "email": MUX_TEST_ID}]},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"], "routeOnly": True},
                "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/mux-test"}},
            })
            profile["routing"]["rules"].append({
                "type": "field", "inboundTag": [WS_TAG], "network": "tcp",
                "ip": ["127.0.0.0/8"], "port": "18480-18483", "outboundTag": "DIRECT",
            })
            inbounds.append({"usersCount": 1, "tag": WS_TAG, "hash": "mux-test"})
        plugin = None
        if torrent:
            profile["outbounds"][1]["settings"]["finalRules"][0]["port"] += ",18492"
            profile["routing"]["rules"].append({
                "type": "field", "network": "tcp", "port": 18492, "outboundTag": "DIRECT",
            })
            plugin = {"uuid": str(uuid.uuid4()), "name": "Torrent Blocker test", "config": {
                "torrentBlocker": {"enabled": True, "blockDuration": 60,
                                   "ignoreLists": {"ip": [], "userId": []}},
                "sharedLists": [],
            }}
            result = api("plugin/sync", {"plugin": plugin})
            assert result["accepted"], result
        status = api("xray/start", {
            "internals": {"hashes": {"emptyConfig": "nightvpn-test", "inbounds": inbounds},
                          "forceRestart": True},
            "xrayConfig": profile,
        })
        manifest = Path(__file__).with_name("Cargo.toml")
        version = tomllib.loads(manifest.read_text())["package"]["version"]
        assert status["isStarted"] and status["version"] == version, status
        api("stats/get-system-stats")
        print("PASS stock Remnanode 3.4.3 started Rust from abstract socket and read gRPC system stats")

        if "--xhttp" in sys.argv:
            start_xray_client(stack, stage, 11096, {
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "127.0.0.1", "port": xhttp_port,
                    "users": [{"id": xhttp_account, "encryption": "none"}],
                }]},
                "streamSettings": {
                    "network": "xhttp", "security": "reality",
                    "xhttpSettings": {"path": xhttp_path, "mode": "auto"},
                    "realitySettings": {"serverName": "example.test", "fingerprint": "firefox",
                                        "password": public, "shortId": short_id},
                },
            })
            request_through(11096, "https://127.0.0.1:18483/", upload=True)
            stats = api("stats/get-users-stats", {"reset": False})["users"]
            user = next(row for row in stats if row["username"] == xhttp_email)
            assert user["uplink"] >= len(BODY) and user["downlink"] >= len(BODY), user
            print("PASS XHTTP traffic is counted in both directions by Remnanode")

        client_flow = inbound["settings"]["flow"] if shadow else "xtls-rprx-vision"
        xray_client(stack, stage, original, client_flow, public, short_id, 11080)
        if torrent:
            torrent_check(stack, stage, original, public, short_id, plugin)
            stop_core()
            return
        if shadow:
            request_through(11080, "http://127.0.0.1:18480/")
            request_through(11080, "http://127.0.0.1:18484/", ok=False)
            print(f"PASS shadow of live profile, {original_outbounds} outbounds and {len(profile['routing']['rules'])-1} original rules loaded")
            stop_core()
            return
        request_through(11080, "http://127.0.0.1:18480/")
        request_through(11080, "https://localhost:18481/")
        request_through(11080, "https://127.0.0.1:18483/", upload=True)
        request_through(11080, "http://localhost:18480/", ok=False)
        request_through(11080, "http://127.0.0.1:18484/", ok=False)
        print("PASS first matching domain rule, DNS/IPIfNonMatch, CIDR, ports, inbound and default BLOCK")
        if features:
            request_through(11080, "http://doubleclick.net:18480/")
            request_through(11080, "http://lab-socks.example.test:18480/")
            request_through(11080, "http://lab-vless.example.test:18480/")
            request_through(11080, "http://plain.example.test:18480/", upload=True)
            request_through(11080, "http://vision.example.test:18480/")
            request_through(11080, "http://pin-mismatch.example.test:18480/", ok=False)
            request_through(11080, "http://127.0.0.1:18480/", ok=False, host="blocked.example.test")
            outbounds = api("stats/get-all-outbounds-stats", {"reset": False})
            assert all(tag in json.dumps(outbounds) for tag in
                       ("HTTP-TEST", "SOCKS-TEST", "VLESS-TEST", "VLESS-PLAIN-TEST", "VISION-TEST")), outbounds
            print("PASS GeoIP/GeoSite, sniffed HTTP Host, authenticated HTTP CONNECT, SOCKS, VLESS/TLS, Vision and outbound counters")
        datagrams(11080, 18486)
        datagrams(11080, 18487, blocked=True)
        if features and not companion:
            datagrams(11080, 18496)
            datagrams(11080, 18497)
            datagrams(11080, 18498)
            print("PASS XUDP over VLESS/Vision, UDP ASSOCIATE over SOCKS and TCP/UDP over plain VLESS")
        print("PASS Vision XUDP echo and UDP BLOCK")

        if test_mux:
            mux_port = 11082
            start_xray_client(stack, stage, mux_port, {
                "protocol": "vless",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": WS_PORT,
                                       "users": [{"id": mux_account, "encryption": "none"}]}]},
                "streamSettings": {"network": "ws", "wsSettings": {"path": "/mux-test?ed=2048"}},
                "mux": {"enabled": True, "concurrency": 8, "xudpConcurrency": 16,
                        "xudpProxyUDP443": "reject"},
            })
            with ThreadPoolExecutor(max_workers=8) as requests:
                futures = [
                    requests.submit(request_through, mux_port, "https://127.0.0.1:18483/", upload=True)
                    for _ in range(8)
                ]
                futures.append(requests.submit(request_through, mux_port, "http://127.0.0.1:18484/", ok=False))
                futures.append(requests.submit(datagrams, mux_port, 18486))
                for future in futures:
                    future.result()
            request_through(mux_port, "https://127.0.0.1:18483/")
            print("PASS concurrent TCP Mux over WebSocket, blocked stream isolation and XUDP")

        no_proxy = ssl.create_default_context(cafile=str(LAB / "ca.crt"))
        expected = ssl.PEM_cert_to_DER_cert((LAB / "site.crt").read_text())
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            no_proxy.minimum_version = version
            no_proxy.maximum_version = version
            with socket.create_connection(("127.0.0.1", CORE_PORT), timeout=3) as raw:
                with no_proxy.wrap_socket(raw, server_hostname="example.test") as client:
                    assert client.getpeercert(binary_form=True) == expected
                    client.sendall(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
                    reply = http.client.HTTPResponse(client)
                    reply.begin()
                    assert reply.status == 200 and reply.getheader("Strict-Transport-Security") == "max-age=86400"
                    assert reply.read() == BODY
        print("PASS ordinary browser TLS gets the configured origin certificate, HSTS and page")

        xray_client(stack, stage, added, "", public, short_id_alt, 11081)
        request_through(11081, "http://127.0.0.1:18480/", ok=False)
        result = api("handler/add-users", {"affectedInboundTags": [TAG], "users": [{
            "inboundData": [{"type": "vless", "tag": TAG, "flow": ""}],
            "userData": {"userId": ADDED_ID, "hashUuid": added, "vlessUuid": added,
                         "trojanPassword": "", "ssPassword": ""},
        }]})
        assert result["success"], result
        request_through(11081, "http://127.0.0.1:18480/")
        # Go's plain VLESS sends command UDP for port 53; other ports may use XUDP.
        datagrams(11081, 53)
        stats = api("stats/get-users-stats", {"reset": True})["users"]
        measured = {user["username"]: user for user in stats}
        assert measured[TEST_ID]["downlink"] >= len(BODY) * 3 and measured[TEST_ID]["uplink"] >= len(BODY), stats
        assert measured[ADDED_ID]["downlink"] >= len(BODY) and measured[ADDED_ID]["uplink"] > 0, stats
        reset = api("stats/get-users-stats", {"reset": False})["users"]
        assert all(user["downlink"] == user["uplink"] == 0 for user in reset), reset
        result = api("handler/remove-users", {"users": [{"userId": ADDED_ID, "hashUuid": added}]})
        assert result["success"], result
        request_through(11081, "http://127.0.0.1:18480/", ok=False)
        request_through(11080, "http://127.0.0.1:18480/")
        print("PASS dynamic user add/remove without restart, second Short ID, plain UDP and stats/reset")
        if test_mux:
            check_mux_accounting(stack, mux_port)
        stop_core()


if __name__ == "__main__":
    if "--shadowsocks" in sys.argv:
        check_shadowsocks()
    else:
        main()
