"""Run from the isolated test container with the stage mounted at /src."""
import hashlib
import http.server
import json
import os
import pathlib
import secrets
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from contextlib import ExitStack
from copy import deepcopy

ROOT = pathlib.Path(os.environ.get("NIGHTVPN_TEST_ROOT", "/src"))
XRAY = ROOT / "xray-go"
PROTOTYPE = ROOT / "prototype/target/release/nightvpn-xray-rust-prototype"
ORIGINS = (18480, 18481, 18483)
BODY = bytes(range(256)) * 4096


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        if self.rfile.read(int(self.headers["Content-Length"])) != BODY:
            self.send_error(400)
            return
        self.do_GET()

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *_):
        pass


class DotOrigin(socketserver.StreamRequestHandler):
    def handle(self):
        size = self.rfile.read(2)
        if not size:
            return
        request = self.rfile.read(struct.unpack("!H", size)[0])
        assert request[-4:] == b"\x00\x01\x00\x01"
        reply = (
            request[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
            + request[12:] + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
        )
        self.wfile.write(struct.pack("!H", len(reply)) + reply)


class ProxyProtocolRelay(socketserver.BaseRequestHandler):
    def handle(self):
        def copy(source, destination):
            try:
                while data := source.recv(65536):
                    destination.sendall(data)
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        with socket.create_connection(self.server.destination, timeout=5) as upstream:
            upstream.sendall(self.server.header)
            sender = threading.Thread(target=copy, args=(self.request, upstream))
            sender.start()
            copy(upstream, self.request)
            sender.join(timeout=5)


def wait_port(port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and process.poll() is None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"process failed to listen on {port}")


def run():
    with ExitStack() as stack:
        stage = pathlib.Path(stack.enter_context(tempfile.TemporaryDirectory()))
        key, cert = stage / "origin.key", stage / "origin.crt"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=localhost", "-keyout", key, "-out", cert],
            check=True, capture_output=True,
        )
        for port in ORIGINS:
            origin = stack.enter_context(http.server.ThreadingHTTPServer(("127.0.0.1", port), Origin))
            if port != ORIGINS[0]:
                tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                version = ssl.TLSVersion.TLSv1_2 if port == ORIGINS[1] else ssl.TLSVersion.TLSv1_3
                tls.minimum_version = version
                tls.maximum_version = version
                tls.load_cert_chain(cert, key)
                origin.socket = tls.wrap_socket(origin.socket, server_side=True)
            threading.Thread(target=origin.serve_forever, daemon=True).start()
            stack.callback(origin.shutdown)

        def write_config(name, data):
            path = stage / name
            path.write_text(json.dumps(data))
            return path

        def start(name, arguments, port, env=None):
            log = stack.enter_context(open(stage / f"{name}.log", "w+"))
            process = stack.enter_context(subprocess.Popen(arguments, stdout=log, stderr=log, env=env))

            def stop():
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                log.seek(0)
                print(f"{name} log:\n{log.read()[-3500:]}", flush=True)
            stack.callback(stop)
            wait_port(port, process)
            return process

        keys = subprocess.check_output([XRAY, "x25519"], text=True)
        keys = dict(line.split(": ", 1) for line in keys.splitlines() if ": " in line)
        private_key = keys["PrivateKey"]
        public_key = keys.get("Password (PublicKey)") or keys.get("Password") or keys.get("PublicKey")
        if not public_key:
            raise RuntimeError("Xray did not return a public key")
        short_id = secrets.token_hex(8)
        client_id = str(uuid.uuid4())
        server = {
            "listen": "127.0.0.1:18443",
            "targets": [f"127.0.0.1:{port}" for port in ORIGINS],
            "uuid": client_id,
            "server_name": "example.test",
            "client_version": [26, 7, 28],
            "short_id": short_id,
            "private_key": private_key,
        }
        start("rust", [PROTOTYPE, write_config("rust.json", server)], 18443)
        client = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"port": 11080, "listen": "127.0.0.1", "protocol": "socks"}],
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "127.0.0.1",
                    "port": 18443,
                    "users": [{"id": client_id, "flow": "xtls-rprx-vision", "encryption": "none"}],
                }]},
                "streamSettings": {
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "example.test",
                        "fingerprint": "chrome",
                        "password": public_key,
                        "shortId": short_id,
                    },
                },
            }],
        }

        def start_client(name, config, port):
            config["inbounds"][0]["port"] = port
            path = write_config(f"{name}.json", config)
            start(name, [XRAY, "run", "-c", path], port)

        def fetch(port, url, succeeds=True, upload=False):
            method = ["--data-binary", "@-"] if upload else []
            result = subprocess.run(
                ["curl", "-fkSs", "--max-time", "8", "--socks5-hostname",
                 f"127.0.0.1:{port}", *method, url],
                input=BODY if upload else None,
                capture_output=True,
            )
            if succeeds:
                assert result.returncode == 0, result.stderr.decode()
                assert result.stdout == BODY, f"body mismatch ({len(result.stdout)} bytes)"
                action = "upload and download" if upload else "download"
                print(f"PASS {action} {url}: {len(BODY)} bytes, sha256 {hashlib.sha256(BODY).hexdigest()}", flush=True)
            else:
                assert result.returncode != 0 and not result.stdout, "unexpected origin response"
                print(f"PASS rejection on SOCKS {port}", flush=True)

        start_client("vision", deepcopy(client), 11080)
        fetch(11080, f"http://127.0.0.1:{ORIGINS[0]}/")
        fetch(11080, f"https://127.0.0.1:{ORIGINS[1]}/")
        fetch(11080, f"https://127.0.0.1:{ORIGINS[2]}/", upload=True)
        assert "Vision uplink switched to direct" in (stage / "rust.log").read_text()
        fetch(11080, "http://127.0.0.1:18482/", succeeds=False)

        for name, port in (("plain", 11081), ("wrong-uuid", 11082), ("wrong-short-id", 11083)):
            config = deepcopy(client)
            outbound = config["outbounds"][0]
            user = outbound["settings"]["vnext"][0]["users"][0]
            if name == "plain":
                del user["flow"]
            if name == "wrong-uuid":
                user["id"] = str(uuid.uuid4())
            if name == "wrong-short-id":
                outbound["streamSettings"]["realitySettings"]["shortId"] = secrets.token_hex(8)
            start_client(name, config, port)
            fetch(port, f"http://127.0.0.1:{ORIGINS[0]}/", succeeds=name == "plain")

        proxy_port = 18449
        proxy_server = {
            "inbounds": [{
                "tag": "reality-proxy", "listen": "127.0.0.1", "port": proxy_port,
                "protocol": "vless",
                "settings": {"decryption": "none", "clients": [{
                    "id": client_id, "email": "proxy-test", "flow": "xtls-rprx-vision",
                }]},
                "streamSettings": {
                    "network": "raw", "security": "reality",
                    "sockopt": {"acceptProxyProtocol": True},
                    "realitySettings": {
                        "target": f"127.0.0.1:{ORIGINS[2]}", "serverNames": ["example.test"],
                        "privateKey": private_key, "shortIds": [short_id],
                    },
                },
            }],
            "outbounds": [{
                "tag": "direct", "protocol": "freedom",
                "settings": {"finalRules": [{
                    "action": "allow", "ip": ["127.0.0.1/32"], "port": str(ORIGINS[2]),
                }]},
            }],
        }
        start("rust-reality-proxy", [PROTOTYPE, write_config("reality-proxy.json", proxy_server)], proxy_port)
        headers = (
            b"PROXY TCP4 192.0.2.10 192.0.2.20 40123 443\r\n",
            b"\r\n\r\n\x00\r\nQUIT\n\x21\x21\x00\x24"
            + socket.inet_pton(socket.AF_INET6, "2001:db8::10")
            + socket.inet_pton(socket.AF_INET6, "2001:db8::20")
            + struct.pack("!HH", 40123, 443),
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        for version, header in enumerate(headers, start=1):
            relay = stack.enter_context(socketserver.ThreadingTCPServer(("127.0.0.1", 0), ProxyProtocolRelay))
            relay.destination = ("127.0.0.1", proxy_port)
            relay.header = header
            threading.Thread(target=relay.serve_forever, daemon=True).start()
            stack.callback(relay.shutdown)
            config = deepcopy(client)
            config["outbounds"][0]["settings"]["vnext"][0]["port"] = relay.server_address[1]
            socks_port = 11089 + version
            start_client(f"proxy-v{version}", config, socks_port)
            fetch(socks_port, f"https://127.0.0.1:{ORIGINS[2]}/", upload=True)
            with socket.create_connection(relay.server_address, timeout=3) as raw:
                with context.wrap_socket(raw, server_hostname="example.test") as tls:
                    assert ssl.DER_cert_to_PEM_cert(tls.getpeercert(binary_form=True)) == cert.read_text()
            print(f"PASS REALITY PROXY v{version}, Vision and TLS fallback", flush=True)
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as raw:
            try:
                with context.wrap_socket(raw, server_hostname="example.test"):
                    raise AssertionError("REALITY accepted a connection without a PROXY header")
            except (ConnectionResetError, ssl.SSLEOFError):
                print("PASS REALITY rejected a connection without a PROXY header", flush=True)

        xhttp_port = 18450
        xhttp_path = "/api/v2/sync"
        xhttp_server = deepcopy(proxy_server)
        xhttp_inbound = xhttp_server["inbounds"][0]
        xhttp_inbound.update(tag="reality-xhttp", port=xhttp_port)
        xhttp_inbound["settings"]["clients"][0].pop("flow")
        stream = xhttp_inbound["streamSettings"]
        stream.pop("sockopt")
        stream.update(network="xhttp", xhttpSettings={"path": xhttp_path, "mode": "stream-one"})
        start("rust-xhttp", [PROTOTYPE, write_config("rust-xhttp.json", xhttp_server)], xhttp_port)
        for index, mode in enumerate(("auto", "stream-one")):
            xhttp_client = deepcopy(client)
            outbound = xhttp_client["outbounds"][0]
            server = outbound["settings"]["vnext"][0]
            server["port"] = xhttp_port
            server["users"][0].pop("flow")
            stream = outbound["streamSettings"]
            stream.update(network="xhttp", xhttpSettings={"path": xhttp_path, "mode": mode})
            stream["realitySettings"]["fingerprint"] = "firefox"
            socks_port = 11092 + index
            start_client(f"xhttp-{mode}", xhttp_client, socks_port)
            fetch(socks_port, f"https://127.0.0.1:{ORIGINS[2]}/", upload=True)
        stream["xhttpSettings"]["path"] = "/wrong"
        start_client("xhttp-wrong-path", xhttp_client, 11094)
        fetch(11094, f"https://127.0.0.1:{ORIGINS[2]}/", succeeds=False)
        with socket.create_connection(("127.0.0.1", xhttp_port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname="example.test") as tls:
                assert ssl.DER_cert_to_PEM_cert(tls.getpeercert(binary_form=True)) == cert.read_text()
        print("PASS XHTTP/2 REALITY with Xray auto and stream-one, wrong path rejection and TLS fallback")

        grpc_server = deepcopy(xhttp_server)
        for index, security in enumerate(("reality", "none")):
            grpc_port = 18455 + index
            inbound = grpc_server["inbounds"][0]
            inbound.update(tag=f"grpc-{security}", port=grpc_port)
            inbound["streamSettings"] = {"network": "grpc", "security": security,
                                         "grpcSettings": {"serviceName": "syncV2", "multiMode": True}}
            if security == "reality":
                inbound["streamSettings"]["realitySettings"] = deepcopy(
                    xhttp_inbound["streamSettings"]["realitySettings"])
            start(f"rust-grpc-{security}", [PROTOTYPE, write_config(f"rust-grpc-{security}.json", grpc_server)], grpc_port)
            for multi in (False, True):
                grpc_client = deepcopy(xhttp_client)
                outbound = grpc_client["outbounds"][0]
                outbound["settings"]["vnext"][0]["port"] = grpc_port
                old_stream = outbound["streamSettings"]
                outbound["streamSettings"] = {"network": "grpc", "security": security,
                                               "grpcSettings": {"serviceName": "syncV2", "multiMode": multi}}
                if security == "reality":
                    outbound["streamSettings"]["realitySettings"] = old_stream["realitySettings"]
                socks_port = 11100 + index * 2 + multi
                start_client(f"grpc-{security}-{multi}", grpc_client, socks_port)
                fetch(socks_port, f"https://127.0.0.1:{ORIGINS[2]}/", upload=True)
        outbound["streamSettings"]["grpcSettings"]["serviceName"] = "wrong"
        start_client("grpc-wrong-path", grpc_client, 11104)
        fetch(11104, f"https://127.0.0.1:{ORIGINS[2]}/", succeeds=False)
        print("PASS gRPC REALITY and loopback h2c: Tun, TunMulti, upload/download and wrong service rejection")

        bridge_port = 18444
        bridge = {
            "inbounds": [{
                "tag": "bridge", "listen": "127.0.0.1", "port": bridge_port,
                "protocol": "vless",
                "settings": {
                    "decryption": "none", "flow": "xtls-rprx-vision",
                    "clients": [{"id": client_id}],
                },
                "streamSettings": {
                    "network": "raw", "security": "tls",
                    "tlsSettings": {
                        "minVersion": "1.2",
                        "certificates": [{
                            "certificate": cert.read_text().splitlines(),
                            "key": key.read_text().splitlines(),
                        }],
                    },
                },
            }],
            "outbounds": [{
                "tag": "DIRECT", "protocol": "freedom",
                "settings": {"finalRules": [{
                    "action": "allow", "ip": ["127.0.0.1/32"],
                    "port": ",".join(map(str, ORIGINS)),
                }]},
            }],
        }
        start("rust-bridge", [PROTOTYPE, write_config("rust-bridge.json", bridge)], bridge_port)
        der = ssl.PEM_cert_to_DER_cert(cert.read_text())
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            context = ssl.create_default_context(cafile=str(cert))
            context.minimum_version = version
            context.maximum_version = version
            context.set_alpn_protocols(["h2", "http/1.1"])
            with socket.create_connection(("127.0.0.1", bridge_port), timeout=3) as raw:
                with context.wrap_socket(raw, server_hostname="localhost") as conn:
                    assert conn.getpeercert(binary_form=True) == der
                    assert conn.selected_alpn_protocol() == "h2"
        bridge_client = deepcopy(client)
        outbound = bridge_client["outbounds"][0]
        outbound["settings"]["vnext"][0]["port"] = bridge_port
        outbound["streamSettings"] = {
            "network": "raw", "security": "tls",
            "tlsSettings": {"serverName": "localhost",
                            "pinnedPeerCertSha256": hashlib.sha256(der).hexdigest()},
        }
        start_client("tls-bridge", bridge_client, 11084)
        fetch(11084, f"http://127.0.0.1:{ORIGINS[0]}/")
        fetch(11084, f"https://127.0.0.1:{ORIGINS[2]}/", upload=True)
        outbound["settings"]["vnext"][0]["users"][0]["id"] = str(uuid.uuid4())
        start_client("tls-bridge-wrong-uuid", bridge_client, 11085)
        fetch(11085, f"http://127.0.0.1:{ORIGINS[0]}/", succeeds=False)
        print("PASS VLESS RAW TLS bridge with inline certificate, pinned Vision client and TLS 1.2/1.3")

        dot_key, dot_cert = stage / "dot.key", stage / "dot.crt"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
             "-addext", "basicConstraints=critical,CA:FALSE",
             "-keyout", dot_key, "-out", dot_cert],
            check=True, capture_output=True,
        )
        dot = stack.enter_context(socketserver.ThreadingTCPServer(("127.0.0.1", 0), DotOrigin))
        dot_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        dot_context.load_cert_chain(dot_cert, dot_key)
        dot.socket = dot_context.wrap_socket(dot.socket, server_side=True)
        threading.Thread(target=dot.serve_forever, daemon=True).start()
        stack.callback(dot.shutdown)
        dot_port = dot.server_address[1]

        for index, (host, blocked) in enumerate((("localhost", False), ("127.0.0.1", False),
                                                 ("localhost", True))):
            backend_port = 18446 + index
            socks_port = 11086 + index
            config = deepcopy(bridge)
            config["inbounds"][0]["port"] = backend_port
            config["dns"] = {"queryStrategy": "UseIPv4", "servers": [f"tls://{host}:{dot_port}"]}
            config["outbounds"][0]["settings"]["targetStrategy"] = "ForceIPv4"
            if blocked:
                config["outbounds"].append({"tag": "BLOCK", "protocol": "blackhole"})
                config["routing"] = {"rules": [
                    {"type": "field", "network": "tcp", "port": str(dot_port), "outboundTag": "BLOCK"},
                ]}
            name = f"dot-{index}"
            start(name, [PROTOTYPE, write_config(f"{name}.json", config)], backend_port,
                  env={**os.environ, "SSL_CERT_FILE": str(dot_cert)})
            outbound["settings"]["vnext"][0]["port"] = backend_port
            outbound["settings"]["vnext"][0]["users"][0]["id"] = client_id
            start_client(f"{name}-client", deepcopy(bridge_client), socks_port)
            fetch(socks_port, f"http://dot.example.test:{ORIGINS[0]}/", succeeds=index == 0)
        print("PASS DNS over TLS framing, certificate identity verification and TCP route ACL")


if __name__ == "__main__":
    run()
