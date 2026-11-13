"""Run an isolated stock Remnanode on the server with ephemeral panel credentials."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def credentials(path):
    def openssl(*args, **kwargs):
        return run("openssl", *args, cwd=path, stderr=subprocess.DEVNULL, **kwargs)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=NightVPN lab CA", "-keyout", "ca.key", "-out", "ca.crt")
    for name, usage in (("node", "serverAuth"), ("panel", "clientAuth"), ("site", "serverAuth")):
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}",
                "-keyout", f"{name}.key", "-out", f"{name}.csr")
        (path / "extensions").write_text(
            f"extendedKeyUsage={usage}\nsubjectAltName=IP:127.0.0.1,DNS:example.test\n"
        )
        openssl("x509", "-req", "-days", "1", "-in", f"{name}.csr", "-CA", "ca.crt",
                "-CAkey", "ca.key", "-CAcreateserial", "-extfile", "extensions", "-out", f"{name}.crt")
    openssl("pkey", "-in", "panel.key", "-pubout", "-out", "panel.pub")
    payload = {
        "caCertPem": (path / "ca.crt").read_text(),
        "nodeCertPem": (path / "node.crt").read_text(),
        "nodeKeyPem": (path / "node.key").read_text(),
        "jwtPublicKey": (path / "panel.pub").read_text(),
    }
    secret = base64.b64encode(json.dumps(payload).encode()).decode()
    (path / "node.env").write_text(f"NODE_PORT=13001\nSECRET_KEY={secret}\nSNI_VERIFICATION=false\n")
    body = b".".join([
        b64(b'{"alg":"RS256","typ":"JWT"}'),
        b64(json.dumps({"sub": "integration-test", "exp": int(time.time()) + 900}).encode()),
    ])
    signature = openssl("dgst", "-sha256", "-sign", "panel.key", input=body, stdout=subprocess.PIPE).stdout
    (path / "token").write_bytes(body + b"." + b64(signature))


def production_fixture(path):
    live = json.loads(run("docker", "exec", "remnanode", "cli", "--dump-config-raw",
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout)
    new_id = str(uuid.uuid4())
    def scrub(value):
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if isinstance(value, dict):
            clean = {}
            for key, item in value.items():
                if key == "id":
                    clean[key] = new_id
                elif key in ("password", "pass", "user", "privateKey"):
                    clean[key] = "nightvpn-lab"
                elif key in ("address", "url") and isinstance(item, str):
                    clean[key] = "@nightvpn-lab:/internal/webhook?token=lab" if key == "url" else "127.0.0.1"
                else:
                    clean[key] = scrub(item)
            return clean
        return value
    selected = {key: live[key] for key in ("outbounds", "routing")}
    selected = scrub(selected)
    selected["inbounds"] = []
    for source in live["inbounds"]:
        if source["protocol"] != "vless":
            continue
        stream = source["streamSettings"]
        reality = stream["realitySettings"]
        selected["inbounds"].append({
            "tag": source["tag"], "protocol": "vless", "listen": "127.0.0.1",
            "port": 18443, "settings": {"decryption": source["settings"]["decryption"],
                                       "flow": source["settings"].get("flow", ""), "clients": []},
            "sniffing": source["sniffing"],
            "streamSettings": {"network": stream["network"], "security": stream["security"],
                "sockopt": stream.get("sockopt", {}),
                "realitySettings": {k: v for k, v in reality.items()
                    if k in ("xver", "show", "minClientVer", "maxClientVer", "maxTimeDiff")}},
        })
    assert len(selected["inbounds"]) == 1
    assert len(selected["routing"]["rules"]) == len(live["routing"]["rules"])
    (path / "shadow-profile.json").write_text(json.dumps(selected))


def main():
    os.umask(0o077)
    stage = Path(sys.argv[1]).resolve(strict=True)
    core = stage / "prototype/target/release/nightvpn-xray-rust-prototype"
    assert core.is_file()
    name = f"nightvpn-rust-remna-{uuid.uuid4().hex[:8]}"
    with tempfile.TemporaryDirectory(prefix="nightvpn-test-") as tmp:
        path = Path(tmp)
        credentials(path)
        shadow = "--live-profile" in sys.argv
        torrent = "--torrent" in sys.argv
        native = "--native" in sys.argv
        companion = not native and (shadow or torrent or "--companion" in sys.argv)
        if shadow:
            production_fixture(path)
        extra = []
        if companion:
            extra += ["-e", "NIGHTVPN_ROUTE_CORE=/opt/route-xray", "--mount", f"type=bind,src={stage}/xray-go,dst=/opt/route-xray,readonly"]
        if "--splice" in sys.argv:
            extra += ["-e", "NIGHTVPN_SPLICE=1"]
        run(
            "docker", "run", "-d", "--name", name, "--network", "none",
            "--cpus", "2", "--memory", "768m", "--env-file", str(path / "node.env"),
            "--mount", f"type=bind,src={core},dst=/usr/local/bin/xray,readonly",
            *extra, *(["--cap-add", "NET_ADMIN"] if torrent else []), "remnawave/node:3.4.3", stdout=subprocess.DEVNULL,
        )
        try:
            run(
                "docker", "run", "--rm", "--network", f"container:{name}", "--cpus", "2",
                "--memory", "512m", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev",
                "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges",
                "--mount", f"type=bind,src={stage},dst=/src,readonly",
                "--mount", f"type=bind,src={path},dst=/lab,readonly",
                "rust:bookworm", "python3", "-u", "/src/prototype/test_node_client.py",
                *(["--companion"] if companion else []), *(["--live-profile"] if shadow else []),
                *(["--torrent"] if torrent else []),
                *(["--native"] if native else []),
                *(["--shadowsocks"] if "--shadowsocks" in sys.argv else []),
                *(["--xhttp"] if "--xhttp" in sys.argv else []),
            )
            processes = run("docker", "top", name, "-eo", "pid,comm",
                            stdout=subprocess.PIPE, text=True).stdout.splitlines()
            assert not any(row.split()[-1] in ("route-xray", "rw-core", "xray") for row in processes[1:]), processes
            print("PASS Remnanode stop closed the listener and reaped the routing companion")
        except subprocess.CalledProcessError:
            subprocess.run(["docker", "exec", name, "tail", "-n", "45", "/var/log/xray/current"], check=False)
            raise
        finally:
            run("docker", "rm", "-f", name, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
