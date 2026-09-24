#!/usr/bin/env python3
"""Run only inside a disposable root container/CI VM; installs and purges Sederial."""
import argparse
import hashlib
import os
from pathlib import Path
import pwd
import socket
import struct
import subprocess
import tempfile
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument("--disposable-system", action="store_true", required=True)
parser.add_argument("--systemd", action="store_true")
parser.add_argument("package", type=Path)
args = parser.parse_args()
assert os.geteuid() == 0, "Run only in a disposable root test environment"
config = Path("/etc/sederial/sederial.toml")
unit = Path("/usr/lib/systemd/system/sederial.service")
process = None
stop = threading.Event()
mock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
mock.bind(("127.0.0.1", 0))
mock.settimeout(0.1)
port = mock.getsockname()[1]

def run(*command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)

def responder():
    while not stop.is_set():
        try:
            data, peer = mock.recvfrom(65535)
        except socket.timeout:
            continue
        reply = bytearray(data)
        reply[2:4] = b"\x81\x80"
        mock.sendto(reply, peer)

worker = threading.Thread(target=responder)
worker.start()
query = bytes.fromhex("123401000001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"

def resolves():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(0.2)
        for _ in range(40):
            try:
                client.sendto(query, ("127.0.0.1", 53))
                reply, source = client.recvfrom(65535)
                assert source == ("127.0.0.1", 53)
                assert reply[:2] == query[:2] and reply[3] & 15 == 0
                return
            except socket.timeout:
                time.sleep(0.05)
        raise AssertionError("installed service did not answer on port 53")

def main_pid():
    return int(subprocess.check_output(["systemctl", "show", "sederial", "-p", "MainPID", "--value"], text=True))

try:
    run("apt-get", "install", "--yes", str(args.package.resolve()))
    user = pwd.getpwnam("sederial")
    assert user.pw_uid != 0 and user.pw_shell.endswith("nologin")
    assert unit.is_file()
    if args.systemd:
        assert subprocess.run(["systemctl", "is-active", "--quiet", "sederial"]).returncode != 0
        assert subprocess.run(["systemctl", "is-enabled", "--quiet", "sederial"]).returncode != 0
        run("dpkg", "-i", str(args.package.resolve()))
        assert subprocess.run(["systemctl", "is-active", "--quiet", "sederial"]).returncode != 0
    config.write_text(f"# local administrator change\nlisten='127.0.0.1:53'\n[default]\nservers=['127.0.0.1:{port}']\n")
    digest = hashlib.sha256(config.read_bytes()).digest()
    run("systemd-analyze", "verify", str(unit))
    if args.systemd:
        run("systemctl", "enable", "--now", "sederial")
        resolves()
        pid = main_pid()
    else:
        process = subprocess.Popen(["setpriv", "--reuid=sederial", "--regid=sederial", "--init-groups",
            "--inh-caps=+net_bind_service", "--ambient-caps=+net_bind_service", "--bounding-set=-all,+net_bind_service",
            "/usr/bin/sederial"])
        resolves()
        pid = process.pid
    status = Path(f"/proc/{pid}/status").read_text().splitlines()
    fields = dict(line.split(":", 1) for line in status if ":" in line)
    assert int(fields["Uid"].split()[0]) == user.pw_uid
    assert int(fields["CapEff"].strip(), 16) == 1 << 10  # CAP_NET_BIND_SERVICE only
    # A package with changed defaults and a higher version exercises dpkg's
    # actual conffile upgrade decision, rather than just reinstalling identical bytes.
    with tempfile.TemporaryDirectory(prefix="sederial-upgrade-") as temp:
        root = Path(temp) / "root"
        run("dpkg-deb", "-R", str(args.package), str(root))
        control = root / "DEBIAN/control"
        control.write_text("\n".join(line + "+test1" if line.startswith("Version:") else line
                                      for line in control.read_text().splitlines()) + "\n")
        with (root / "etc/sederial/sederial.toml").open("a") as f:
            f.write("\n# changed packaged default\n")
        upgrade = Path(temp) / "upgrade.deb"
        run("dpkg-deb", "--root-owner-group", "--build", str(root), str(upgrade))
        run("dpkg", "--force-confold", "-i", str(upgrade))
    assert hashlib.sha256(config.read_bytes()).digest() == digest
    resolves()
    if args.systemd:
        assert main_pid() != pid, "active service was not restarted on upgrade"
        run("systemctl", "restart", "sederial")
        resolves()
        run("systemctl", "status", "--no-pager", "sederial")
        run("systemctl", "stop", "sederial")
        assert subprocess.run(["systemctl", "is-active", "--quiet", "sederial"]).returncode != 0
        run("systemctl", "start", "sederial")
        resolves()
    else:
        process.terminate()
        assert process.wait(timeout=5) == 0
        process = None
    run("dpkg", "--remove", "sederial")
    assert config.is_file() and hashlib.sha256(config.read_bytes()).digest() == digest
    if args.systemd:
        assert subprocess.run(["systemctl", "is-active", "--quiet", "sederial"]).returncode != 0
    run("dpkg", "--purge", "sederial")
    assert not config.exists() and not unit.exists()
    assert not Path("/etc/systemd/system/multi-user.target.wants/sederial.service").is_symlink()
    print("Package lifecycle, modified conffile, non-root port 53 and capability checks passed")
finally:
    if process is not None:
        process.terminate()
        process.wait(timeout=5)
    if args.systemd and unit.exists():
        subprocess.run(["systemctl", "stop", "sederial"], check=False)
    if config.exists() or unit.exists():
        subprocess.run(["dpkg", "--purge", "sederial"], check=False)
    stop.set()
    worker.join(timeout=2)
    mock.close()
