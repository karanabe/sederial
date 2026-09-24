#!/usr/bin/env python3
"""Check real package/archive contents and optional native executable behavior."""
import argparse
from pathlib import Path
import subprocess
import tarfile
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("version")
parser.add_argument("target", choices=["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"])
parser.add_argument("--native", action="store_true")
args = parser.parse_args()
arch = {"x86_64-unknown-linux-gnu": "amd64", "aarch64-unknown-linux-gnu": "arm64"}[args.target]
package = Path(f"dist/sederial_{args.version}_{arch}.deb")
archive = Path(f"dist/sederial-{args.target}.tar.gz")

def output(*command):
    return subprocess.check_output(command, text=True).strip()

assert output("dpkg-deb", "-f", package, "Package") == "sederial"
assert output("dpkg-deb", "-f", package, "Version") == args.version
assert output("dpkg-deb", "-f", package, "Architecture") == arch
assert "libc6 (>= " in output("dpkg-deb", "-f", package, "Depends")
with tempfile.TemporaryDirectory(prefix="sederial-artifact-") as temp:
    root = Path(temp)
    subprocess.run(["dpkg-deb", "-R", package, root / "deb"], check=True)
    deb = root / "deb"
    assert (deb / "DEBIAN/conffiles").read_text() == "/etc/sederial/sederial.toml\n"
    for path in ["usr/bin/sederial", "etc/sederial/sederial.toml", "usr/lib/systemd/system/sederial.service",
                 "usr/share/doc/sederial/README.md"]:
        assert (deb / path).is_file(), path
    for script in ["postinst", "prerm", "postrm"]:
        assert (deb / "DEBIAN" / script).stat().st_mode & 0o111
        subprocess.run(["sh", "-n", deb / "DEBIAN" / script], check=True)
    with tarfile.open(archive) as tar:
        assert all(member.uid == member.gid == 0 for member in tar.getmembers())
        tar.extractall(root / "tar", filter="data")
    assert (root / "tar/sederial").read_bytes() == (deb / "usr/bin/sederial").read_bytes()
    assert (root / "tar/README.md").is_file()
    if args.native:
        assert output(deb / "usr/bin/sederial", "--version") == f"sederial {args.version}"
        subprocess.run([deb / "usr/bin/sederial", "--config", deb / "etc/sederial/sederial.toml", "--check"], check=True)
print(f"Verified {package} and {archive}")
