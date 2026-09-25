#!/usr/bin/env python3
"""Check real package/archive contents and optional native executable behavior."""
import argparse
from pathlib import Path
import subprocess
import tarfile
import tempfile
from licenses import collect

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
    expected = collect(args.target)
    for directory in [deb / "usr/share/doc/sederial", root / "tar"]:
        for name, original in expected.items():
            actual = (directory / name).read_bytes()
            assert actual.strip() and actual == original, f"missing or changed attribution: {name}"
        copyright_text = (directory / "copyright").read_text()
        assert "Copyright (c) 2026 karanabe" in copyright_text
        assert "Permission is hereby granted" in copyright_text
        assert "Apache License" in copyright_text
        assert (directory / "RFC-COMPLIANCE.md").read_bytes() == Path("RFC-COMPLIANCE.md").read_bytes()
    # Check the dependency floor against the packaged executable itself.
    import re
    versions = re.findall(r"Name: GLIBC_([0-9.]+)", output("readelf", "--version-info", deb / "usr/bin/sederial"))
    floor = max(versions, key=lambda value: tuple(map(int, value.split("."))))
    assert f"libc6 (>= {floor})" in output("dpkg-deb", "-f", package, "Depends")
    machine = {"amd64": "Advanced Micro Devices X86-64", "arm64": "AArch64"}[arch]
    assert machine in output("readelf", "-h", deb / "usr/bin/sederial")
    if args.native:
        assert output(deb / "usr/bin/sederial", "--version") == f"sederial {args.version}"
        subprocess.run([deb / "usr/bin/sederial", "--config", deb / "etc/sederial/sederial.toml", "--check"], check=True)
print(f"Verified {package} and {archive}")
