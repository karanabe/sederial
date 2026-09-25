#!/usr/bin/env python3
"""Collect unmodified license/notice sources for the locked target runtime graph.

Usage: python3 scripts/licenses.py TARGET OUTPUT_DIRECTORY
Run after building with the pinned toolchain. Cargo is offline; this does not fetch.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def output(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True)


def collect(target):
    tree = output("cargo", "tree", "--offline", "--locked", "--target", target,
                  "--edges=normal", "--prefix=none", "--format={p}")
    runtime = {tuple(line.split()[:2]) for line in tree.splitlines()}
    metadata = json.loads(output("cargo", "metadata", "--offline", "--locked",
                                 "--filter-platform", target, "--format-version=1"))
    files = {name: (ROOT / name).read_bytes() for name in ["LICENSE-MIT", "LICENSE-APACHE"]}
    copyright_text = ["Sederial\nSource: https://github.com/karanabe/sederial\n",
                      "License: MIT OR Apache-2.0\n", files["LICENSE-MIT"].decode(),
                      files["LICENSE-APACHE"].decode()]
    found = set()
    for package in sorted(metadata["packages"], key=lambda p: p["name"]):
        identity = (package["name"], "v" + package["version"])
        if identity not in runtime:
            continue
        found.add(identity)
        if package["name"] == "sederial":
            continue
        assert package["license"] in {"MIT", "MIT OR Apache-2.0", "Apache-2.0 OR MIT"}, identity
        source = Path(package["manifest_path"]).parent
        notices = sorted(p for p in source.iterdir() if p.is_file()
                         and p.name.upper().startswith(("LICENSE", "COPYRIGHT", "NOTICE")))
        assert any(p.name == "LICENSE-MIT" for p in notices), identity
        copyright_text.append(f"\nDependency: {package['name']} {package['version']}\n"
                              f"Source: {package['repository']}\nLicense: {package['license']}\n")
        for notice in notices:
            data = notice.read_bytes()
            assert data.strip(), notice
            files[f"third-party/{package['name']}-{package['version']}/{notice.name}"] = data
            copyright_text.extend([f"\n{notice.name}:\n", data.decode()])
    assert found == runtime, (found, runtime)
    # rustc links the standard library statically. Use the toolchain's own
    # library attribution, including its third-party licenses, without guessing.
    sysroot = Path(output("rustc", "--print", "sysroot").strip())
    rust_notice = sysroot / "share/doc/rust/COPYRIGHT-library.html"
    rust_data = rust_notice.read_bytes()
    assert b"Rust" in rust_data and b"Copyright" in rust_data and len(rust_data) > 1000
    files["third-party/rust-COPYRIGHT-library.html"] = rust_data
    copyright_text.append("\nRust standard library and its dependencies:\n"
                          "See third-party/rust-COPYRIGHT-library.html for the toolchain's\n"
                          "original copyright and full license notices. This upstream file\n"
                          "includes library components beyond those used by this binary.\n")
    files["copyright"] = "\n".join(copyright_text).encode()
    files["licenses.json"] = (json.dumps({
        "target": target,
        "rustc": output("rustc", "--version").strip(),
        "runtime": sorted(" ".join(item) for item in runtime),
        "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())},
    }, indent=2) + "\n").encode()
    return files


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    for name, data in collect(sys.argv[1]).items():
        destination = Path(sys.argv[2]) / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
