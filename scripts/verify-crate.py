#!/usr/bin/env python3
"""Build, test and package the actual .crate in a directory outside the checkout."""
import argparse
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("crate", type=Path)
parser.add_argument("--target", required=True,
                    choices=["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"])
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix="sederial-crate-") as temporary:
    directory = Path(temporary)
    with tarfile.open(args.crate) as archive:
        archive.extractall(directory, filter="data")
    source, = directory.iterdir()
    # Never share fingerprints with the checkout or package verification build.
    env = dict(os.environ, CARGO_TARGET_DIR=str(directory / "build"), SOURCE_DATE_EPOCH="0")
    def run(*command):
        subprocess.run(command, cwd=source, env=env, check=True)
    run("cargo", "test", "--locked", "--offline", "--target", args.target)
    run("cargo", "build", "--release", "--locked", "--offline", "--target", args.target)
    import tomllib
    version = tomllib.loads((source / "Cargo.toml").read_text())["package"]["version"]
    binary = directory / "build" / args.target / "release/sederial"
    run("sh", "scripts/package.sh", version, args.target, str(binary))
    run("python3", "scripts/verify-artifacts.py", version, args.target, "--native")
    run("python3", "tests/standalone_smoke.py", str(binary))
print("Crate source independently built, tested, packaged and smoke tested")
