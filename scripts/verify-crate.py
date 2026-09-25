#!/usr/bin/env python3
"""Build, test and smoke test the actual .crate outside the checkout."""
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
root = Path(__file__).resolve().parent.parent
toolchain = subprocess.check_output(["rustup", "show", "active-toolchain"], text=True).split()[0]
with tempfile.TemporaryDirectory(prefix="sederial-crate-") as temporary:
    directory = Path(temporary)
    with tarfile.open(args.crate) as archive:
        archive.extractall(directory, filter="data")
    source, = directory.iterdir()
    # Never share fingerprints with the checkout or package verification build.
    # Keep the caller's selected toolchain after leaving the repository, even
    # though rust-toolchain.toml is intentionally absent from the crate.
    env = dict(os.environ, CARGO_TARGET_DIR=str(directory / "build"), RUSTUP_TOOLCHAIN=toolchain)
    def run(*command):
        subprocess.run(command, cwd=source, env=env, check=True)
    run("cargo", "test", "--locked", "--offline", "--target", args.target)
    run("cargo", "build", "--release", "--locked", "--offline", "--target", args.target)
    binary = directory / "build" / args.target / "release/sederial"
    run("python3", str(root / "tests/standalone_smoke.py"), str(binary))
print("Crate source independently built, tested and smoke tested")
