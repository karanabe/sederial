#!/usr/bin/env python3
"""Reviewable dependency allowlist for the runtime Linux graph, without extra crates."""
import argparse
import subprocess
import sys

ALLOWED = {
    "sederial", "toml", "toml_parser", "toml_datetime", "serde_spanned", "winnow",
    "signal-hook", "signal-hook-registry", "errno", "libc",
}
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--target", choices=["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"], default="x86_64-unknown-linux-gnu")
args = parser.parse_args()
tree = subprocess.check_output([
    "cargo", "tree", "--locked", "--edges=normal", "--prefix=none", "--format={p}",
    "--target", args.target,
], text=True)
names = {line.split()[0] for line in tree.splitlines() if line.strip()}
if names != ALLOWED:
    sys.exit(f"Dependency policy changed; review allowlist. Added: {names - ALLOWED}, removed: {ALLOWED - names}")
print(f"Dependency policy passed ({args.target}): {len(names) - 1} runtime crates; no error framework or async runtime.")
