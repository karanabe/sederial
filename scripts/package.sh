#!/bin/sh
# Package an already built Linux binary. No cross-compilation or downloads here.
set -eu
umask 022
if [ "$#" -ne 3 ]; then
    echo 'Usage: scripts/package.sh VERSION TARGET BINARY' >&2
    exit 2
fi
version=$1
target=$2
binary=$(realpath "$3")
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "$version" in ''|*[!0-9.]*|.*|*.) echo 'Expected numeric X.Y.Z version' >&2; exit 2;; esac
if ! echo "$version" | awk -F. 'NF == 3 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {ok=1} END {exit !ok}'; then
    echo 'Expected numeric X.Y.Z version' >&2; exit 2
fi
case "$target" in
    x86_64-unknown-linux-gnu) arch=amd64; machine='Advanced Micro Devices X86-64';;
    aarch64-unknown-linux-gnu) arch=arm64; machine='AArch64';;
    *) echo "Unsupported release target: $target" >&2; exit 2;;
esac
if ! LC_ALL=C readelf -h "$binary" | grep -F "$machine" >/dev/null; then
    echo "Binary architecture does not match $target" >&2; exit 2
fi
manifest_version=$(python3 -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["package"]["version"])' "$root/Cargo.toml")
if [ "$version" != "$manifest_version" ]; then
    echo "Version $version does not match Cargo.toml ($manifest_version)" >&2; exit 2
fi
mkdir -p "$root/dist"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
pkg=$stage/package
install -D -m 755 "$binary" "$pkg/usr/bin/sederial"
install -D -m 644 "$root/packaging/sederial.toml" "$pkg/etc/sederial/sederial.toml"
install -D -m 644 "$root/packaging/sederial.service" "$pkg/usr/lib/systemd/system/sederial.service"
mkdir -p "$pkg/usr/share/doc/sederial" "$pkg/DEBIAN"
install -m 644 "$root/README.md" "$root/RFC-COMPLIANCE.md" "$pkg/usr/share/doc/sederial/"
python3 "$root/scripts/licenses.py" "$target" "$pkg/usr/share/doc/sederial"
printf '/etc/sederial/sederial.toml\n' > "$pkg/DEBIAN/conffiles"
for script in postinst prerm postrm; do
    install -m 755 "$root/packaging/debian/$script" "$pkg/DEBIAN/$script"
done
# Derive the glibc floor from the actual ELF instead of claiming an older ABI.
glibc=$(LC_ALL=C readelf --version-info "$binary" | sed -n 's/.*Name: GLIBC_\([0-9.]*\).*/\1/p' | sort -Vu | tail -n 1)
if [ -z "$glibc" ]; then echo 'Expected a dynamically linked GNU/Linux binary' >&2; exit 2; fi
cat > "$pkg/DEBIAN/control" <<EOF
Package: sederial
Version: $version
Section: net
Priority: optional
Architecture: $arch
Maintainer: karanabe <karanabe@users.noreply.github.com>
Depends: libc6 (>= $glibc), libgcc-s1, adduser, init-system-helpers (>= 1.54)
Installed-Size: $(du -sk "$pkg/usr" "$pkg/etc" | awk '{total += $1} END {print total}')
Description: Lightweight DNS forwarder for split-DNS environments
 Routes DNS requests using longest domain suffix matching and forwards them
 over UDP and TCP with bounded resource usage. Includes systemd integration.
EOF
# Fixed timestamps and ordering make repeated packaging of the same binary reproducible.
epoch=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}
case "$epoch" in ''|*[!0-9]*) echo 'SOURCE_DATE_EPOCH must be an integer' >&2; exit 2;; esac
export SOURCE_DATE_EPOCH=$epoch
find "$pkg" -exec touch -h -d "@$epoch" {} +
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$root/dist/sederial_${version}_${arch}.deb"
archive=$stage/archive
mkdir -p "$archive"
install -m 755 "$binary" "$archive/sederial"
cp -R "$pkg/usr/share/doc/sederial/." "$archive/"
install -m 644 "$root/packaging/sederial.toml" "$root/packaging/sederial.service" "$archive/"
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -C "$archive" -cf - . \
    | gzip -n > "$root/dist/sederial-${target}.tar.gz"
echo "Built $target artifacts in $root/dist (glibc >= $glibc)"
