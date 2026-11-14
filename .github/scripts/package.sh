#!/bin/sh
set -eu
version=$1
arch=$2
cmake -S . -B build-product -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build-product --parallel 2
mkdir -p dist
(cd build-product && cpack -G DEB -B ../dist)
deb="dist/opensabba_${version}_${arch}.deb"
test -f "$deb"
dpkg-deb -I "$deb"
dpkg-deb -c "$deb"
# Installation only lays down files; no service or initramfs mutation is automatic.
controls=$(dpkg-deb --ctrl-tarfile "$deb" | tar -tf -)
if printf '%s
' "$controls" | grep -E '(^|/)(preinst|postinst|prerm|postrm|triggers)$'; then
  echo "Unexpected package maintainer scripts or triggers" >&2
  exit 1
fi
# Archive the same product-only install tree, retaining installed unit/hook paths.
DESTDIR="$PWD/stage" cmake --install build-product
tar -C stage -czf "dist/opensabba-${version}-linux-${arch}.tar.gz" .
python3 .github/scripts/check-archive.py "dist/opensabba-${version}-linux-${arch}.tar.gz" "$version"
