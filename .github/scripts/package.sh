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
# Archive the same product-only install tree, retaining installed unit/hook paths.
DESTDIR="$PWD/stage" cmake --install build-product
tar -C stage -czf "dist/opensabba-${version}-linux-${arch}.tar.gz" .
