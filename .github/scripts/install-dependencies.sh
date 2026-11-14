#!/bin/sh
set -eu
apt-get update
# Compiler/CMake/OpenSSL/LZ4/Python are documented build/test dependencies.
# e2fsprogs + xfsprogs create independent filesystem specimens; lvm2,
# thin-provisioning-tools, util-linux, kmod and udev run lvm_kernel_layouts.
# dpkg-dev supplies dpkg-shlibdeps for CPack's dependency calculation.
apt-get install -y --no-install-recommends \
  build-essential cmake libssl-dev liblz4-dev openssl python3 \
  e2fsprogs xfsprogs lvm2 thin-provisioning-tools util-linux kmod udev dpkg-dev
