# Raspberry Pi and Debian ARM64

The target is 64-bit Debian (`aarch64`, Debian `arm64`). Dependencies are C++20, CMake 3.20+, OpenSSL 3 and LZ4. Tests need Python 3.11+ and a POSIX shell.

```sh
sudo apt install build-essential cmake libssl-dev liblz4-dev openssl python3 e2fsprogs xfsprogs lvm2 thin-provisioning-tools util-linux kmod udev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
sudo cmake --install build
```

Reduce parallelism on memory-limited boards. CMake can generate a Debian package. Driver compilation needs matching kernel headers; user-space cross compilation does not build a module.

Install the separate [synosnap fork](https://github.com/Peppershade/abb-linux-agent) with its [read-ordering fix](snapshot-read-ordering.md). Validate the exact kernel/filesystem combination; healthy status alone cannot prove snapshot consistency.

Capture normally needs root in the host mount namespace. Allow space for COW growth and private work files. Each origin owns its COW; journals/raw caches use separate storage. Windows supports development and portable tests; machine capture needs Linux.

See [usage](usage.md), [authentication](authentication.md), [proxy](proxy.md) and [startup](service-startup.md). NAS port defaults to 5510.
