# OpenSabba

OpenSabba is an experimental C++20 command-line client for Synology Active Backup for Business, targeting 64-bit Linux and Raspberry Pi Debian ARM64.

Implemented features include authentication/registration, background service operation, task discovery, full/incremental machine backup, snapshot tracking, durable upload resume/recovery, NAS events, regular-file/directory restore, HTTP CONNECT proxies, bandwidth policy and diagnostic export. Storage layouts, kernels and unattended recovery need deployment-specific validation.

Snapshots require the separate [synosnap fork](https://github.com/Peppershade/abb-linux-agent), built for the running kernel with its [read-ordering fix](docs/snapshot-read-ordering.md). Driver source/modules are not included.

## Build and test

Dependencies: C++20, CMake 3.20+, OpenSSL 3, LZ4 and Python 3.11+ for tests.

```sh
sudo apt install build-essential cmake libssl-dev liblz4-dev python3
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

Set `-DBUILD_TESTING=OFF` for product-only builds. Testing builds the uninstalled diagnostic executable `opensabba-lab`. Linux-only fixtures need local filesystem/device facilities; portable tests also build on Windows with MSYS2 UCRT64.

Zig ARM64 cross-builds use an external Debian ARM64 sysroot containing OpenSSL 3 and LZ4:

```sh
cmake -S . -B build-arm64 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/linux-arm64-zig.cmake \
  -DZIG_EXECUTABLE=/path/to/zig -DOPENSABBA_ARM64_OPENSSL_ROOT=/path/to/arm64-sysroot \
  -DBUILD_TESTING=OFF
cmake --build build-arm64 -j2
```

No toolchain binaries are included. See [Raspberry Pi notes](docs/raspberry-pi.md), [usage](docs/usage.md) and [CLI reference](docs/cli-parity.md).

## License and notice

OpenSabba is licensed under the [Mozilla Public License 2.0](LICENSE) (MPL-2.0). Its Unicode-derived NTLM uppercase table uses [Unicode License v3](LICENSES/Unicode-3.0.txt). The separate driver has its own license.

OpenSabba is an independent project, not affiliated with or endorsed by Synology. Synology and Active Backup for Business are trademarks of Synology Inc.
