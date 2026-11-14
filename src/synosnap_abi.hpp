#pragma once
// Independently described Linux LP64 ioctl layout, verified against the official agent
// 0.12.10 and Peppershade d04e7ee headers. No driver implementation is included.
#include <cstddef>
#include <cstdint>
#include <sys/ioctl.h>

namespace opensabba::synosnap_abi {
struct Setup {
    const char* origin;
    const char* cow;
    std::uint64_t allocated_mib;
    std::uint64_t cache_bytes;
    std::uint32_t minor;
    std::uint8_t ignore_errors;
};
static_assert(sizeof(Setup) == 40 && offsetof(Setup, minor) == 32 &&
              offsetof(Setup, ignore_errors) == 36);
struct Info {
    std::uint8_t cancelled;
    std::uint32_t minor;
    std::uint32_t flags;
    std::uint64_t state;
    std::int32_t error;
    std::uint64_t cache_size;
    std::uint64_t allocated_size;
    std::uint64_t sequence;
    std::uint8_t uuid[16];
    char cow[4096];
    char origin[4096];
    std::uint64_t version;
    std::uint64_t changed_blocks;
    std::uint8_t ignore_errors;
};
struct Renew {
    const char* cow;
    std::uint64_t allocated_mib;
    std::uint32_t minor;
};
struct Reload {
    const char* origin;
    const char* cow;
    std::uint64_t cache_bytes;
    std::uint32_t minor;
    std::uint8_t ignore_errors;
};
static_assert(sizeof(Reload) == 32 && offsetof(Reload,minor) == 24);
static_assert(sizeof(Renew) == 24 && offsetof(Renew, minor) == 16);
static_assert(sizeof(void*) == 8 && sizeof(unsigned long) == 8,
              "synosnap control requires a native Linux LP64 process");
static_assert(sizeof(Info) == 8288 && offsetof(Info, minor) == 4 &&
              offsetof(Info, state) == 16 && offsetof(Info, cow) == 72 &&
              offsetof(Info, origin) == 4168 && offsetof(Info, version) == 8264 &&
              offsetof(Info, ignore_errors) == 8280);
constexpr unsigned long info = _IOR('A', 8, Info);
constexpr unsigned long free_minor = _IOR('A', 9, std::int32_t);
constexpr unsigned long setup = _IOW('A', 1, Setup);
constexpr unsigned long reload_snapshot = _IOW('A',2,Reload);
constexpr unsigned long reload_incremental = _IOW('A',3,Reload);
constexpr unsigned long destroy = _IOW('A', 4, std::uint32_t);
constexpr unsigned long track = _IOW('A', 5, std::uint32_t);
constexpr unsigned long renew = _IOW('A', 6, Renew);
static_assert(track == 0x40044105UL && renew == 0x40184106UL);
static_assert(setup == 0x40284101UL && destroy == 0x40044104UL);
static_assert(reload_snapshot == 0x40204102UL && reload_incremental == 0x40204103UL);
static_assert(info == 0xa0604108UL && free_minor == 0x80044109UL);
}
