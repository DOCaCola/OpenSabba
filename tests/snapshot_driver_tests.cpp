#include "opensabba/snapshot_driver.hpp"
#include "opensabba/capture.hpp"
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <fcntl.h>
#include <sys/file.h>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <vector>

namespace {
using opensabba::pstream::Value;
std::string mode;
int open_attempts, opened, closed, queried, mutations;
bool locked;
std::vector<std::string> setup_calls;
void check(bool condition, const char* why) { if (!condition) throw std::runtime_error(why); }
template<class T> void put(void* buffer, std::size_t at, T value) {
    std::memcpy(static_cast<char*>(buffer)+at, &value, sizeof(value));
}
const Value::Object& fields(const Value& value) { return std::get<Value::Object>(value.data); }
std::string text(const Value& value, const char* key) { return std::get<std::string>(fields(value).at(key).data); }
std::uint64_t number(const Value& value, const char* key) {
    return std::get<std::uint64_t>(fields(value).at(key).data);
}
}
extern "C" int __wrap_open(const char* path, int flags, ...) {
    check(std::string(path) == "/dev/synosnap-ctl", "opened an unexpected device");
    check(flags == (O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK), "unsafe open flags");
    ++open_attempts;
    if (mode == "absent" || mode == "denied" || mode == "symlink") {
        errno = mode == "absent" ? ENOENT : mode == "denied" ? EACCES : ELOOP;
        return -1;
    }
    ++opened;
    return 123;
}
extern "C" int __wrap_open64(const char* path, int flags, ...) { return __wrap_open(path, flags); }
extern "C" int __wrap_close(int fd) { check(fd == 123, "wrong descriptor closed"); locked = false; ++closed; return 0; }
extern "C" int __wrap_flock(int fd, int operation) {
    check(fd == 123 && (operation == (LOCK_EX | LOCK_NB) || operation == (LOCK_SH | LOCK_NB)), "invalid driver locking");
    if (mode == "locked") { errno = EWOULDBLOCK; return -1; }
    locked = true; return 0;
}
extern "C" int __wrap_fstat(int fd, struct stat* data) {
    check(fd == 123, "wrong descriptor inspected");
    if (mode == "stat-error") { errno = EIO; return -1; }
    data->st_mode = mode == "regular" ? S_IFREG : S_IFCHR;
    return 0;
}
extern "C" int __wrap_stat(const char* path, struct stat*) {
    check(std::string(path) == "/dev/synosnap0", "wrong fresh setup stat path");
    setup_calls.push_back("stat");
    if (mode == "fresh-no-node" || mode == "bad-state-no-node") { errno = ENOENT; return -1; }
    return 0;
}
extern "C" int __wrap_umount(const char* path) {
    check(std::string(path) == "/tmp/dev/synosnap0", "wrong official unmount path");
    setup_calls.push_back("umount");
    if (mode == "fresh-unmount-fails" || mode == "bad-state-unmount-fails") { errno = EBUSY; return -1; }
    return 0;
}
extern "C" int __wrap_ioctl(int fd, unsigned long request, ...) {
    check(fd == 123, "wrong ioctl descriptor");
    check(locked, "driver ioctl was not serialized");
    ++queried;
    va_list arguments; va_start(arguments, request);
    void* out = va_arg(arguments, void*); va_end(arguments);
    // Independent literal wire oracle; never include the implementation ABI header.
    if (request == 0x40044105UL || request == 0x40184106UL) {
        check(queried == 2, "transition skipped identity query");
        if (request == 0x40044105UL) {
            check(mode == "track" || mode == "track-busy", "unexpected tracking mutation");
            check(*static_cast<std::uint32_t*>(out) == 0, "wrong tracking minor");
        } else {
            check(mode.starts_with("renew-") || mode == "renew", "unexpected renewal mutation");
            const char* cow;
            std::uint64_t size;
            std::uint32_t minor;
            auto* raw = static_cast<unsigned char*>(out);
            std::memcpy(&cow, raw, 8);
            std::memcpy(&size, raw+8, 8);
            std::memcpy(&minor, raw+16, 4);
            check(std::string(cow) == "/new-cow" && size == (mode == "renew-default" ? 0 : 64) &&
                minor == 0, "renewal ABI or units");
        }
        ++mutations;
        if (mode.ends_with("-busy")) { errno = EBUSY; return -1; }
        if (mode.ends_with("-denied")) { errno = EACCES; return -1; }
        if (mode.ends_with("-permission")) { errno = EPERM; return -1; }
        if (mode.ends_with("-abi")) { errno = ENOTTY; return -1; }
        if (mode.ends_with("-space")) { errno = ENOSPC; return -1; }
        if (mode.ends_with("-invalid-origin")) { errno = EINVAL; return -1; }
        if (mode.ends_with("-io")) { errno = EIO; return -1; }
        return 0;
    }
    if (request == 0x40284101UL) {
        check(mode.starts_with("create-") || mode == "create" || mode.starts_with("fresh-"), "unexpected creation");
        if (mode.starts_with("fresh-")) setup_calls.push_back("setup");
        auto* raw = static_cast<unsigned char*>(out);
        const char *origin, *cow;
        std::memcpy(&origin, raw, 8); std::memcpy(&cow, raw+8, 8);
        check(std::string(origin) == "/dev/loop0" && std::string(cow) == "/cow", "setup paths");
        std::uint64_t size, cache;
        std::memcpy(&size, raw+16, 8); std::memcpy(&cache, raw+24, 8);
        check(size == (mode == "create-default" ? 0 : 64) && cache == 0, "allocation units or cache incorrect");
        std::uint32_t minor; std::memcpy(&minor, raw+32, 4);
        check(minor == (mode == "fresh-exhausted" ? UINT32_MAX : 0) && raw[36] == 0,
              "minor or ignore-errors incorrect");
        ++mutations;
        if (mode == "fresh-exhausted") { errno = EINVAL; return -1; }
        if (mode == "create-busy" || mode == "fresh-setup-fails" ||
            mode == "fresh-query-setup-fails") { errno = EBUSY; return -1; }
        if (mode == "create-denied") { errno = EACCES; return -1; }
        if (mode == "create-permission") { errno = EPERM; return -1; }
        if (mode == "create-abi") { errno = ENOTTY; return -1; }
        if (mode == "create-space") { errno = ENOSPC; return -1; }
        if (mode == "create-invalid-origin") { errno = EINVAL; return -1; }
        if (mode == "create-io") { errno = EIO; return -1; }
        return 0;
    }
    if (request == 0x40204102UL || request == 0x40204103UL) {
        check(request == (mode == "reload-snapshot" ? 0x40204102UL : 0x40204103UL), "wrong reload ioctl");
        const auto* raw = static_cast<unsigned char*>(out);
        const char *origin, *cow;
        std::uint64_t cache;
        std::uint32_t minor;
        std::memcpy(&origin,raw,8); std::memcpy(&cow,raw+8,8);
        std::memcpy(&cache,raw+16,8); std::memcpy(&minor,raw+24,4);
        check(std::string(origin) == "/dev/loop0" && std::string(cow) == "/.synosnap_data/test" &&
            !cache && !minor && !raw[28], "reload ABI differs from official");
        ++mutations;
        return 0;
    }
    if (request == 0x40044104UL) {
        if (mode.starts_with("bad-state")) {
            check(*static_cast<std::uint32_t*>(out) == 0, "wrong bad-state minor");
            setup_calls.push_back("destroy");
            ++mutations;
            if (mode == "bad-state-absent" || mode == "bad-state-destroy-fails") {
                errno = mode == "bad-state-absent" ? ENOENT : EBUSY;
                return -1;
            }
            return 0;
        }
        if (mode.starts_with("fresh-")) {
            check(*static_cast<std::uint32_t*>(out) == 0, "wrong fresh destroy minor");
            setup_calls.push_back("destroy");
            ++mutations;
            if (mode == "fresh-destroy-fails" || mode == "fresh-setup-fails") {
                errno = EBUSY;
                return -1;
            }
            return 0;
        }
        check(mode == "release" || mode == "destroy-busy", "destroyed a foreign snapshot");
        check(queried == 2 && *static_cast<std::uint32_t*>(out) == 0, "release skipped identity query");
        ++mutations;
        if (mode == "destroy-busy") { errno = EBUSY; return -1; }
        return 0;
    }
    check(request == 0x80044109UL || request == 0xa0604108UL, "unexpected ioctl");
    if (mode.starts_with("fresh-")) {
        check(request == 0xa0604108UL, "fresh setup queried kernel free minor");
        setup_calls.push_back("info");
        if (mode == "fresh-absent" || mode == "fresh-query-fails" || mode == "fresh-exhausted" ||
            mode == "fresh-query-setup-fails") {
            const auto* raw = static_cast<unsigned char*>(out);
            check(*reinterpret_cast<const std::uint32_t*>(raw+4) ==
                  (mode == "fresh-exhausted" ? UINT32_MAX : 0), "wrong fresh info minor");
            errno = mode == "fresh-absent" ? ENOENT : mode == "fresh-exhausted" ? EINVAL : EIO;
            return -1;
        }
    }
    if (mode == "renew-query-error") { errno = EIO; return -1; }
    if (mode == "no-free" || mode == "missing-minor" || mode == "abi-error" || mode == "release-absent" ||
        mode == "reader-absent") {
        errno = mode == "abi-error" ? ENOTTY : ENOENT; return -1;
    }
    if (request == 0x80044109UL) {
        *static_cast<std::int32_t*>(out) = mode == "bad-free" ? 255 : 0;
        return 0;
    }
    auto* raw = static_cast<unsigned char*>(out);
    check(*reinterpret_cast<std::uint32_t*>(raw+4) == 0, "minor zero not passed");
    for (std::size_t n = 0; n < 8288; ++n) check(raw[n] == 0, "ioctl buffer not initialized");
    put<std::uint32_t>(out, 4, mode == "wrong-minor" ? 1 : 0);
    put<std::uint64_t>(out, 16, (mode == "unverified" || mode == "reader-unverified") ? 4 :
        mode == "reader-incremental" ? 2 : mode == "reader-inactive" ? 1 : 11);
    put<std::int32_t>(out, 24, mode.starts_with("reader-") && mode != "reader-error" ? 0 : -5);
    if (mode.starts_with("track") || mode.starts_with("renew")) {
        put<std::uint64_t>(out, 16, ((mode.starts_with("renew") && mode != "renew-wrong-mode") ||
            mode == "track-wrong-mode") ? 10 : 11);
        put<std::int32_t>(out, 24, 0);
    }
    if (mode == "reader-cancelled") raw[0] = 1;
    if (mode == "reader-ignore") raw[8280] = 1;
    put<std::uint64_t>(out, 32, 33554432);
    put<std::uint64_t>(out, 40, 1073741824);
    put<std::uint64_t>(out, 48, 9);
    raw[56] = mode == "recycled" || mode.ends_with("-identity") ? 0xcd : 0xab;
    std::strcpy(reinterpret_cast<char*>(raw+72), "/cow");
    std::strcpy(reinterpret_cast<char*>(raw+4168), "/dev/loop0");
    put<std::uint64_t>(out, 8264, 1);
    put<std::uint64_t>(out, 8272, 12345);
    if (mode == "bad-bool") raw[0] = 2;
    if (mode == "bad-path") std::memset(raw+72, 'x', 4096);
    return 0;
}
int main() {
    try {
        for (const auto* scenario : {"bad-state", "bad-state-absent", "bad-state-no-node",
                                    "bad-state-destroy-fails", "bad-state-unmount-fails"}) {
            mode = scenario;
            open_attempts = opened = closed = queried = mutations = 0;
            setup_calls.clear();
            opensabba::snapshot_driver_bad_state(Value{Value::Object{
                {"minor",Value{std::uint64_t{0}}},{"origin_path",Value{std::string("/dev/loop0")}}}});
            check(queried == 1 && mutations == 1 && opened == closed, "bad-state cleanup skipped destroy");
            check(setup_calls == (mode == "bad-state-no-node" ?
                  std::vector<std::string>{"stat","destroy"} :
                  std::vector<std::string>{"stat","umount","destroy"}), "wrong bad-state cleanup order");
        }
        for (const auto* item : {"absent", "denied", "symlink", "regular", "stat-error", "free",
                 "no-free", "bad-free", "abi-error", "info", "unverified", "missing-minor",
                 "wrong-minor", "bad-bool", "bad-path", "invalid-minor", "locked"}) {
            mode = item; open_attempts = opened = closed = queried = 0;
            const bool info = mode == "info" || mode == "unverified" || mode == "missing-minor" ||
                              mode == "wrong-minor" || mode == "bad-bool" || mode == "bad-path";
            bool failed = false;
            try {
                auto value = opensabba::snapshot_driver_status(mode == "invalid-minor"
                    ? std::optional<std::uint32_t>{255} : info ? std::optional<std::uint32_t>{0} : std::nullopt);
                check(number(value, "live_backup_supported") == 1, "missing single-volume backup capability");
                if (mode == "absent") check(text(value, "status") == "control-absent", "missing status");
                if (mode == "free") check(number(value, "free_minor") == 0, "free minor zero lost");
                if (mode == "no-free") check(text(value, "status") == "no-free-minor", "full slots misreported");
                if (mode == "info") {
                    check(number(value, "snapshot_mode") == 1 && number(value, "active") == 1 &&
                          number(value, "traced") == 1 && number(value, "unverified") == 0, "state bits");
                    check(number(value, "changed_blocks") == 12345 && number(value, "sequence") == 9, "CBT identity");
                    check(text(value, "error_code") == "-5" && text(value, "origin_path") == "/dev/loop0" &&
                          text(value, "uuid") == "ab000000000000000000000000000000", "information decoding");
                    check(text(value, "error_message") == std::strerror(EIO), "driver errno is not readable");
                }
                if (mode == "unverified") check(!fields(value).contains("changed_blocks") &&
                    !fields(value).contains("cow_format_version"), "unknown CBT metadata claimed valid");
            } catch (const opensabba::pstream::Error&) { failed = true; }
            const bool expected = mode != "absent" && mode != "free" && mode != "no-free" &&
                                  mode != "info" && mode != "unverified";
            check(failed == expected, "incorrect success/failure");
            check(closed == ((mode == "absent" || mode == "denied" || mode == "symlink" ||
                              mode == "invalid-minor") ? 0 : 1), "descriptor leaked");
            if (mode == "invalid-minor") check(open_attempts == 0, "invalid input opened device");
            check(opened == closed, "successful control open was not closed");
            if (mode == "regular" || mode == "stat-error") check(queried == 0, "invalid node reached ioctl");
        }
        std::cout << "17 read-only synosnap control cases passed\n";
        for (auto item : {"create", "create-default", "create-busy", "invalid-create"}) {
            mode = item; open_attempts = opened = closed = queried = mutations = 0;
            bool failed = false;
            try { opensabba::snapshot_driver_create(0, "/dev/loop0", "/cow",
                mode == "invalid-create" ? UINT64_MAX : mode == "create-default" ? 0 : 64); }
            catch (const opensabba::pstream::Error&) { failed = true; }
            check(failed == (mode != "create" && mode != "create-default"), "creation failure not propagated");
            check(mutations == (mode == "invalid-create" ? 0 : 1) && opened == closed, "creation retried or leaked");
        }
        mode = "info";
        const auto expected = opensabba::snapshot_driver_status(0);
        for (auto item : {"release", "destroy-busy", "release-absent", "recycled", "wrong-sequence", "wrong-origin", "wrong-cow"}) {
            mode = item; open_attempts = opened = closed = queried = mutations = 0;
            auto saved = expected;
            auto& map = std::get<Value::Object>(saved.data);
            if (mode == "wrong-sequence") map["sequence"] = Value{std::uint64_t{8}};
            if (mode == "wrong-origin") map["origin_path"] = Value{std::string("/dev/other")};
            if (mode == "wrong-cow") map["cow_path"] = Value{std::string("/other")};
            bool failed = false;
            try { opensabba::snapshot_driver_release(saved); }
            catch (const opensabba::pstream::Error&) { failed = true; }
            check(failed == (mode != "release" && mode != "release-absent"), "release outcome incorrect");
            check(mutations == ((mode == "release" || mode == "destroy-busy") ? 1 : 0) && opened == closed,
                  "foreign snapshot destroyed, retry performed, or descriptor leaked");
        }
        std::cout << "10 snapshot creation/identity-bound release cases passed\n";
        for (const auto item : {"fresh-occupied","fresh-absent","fresh-query-fails",
                               "fresh-no-node","fresh-unmount-fails","fresh-destroy-fails","fresh-setup-fails",
                               "fresh-exhausted","fresh-query-setup-fails"}) {
            mode = item; open_attempts = opened = closed = queried = mutations = 0;
            setup_calls.clear();
            int error = 0;
            try { opensabba::snapshot_driver_setup(mode == "fresh-exhausted" ? UINT32_MAX : 0,
                                                  "/dev/loop0","/cow",64); }
            catch (const opensabba::SnapshotAcquisitionError& result) { error = result.error; }
            check(error == (mode == "fresh-setup-fails" || mode == "fresh-query-setup-fails" ?
                EBUSY : mode == "fresh-exhausted" ? EINVAL : 0),
                  "fresh setup reported cleanup error");
            std::vector<std::string> calls{"info"};
            if (mode != "fresh-absent" && mode != "fresh-query-fails" && mode != "fresh-exhausted" &&
                mode != "fresh-query-setup-fails") {
                calls.push_back("stat");
                if (mode != "fresh-no-node") calls.push_back("umount");
                calls.push_back("destroy");
            }
            calls.push_back("setup");
            check(setup_calls == calls && opened == closed && opened == 2,
                  "fresh setup sequence, retry or descriptor lifetime differs from official");
            if (mode == "fresh-query-setup-fails") {
                // The selected minor is occupied by an unrelated old COW.
                // A failed query followed by definitive setup rejection must
                // not query it again or acquire cleanup authority over it.
                opensabba::CaptureJournal journal{
                    std::string(32,'a'),"11223344-5566-7788-99aa-bbccddeeff00",
                    opensabba::CapturePhase::snapshot_intent,Value{Value::Object{}},
                    Value{Value::Object{{"snapshot_attempted",Value{std::uint64_t{1}}},
                        {"snapshot_released",Value{std::uint64_t{0}}}}}};
                int retired = 0, persisted = 0;
                const auto omitted = opensabba::record_snapshot_acquisition_failure(journal,journal.reservation,true,
                    opensabba::SnapshotAcquisitionError("setup EBUSY",error),[&] {
                        check(persisted == 1,"cleanup preceded durable rejected-ioctl evidence");
                        ++retired;
                    },[&](const opensabba::CaptureJournal& saved) {
                        check(opensabba::capture_snapshot_omitted(saved.snapshot),"rejected setup gained a snapshot");
                        (void)opensabba::capture_journal_from_value(opensabba::pstream::decode(
                            opensabba::pstream::encode(opensabba::capture_journal_value(saved))));
                        ++persisted;
                    });
                check(opensabba::capture_snapshot_omitted(omitted) && retired == 1 && persisted == 1 &&
                    number(journal.reservation,"snapshot_released") == 1 &&
                    setup_calls == calls && queried == 2 && mutations == 1 && opened == closed,
                    "failed fresh acquisition touched a foreign slot or lost omission evidence");
            }
        }
        std::cout << "9 history-selected fresh setup and definitive omission cases passed\n";
        const struct {
            const char* mode;
            int error;
            bool per_origin;
            int mutations, queries;
        } acquisition_cases[]{
            {"create-space",ENOSPC,true,1,1}, {"create-busy",EBUSY,true,1,1},
            {"create-invalid-origin",EINVAL,true,1,1}, {"create-io",EIO,true,1,1},
            {"create-denied",EACCES,false,1,1}, {"create-permission",EPERM,false,1,1},
            {"create-abi",ENOTTY,false,1,1},
            {"renew-space",ENOSPC,true,1,2}, {"renew-busy",EBUSY,true,1,2},
            {"renew-invalid-origin",EINVAL,true,1,2}, {"renew-io",EIO,true,1,2},
            {"renew-denied",EACCES,false,1,2}, {"renew-permission",EPERM,false,1,2},
            {"renew-abi",ENOTTY,false,1,2},
            {"denied",EACCES,false,0,0}, {"renew-identity",0,false,0,1},
            {"renew-query-error",EIO,false,0,1}
        };
        for (const auto& item : acquisition_cases) {
            mode = item.mode; open_attempts = opened = closed = queried = mutations = 0;
            bool failed = false, per_origin = false;
            int error = 0;
            try {
                if (mode.starts_with("renew"))
                    opensabba::snapshot_driver_renew(expected,"/new-cow",64);
                else opensabba::snapshot_driver_create(0,"/dev/loop0","/cow",64);
            } catch (const opensabba::SnapshotAcquisitionError& result) {
                failed = per_origin = true; error = result.error;
            }
            catch (const opensabba::SnapshotDriverError& result) { failed = true; error = result.error; }
            catch (const opensabba::pstream::Error&) { failed = true; }
            check(failed && per_origin == item.per_origin && error == item.error,
                  "acquisition error classification");
            check(open_attempts == 1 && opened == (mode == "denied" ? 0 : 1) &&
                  opened == closed && mutations == item.mutations && queried == item.queries,
                  "acquisition retried, leaked control or mutated before validation");
        }
        std::cout << "17 acquisition errno/stage classification cases passed\n";
        for (auto item : {"reader-error", "reader-unverified", "reader-incremental",
                          "reader-inactive", "reader-cancelled", "reader-ignore",
                          "reader-identity", "reader-absent"}) {
            mode = item; open_attempts = opened = closed = queried = mutations = 0;
            bool failed = false;
            try { opensabba::SnapshotReader source(expected); }
            catch (const opensabba::pstream::Error& error) {
                failed = true;
                if (mode == "reader-cancelled")
                    check(std::string(error.what()).find("COW capacity exhausted") != std::string::npos &&
                          std::string(error.what()).find("--cow-mib") != std::string::npos,
                          "COW exhaustion lacks actionable diagnostic");
                else
                    check(std::string(error.what()).find("COW capacity exhausted") == std::string::npos,
                          "unrelated snapshot failure mislabeled as COW exhaustion");
            }
            check(failed && opened == 1 && closed == 1 && queried == 1 && mutations == 0,
                  "unusable snapshot was opened or control leaked");
        }
        std::cout << "8 snapshot source health/identity rejection cases passed\n";
        for (auto item : {"track", "track-busy", "track-wrong-mode", "track-identity",
                          "renew", "renew-default", "renew-busy", "renew-wrong-mode", "renew-identity"}) {
            mode = item; open_attempts = opened = closed = queried = mutations = 0;
            bool failed = false;
            try {
                if (mode.starts_with("track")) opensabba::snapshot_driver_track(expected);
                else opensabba::snapshot_driver_renew(expected, "/new-cow", mode == "renew-default" ? 0 : 64);
            } catch (const opensabba::pstream::Error&) { failed = true; }
            check(failed == (mode != "track" && mode != "renew" && mode != "renew-default"), "transition result");
            check(opened == closed && mutations == ((mode == "track" || mode == "renew" || mode == "renew-default" ||
                mode.ends_with("-busy")) ? 1 : 0), "transition retried, leaked or mutated foreign source");
        }
        for (auto item : {"reload-snapshot","reload-incremental"}) {
            mode = item; open_attempts = opened = closed = queried = mutations = 0;
            opensabba::snapshot_driver_reload(0,"/dev/loop0","/.synosnap_data/test",mode == "reload-snapshot");
            check(mutations == 1 && opened == closed,"reload repeated or leaked control");
        }
        std::cout << "9 identity-bound transitions and both boot reload ABIs passed\n";
    } catch (const std::exception& e) { std::cerr << mode << ": " << e.what() << '\n'; return 1; }
}
