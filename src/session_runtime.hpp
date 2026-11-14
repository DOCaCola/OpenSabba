#pragma once
// Private runtime shared by the CLI/daemon and typed test adapters.
#include "opensabba/session.hpp"
#include "opensabba/cli.hpp"
#include "opensabba/historical_logs.hpp"
#include "opensabba/server_time.hpp"
#include "opensabba/snapshot.hpp"
#include "opensabba/backup_job.hpp"
#include "opensabba/events.hpp"
#include "opensabba/machine_capture.hpp"
#include <openssl/rand.h>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <optional>
#include <vector>
#include <iostream>
#ifndef _WIN32
#include <fcntl.h>
#include <dirent.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
namespace opensabba::session_detail {
using pstream::Value;
using pstream::Error;
#ifndef _WIN32
// Service bindings and pending captures carry the closed 64 KiB CBT bitmaps.
inline constexpr pstream::Limits session_limits{24*1024*1024, 1000000, 20};
inline constexpr pstream::Limits backup_limits{24*1024*1024, 1000000, 20};

class File {
public:
    int fd;
    explicit File(int value) : fd(value) {
        if (fd < 0) throw CliError(8, "cannot open private session storage");
    }
    ~File() { close(fd); }
    File(const File&) = delete;
    File& operator=(const File&) = delete;
};

inline std::string random_hex(std::size_t count) {
    pstream::Bytes bytes(count);
    if (RAND_bytes(bytes.data(), static_cast<int>(count)) != 1)
        throw Error("cannot generate device identity");
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (auto byte : bytes) {
        result += hex[byte >> 4];
        result += hex[byte & 15];
    }
    return result;
}

inline std::string new_uuid() {
    auto hex = random_hex(16);
    hex[12] = '4';
    hex[16] = "89ab"[std::string_view("0123456789abcdef").find(hex[16]) & 3];
    return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) +
           "-" + hex.substr(16, 4) + "-" + hex.substr(20);
}

inline void check_private(int fd, bool directory) {
    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_uid != getuid() || (st.st_mode & 0077) ||
        (directory ? !S_ISDIR(st.st_mode) : (!S_ISREG(st.st_mode) || st.st_nlink != 1)))
        throw CliError(8, "session storage must be owned by this user and accessible only to this user");
}

inline std::filesystem::path storage_path(bool create = true) {
    const char* config = std::getenv("XDG_CONFIG_HOME");
    std::filesystem::path base;
    if (config && *config) {
        base = config;
        if (!base.is_absolute()) throw Error("XDG_CONFIG_HOME must be an absolute path");
    } else {
        const char* home = std::getenv("HOME");
        if (!home || !*home) throw Error("HOME is not set");
        base = std::filesystem::path(home) / ".config";
        if (!base.is_absolute()) throw Error("HOME must be an absolute path");
    }
    auto path = base / "opensabba";
    if (create) {
        std::filesystem::create_directories(base);
        if (mkdir(path.c_str(), 0700) != 0 && errno != EEXIST)
            throw Error("cannot create private session directory");
    }
    return path;
}

class Store {
    File dir_;
public:
    bool try_lock() {
        if (flock(dir_.fd, LOCK_EX | LOCK_NB) == 0) return true;
        if (errno == EWOULDBLOCK) return false;
        throw Error("cannot lock private session storage");
    }
    std::string control_name() const {
        struct stat st{};
        if (fstat(dir_.fd,&st)) throw Error("cannot identify service session directory");
        return "opensabba-"+std::to_string(getuid())+"-"+std::to_string(st.st_dev)+"-"+std::to_string(st.st_ino);
    }
    explicit Store(bool exclusive = true, bool create = true) : dir_(open(storage_path(create).c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) {
        check_private(dir_.fd, true);
        if (exclusive && flock(dir_.fd, LOCK_EX | LOCK_NB) != 0)
            throw Error("another OpenSabba session command is running; stop the service before changing the session");
    }
    std::optional<Value> read(const char* name, pstream::Limits limits = session_limits) {
        int fd = openat(dir_.fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0 && errno == ENOENT) return {};
        File file(fd);
        check_private(file.fd, false);
        pstream::Bytes bytes;
        std::uint8_t buffer[4096];
        for (;;) {
            auto count = ::read(file.fd, buffer, sizeof(buffer));
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) throw Error("cannot read saved session");
            if (count == 0) break;
            if (bytes.size() + static_cast<std::size_t>(count) > limits.max_bytes)
                throw Error("saved session exceeds size limit");
            bytes.insert(bytes.end(), buffer, buffer + count);
        }
        try {
            return pstream::decode(bytes, limits);
        } catch (const Error& error) {
            throw CliError(9, error.what());
        }
    }
    void write(const char* name, const Value& value, pstream::Limits limits = session_limits) {
        const auto bytes = pstream::encode(value, limits);
        const auto temporary = ".tmp-" + random_hex(16);
        File file(openat(dir_.fd, temporary.c_str(),
                         O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        try {
            std::size_t offset = 0;
            while (offset < bytes.size()) {
                auto count = ::write(file.fd, bytes.data() + offset, bytes.size() - offset);
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) throw Error("cannot write saved session");
                offset += static_cast<std::size_t>(count);
            }
            if (fsync(file.fd) != 0 ||
                renameat(dir_.fd, temporary.c_str(), dir_.fd, name) != 0 ||
                fsync(dir_.fd) != 0)
                throw Error("cannot commit saved session");
            historical_journal_event(storage_path(false),name,value);
        } catch (...) {
            unlinkat(dir_.fd, temporary.c_str(), 0);
            throw;
        }
    }
    std::vector<std::string> names() const {
        const int fd = openat(dir_.fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) throw Error("cannot enumerate private journals");
        auto* directory = fdopendir(fd);
        if (!directory) { close(fd); throw Error("cannot enumerate private journals"); }
        std::vector<std::string> result;
        try {
            errno = 0;
            while (auto* entry = readdir(directory)) result.emplace_back(entry->d_name);
            if (errno) throw Error("cannot enumerate private journals");
        } catch (...) { closedir(directory); throw; }
        closedir(directory);
        return result;
    }
    void logout() {
        if (unlinkat(dir_.fd, "session.pstream", 0) != 0 && errno != ENOENT)
            throw Error("cannot remove saved session");
        if (fsync(dir_.fd) != 0) throw Error("cannot persist session removal");
        auto time = read("server-time.pstream");
        auto reset = time ? server_time_from_value(*time) : ServerTime{};
        reset.offset.clear();
        reset.difference = 0;
        write("server-time.pstream",server_time_value(reset));
        set_server_time(reset);
    }
    void remove(const char* name) {
        if (unlinkat(dir_.fd, name, 0) != 0 && errno != ENOENT)
            throw Error("cannot remove retired journal binding");
        if (fsync(dir_.fd) != 0) throw Error("cannot persist retired journal binding removal");
    }
};

inline const Value::Object& fields(const Value& value) {
    auto* object = std::get_if<Value::Object>(&value.data);
    if (!object) throw Error("invalid saved session map");
    return *object;
}
inline const Value& field(const Value& value, const char* key) {
    const auto& map = fields(value);
    auto found = map.find(key);
    if (found == map.end()) throw Error(std::string("saved record missing ") + key);
    return found->second;
}
inline std::string text(const Value& value, const char* key, bool empty = false) {
    auto* result = std::get_if<std::string>(&field(value, key).data);
    if (!result || (!empty && result->empty())) throw Error("invalid saved session string");
    return *result;
}
inline std::uint64_t number(const Value& value, const char* key) {
    auto* result = std::get_if<std::uint64_t>(&field(value, key).data);
    if (!result) throw Error("invalid saved session integer");
    return *result;
}
inline std::string safe_display(std::string input) {
    for (auto& ch : input)
        if (static_cast<unsigned char>(ch) < 32 || static_cast<unsigned char>(ch) >= 127) ch = '?';
    return input;
}

inline SavedAuth auth_from(const Value& session) {
    return {text(session, "username"), text(session, "device_uuid"),
            text(session, "token"), text(session, "ds_id")};
}

inline void set(Value& session, const char* key, Value value) {
    std::get<Value::Object>(session.data)[key] = std::move(value);
}

static_assert(std::atomic_bool::is_always_lock_free);
inline std::atomic_bool service_stop{false};
inline std::atomic_bool service_reload{false};
inline void stop_service(int) { service_stop = 1; }

class Signals {
    struct sigaction old_int_{}, old_term_{}, old_hup_{}, old_quit_{};
public:
    explicit Signals() {
        service_stop = false;
        service_reload = false;
        struct sigaction action{};
        action.sa_handler = stop_service;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT, &action, &old_int_) != 0)
            throw Error("cannot install signal handler");
        if (sigaction(SIGTERM, &action, &old_term_) != 0) {
            sigaction(SIGINT, &old_int_, nullptr);
            throw Error("cannot install signal handler");
        }
        if (sigaction(SIGHUP, &action, &old_hup_) != 0) {
            sigaction(SIGTERM, &old_term_, nullptr);
            sigaction(SIGINT, &old_int_, nullptr);
            throw Error("cannot install signal handler");
        }
        if (sigaction(SIGQUIT, &action, &old_quit_) != 0) {
            sigaction(SIGHUP, &old_hup_, nullptr);
            sigaction(SIGTERM, &old_term_, nullptr);
            sigaction(SIGINT, &old_int_, nullptr);
            throw Error("cannot install signal handler");
        }
    }
    ~Signals() {
        sigaction(SIGINT, &old_int_, nullptr);
        sigaction(SIGTERM, &old_term_, nullptr);
        sigaction(SIGHUP, &old_hup_, nullptr);
        sigaction(SIGQUIT, &old_quit_, nullptr);
    }
};

inline void print_backup_progress(const Value& saved) {
    std::cout << "Backup: " << text(saved, "phase");
    if (text(saved, "phase") == "upload" && fields(saved).contains("sent_bytes"))
        std::cout << " (" << number(saved, "sent_bytes") << "/" << number(saved, "image_size")
                  << " image bytes processed; NAS checkpoint checked on resume)";
    std::cout << '\n' << std::flush;
}

inline EventInbox load_inbox(Store& store, const SavedAuth& auth) {
    const auto saved = store.read("events.pstream", event_limits);
    return saved ? EventInbox(auth, *saved) : EventInbox(auth);
}
#endif
}
#ifndef _WIN32
namespace opensabba {
Endpoint endpoint_from(const pstream::Value&);
DeviceMetadata device_metadata();
void refresh_server_time(session_detail::Store&,const Endpoint&,const SavedAuth&);
void validate_service_source(const pstream::Value&,const SavedAuth&);
std::vector<MetadataDisk> machine_metadata_disks(ReadyMachineCapture&,const std::string&,
    bool incremental = false,std::span<const IncrementalBackup> deltas = {});
void verify_machine_images(ReadyMachineCapture&,const std::function<bool()>& cancelled = {});
}
#endif
