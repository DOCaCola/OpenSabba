#include "opensabba/snapshot_driver.hpp"
#include "opensabba/source_read.hpp"
#include "opensabba/filesystem.hpp"
#include "opensabba/machine.hpp"
#include <algorithm>
#include <cstring>
#include <string>
#include <fstream>
#include <array>
#include <chrono>
#include <filesystem>
#ifdef __linux__
#include "synosnap_abi.hpp"
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/fs.h>
#include <sys/sysmacros.h>
#include <sys/mount.h>
#include <syslog.h>
#endif

namespace opensabba {
using pstream::Error;
using pstream::Value;
#ifdef __linux__
namespace {
[[noreturn]] void control_error(std::string_view operation, int error, bool acquisition = false) {
    std::string reason;
    if (error == EACCES || error == EPERM) reason = "permission denied accessing synosnap control";
    else if (error == EINVAL && acquisition) reason = "origin cannot enter the requested snapshot state";
    else if (error == ENOTTY || error == EINVAL)
        reason = "synosnap ioctl ABI is unsupported or the requested minor is outside the driver's range";
    else if (error == ENOENT) reason = "requested synosnap snapshot does not exist";
    else reason = std::strerror(error);
    const auto message = std::string(operation) + ": " + reason + " (errno " + std::to_string(error) + ")";
    if (acquisition && error != EACCES && error != EPERM && error != ENOTTY)
        throw SnapshotAcquisitionError(message,error);
    throw SnapshotDriverError(message,error);
}
std::string path_text(const char (&bytes)[4096]) {
    const auto* end = static_cast<const char*>(std::memchr(bytes, 0, sizeof(bytes)));
    if (!end) throw Error("synosnap returned an unterminated path");
    return std::string(bytes, end);
}
class Control {
public:
    int fd;
    explicit Control(bool allow_absent = false, bool reading = false)
        : fd(open("/dev/synosnap-ctl", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)) {
        if (fd < 0) {
            const auto error = errno;
            if (allow_absent && error == ENOENT) return;
            if (error == ENOENT) throw Error("synosnap control device is absent; load the separate driver first");
            control_error("open snapshot control", error);
        }
        try {
            struct stat details{};
            if (fstat(fd, &details) != 0) control_error("inspect snapshot control", errno);
            if (!S_ISCHR(details.st_mode)) throw Error("synosnap control is not a character device");
            if (flock(fd, (reading ? LOCK_SH : LOCK_EX) | LOCK_NB) != 0) {
                const auto error = errno;
                if (error == EWOULDBLOCK) throw Error("another OpenSabba process is using synosnap control");
                control_error("lock snapshot control", error);
            }
        } catch (...) { close(fd); throw; }
    }
    ~Control() { if (fd >= 0) close(fd); }
    Control(const Control&) = delete;
    Control& operator=(const Control&) = delete;
};
std::optional<synosnap_abi::Info> read_info(int fd, std::uint32_t minor) {
    if (minor >= 255) throw Error("synosnap minor must be between 0 and 254");
    synosnap_abi::Info info{};
    info.minor = minor;
    if (ioctl(fd, synosnap_abi::info, &info) != 0) {
        const auto error = errno;
        if (error == ENOENT) return {};
        control_error("query snapshot information", error);
    }
    if (info.minor != minor || info.cancelled > 1 || info.ignore_errors > 1)
        throw Error("synosnap returned inconsistent snapshot information");
    return info;
}
Value information_value(const synosnap_abi::Info&);
void check_identity(const Value& expected, const Value& current) {
    const auto& fields = std::get<Value::Object>(expected.data);
    const auto& actual = std::get<Value::Object>(current.data);
    for (const auto key : {"minor", "uuid", "sequence", "origin_path", "cow_path"})
        if (fields.at(key) != actual.at(key))
            throw Error("snapshot identity changed; refusing to use a different snapshot");
}
}
#endif

Value snapshot_driver_status(std::optional<std::uint32_t> minor) {
#ifndef __linux__
    (void)minor;
    throw Error("synosnap control inspection requires Linux");
#else
    // The driver's hard limit is 255 slots, numbered 0..254.
    if (minor && *minor >= 255) throw Error("synosnap minor must be between 0 and 254");
    Value::Object result{
        {"driver", Value{std::string("synosnap")}},
        {"control", Value{std::string("/dev/synosnap-ctl")}},
        {"live_backup_supported", Value{std::uint64_t{1}}}};
    Control control(true,true);
    if (control.fd < 0) {
        result["status"] = Value{std::string("control-absent")};
        return Value{std::move(result)};
    }
    if (!minor) {
        std::int32_t free = -1;
        if (ioctl(control.fd, synosnap_abi::free_minor, &free) != 0) {
            const auto error = errno;
            // GET_FREE returns ENOENT when every slot is occupied.
            if (error != ENOENT) control_error("query free snapshot minor", error);
            result["status"] = Value{std::string("no-free-minor")};
        } else {
            if (free < 0 || free >= 255) throw Error("synosnap returned an invalid free minor");
            result["status"] = Value{std::string("control-available")};
            result["free_minor"] = Value{static_cast<std::uint64_t>(free)};
        }
        return Value{std::move(result)};
    }
    const auto info = read_info(control.fd, *minor);
    if (!info) control_error("query snapshot information", ENOENT);
    return information_value(*info);
#endif
}

#ifdef __linux__
namespace {
Value information_value(const synosnap_abi::Info& info) {
    Value::Object result{{"driver", Value{std::string("synosnap")}},
        {"control", Value{std::string("/dev/synosnap-ctl")}},
        {"live_backup_supported", Value{std::uint64_t{1}}}};
    constexpr char hex[] = "0123456789abcdef";
    std::string uuid;
    for (const auto byte : info.uuid) { uuid += hex[byte >> 4]; uuid += hex[byte & 15]; }
    result["status"] = Value{std::string("snapshot-information")};
    result["minor"] = Value{std::uint64_t{info.minor}};
    result["state"] = Value{info.state};
    result["flags"] = Value{std::uint64_t{info.flags}};
    for (const auto& [name, bit] : {std::pair{"snapshot_mode", 0}, {"active", 1},
                                   {"unverified", 2}, {"traced", 3}})
        result[name] = Value{(info.state >> bit) & 1};
    result["cancelled"] = Value{std::uint64_t{info.cancelled}};
    // PStream's integer variant is unsigned; retain the signed kernel result as text.
    result["error_code"] = Value{std::to_string(info.error)};
    if (info.error == 0) result["error_message"] = Value{std::string("no driver error")};
    else if (info.error < 0 && info.error >= -4095)
        result["error_message"] = Value{std::string(std::strerror(-info.error))};
    result["ignore_snapshot_errors"] = Value{std::uint64_t{info.ignore_errors}};
    result["cache_bytes"] = Value{info.cache_size};
    result["cow_allocated_bytes"] = Value{info.allocated_size};
    result["sequence"] = Value{info.sequence};
    result["uuid"] = Value{std::move(uuid)};
    result["cow_path"] = Value{path_text(info.cow)};
    result["origin_path"] = Value{path_text(info.origin)};
    // The driver leaves these fields unwritten for an unverified reloaded slot.
    if (!(info.state & 4)) {
        result["cow_format_version"] = Value{info.version};
        result["changed_blocks"] = Value{info.changed_blocks};
    }
    return Value{std::move(result)};
}
}
#endif

Value snapshot_origin_identity(const std::string& path) {
#ifndef __linux__
    (void)path;
    throw Error("snapshot origins require Linux");
#else
    const auto canonical = std::filesystem::canonical(path).string();
    const int fd = open(canonical.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) control_error("open snapshot origin", errno);
    try {
        struct stat st{};
        std::uint64_t size{};
        if (fstat(fd, &st) != 0 || !S_ISBLK(st.st_mode))
            throw Error("snapshot origin must be a block device");
        if (ioctl(fd, BLKGETSIZE64, &size) != 0)
            throw Error("cannot inspect snapshot origin geometry and filesystem");
        const auto filesystem = inspect_linux_filesystem(size,
            [&](std::uint64_t offset, std::size_t length) {
                pstream::Bytes bytes(length);
                if (pread(fd,bytes.data(),length,static_cast<off_t>(offset)) !=
                    static_cast<ssize_t>(length))
                    throw Error("cannot read snapshot origin filesystem");
                return bytes;
            },false);
        auto uuid = filesystem.uuid;
        uuid.erase(std::remove(uuid.begin(),uuid.end(),'-'),uuid.end());
        Value result{Value::Object{{"origin_path", Value{canonical}},
            {"origin_device", Value{std::uint64_t{st.st_rdev}}},
            {"size", Value{size}}, {"filesystem_uuid", Value{uuid}}}};
        close(fd);
        return result;
    } catch (...) { close(fd); throw; }
#endif
}

void snapshot_driver_require_untracked(const std::string& origin, std::uint64_t device) {
#ifndef __linux__
    (void)origin; (void)device;
    throw Error("snapshot retirement requires Linux");
#else
    Control control(true,true);
    if (control.fd < 0) {
        if (std::filesystem::exists("/sys/module/synosnap"))
            throw Error("synosnap is loaded but its control device is missing; cannot verify snapshot retirement");
        return;
    }
    std::ifstream parameters("/sys/module/synosnap/parameters/max_snap_devices");
    unsigned count{};
    if (!(parameters >> count) || !count || count > 255)
        throw Error("cannot establish driver slot count for snapshot retirement");
    for (unsigned minor = 0; minor < count; ++minor) {
        const auto info = read_info(control.fd, minor);
        if (!info) continue;
        const auto path = path_text(info->origin);
        if (path == origin)
            throw Error("origin is still attached to synosnap; reboot recovery cannot retire a live chain");
        struct stat st{};
        if (stat(path.c_str(), &st) != 0 || !S_ISBLK(st.st_mode))
            throw Error("cannot identify a driver-attached origin during snapshot retirement");
        if (st.st_rdev == device)
            throw Error("origin is still attached to synosnap under another path; reboot recovery refused");
    }
#endif
}

std::optional<Value> snapshot_driver_information(std::uint32_t minor) {
#ifndef __linux__
    (void)minor;
    throw Error("synosnap control requires Linux");
#else
    if (minor >= 255) throw Error("synosnap minor must be between 0 and 254");
    Control control(false,true);
    const auto info = read_info(control.fd, minor);
    return info ? std::optional<Value>{information_value(*info)} : std::nullopt;
#endif
}

void snapshot_driver_create(std::uint32_t minor, const std::string& origin,
                            const std::string& cow, std::uint64_t allocated_mib) {
#ifndef __linux__
    (void)minor; (void)origin; (void)cow; (void)allocated_mib;
    throw Error("synosnap control requires Linux");
#else
    if (minor >= 255 || allocated_mib > (UINT64_MAX >> 20) ||
        origin.empty() || cow.empty() || origin.front() != '/' || cow.front() != '/' ||
        origin.size() >= 4096 || cow.size() >= 4096 ||
        origin.find('\0') != origin.npos || cow.find('\0') != cow.npos)
        throw Error("invalid snapshot creation parameters");
    Control control;
    synosnap_abi::Setup setup{origin.c_str(), cow.c_str(), allocated_mib, 0, minor, 0};
    if (ioctl(control.fd, synosnap_abi::setup, &setup) != 0)
        control_error("create snapshot", errno, true);
#endif
}

void snapshot_driver_setup(std::uint32_t minor, const std::string& origin,
                           const std::string& cow, std::uint64_t allocated_mib) {
#ifndef __linux__
    (void)minor; (void)origin; (void)cow; (void)allocated_mib;
    throw Error("synosnap control requires Linux");
#else
    {
        Control control;
        synosnap_abi::Info info{};
        info.minor = minor;
        // Snapshot setup: failed information queries skip cleanup and
        // still attempt setup. Neither unmount nor destroy failure blocks it.
        if (ioctl(control.fd,synosnap_abi::info,&info) == 0) {
            const auto device = "/dev/synosnap"+std::to_string(minor);
            struct stat st{};
            if (stat(device.c_str(),&st) == 0) {
                syslog(LOG_INFO,"Snapshot device %s exist, try to umount it's mountpoint.",device.c_str());
                const auto result = umount(("/tmp"+device).c_str());
                syslog(LOG_INFO,"Umount status = %d",result);
            }
            (void)ioctl(control.fd,synosnap_abi::destroy,&minor);
        }
    }
    syslog(LOG_INFO,"Create new snapshot for %s with minor %d",origin.c_str(),static_cast<int>(minor));
    // Preserve Free-minor selection's unsigned -1 through the real setup ioctl.
    // The driver rejects it with EINVAL; no user-space capacity error replaces
    // official agent's setup errno and failed-origin log (activity 7116).
    Control control;
    synosnap_abi::Setup setup{origin.c_str(),cow.c_str(),allocated_mib,0,minor,0};
    if (ioctl(control.fd,synosnap_abi::setup,&setup) != 0)
        control_error("create snapshot",errno,true);
#endif
}

void snapshot_driver_bad_state(const Value& saved) {
#ifndef __linux__
    (void)saved;
    throw Error("synosnap control requires Linux");
#else
    auto minor = static_cast<std::uint32_t>(std::get<std::uint64_t>(std::get<Value::Object>(saved.data).at("minor").data));
    const auto& origin = std::get<std::string>(std::get<Value::Object>(saved.data).at("origin_path").data);
    syslog(LOG_WARNING,"Previous backup left in bad state, try to destroy and recreate snapshot.");
    Control control;
    const auto device = "/dev/synosnap"+std::to_string(minor);
    struct stat st{};
    if (stat(device.c_str(),&st) == 0) {
        syslog(LOG_INFO,"Snapshot device %s exist, try to umount it's mountpoint.",device.c_str());
        const auto result = umount(("/tmp"+device).c_str());
        syslog(LOG_INFO,"Umount status = %d",result);
    }
    if (ioctl(control.fd,synosnap_abi::destroy,&minor) != 0)
        syslog(LOG_ERR,"Failed to destroy %s(%s)",origin.c_str(),device.c_str());
#endif
}

void snapshot_driver_release(const Value& expected) {
#ifndef __linux__
    (void)expected;
    throw Error("synosnap control requires Linux");
#else
    const auto& fields = std::get<Value::Object>(expected.data);
    const auto minor = std::get<std::uint64_t>(fields.at("minor").data);
    if (minor >= 255) throw Error("invalid saved snapshot minor");
    Control control;
    const auto info = read_info(control.fd, static_cast<std::uint32_t>(minor));
    if (!info) return; // A lost destroy reply is recoverable by observed absence.
    const auto current = information_value(*info);
    check_identity(expected, current);
    auto index = static_cast<std::uint32_t>(minor);
    if (ioctl(control.fd, synosnap_abi::destroy, &index) != 0)
        control_error("release snapshot", errno);
#endif
}

#ifdef __linux__
namespace {
synosnap_abi::Info transition_source(int fd, const Value& expected, bool snapshot) {
    const auto minor = std::get<std::uint64_t>(std::get<Value::Object>(expected.data).at("minor").data);
    if (minor >= 255) throw Error("invalid saved snapshot minor");
    const auto info = read_info(fd, static_cast<std::uint32_t>(minor));
    if (!info) throw Error("owned snapshot no longer exists");
    check_identity(expected, information_value(*info));
    if ((info->state & 7) != (snapshot ? 3U : 2U) ||
        info->cancelled || info->error || info->ignore_errors)
        throw Error("snapshot transition requires a healthy active source in the expected mode");
    return *info;
}
}
#endif
void snapshot_driver_track(const Value& expected) {
#ifdef __linux__
    Control control;
    auto minor = transition_source(control.fd, expected, true).minor;
    if (ioctl(control.fd, synosnap_abi::track, &minor) != 0)
        control_error("switch snapshot to changed-block tracking", errno);
#else
    (void)expected;
    throw Error("snapshot transitions require Linux");
#endif
}
void snapshot_driver_renew(const Value& expected, const std::string& cow, std::uint64_t allocated_mib) {
#ifdef __linux__
    if (cow.empty() || cow.front() != '/' || cow.size() >= 4096 || cow.find('\0') != cow.npos ||
        allocated_mib > (UINT64_MAX >> 20))
        throw Error("invalid snapshot renewal parameters");
    Control control;
    const auto info = transition_source(control.fd, expected, false);
    if (info.sequence == UINT64_MAX) throw Error("snapshot sequence cannot be incremented");
    if (cow == std::string(info.cow)) throw Error("renewal requires a new COW file");
    synosnap_abi::Renew request{cow.c_str(), allocated_mib, info.minor};
    if (ioctl(control.fd, synosnap_abi::renew, &request) != 0)
        control_error("renew snapshot from changed-block tracking", errno, true);
#else
    (void)expected; (void)cow; (void)allocated_mib;
    throw Error("snapshot transitions require Linux");
#endif
}
void snapshot_driver_reload(std::uint32_t minor, const std::string& origin,
                            const std::string& cow, bool snapshot) {
#ifdef __linux__
    if (minor >= 255 || !origin.starts_with("/dev/") || !cow.starts_with("/.synosnap_data/") ||
        origin.find('\0') != origin.npos || cow.find('\0') != cow.npos ||
        origin.size() >= 4096 || cow.size() >= 4096 ||
        std::filesystem::path(cow).parent_path() != "/.synosnap_data")
        throw Error("invalid boot snapshot reload parameters");
    Control control;
    synosnap_abi::Reload request{origin.c_str(),cow.c_str(),0,minor,0};
    if (ioctl(control.fd,snapshot ? synosnap_abi::reload_snapshot : synosnap_abi::reload_incremental,&request))
        control_error("reload snapshot tracking before origin mount",errno);
#else
    (void)minor; (void)origin; (void)cow; (void)snapshot;
    throw Error("snapshot reload requires Linux");
#endif
}

#ifdef __linux__
struct SnapshotReader::Impl {
    Control control{false,true};
    Value identity;
    std::uint32_t minor;
    int fd = -1;
    int metadata_fd = -1;
    std::uint64_t length = 0;
    int sector_size = 512;
    BadClusterContext bad_clusters;
    explicit Impl(const Value& expected, bool interval_source) : identity(expected) {
        const auto index = std::get<std::uint64_t>(std::get<Value::Object>(identity.data).at("minor").data);
        if (index >= 255) throw Error("invalid saved snapshot minor");
        minor = static_cast<std::uint32_t>(index);
        verify();
        const auto name = "synosnap" + std::to_string(minor);
        // Match the opened descriptor to the kernel's block-device registration.
        std::ifstream sysfs("/sys/class/block/" + name + "/dev");
        unsigned int device_major{}, device_minor{};
        char separator{};
        if (!(sysfs >> device_major >> separator >> device_minor) || separator != ':')
            throw Error("cannot identify the registered synosnap block device");
        fd = open(("/dev/" + name).c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (fd < 0) control_error("open snapshot block device", errno);
        try {
            struct stat st{};
            if (fstat(fd, &st) != 0 || !S_ISBLK(st.st_mode) ||
                st.st_rdev != makedev(device_major, device_minor))
                throw Error("snapshot path does not match its registered block device");
            if (ioctl(fd, BLKGETSIZE64, &length) != 0) control_error("query snapshot size", errno);
            if (ioctl(fd, BLKSSZGET, &sector_size) != 0) control_error("query snapshot sector size", errno);
            if (!length || length % 512 || length > INT64_MAX)
                throw Error("snapshot has an unsupported byte extent");
            const auto& origin = std::get<std::string>(
                std::get<Value::Object>(identity.data).at("origin_path").data);
            if (interval_source) {
                bad_clusters = snapshot_bad_cluster_context(origin,length,[&](auto at,auto count) {
                    return read_source_at(fd,at,count,"/dev/"+name,origin,
                        static_cast<std::size_t>(sector_size));
                });
                if (!bad_clusters.ranges.empty()) {
                    // File-system parsers use ordinary buffered reads, before
                    // The snapshot provider opens the payload path with O_DIRECT.
                    metadata_fd = fd;
                    fd = open(("/dev/"+name).c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
                    if (fd < 0) control_error("open snapshot interval source",errno);
                    struct stat interval{};
                    if (fstat(fd,&interval) || interval.st_rdev != st.st_rdev || !S_ISBLK(interval.st_mode))
                        throw Error("snapshot interval source identity changed");
                    enable_source_direct(fd);
                }
            }
            verify();
        } catch (...) {
            if (metadata_fd >= 0) close(metadata_fd);
            close(fd); fd = -1; throw;
        }
    }
    ~Impl() {
        if (metadata_fd >= 0) close(metadata_fd);
        if (fd >= 0) close(fd);
    }
    void verify(bool reading = false) const {
        const auto info = read_info(control.fd, minor);
        if (!info) throw Error("owned snapshot no longer exists");
        check_identity(identity, information_value(*info));
        if (reading && (info->error || info->cancelled))
            throw SourceReadError(EIO,"/dev/synosnap"+std::to_string(minor),
                std::get<std::string>(std::get<Value::Object>(identity.data).at("origin_path").data),
                0,static_cast<std::size_t>(sector_size),info->error ? info->error : -27);
        // The supported synosnap ABI sets cancelled when its COW write position
        // reaches file_max (snap_cancel in __cow_write_data).
        if (info->cancelled)
            throw Error("snapshot COW capacity exhausted; backup cannot continue; create a new snapshot with a larger --cow-mib");
        if ((info->state & 7) != 3 || info->error || info->ignore_errors)
            throw Error("snapshot is not healthy and active; backup cannot continue");
    }
};
SnapshotReader::SnapshotReader(const Value& identity, bool interval_source)
    : impl_(std::make_unique<Impl>(identity,interval_source)) {}
SnapshotReader::~SnapshotReader() = default;
std::uint64_t SnapshotReader::size() const { return impl_->length; }
const BadClusterContext& SnapshotReader::bad_clusters() const { return impl_->bad_clusters; }
void SnapshotReader::verify() const { impl_->verify(true); }
namespace {
void verify_unused_cow(int control, const std::string& path, std::uint64_t device, std::uint64_t inode) {
    std::ifstream parameters("/sys/module/synosnap/parameters/max_snap_devices");
    unsigned count{};
    if (!(parameters >> count) || !count || count > 255)
        throw Error("cannot establish driver slot count for COW cleanup");
    for (unsigned minor = 0; minor < count; ++minor) {
        const auto info = read_info(control, minor);
        if (!info) continue;
        auto cow = path_text(info->cow);
        if (cow.starts_with("/.synosnap_data/")) {
            struct stat origin{};
            if (stat(path_text(info->origin).c_str(),&origin) || !S_ISBLK(origin.st_mode))
                throw Error("cannot identify origin for its relative COW path");
            std::ifstream input("/proc/self/mountinfo");
            const std::string mountinfo((std::istreambuf_iterator<char>(input)),{});
            const auto mounts = parse_machine_mounts(mountinfo);
            const auto found = std::find_if(mounts.begin(),mounts.end(),[&](const MachineMount& mount) {
                return mount.root == "/" && makedev(mount.device.major,mount.device.minor) == origin.st_rdev;
            });
            if (found == mounts.end()) throw Error("relative COW origin is not mounted");
            cow = (std::filesystem::path(found->path)/cow.substr(1)).string();
        }
        if (cow == path) throw Error("COW cleanup candidate is still attached to the driver");
        struct stat st{};
        if (stat(cow.c_str(), &st) != 0)
            throw Error("cannot identify a driver-attached COW file during cleanup");
        if (st.st_dev == device && st.st_ino == inode)
            throw Error("COW cleanup candidate is attached to the driver under another path");
    }
}
}
void with_unused_snapshot_cow(const std::string& path, std::uint64_t device, std::uint64_t inode,
                              const std::function<void()>& operation) {
    Control control(true);
    if (control.fd >= 0) verify_unused_cow(control.fd,path,device,inode);
    else if (std::filesystem::exists("/sys/module/synosnap"))
        throw Error("loaded synosnap module has no control device for COW cleanup");
    operation();
}
void SnapshotReader::verify_cow_unused(const std::string& path, std::uint64_t device, std::uint64_t inode) const {
    verify();
    verify_unused_cow(impl_->control.fd,path,device,inode);
    verify();
}
pstream::Bytes SnapshotReader::read(std::uint64_t offset, std::size_t length,
                                   std::uint64_t* read_nanoseconds) {
    return read_from(false,offset,length,read_nanoseconds);
}
pstream::Bytes SnapshotReader::read_metadata(std::uint64_t offset, std::size_t length) {
    return read_from(true,offset,length,nullptr);
}
pstream::Bytes SnapshotReader::read_from(bool metadata, std::uint64_t offset, std::size_t length,
                                        std::uint64_t* read_nanoseconds) {
    verify();
    pstream::Bytes result;
    try {
        result = read_source_at(metadata && impl_->metadata_fd >= 0 ? impl_->metadata_fd : impl_->fd,
            offset,length,"/dev/synosnap"+std::to_string(impl_->minor),
            std::get<std::string>(std::get<Value::Object>(impl_->identity.data).at("origin_path").data),
            static_cast<std::size_t>(impl_->sector_size),read_nanoseconds);
    } catch (SourceReadError& error) {
        const auto info = read_info(impl_->control.fd,impl_->minor);
        if (!info) throw Error("owned snapshot no longer exists");
        check_identity(impl_->identity,information_value(*info));
        error.snapshot_error = info->error ? info->error : info->cancelled ? -27 : 0;
        throw;
    }
    verify();
    return result;
}
#else
void with_unused_snapshot_cow(const std::string&, std::uint64_t, std::uint64_t,
                              const std::function<void()>&) { throw Error("COW cleanup requires Linux"); }
struct SnapshotReader::Impl {};
SnapshotReader::SnapshotReader(const Value&, bool) { throw Error("snapshot source requires Linux"); }
SnapshotReader::~SnapshotReader() = default;
void SnapshotReader::verify_cow_unused(const std::string&, std::uint64_t, std::uint64_t) const {
    throw Error("COW cleanup requires Linux");
}
std::uint64_t SnapshotReader::size() const { throw Error("snapshot source requires Linux"); }
const BadClusterContext& SnapshotReader::bad_clusters() const { throw Error("snapshot source requires Linux"); }
void SnapshotReader::verify() const { throw Error("snapshot source requires Linux"); }
pstream::Bytes SnapshotReader::read(std::uint64_t, std::size_t, std::uint64_t*) { throw Error("snapshot source requires Linux"); }
pstream::Bytes SnapshotReader::read_metadata(std::uint64_t, std::size_t) { throw Error("snapshot source requires Linux"); }
#endif
}
