#include "opensabba/tracking_record.hpp"
#ifdef __linux__
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace opensabba {
using pstream::Value;
using pstream::Error;
namespace {
namespace fs = std::filesystem;
const Value& field(const Value& value, const char* key) {
    return std::get<Value::Object>(value.data).at(key);
}
const std::string& text(const Value& value, const char* key) {
    return std::get<std::string>(field(value,key).data);
}
class File {
public:
    int fd;
    explicit File(int value) : fd(value) {
        if (fd < 0) throw Error("cannot open tracking record storage: "+std::string(std::strerror(errno)));
    }
    ~File() { close(fd); }
    File(const File&) = delete;
};
struct stat inspect(int fd, bool directory) {
    struct stat st{};
    if (fstat(fd,&st) || st.st_uid != geteuid() ||
        (directory ? !S_ISDIR(st.st_mode) || (st.st_mode & 0022) :
            !S_ISREG(st.st_mode) || st.st_nlink != 1 || (st.st_mode & 0077)))
        throw Error("tracking record storage must be owned and not writable by others; records must be private");
    return st;
}
std::string name_for(const Value& volume) {
    return "reload_"+fs::path(machine_tracking_device(volume)).filename().string();
}
std::string history_name(const Value& reserved) {
    return "tracking-retired_"+fs::path(text(reserved,"cow_relative")).filename().string();
}
Value history_identity(const Value& reserved) {
    return Value{Value::Object{{"filesystem_uuid",field(reserved,"tracking_filesystem_uuid")},
        {"cow_relative",field(reserved,"cow_relative")},{"minor",field(reserved,"minor")},
        {"cow",field(reserved,"cow")}}};
}
std::optional<Value> read_owner(int directory, const std::string& name) {
    const int descriptor = openat(directory,name.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if (descriptor < 0 && errno == ENOENT) return std::nullopt;
    File file(descriptor);
    const auto st = inspect(file.fd,false);
    if (st.st_size <= 0 || st.st_size > 65536) throw Error("invalid machine tracking reload record size");
    std::string record(static_cast<std::size_t>(st.st_size),'\0');
    std::size_t done = 0;
    while (done < record.size()) {
        const auto count = pread(file.fd,record.data()+done,record.size()-done,static_cast<off_t>(done));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw Error("cannot read tracking owner record");
        done += static_cast<std::size_t>(count);
    }
    return machine_tracking_record_owner(record);
}
}
MachineTrackingRecords::MachineTrackingRecords(fs::path directory) : directory_(std::move(directory)) {}
std::optional<MachineTrackingOwnerRecord> MachineTrackingRecords::find(
    const Value& volume, std::uint32_t minor, std::string_view cow_relative) const {
    struct stat st{};
    if (lstat(directory_.c_str(),&st) && errno == ENOENT) return std::nullopt;
    File directory(open(directory_.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    inspect(directory.fd,true);
    std::optional<MachineTrackingOwnerRecord> result;
    for (const auto& entry : fs::directory_iterator(directory_)) {
        const auto name = entry.path().filename().string();
        if (!name.starts_with("reload_")) continue;
        const auto owner = read_owner(directory.fd,name);
        if (!owner || text(*owner,"device") != machine_tracking_device(volume) ||
            field(*owner,"filesystem_uuid") != field(volume,"filesystem_uuid") ||
            std::get<std::uint64_t>(field(*owner,"minor").data) != minor ||
            text(*owner,"cow_relative") != cow_relative) continue;
        // Identical copies carry the same literal origin and recovery
        // evidence; directory order is not authority.
        if (result && result->owner != *owner)
            throw Error("machine tracking COW has conflicting recovery metadata");
        result = MachineTrackingOwnerRecord{*owner,name};
    }
    return result;
}
void MachineTrackingRecords::publish(const Value& volume, const Value& reserved,
                                    const Value& snapshot, std::string_view executable, bool active) const {
    publish_owner(volume,machine_tracking_owner(volume,reserved,snapshot),executable,active);
}
void MachineTrackingRecords::publish_owner(const Value& volume, const Value& owner,
                                          std::string_view executable, bool active) const {
    fs::create_directories(directory_);
    File directory(open(directory_.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    inspect(directory.fd,true);
    // Reload records replace any prior contents for the current bdev basename.
    // This does not retire the displaced origin's history or COW files.
    const auto name = name_for(volume);
    const auto content = machine_tracking_record(owner,executable,active);
    const auto temporary = "."+name+".tmp";
    File out(openat(directory.fd,temporary.c_str(),O_WRONLY|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0700));
    inspect(out.fd,false);
    // A retry may reuse a private partial temporary file. Verify it before
    // truncation, then establish the executable mode independently of umask.
    if (fchmod(out.fd,0700) || ftruncate(out.fd,0)) throw Error("cannot prepare tracking owner record");
    std::size_t done = 0;
    while (done < content.size()) {
        const auto count = write(out.fd,content.data()+done,content.size()-done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw Error("cannot write tracking owner record");
        done += static_cast<std::size_t>(count);
    }
    if (fsync(out.fd) || renameat(directory.fd,temporary.c_str(),directory.fd,name.c_str()) ||
        fsync(directory.fd))
        throw Error("cannot persist synosnap reload record");
}
void MachineTrackingRecords::retire(const Value& volume) const {
    struct stat st{};
    if (lstat(directory_.c_str(),&st) && errno == ENOENT) return;
    File directory(open(directory_.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    inspect(directory.fd,true);
    // Reload-record removal and Bad-state cleanup remove
    // the saved history's bdev basename without checking its current contents.
    const auto name = name_for(volume);
    if ((unlinkat(directory.fd,name.c_str(),0) && errno != ENOENT) || fsync(directory.fd))
        throw Error("cannot remove retired synosnap reload record");
}
MachineTrackingHistory::MachineTrackingHistory(fs::path directory) : directory_(std::move(directory)) {}
bool MachineTrackingHistory::retired(const Value& reserved) const {
    const auto path = directory_/history_name(reserved);
    const int descriptor = open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if (descriptor < 0 && errno == ENOENT) return false;
    File file(descriptor);
    const auto st = inspect(file.fd,false);
    if (st.st_size <= 0 || st.st_size > 65536) throw Error("invalid retired tracking history size");
    pstream::Bytes bytes(static_cast<std::size_t>(st.st_size));
    std::size_t done = 0;
    while (done < bytes.size()) {
        const auto count = pread(file.fd,bytes.data()+done,bytes.size()-done,static_cast<off_t>(done));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw Error("cannot read retired tracking history");
        done += static_cast<std::size_t>(count);
    }
    if (pstream::decode(bytes) != history_identity(reserved))
        throw Error("retired tracking history differs from its reservation");
    return true;
}
void MachineTrackingHistory::retire(const Value& reserved) const {
    if (retired(reserved)) return;
    File directory(open(directory_.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    inspect(directory.fd,true);
    const auto name = history_name(reserved), temporary = "."+name+".tmp";
    File out(openat(directory.fd,temporary.c_str(),O_WRONLY|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600));
    inspect(out.fd,false);
    if (fchmod(out.fd,0600) || ftruncate(out.fd,0))
        throw Error("cannot prepare tracking history retirement");
    const auto bytes = pstream::encode(history_identity(reserved));
    std::size_t done = 0;
    while (done < bytes.size()) {
        const auto count = write(out.fd,bytes.data()+done,bytes.size()-done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw Error("cannot write tracking history retirement");
        done += static_cast<std::size_t>(count);
    }
    if (fsync(out.fd) || renameat(directory.fd,temporary.c_str(),directory.fd,name.c_str()) || fsync(directory.fd))
        throw Error("cannot persist tracking history retirement");
}
MachineTrackingDatabaseStore::MachineTrackingDatabaseStore(fs::path path) : path_(std::move(path)) {}
MachineTrackingDatabase MachineTrackingDatabaseStore::load() const {
    const int descriptor = open(path_.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    // No import from immutable captures or reload commands: an absent DB is
    // official agent's empty-history setup path, including occupied-slot handling.
    if (descriptor < 0 && errno == ENOENT) return {};
    File file(descriptor);
    const auto st = inspect(file.fd,false);
    constexpr pstream::Limits limits{24*1024*1024,1000000,20};
    if (st.st_size <= 0 || st.st_size > static_cast<off_t>(limits.max_bytes))
        throw Error("invalid tracking history database size");
    pstream::Bytes bytes(static_cast<std::size_t>(st.st_size));
    std::size_t done = 0;
    while (done < bytes.size()) {
        const auto count = pread(file.fd,bytes.data()+done,bytes.size()-done,static_cast<off_t>(done));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw Error("cannot read tracking history database");
        done += static_cast<std::size_t>(count);
    }
    return MachineTrackingDatabase(pstream::decode(bytes,limits));
}
void MachineTrackingDatabaseStore::save(const MachineTrackingDatabase& history) const {
    File directory(open(path_.parent_path().c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    inspect(directory.fd,true);
    const auto name = path_.filename().string(), temporary = "."+name+".tmp";
    File out(openat(directory.fd,temporary.c_str(),O_WRONLY|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600));
    inspect(out.fd,false);
    if (fchmod(out.fd,0600) || ftruncate(out.fd,0)) throw Error("cannot prepare tracking history database");
    const auto bytes = pstream::encode(history.value());
    std::size_t done = 0;
    while (done < bytes.size()) {
        const auto count = write(out.fd,bytes.data()+done,bytes.size()-done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw Error("cannot write tracking history database");
        done += static_cast<std::size_t>(count);
    }
    if (fsync(out.fd) || renameat(directory.fd,temporary.c_str(),directory.fd,name.c_str()) || fsync(directory.fd))
        throw Error("cannot persist tracking history database");
}

}
#endif
