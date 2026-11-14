#include "opensabba/machine_capture.hpp"
#include "opensabba/machine.hpp"
#include "opensabba/backup_cache.hpp"
#include "opensabba/machine_tracking.hpp"
#include "opensabba/tracking_record.hpp"
#include "opensabba/capture.hpp"
#include "opensabba/snapshot.hpp"
#include "opensabba/snapshot_driver.hpp"
#include "opensabba/source_read.hpp"
#include "opensabba/server_time.hpp"
#include "opensabba/filesystem.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <charconv>
#include <csignal>
#include <ctime>
#include <chrono>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <cstring>
#include <set>
#include <sstream>
#include <vector>
#ifdef __linux__
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#endif

namespace opensabba {
using pstream::Value;
using pstream::Bytes;
using pstream::Error;
#ifdef __linux__
namespace {
namespace fs = std::filesystem;
constexpr pstream::Limits journal_limits{24*1024*1024, 1000000, 20};
struct File {
    int fd = -1;
    explicit File(int descriptor) : fd(descriptor) {
        if (fd < 0) throw Error("cannot open capture storage or source: "+std::string(std::strerror(errno)));
    }
    ~File() { if (fd >= 0) close(fd); }
    File(const File&) = delete;
    File& operator=(const File&) = delete;
};
const Value& field(const Value& value, const char* key) {
    const auto* object = std::get_if<Value::Object>(&value.data);
    if (!object || !object->contains(key)) throw Error(std::string("capture field missing: ")+key);
    return object->at(key);
}
std::string text(const Value& value, const char* key) {
    const auto* result = std::get_if<std::string>(&field(value,key).data);
    if (!result) throw Error(std::string("invalid capture string: ")+key);
    return *result;
}
std::uint64_t number(const Value& value, const char* key) {
    const auto* result = std::get_if<std::uint64_t>(&field(value,key).data);
    if (!result) throw Error(std::string("invalid capture number: ")+key);
    return *result;
}
const Value::Array& array(const Value& value, const char* key) {
    const auto* result = std::get_if<Value::Array>(&field(value,key).data);
    if (!result) throw Error(std::string("invalid capture array: ")+key);
    return *result;
}
const Value::Array& optional_array(const Value& value, const char* key) {
    static const Value::Array empty;
    const auto& object = std::get<Value::Object>(value.data);
    if (!object.contains(key)) return empty;
    return array(value,key);
}
std::string raw_source_alias(const Value& plan, std::uint64_t offset) {
    const auto alias = [&](const Value& volume) -> std::optional<std::string> {
        const auto& fields = std::get<Value::Object>(volume.data);
        if (fields.contains("lv_uuid") || offset < number(volume,"offset") ||
            offset >= number(volume,"offset")+number(volume,"length")) return {};
        const auto mount = text(volume,"mount_path");
        return mount.empty() ? text(volume,"device") : mount;
    };
    const auto& fields = std::get<Value::Object>(plan.data);
    for (const auto key : {"boot","root"})
        if (fields.contains(key))
            if (const auto found = alias(fields.at(key))) return *found;
    for (const auto key : {"selected_extra","excluded"})
        for (const auto& volume : optional_array(plan,key))
            if (const auto found = alias(volume)) return *found;
    return text(plan,"disk");
}
Value::Array& mutable_array(Value& value, const char* key) {
    auto& object = std::get<Value::Object>(value.data);
    auto* result = std::get_if<Value::Array>(&object.at(key).data);
    if (!result) throw Error(std::string("invalid capture array: ")+key);
    return *result;
}
std::vector<std::string> selected_mounts(const Value& plan) {
    std::vector<std::string> paths;
    for (const auto& entry : optional_array(plan,"selected_extra"))
        paths.push_back(text(entry,"mount_path"));
    for (const auto& disk : optional_array(plan,"additional_disks"))
        for (const auto& entry : array(disk,"selected_extra"))
            paths.push_back(text(entry,"mount_path"));
    return paths;
}
std::string extra_cow_name(const Value& entry) {
    if (std::get<Value::Object>(entry.data).contains("lv_uuid"))
        return "extra-lv-"+text(entry,"lv_uuid")+".cow";
    return "extra-"+std::to_string(number(entry,"disk_index"))+"-"+
        std::to_string(number(entry,"partition"))+".cow";
}
std::string additional_image_name(std::size_t index) {
    return "raw-"+std::to_string(index)+".cache";
}
std::vector<const Value*> selected_partitions(const Value& plan) {
    std::vector<const Value*> result;
    for (const auto& entry : optional_array(plan,"selected_extra")) result.push_back(&entry);
    for (const auto& disk : optional_array(plan,"additional_disks"))
        for (const auto& entry : array(disk,"selected_extra")) result.push_back(&entry);
    return result;
}
std::vector<const Value*> selected_logical_volumes(const Value& plan) {
    std::vector<const Value*> result;
    if (std::get<Value::Object>(plan.data).contains("root")) {
        const auto& root = field(plan,"root");
        if (std::get<Value::Object>(root.data).contains("lv_uuid")) result.push_back(&root);
    }
    for (const auto& entry : optional_array(plan,"selected_extra"))
        if (std::get<Value::Object>(entry.data).contains("lv_uuid")) result.push_back(&entry);
    return result;
}
std::uint64_t decimal(std::string_view text) {
    std::uint64_t value{};
    const auto [end, error] = std::from_chars(text.data(),text.data()+text.size(),value);
    if (error != std::errc{} || end != text.data()+text.size() || text.empty())
        throw Error("invalid capture numeric argument");
    return value;
}
std::string boot_id() {
    std::ifstream input("/proc/sys/kernel/random/boot_id");
    std::string id;
    if (!std::getline(input,id)) throw Error("cannot read capture boot identity");
    return id;
}
std::string random_id() {
    unsigned char bytes[16];
    if (RAND_bytes(bytes,sizeof(bytes)) != 1) throw Error("cannot generate capture identity");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    std::string value;
    constexpr char hex[] = "0123456789abcdef";
    for (auto byte : bytes) { value += hex[byte>>4]; value += hex[byte&15]; }
    return value;
}
struct stat inspect(int fd) {
    struct stat result{};
    if (fstat(fd,&result)) throw Error("cannot inspect capture descriptor");
    return result;
}
void private_file(int fd, bool directory) {
    const auto st = inspect(fd);
    if (st.st_uid != geteuid() || (st.st_mode & 0077) ||
        (directory ? !S_ISDIR(st.st_mode) : (!S_ISREG(st.st_mode) || st.st_nlink != 1)))
        throw Error("capture storage must be private, owned, and of the expected type");
}
Bytes read_at(int fd, std::uint64_t offset, std::size_t size) {
    Bytes bytes(size);
    std::size_t done = 0;
    while (done < size) {
        const auto count = pread(fd,bytes.data()+done,size-done,static_cast<off_t>(offset+done));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw MachineRawCacheCopyError("capture source read failed");
        done += static_cast<std::size_t>(count);
    }
    return bytes;
}
void write_at(int fd, std::uint64_t offset, const Bytes& bytes,
              const char* description = "capture image write failed") {
    std::size_t done = 0;
    while (done < bytes.size()) {
        const auto count = pwrite(fd,bytes.data()+done,bytes.size()-done,static_cast<off_t>(offset+done));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) throw MachineRawCacheCopyError(std::string(description)+": "+std::strerror(errno));
        if (count == 0) throw MachineRawCacheCopyError(std::string(description)+": no write progress");
        done += static_cast<std::size_t>(count);
    }
}
MachineMount mount_from_plan(const Value& value) {
    const auto dev = text(value,"device_number");
    const auto at = dev.find(':');
    if (at == dev.npos) throw Error("invalid capture mount device");
    const auto major_n = decimal(dev.substr(0,at)), minor_n = decimal(dev.substr(at+1));
    if (major_n > UINT32_MAX || minor_n > UINT32_MAX) throw Error("capture mount device is out of range");
    return {number(value,"mount_id"), {static_cast<std::uint32_t>(major_n),static_cast<std::uint32_t>(minor_n)},
        "/",text(value,"mount_path"),text(value,"filesystem"),text(value,"mount_options"),text(value,"super_options")};
}
Value file_identity(int fd) {
    const auto st = inspect(fd);
    return Value{Value::Object{{"device",Value{std::uint64_t{st.st_dev}}},{"inode",Value{std::uint64_t{st.st_ino}}}}};
}
void check_file_identity(int fd, const Value& expected) {
    // Kernel device numbers can change at reboot. This check binds private
    // cache inputs to their journal; retention does not consume those inputs.
    if (field(file_identity(fd),"inode") != field(expected,"inode"))
        throw Error("capture file identity changed");
}
class Storage {
public:
    fs::path path;
    fs::path raw_path;
    File directory;
    std::unique_ptr<File> raw_directory;
    const char* journal_name = "capture.pstream";
    explicit Storage(fs::path location) : path(fs::canonical(location)), raw_path(path),
        directory(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) {
        private_file(directory.fd,true);
        if (flock(directory.fd,LOCK_EX | LOCK_NB))
            throw Error("capture is still owned by another process");
        open_raw_directory(path);
    }
    void open_raw_directory(const fs::path& location) {
        raw_path = fs::canonical(location);
        raw_directory = std::make_unique<File>(open(raw_path.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        private_file(raw_directory->fd,true);
    }
    int raw_fd() const { return raw_directory->fd; }
    std::unique_ptr<File> open_output(const Value& reserved,const std::string& name,int flags) {
        if (std::holds_alternative<std::monostate>(field(reserved,"output").data)) return {};
        auto result = std::make_unique<File>(openat(raw_fd(),name.c_str(),flags|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
        private_file(result->fd,false);
        check_file_identity(result->fd,field(reserved,"output"));
        return result;
    }
    void save_value(const Value& value, const char* destination) {
        const auto bytes = pstream::encode(value,journal_limits);
        const auto temporary = "journal-"+random_id()+".tmp";
        File out(openat(directory.fd,temporary.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
        try {
            write_at(out.fd,0,bytes,"capture journal write failed");
            if (fsync(out.fd) ||
                renameat(directory.fd,temporary.c_str(),directory.fd,destination) ||
                fsync(directory.fd))
                throw Error(std::string("cannot commit capture journal: ")+std::strerror(errno));
        } catch (...) {
            // Before rename, discard only this attempt's temporary file. After
            // rename, the committed journal must remain available for recovery.
            unlinkat(directory.fd,temporary.c_str(),0);
            throw;
        }
    }
    void save(const CaptureJournal& journal) {
        try { save_value(capture_journal_value(journal),journal_name); }
        catch (const std::exception& error) { throw CapturePersistenceError(error.what()); }
    }
    Value load_value(const char* name) {
        File in(openat(directory.fd,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
        private_file(in.fd,false);
        const auto size = inspect(in.fd).st_size;
        if (size <= 0 || static_cast<std::uint64_t>(size) > journal_limits.max_bytes)
            throw Error("invalid capture journal size");
        return pstream::decode(read_at(in.fd,0,static_cast<std::size_t>(size)),journal_limits);
    }
    CaptureJournal load() {
        auto result = capture_journal_from_value(load_value("capture.pstream"));
        if (number(result.reservation,"raw_storage_ready")) {
            const auto& task = field(result.reservation,"raw_cache_policy");
            const auto policy = backup_cache_policy(task);
            open_raw_directory(policy.enabled ?
                backup_cache_directory(policy,text(task,"task_uuid"),false)/("capture-"+result.id) :
                fs::path{text(result.reservation,"raw_directory")});
            if (inspect(raw_fd()).st_ino != number(result.reservation,"raw_directory_inode"))
                throw Error("raw interval storage differs from its capture reservation");
        }
        return result;
    }
    void discard_unpublished(int parent, const std::string& name) {
        struct stat journal{};
        // A rename may have succeeded even when the following directory fsync
        // failed. Preserve that published reservation for explicit recovery.
        if (fstatat(directory.fd,"capture.pstream",&journal,AT_SYMLINK_NOFOLLOW) == 0) return;
        if (errno != ENOENT) throw Error("cannot determine whether capture reservation was published");
        struct stat reservation_stat{};
        if (fstatat(directory.fd,"reservation.pstream",&reservation_stat,AT_SYMLINK_NOFOLLOW) == 0) {
            const auto marker = load_value("reservation.pstream");
            if (number(marker,"raw_storage_ready")) open_raw_directory(text(marker,"raw_directory"));
            for (const auto& file : optional_array(marker,"tracking"))
                prune_machine_tracking(file);
        } else if (errno != ENOENT) throw Error("cannot inspect unpublished tracking reservation");
        for (const auto& file : fs::directory_iterator(raw_path)) {
            const auto basename = file.path().filename().string();
            if (basename != "raw.cache" && !(basename.starts_with("raw-") && basename.ends_with(".cache"))) continue;
            if (unlinkat(raw_fd(),basename.c_str(),0) && errno != ENOENT)
                throw Error("cannot remove unpublished raw interval cache");
        }
        if (fsync(raw_fd())) throw Error("cannot persist unpublished raw interval cleanup");
        if (raw_path != path) {
            File raw_parent(open(raw_path.parent_path().c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
            if (unlinkat(raw_parent.fd,raw_path.filename().c_str(),AT_REMOVEDIR) || fsync(raw_parent.fd))
                throw Error("cannot remove unpublished raw interval directory");
        }
        for (const auto& file : fs::directory_iterator(path)) {
            const auto name = file.path().filename().string();
            if (name != "raw.cache" && name != "root.cow" &&
                !(name.starts_with("raw-") && name.ends_with(".cache")) &&
                !(name.starts_with("extra-") && name.ends_with(".cow"))) continue;
            if (unlinkat(directory.fd,name.c_str(),0) && errno != ENOENT)
                throw Error("cannot remove uncommitted capture "+name+": "+std::strerror(errno));
        }
        // Keep the recovery marker durable until removal of the large files
        // is durable. A crash afterwards can at most leave an empty directory.
        if (fsync(directory.fd) ||
            (unlinkat(directory.fd,"reservation.pstream",0) && errno != ENOENT) ||
            fsync(directory.fd))
            throw Error(std::string("cannot retire uncommitted capture files: ")+std::strerror(errno));
        if (unlinkat(parent,name.c_str(),AT_REMOVEDIR) || fsync(parent))
            throw Error(std::string("cannot remove uncommitted capture directory: ")+std::strerror(errno));
    }
    void discard_reservation() {
        struct stat journal{};
        if (fstatat(directory.fd,"capture.pstream",&journal,AT_SYMLINK_NOFOLLOW) == 0)
            throw Error("capture journal exists; use machine recover instead");
        if (errno != ENOENT) throw Error("cannot inspect capture journal");
        const auto reservation = load_value("reservation.pstream");
        if (number(reservation,"raw_storage_ready")) open_raw_directory(text(reservation,"raw_directory"));
        const auto directory_stat = inspect(directory.fd);
        if (text(reservation,"format") != "opensabba-unpublished-reservation-v3" ||
            text(reservation,"directory") != path.string() ||
            path.filename() != "capture-"+text(reservation,"id") ||
            number(reservation,"directory_inode") != directory_stat.st_ino ||
            text(reservation,"filesystem_uuid") != machine_filesystem_uuid(
                {major(directory_stat.st_dev),minor(directory_stat.st_dev)}))
            throw Error("unpublished capture reservation identity does not match its directory");
        // Validate the entire directory before removing anything. A crash in
        // initial journal publication can also leave an incomplete temp file.
        std::vector<std::string> temporaries;
        for (const auto& entry : fs::directory_iterator(path)) {
            const auto name = entry.path().filename().string();
            if (name == "raw.cache" || name == "root.cow" || name == "reservation.pstream" ||
                (((name.starts_with("extra-") && name.ends_with(".cow")) ||
                  (name.starts_with("raw-") && name.ends_with(".cache"))) &&
                 std::get<Value::Object>(reservation.data).contains(name))) continue;
            if (name.size() != 44 || !name.starts_with("journal-") || !name.ends_with(".tmp") ||
                name.substr(8,32).find_first_not_of("0123456789abcdef") != std::string::npos)
                throw Error("unexpected file in unpublished capture reservation: "+name);
            File file(openat(directory.fd,name.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
            private_file(file.fd,false);
            temporaries.push_back(name);
        }
        std::vector<std::string> files{"raw.cache","root.cow"};
        for (const auto& [name, value] : std::get<Value::Object>(reservation.data))
            if ((name.starts_with("extra-") && name.ends_with(".cow")) ||
                (name.starts_with("raw-") && name.ends_with(".cache"))) files.push_back(name);
        for (const auto& name : files) {
            const auto raw = name == "raw.cache" || (name.starts_with("raw-") && name.ends_with(".cache"));
            const int fd = openat(raw ? raw_fd() : directory.fd,name.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
            if (fd < 0 && errno == ENOENT) continue; // Interrupted explicit cleanup.
            File file(fd);
            private_file(file.fd,false);
            const auto st = inspect(file.fd);
            if (st.st_dev != inspect(raw ? raw_fd() : directory.fd).st_dev ||
                st.st_ino != number(field(reservation,name.c_str()),"inode"))
                throw Error("capture file identity changed");
        }
        File parent(open(path.parent_path().c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        private_file(parent.fd,true);
        File named(openat(parent.fd,path.filename().c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        if (file_identity(named.fd) != file_identity(directory.fd))
            throw Error("capture directory path changed");
        for (const auto& name : temporaries) {
            if (unlinkat(directory.fd,name.c_str(),0))
                throw Error(std::string("cannot remove unpublished temporary journal: ")+std::strerror(errno));
        }
        discard_unpublished(parent.fd,path.filename().string());
    }
};

std::string cache_digest(int fd, std::uint64_t offset, std::uint64_t length) {
    std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> digest(EVP_MD_CTX_new(),EVP_MD_CTX_free);
    if (!digest || EVP_DigestInit_ex(digest.get(),EVP_md5(),nullptr) != 1)
        throw Error("cannot initialize raw interval cache digest");
    for (std::uint64_t at = 0; at < length;) {
        const auto bytes = read_at(fd,offset+at,static_cast<std::size_t>(std::min<std::uint64_t>(4*1024*1024,length-at)));
        if (EVP_DigestUpdate(digest.get(),bytes.data(),bytes.size()) != 1) throw Error("cannot hash raw interval cache");
        at += bytes.size();
    }
    unsigned char bytes[16]; unsigned size{};
    if (EVP_DigestFinal_ex(digest.get(),bytes,&size) != 1 || size != 16) throw Error("cannot hash raw interval cache");
    std::string result;
    constexpr char hex[] = "0123456789abcdef";
    for (auto byte : bytes) { result += hex[byte>>4]; result += hex[byte&15]; }
    return result;
}

class LinuxCapture final : public CaptureOperations {
    Storage& storage_;
    CaptureJournal& journal_;
    std::unique_ptr<File> disk_, output_;
    struct Additional {
        std::unique_ptr<File> disk, output;
    };
    std::vector<Additional> additional_;
    std::uint64_t root_offset_, root_length_, disk_length_;
    std::uint32_t sector_;
    std::function<bool()> cancelled_, stopping_;
    std::string origin_, cow_;
    Value runtime_plan_;
    bool tracking() const {
        return std::get<Value::Object>(journal_.reservation.data).contains("cow_path");
    }
    Value readable_snapshot(const Value& saved, const Value& volume, const Value& reserved) {
        if (std::holds_alternative<std::monostate>(runtime_plan_.data)) return saved;
        const auto current = snapshot_driver_information(static_cast<std::uint32_t>(number(reserved,"minor")));
        if (!current) throw Error("reloaded machine snapshot is absent");
        for (const auto key : {"uuid","sequence","minor","cow_path"})
            if (field(*current,key) != field(saved,key)) throw Error("reloaded machine snapshot identity changed");
        if (text(*current,"origin_path") != text(volume,"device"))
            throw Error("reloaded machine snapshot origin changed");
        return *current;
    }
    void prepare_filesystem_snapshot(SnapshotReader& reader, const std::string& origin, std::uint64_t length, Value& reserved) {
        auto unused = snapshot_used_context(origin,std::max(length,reader.size()),[&](auto at,auto size) {
            check_cancel();
            return reader.read(at,size);
        });
        // A smaller current interval can still use the older snapshot's
        // filesystem map. Its wire queries stop at the current volume end.
        std::erase_if(unused,[&](auto& range) {
            if (range.offset >= length) return true;
            range.length = std::min(range.length,length-range.offset);
            return false;
        });
        auto& properties = std::get<Value::Object>(reserved.data);
        if (!properties.contains("cache_unused")) {
            std::vector<std::filesystem::path> files;
            if (std::get<Value::Object>(journal_.reservation.data).contains("cache_exclusions"))
                for (const auto& entry : std::get<Value::Array>(field(journal_.reservation,"cache_exclusions").data))
                    files.emplace_back(std::get<std::string>(entry.data));
            if (!std::holds_alternative<std::monostate>(field(journal_.reservation,"output").data))
                files.push_back(storage_.raw_path/"raw.cache");
            for (std::size_t index = 0; index < optional_array(journal_.plan,"additional_disks").size(); ++index)
                if (!std::holds_alternative<std::monostate>(field(array(journal_.reservation,"disks")[index],"output").data))
                    files.push_back(storage_.raw_path/additional_image_name(index+1));
            Value::Array ranges;
            for (const auto& range : backup_cache_exclusions(origin,length,files))
                ranges.push_back(Value{Value::Object{{"offset",Value{range.offset}},{"length",Value{range.length}}}});
            properties["cache_unused"] = Value{std::move(ranges)};
        }
        for (const auto& range : std::get<Value::Array>(properties.at("cache_unused").data))
            unused.push_back({number(range,"offset"),number(range,"length")});
        unused = union_unused_ranges(length,std::move(unused));
        Value::Array ranges;
        for (const auto& range : unused)
            ranges.push_back(Value{Value::Object{{"offset",Value{range.offset}},
                {"length",Value{range.length}}}});
        auto& fields = std::get<Value::Object>(reserved.data);
        const Value saved{std::move(ranges)};
        if (fields.contains("filesystem_unused") && fields.at("filesystem_unused") != saved)
            throw Error("snapshot filesystem allocation changed during capture recovery");
        fields["filesystem_unused"] = saved;
        storage_.save(journal_);
    }
    void check_directory() {
        File named(open(storage_.path.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        private_file(named.fd,true);
        if (file_identity(named.fd) != file_identity(storage_.directory.fd))
            throw Error("capture directory path changed");
    }
    void check_cow() {
        if (tracking()) { verify_machine_tracking_cow(journal_.reservation); return; }
        File cow(open(cow_.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
        private_file(cow.fd,false);
        check_file_identity(cow.fd,field(journal_.reservation,"cow"));
    }
    void check_extra_cow(const Value& entry) {
        if (tracking()) { verify_machine_tracking_cow(entry); return; }
        const auto path = tracking() ? text(entry,"cow_path") :
            (storage_.path/extra_cow_name(entry)).string();
        File cow(open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
        private_file(cow.fd,false);
        check_file_identity(cow.fd,field(entry,"cow"));
    }
    void check_files() {
        check_directory();
        // Destroying a synosnap slot unlinks its COW file. Only the image
        // remains an input after a confirmed release.
        if (!number(journal_.reservation,"snapshot_released")) check_cow();
        for (const auto& entry : optional_array(journal_.reservation,"extras"))
            if (!number(entry,"released")) check_extra_cow(entry);
        const auto check_output = [&](const Value& reserved,const Value& plan,const std::string& name) {
            auto file = storage_.open_output(reserved,name,O_RDONLY);
            if (!file) {
                if (!machine_cached_regions(plan).empty()) throw Error("missing raw cache has retained static intervals");
                return;
            }
            const auto length = inspect(file->fd).st_size;
            if (length < 0 || static_cast<std::uint64_t>(length) != number(field(plan,"layout"),"length"))
                throw Error("capture raw interval extent changed");
        };
        if (std::get<Value::Object>(journal_.plan.data).contains("layout"))
            check_output(journal_.reservation,journal_.plan,"raw.cache");
        const auto& disks = optional_array(journal_.plan,"additional_disks");
        const auto& reserved = optional_array(journal_.reservation,"disks");
        if (disks.size() != reserved.size()) throw Error("capture disk reservation differs from selection");
        for (std::size_t index = 0; index < disks.size(); ++index) {
            const auto name = additional_image_name(index+1);
            check_output(reserved[index],disks[index],name);
        }
    }
    void check_snapshot(const Value& identity) {
        if (number(identity,"minor") != number(journal_.reservation,"minor") ||
            text(identity,"origin_path") != origin_ ||
            text(identity,"cow_path") != (tracking() ? text(journal_.reservation,"cow_relative") : cow_) ||
            !number(identity,"sequence") || text(identity,"uuid").size() != 32)
            throw CaptureUncertain("capture driver slot belongs to a different snapshot");
    }
    void check_extra_snapshot(const Value& identity, const Value& planned,
                              const Value& reservation) {
        if (number(identity,"minor") != number(reservation,"minor") ||
            text(identity,"origin_path") != text(planned,"device") ||
            text(identity,"cow_path") != (tracking() ? text(reservation,"cow_relative") :
                (storage_.path/extra_cow_name(planned)).string()) ||
            !number(identity,"sequence") || text(identity,"uuid").size() != 32 ||
            text(reservation,"mount_path") != text(planned,"mount_path"))
            throw CaptureUncertain("capture extra snapshot identity differs from its reservation");
    }
    void check_cancel() {
        // Once snapshot acquisition starts, official agent finishes acquisition/device-spec and
        // publication before the script wrapper observes service-abort.
        if (cancelled() && !(stopping() && journal_.phase >= CapturePhase::snapshot_intent &&
                            journal_.phase <= CapturePhase::seal_intent))
            throw CaptureStopRequested();
    }
    void snapshot_log(std::uint64_t type, const Value& planned, std::string error = {}) {
        Value::Object parameters{{"volume_name",field(planned,"mount_path")}};
        if (!error.empty()) parameters["error_code"] = Value{std::move(error)};
        journal_.logs.push_back(Value{Value::Object{{"log_type",Value{type}},
            {"log_time",Value{server_time_now()}},{"parameters",Value{std::move(parameters)}}}});
        storage_.save(journal_);
    }
    Value omit_snapshot(Value& reservation, bool root, const SnapshotAcquisitionError& error) {
        // A definitive ioctl rejection did not adopt the new COW. In
        // particular, the selected minor can still contain an unrelated slot
        // after setup's preliminary query failed. It is not ours to reconcile.
        const auto omitted = record_snapshot_acquisition_failure(journal_,reservation,root,error,
            [&] { if (tracking()) prune_failed_machine_tracking(reservation); },
            [&](const CaptureJournal& current) { storage_.save(current); });
        check_cancel();
        verify_inputs();
        return omitted;
    }
    void create_snapshot(std::uint32_t minor, const Value& planned,
                         const std::string& cow) {
        snapshot_log(7002,planned);
        try {
            snapshot_driver_create(minor,text(planned,"device"),cow,number(journal_.reservation,"cow_mib"));
        } catch (const SnapshotDriverError& error) {
            std::ostringstream code;
            code << std::hex << static_cast<std::uint64_t>(-static_cast<std::int64_t>(error.error));
            snapshot_log(error.error == EINVAL ? 7116 : 7004,planned,code.str());
            throw;
        }
        snapshot_log(7003,planned);
    }
    Value acquire_tracking(Value& reservation, const Value& planned, bool root) {
        snapshot_log(7002,planned);
        try {
            const auto identity = acquire_machine_tracking(reservation,planned,
                number(journal_.reservation,"cow_mib"),[&](const Value& current) {
                    if (root) journal_.snapshot = current;
                    else std::get<Value::Object>(reservation.data)["snapshot"] = current;
                    storage_.save(journal_);
                });
            snapshot_log(7003,planned);
            return identity;
        } catch (const SnapshotDriverError& error) {
            std::ostringstream code;
            code << std::hex << static_cast<std::uint64_t>(-static_cast<std::int64_t>(error.error));
            snapshot_log(error.error == EINVAL ? 7116 : 7004,planned,code.str());
            throw;
        }
    }
public:
    LinuxCapture(Storage& storage, CaptureJournal& journal, std::function<bool()> cancelled = {},
                 std::function<bool()> stopping = {}) : storage_(storage), journal_(journal),
        root_offset_(number(field(journal.plan,"root"),"offset")),
        root_length_(number(field(journal.plan,"root"),"length")),
        disk_length_(std::get<Value::Object>(journal.plan.data).contains("layout") ?
            number(field(journal.plan,"layout"),"length") : root_length_),
        sector_(std::get<Value::Object>(journal.plan.data).contains("layout") ?
            static_cast<std::uint32_t>(number(field(journal.plan,"layout"),"sector_size")) : 512),
        origin_(text(field(journal.plan,"root"),"device")),
        cow_(std::get<Value::Object>(journal.reservation.data).contains("cow_path") ?
            text(journal.reservation,"cow_path") : (storage.path/"root.cow").string()) {
        cancelled_ = std::move(cancelled);
        stopping_ = std::move(stopping);
        if (text(journal.reservation,"directory") != storage.path.string() ||
            !disk_length_ || disk_length_ > INT64_MAX || root_offset_ > disk_length_ ||
            !root_length_ || (!std::get<Value::Object>(field(journal.plan,"root").data).contains("lv_uuid") &&
                root_length_ > disk_length_-root_offset_) ||
            (sector_ != 512 && sector_ != 4096) ||
            (number(journal.reservation,"minor") >= 255 &&
             !(tracking() && number(journal.reservation,"minor") == machine_tracking_no_minor)))
            throw Error("invalid capture reservation geometry or location");
        std::set<std::uint64_t> slots{number(journal.reservation,"minor")};
        const auto selected = selected_partitions(journal.plan);
        const auto& extras = array(journal.reservation,"extras");
        if (selected.size() != extras.size())
            throw Error("capture snapshot reservation differs from selection");
        for (std::size_t index = 0; index < extras.size(); ++index) {
            const auto slot = number(extras[index],"minor");
            if (((slot >= 255 || !slots.insert(slot).second) &&
                 !(tracking() && slot == machine_tracking_no_minor)) ||
                text(extras[index],"mount_path") != text(*selected[index],"mount_path"))
                throw Error("capture snapshot slots must be distinct and match selected volumes");
        }
        check_directory();
    }
    void open_sources() {
        // Reusing image sources needs the current topology. Resource retirement
        // has its own ownership checks and must not reopen an already released
        // capture merely because its saved topology predates the current boot.
        if (tracking() && boot_id() != journal_.boot_id) {
            runtime_plan_ = std::get<Value::Object>(journal_.plan.data).contains("selection") ?
                rediscover_machine_plan(journal_.plan) : select_machine_extra_volumes(inspect_running_machine(
                text(journal_.plan,"cow_directory")),selected_mounts(journal_.plan),
                machine_bare_metal(journal_.plan));
            origin_ = text(field(runtime_plan_,"root"),"device");
        }
        const auto& source_plan = std::holds_alternative<std::monostate>(runtime_plan_.data) ?
            journal_.plan : runtime_plan_;
        if (std::get<Value::Object>(source_plan.data).contains("layout")) {
            disk_ = std::make_unique<File>(open(text(source_plan,"disk").c_str(),O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));
            output_ = storage_.open_output(journal_.reservation,"raw.cache",O_RDWR);
        }
        const auto& disks = optional_array(source_plan,"additional_disks");
        const auto& reserved = optional_array(journal_.reservation,"disks");
        if (disks.size() != reserved.size()) throw Error("capture additional disk reservation differs from plan");
        for (std::size_t index = 0; index < disks.size(); ++index) {
            const auto name = additional_image_name(index+1);
            Additional item;
            item.disk = std::make_unique<File>(open(text(disks[index],"disk").c_str(),
                O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));
            item.output = storage_.open_output(reserved[index],name,O_RDWR);
            additional_.push_back(std::move(item));
        }
        verify_inputs();
    }
    void persist(const CaptureJournal& journal) override { storage_.save(journal); }
    bool cancelled() override { return cancelled_ && cancelled_(); }
    bool stopping() override { return stopping_ && stopping_(); }
    void verify_inputs() override try {
        check_files();
        if (boot_id() != journal_.boot_id && std::holds_alternative<std::monostate>(runtime_plan_.data))
            throw Error("capture belongs to an earlier boot");
        auto expected = std::holds_alternative<std::monostate>(runtime_plan_.data) ?
            journal_.plan : runtime_plan_;
        // Cache results describe this attempt, not the discovered topology.
        for (auto& disk : mutable_array(expected,"additional_disks"))
            for (const auto key : {"raw_cache_failures","raw_copy_error"})
                std::get<Value::Object>(disk.data).erase(key);
        auto observed = std::get<Value::Object>(journal_.plan.data).contains("selection") ?
            rediscover_machine_plan(expected) : select_machine_extra_volumes(
            inspect_machine(text(expected,"disk"),text(journal_.plan,"cow_directory")),
            selected_mounts(journal_.plan),machine_bare_metal(journal_.plan));
        for (const auto* key : {"disk","device_number","disk_sequence","other_disk_count","layout","cow_directory","cow_device","root","selected_extra","excluded","additional_disks"})
            if (std::get<Value::Object>(observed.data).contains(key) != std::get<Value::Object>(expected.data).contains(key) ||
                (std::get<Value::Object>(expected.data).contains(key) && field(observed,key) != field(expected,key)))
                throw Error(std::string("capture source topology changed: ")+key);
        for (const auto* key : {"volume_policy","swap_page_size","layout_policy"}) {
            const auto& planned = std::get<Value::Object>(journal_.plan.data);
            if (planned.contains(key) && field(observed,key) != planned.at(key))
                throw Error(std::string("capture interval policy changed: ")+key);
        }
        if (std::get<Value::Object>(observed.data).contains("lvm") !=
                std::get<Value::Object>(journal_.plan.data).contains("lvm") ||
            (std::get<Value::Object>(expected.data).contains("lvm") &&
             field(observed,"lvm") != field(expected,"lvm")))
            throw Error("capture LVM topology changed");
        if (disk_) {
            const auto st = inspect(disk_->fd);
            const auto dev = std::to_string(major(st.st_rdev))+":"+std::to_string(minor(st.st_rdev));
            std::uint64_t size{};
            std::uint64_t sequence{};
            int sector{};
            if (!S_ISBLK(st.st_mode) || dev != text(expected,"device_number") ||
                ioctl(disk_->fd,BLKGETSIZE64,&size) || ioctl(disk_->fd,BLKSSZGET,&sector) ||
                ioctl(disk_->fd,BLKGETDISKSEQ,&sequence) || sequence != number(expected,"disk_sequence") ||
                size != disk_length_ || sector != static_cast<int>(sector_))
                throw Error("pinned capture disk no longer matches its planned identity");
            const auto layout = inspect_disk_layout(size,sector_,[&](auto offset,auto count) { return read_at(disk_->fd,offset,count); });
            if (layout_value(layout) != field(journal_.plan,"layout")) throw Error("capture partition table changed");
        }
        const auto& disks = optional_array(expected,"additional_disks");
        if (additional_.size() != disks.size() && !additional_.empty())
            throw Error("capture additional disk descriptors changed");
        for (std::size_t index = 0; index < additional_.size(); ++index) {
            const auto& planned = disks[index];
            const auto st = inspect(additional_[index].disk->fd);
            const auto dev = std::to_string(major(st.st_rdev))+":"+std::to_string(minor(st.st_rdev));
            std::uint64_t size{}, sequence{};
            int sector{};
            if (!S_ISBLK(st.st_mode) || dev != text(planned,"device_number") ||
                ioctl(additional_[index].disk->fd,BLKGETSIZE64,&size) ||
                ioctl(additional_[index].disk->fd,BLKSSZGET,&sector) ||
                ioctl(additional_[index].disk->fd,BLKGETDISKSEQ,&sequence) ||
                sequence != number(planned,"disk_sequence") ||
                size != number(field(planned,"layout"),"length") ||
                sector != static_cast<int>(number(field(planned,"layout"),"sector_size")))
                throw Error("pinned additional disk no longer matches its planned identity");
            const auto layout = inspect_disk_layout(size,static_cast<std::uint32_t>(sector),
                [&](auto offset,auto count) { return read_at(additional_[index].disk->fd,offset,count); });
            if (layout_value(layout) != field(planned,"layout"))
                throw Error("capture additional partition table changed");
        }
    } catch (const std::exception& error) {
        throw CaptureUncertain(error.what());
    }
    Value snapshot_root() override {
        const auto& root = field(journal_.plan,"root");
        if (tracking()) {
            std::get<Value::Object>(journal_.reservation.data)["snapshot_attempted"] = Value{std::uint64_t{1}};
            storage_.save(journal_);
            try { return acquire_tracking(journal_.reservation,root,true); }
            catch (const SnapshotAcquisitionError& error) {
                return omit_snapshot(journal_.reservation,true,error);
            }
        }
        const auto mount = mount_from_plan(root);
        try { snapshot_driver_require_untracked(origin_,makedev(mount.device.major,mount.device.minor)); }
        catch (const std::exception& error) { throw CaptureUncertain(error.what()); }
        std::get<Value::Object>(journal_.reservation.data)["snapshot_attempted"] = Value{std::uint64_t{1}};
        storage_.save(journal_); // Ownership intent survives loss of the setup result.
        const auto minor_n = static_cast<std::uint32_t>(number(journal_.reservation,"minor"));
        try { create_snapshot(minor_n,root,cow_); }
        catch (const SnapshotAcquisitionError& error) {
            return omit_snapshot(journal_.reservation,true,error);
        }
        std::optional<Value> identity;
        try { identity = snapshot_driver_information(minor_n); }
        catch (const std::exception& error) { throw CaptureUncertain(error.what()); }
        if (!identity) throw CaptureUncertain("created capture snapshot is absent");
        check_snapshot(*identity);
        return *identity;
    }
    void snapshot_extra_volumes() override {
        const auto selected = selected_partitions(journal_.plan);
        auto& extras = mutable_array(journal_.reservation,"extras");
        for (std::size_t index = 0; index < selected.size(); ++index) {
            const auto& planned = *selected[index];
            auto& reservation = extras[index];
            const auto mount = mount_from_plan(planned);
            try {
                if (!tracking())
                snapshot_driver_require_untracked(text(planned,"device"),
                    makedev(mount.device.major,mount.device.minor));
            } catch (const std::exception& error) { throw CaptureUncertain(error.what()); }
            std::get<Value::Object>(reservation.data)["attempted"] = Value{std::uint64_t{1}};
            storage_.save(journal_);
            const auto minor_n = static_cast<std::uint32_t>(number(reservation,"minor"));
            if (tracking()) {
                Value identity;
                try { identity = acquire_tracking(reservation,planned,false); }
                catch (const SnapshotAcquisitionError& error) {
                    omit_snapshot(reservation,false,error);
                    continue;
                }
                std::get<Value::Object>(reservation.data)["snapshot"] = identity;
                storage_.save(journal_);
                continue;
            }
            try { create_snapshot(minor_n,planned,(storage_.path/extra_cow_name(planned)).string()); }
            catch (const SnapshotAcquisitionError& error) {
                omit_snapshot(reservation,false,error);
                continue;
            }
            std::optional<Value> identity;
            try { identity = snapshot_driver_information(minor_n); }
            catch (const std::exception& error) { throw CaptureUncertain(error.what()); }
            if (!identity) throw CaptureUncertain("created extra capture snapshot is absent");
            check_extra_snapshot(*identity,planned,reservation);
            std::get<Value::Object>(reservation.data)["snapshot"] = *identity;
            storage_.save(journal_);
        }
    }
    void cache_raw_regions() override {
        const auto verify = [&] { check_cancel(); verify_inputs(); };
        const auto cache = [&](Value& plan, int source, int output) {
            machine_cache_raw_regions(plan,[&](const MachineVolumeRegion& region) {
                for (std::uint64_t at = 0; at < region.length;) {
                    check_cancel();
                    const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(4*1024*1024,region.length-at));
                    write_at(output,region.offset+at,read_at(source,region.offset+at,count));
                    at += count;
                }
            },verify,[&] {
                try { storage_.save(journal_); }
                catch (const std::exception& error) { throw CapturePersistenceError(error.what()); }
            });
        };
        if (disk_) cache(journal_.plan,disk_->fd,output_ ? output_->fd : -1);
        auto& disks = mutable_array(journal_.plan,"additional_disks");
        for (std::size_t index = 0; index < disks.size(); ++index)
            cache(disks[index],additional_[index].disk->fd,additional_[index].output ? additional_[index].output->fd : -1);
        verify_inputs();
    }
    void prepare_snapshot_root(const Value& identity) override {
        if (capture_snapshot_omitted(identity)) return;
        const auto actual = readable_snapshot(identity,field(
            std::holds_alternative<std::monostate>(runtime_plan_.data) ? journal_.plan : runtime_plan_,"root"),
            journal_.reservation);
        check_snapshot(actual);
        {
            SnapshotReader reader(actual);
            prepare_filesystem_snapshot(reader,text(actual,"origin_path"),root_length_,journal_.reservation);
        }
        verify_inputs();
    }
    void prepare_extra_volumes() override {
        const auto selected = selected_partitions(journal_.plan);
        auto& extras = mutable_array(journal_.reservation,"extras");
        if (selected.size() != extras.size())
            throw Error("capture extra reservation does not match its selection");
        for (std::size_t index = 0; index < selected.size(); ++index) {
            const auto& planned = *selected[index];
            auto& reservation = extras[index];
            if (capture_snapshot_omitted(field(reservation,"snapshot"))) continue;
            check_cancel();
            verify_inputs();
            const auto& runtime = std::holds_alternative<std::monostate>(runtime_plan_.data) ?
                journal_.plan : runtime_plan_;
            const auto current_selected = selected_partitions(runtime);
            const auto identity = readable_snapshot(field(reservation,"snapshot"),
                *current_selected[index],reservation);
            check_extra_snapshot(identity,*current_selected[index],reservation);
            {
                SnapshotReader reader(identity);
                prepare_filesystem_snapshot(reader,text(identity,"origin_path"),number(planned,"length"),reservation);
            }
            verify_inputs();
        }
    }
    Value seal_raw_cache() override {
        const auto artifact = [&](File* output, const Value& plan, std::uint64_t sector) {
            if (output && (fsync(output->fd) || fchmod(output->fd,0400) || fsync(output->fd)))
                throw Error("cannot persist captured raw intervals");
            Value::Array cached;
            for (const auto& region : machine_cached_regions(plan))
                cached.push_back(Value{Value::Object{{"offset",Value{region.offset}},
                    {"length",Value{region.length}},
                    {"md5",Value{cache_digest(output->fd,region.offset,region.length)}}}});
            return Value{Value::Object{{"length",field(field(plan,"layout"),"length")},
                {"sector_size",Value{sector}},{"sha256",Value{std::string{}}},
                {"cached_regions",Value{std::move(cached)}}}};
        };
        Value::Array images;
        if (std::get<Value::Object>(journal_.plan.data).contains("layout"))
            images.push_back(artifact(output_.get(),journal_.plan,sector_));
        const auto& disks = optional_array(journal_.plan,"additional_disks");
        for (std::size_t index = 0; index < disks.size(); ++index) {
            auto image = artifact(additional_[index].output.get(),disks[index],number(field(disks[index],"layout"),"sector_size"));
            std::get<Value::Object>(image.data)["disk_index"] = Value{std::uint64_t{index+1}};
            images.push_back(std::move(image));
        }
        for (const auto* planned : selected_logical_volumes(journal_.plan))
            images.push_back(Value{Value::Object{{"length",field(*planned,"length")},
                {"sector_size",Value{std::uint64_t{512}}},{"sha256",Value{std::string{}}},
                {"lv_uuid",field(*planned,"lv_uuid")},{"image_name",field(*planned,"image_name")}}});
        auto result = std::move(images.front());
        images.erase(images.begin());
        if (!images.empty()) std::get<Value::Object>(result.data)["additional_images"] = Value{std::move(images)};
        check_files();
        return result;
    }
    void recover_snapshot(const CaptureJournal&) override {
        const auto selected = selected_partitions(journal_.plan);
        auto& extras = mutable_array(journal_.reservation,"extras");
        if (selected.size() != extras.size()) throw Error("capture extra recovery reservation differs from selection");
        const auto pending = [&](const Value& reservation, const char* attempted_key, const char* released_key) {
            const auto attempted = number(reservation,attempted_key), released = number(reservation,released_key);
            if (attempted > 1 || released > 1 || (released && !attempted) ||
                (journal_.phase == CapturePhase::ready && !attempted))
                throw Error("capture snapshot release state is inconsistent");
            return attempted && !released;
        };
        // Validate every reservation before deciding whether any live resource
        // needs inspection. Only explicit, consistent release evidence is final.
        bool outstanding = pending(journal_.reservation,"snapshot_attempted","snapshot_released");
        for (const auto& extra : extras)
            outstanding = pending(extra,"attempted","released") || outstanding;
        if (!outstanding) return;
        check_directory();
        const bool same_boot = boot_id() == journal_.boot_id;
        // Snapshot-resource cleanup resolves saved snapshot IDs; current
        // disk discovery, selection and LVM display mappings do not own them.
        std::string errors;
        const auto release = [&](Value& reservation, const Value& planned, const Value& saved,
                                 bool root) {
            const auto attempted = root ? "snapshot_attempted" : "attempted";
            const auto released = root ? "snapshot_released" : "released";
            if (!number(reservation,attempted) || number(reservation,released)) return;
            try {
                if (tracking()) {
                    const auto minor = static_cast<std::uint32_t>(number(reservation,"minor"));
                    const auto current = minor == machine_tracking_no_minor ? std::optional<Value>{} :
                        snapshot_driver_information(minor);
                    if (current) {
                        // Snapshot completion cannot transition a snapshot
                        // whose failed acquisition never inserted history.
                        if (text(*current,"cow_path") == text(reservation,"cow_relative") &&
                            !std::holds_alternative<std::monostate>(saved.data)) {
                            auto volume = planned;
                            if (!same_boot)
                                std::get<Value::Object>(volume.data)["device"] = field(*current,"origin_path");
                            if (!number(*current,"active") || number(*current,"unverified") ||
                                number(*current,"cancelled") || text(*current,"error_code") != "0")
                                discard_machine_tracking(reservation,volume,saved);
                            else finish_machine_tracking(reservation,volume,saved);
                        } else if (text(*current,"cow_path") != text(reservation,"cow_relative")) {
                            if (!std::get<Value::Object>(reservation.data).contains("prior"))
                                throw Error("capture recovery found a foreign tracking generation");
                            const auto& prior = field(field(reservation,"prior"),"snapshot");
                            for (const auto key : {"uuid","sequence","minor","cow_path"})
                                if (field(prior,key) != field(*current,key))
                                    throw Error("capture recovery found a foreign tracking generation");
                        }
                    }
                } else {
                    const auto current = snapshot_driver_information(
                        static_cast<std::uint32_t>(number(reservation,"minor")));
                    if (current) {
                        // Lost destruction replies need no COW file for an absent
                        // slot. A live slot must still match all ownership evidence.
                        if (root) { check_cow(); check_snapshot(*current); }
                        else { check_extra_cow(reservation); check_extra_snapshot(*current,planned,reservation); }
                        if (!std::holds_alternative<std::monostate>(saved.data))
                            for (const auto* key : {"uuid","sequence","minor","origin_path","cow_path"})
                                if (field(*current,key) != field(saved,key))
                                    throw Error("capture snapshot ownership changed");
                        snapshot_driver_release(*current);
                    }
                }
                std::get<Value::Object>(reservation.data)[released] = Value{std::uint64_t{1}};
                storage_.save(journal_);
            } catch (const std::exception& error) {
                errors += text(planned,"mount_path")+": "+error.what()+"; ";
            }
        };
        release(journal_.reservation,field(journal_.plan,"root"),journal_.snapshot,true);
        for (std::size_t index = 0; index < selected.size(); ++index) {
            auto& reservation = extras[index];
            release(reservation,*selected[index],field(reservation,"snapshot"),false);
        }
        if (!errors.empty()) throw Error("cannot release all owned capture snapshots: "+errors);
    }
};
}
#endif

#ifdef __linux__
struct ReadyMachineCapture::Impl {
    Storage storage;
    CaptureJournal journal;
    std::vector<std::unique_ptr<ImageSource>> images;
    explicit Impl(const fs::path& path) : storage(path), journal(storage.load()) {
        if (journal.phase != CapturePhase::ready || !journal.failure.empty() ||
            text(journal.reservation,"directory") != storage.path.string())
            throw Error("service requires a ready machine snapshot set at its original location");
        std::optional<Value> runtime;
        if (boot_id() != journal.boot_id) {
            if (!std::get<Value::Object>(journal.reservation.data).contains("cow_path"))
                throw Error("disposable machine snapshot belongs to an earlier boot");
            runtime = std::get<Value::Object>(journal.plan.data).contains("selection") ?
                rediscover_machine_plan(journal.plan) : select_machine_extra_volumes(inspect_running_machine(text(journal.plan,"cow_directory")),
                selected_mounts(journal.plan),machine_bare_metal(journal.plan));
        }
        const auto& source_plan = runtime ? *runtime : journal.plan;
        const auto snapshot_source = [&](const Value& saved, const Value& volume) {
            if (capture_snapshot_omitted(saved))
                return std::make_shared<ImageSource>(number(volume,"length"),
                    [](auto, auto size, auto*) { return Bytes(size); }, [] {});
            auto identity = saved;
            if (runtime) {
                const auto current = snapshot_driver_information(static_cast<std::uint32_t>(number(saved,"minor")));
                if (!current) throw Error("reloaded machine snapshot is absent");
                for (const auto key : {"uuid","sequence","minor","cow_path"})
                    if (field(*current,key) != field(saved,key)) throw Error("reloaded machine snapshot identity changed");
                if (text(*current,"origin_path") != text(volume,"device"))
                    throw Error("reloaded machine snapshot origin changed");
                identity = *current;
            }
            auto reader = std::make_shared<SnapshotReader>(identity,true);
            const auto& fields = std::get<Value::Object>(volume.data);
            const auto disk_index = fields.contains("disk_index") ? number(volume,"disk_index") : 0;
            const auto sector = fields.contains("lv_uuid") ? 512 :
                number(field(disk_index ? array(source_plan,"additional_disks").at(disk_index-1) :
                    source_plan,"layout"),"sector_size");
            const auto mount = text(volume,"mount_path");
            const auto alias = mount.empty() ? text(volume,"device") : mount;
            auto source = std::make_shared<ImageSource>(number(volume,"length"),
                [reader,alias,sector](auto offset,auto size,auto elapsed) {
                    try { return reader->read(offset,size,elapsed); }
                    catch (SourceReadError& error) {
                        error.volume = alias;
                        error.sector_size = static_cast<std::size_t>(sector);
                        throw;
                    }
                },
                [reader] { reader->verify(); },
                [reader](auto offset,auto size) { return reader->read_metadata(offset,size); });
            auto bad_clusters = reader->bad_clusters();
            bad_clusters.volume = alias;
            source->set_bad_clusters(bad_clusters);
            return source;
        };
        std::vector<std::shared_ptr<ImageSource>> snapshots{snapshot_source(journal.snapshot,field(source_plan,"root"))};
        const auto runtime_selected = selected_partitions(source_plan);
        const auto& extras = array(journal.reservation,"extras");
        for (std::size_t index = 0; index < extras.size(); ++index)
            snapshots.push_back(snapshot_source(field(extras[index],"snapshot"),*runtime_selected.at(index)));
        const auto selected = selected_partitions(journal.plan);
        const auto physical = [&](const Value& plan, const Value& reserved, const Value& artifact,
                                  const std::string& cache_name, std::size_t disk_index) {
            auto disk = std::make_shared<File>(open(text(plan,"disk").c_str(),O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));
            const auto verify_disk = [disk,plan] {
                const auto st = inspect(disk->fd);
                std::uint64_t length{}, sequence{};
                int sector{};
                if (!S_ISBLK(st.st_mode) ||
                    std::to_string(major(st.st_rdev))+":"+std::to_string(minor(st.st_rdev)) != text(plan,"device_number") ||
                    ioctl(disk->fd,BLKGETSIZE64,&length) || length != number(field(plan,"layout"),"length") ||
                    ioctl(disk->fd,BLKGETDISKSEQ,&sequence) || sequence != number(plan,"disk_sequence") ||
                    ioctl(disk->fd,BLKSSZGET,&sector) || sector != static_cast<int>(number(field(plan,"layout"),"sector_size")))
                    throw Error("machine raw source device identity changed");
            };
            auto cache_fd = storage.open_output(reserved,cache_name,O_RDONLY);
            std::shared_ptr<ImageSource> cache;
            if (cache_fd) cache = std::make_shared<ImageSource>(cache_fd->fd,(storage.raw_path/cache_name).string());
            const auto& policy = disk_index ? array(journal.plan,"additional_disks").at(disk_index-1) : journal.plan;
            const auto cached = machine_cached_regions(policy);
            if (!cache && !cached.empty()) throw Error("missing raw cache has retained static intervals");
            const auto& evidence = array(artifact,"cached_regions");
            if (evidence.size() != cached.size()) throw Error("raw cache interval count changed");
            for (std::size_t index = 0; index < cached.size(); ++index)
                if (number(evidence[index],"offset") != cached[index].offset ||
                    number(evidence[index],"length") != cached[index].length ||
                    text(evidence[index],"md5") != cache_digest(cache_fd->fd,cached[index].offset,cached[index].length))
                    throw Error("raw cache interval content changed");
            const auto regions = disk_index ? machine_additional_static_regions(policy) : machine_static_regions(policy);
            const auto length = number(field(plan,"layout"),"length");
            auto raw = std::make_shared<ImageSource>(length,
                [disk,cache,cached,regions,plan](std::uint64_t offset,std::size_t count,std::uint64_t* elapsed) {
                    Bytes result(count);
                    const auto started = std::chrono::system_clock::now();
                    bool short_read = false;
                    for (const auto& region : regions) {
                        if (!region.read_source) continue;
                        const auto begin = std::max(offset,region.offset), end = std::min(offset+count,region.offset+region.length);
                        for (auto at = begin; at < end;) {
                            auto next = end;
                            bool saved = false;
                            for (const auto& entry : cached) {
                                if (at < entry.offset) next = std::min(next,entry.offset);
                                else if (at < entry.offset+entry.length) {
                                    saved = true; next = std::min(next,entry.offset+entry.length); break;
                                }
                            }
                            const auto size = static_cast<std::size_t>(next-at);
                            Bytes bytes;
                            try {
                                bytes = saved ? cache->read(at,size) :
                                    read_source_at(disk->fd,at,size,text(plan,"disk"),text(plan,"disk"),
                                        static_cast<std::size_t>(number(field(plan,"layout"),"sector_size")));
                            } catch (SourceReadError& error) {
                                error.volume = raw_source_alias(plan,at);
                                error.sector_size = static_cast<std::size_t>(number(field(plan,"layout"),"sector_size"));
                                throw;
                            }
                            std::copy(bytes.begin(),bytes.end(),result.begin()+static_cast<std::ptrdiff_t>(at-offset));
                            if (bytes.size() != size) {
                                result.resize(static_cast<std::size_t>(at-offset)+bytes.size());
                                short_read = true;
                                break;
                            }
                            at = next;
                        }
                        if (short_read) break;
                    }
                    if (elapsed) *elapsed = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::system_clock::now()-started).count());
                    return result;
                },[verify_disk,cache] { verify_disk(); if (cache) cache->verify_unchanged(); });
            std::vector<ImageExtent> extents;
            if (!disk_index && !std::get<Value::Object>(field(journal.plan,"root").data).contains("lv_uuid")) {
                const auto& root = field(journal.plan,"root");
                extents.push_back({number(root,"offset"),number(root,"length"),0,snapshots[0]});
            }
            for (std::size_t index = 0; index < selected.size(); ++index)
                if (!std::get<Value::Object>(selected[index]->data).contains("lv_uuid") &&
                    number(*selected[index],"disk_index") == disk_index)
                    extents.push_back({number(*selected[index],"offset"),number(*selected[index],"length"),0,snapshots[index+1]});
            std::sort(extents.begin(),extents.end(),[](const auto& a,const auto& b) { return a.offset < b.offset; });
            std::vector<ImageExtent> covered;
            const auto append_raw = [&](std::uint64_t begin, std::uint64_t end) {
                // Interval preparation gives each raw disk interval
                // its own end. EOF in one must not consume the next interval.
                for (const auto& region : regions) {
                    const auto first = std::max(begin,region.offset);
                    const auto last = std::min(end,region.offset+region.length);
                    if (first < last) covered.push_back({first,last-first,first,raw});
                }
            };
            std::uint64_t at = 0;
            for (const auto& extent : extents) {
                if (at < extent.offset) append_raw(at,extent.offset);
                covered.push_back(extent); at = extent.offset+extent.length;
            }
            if (at < length) append_raw(at,length);
            return std::make_unique<ImageSource>(length,std::move(covered));
        };
        if (std::get<Value::Object>(source_plan.data).contains("layout"))
            images.push_back(physical(source_plan,journal.reservation,journal.artifact,"raw.cache",0));
        const auto& disks = optional_array(journal.plan,"additional_disks");
        const auto& artifacts = optional_array(journal.artifact,"additional_images");
        const auto& reserved = optional_array(journal.reservation,"disks");
        if (artifacts.size()+1 != machine_image_plans(journal.plan).size() || reserved.size() != disks.size())
            throw Error("machine interval images differ from their plan");
        for (std::size_t index = 0; index < disks.size(); ++index)
            images.push_back(physical(array(source_plan,"additional_disks")[index],reserved[index],artifacts[index],additional_image_name(index+1),index+1));
        const auto logical = selected_logical_volumes(journal.plan);
        for (const auto* planned : logical) {
            std::size_t index = 0;
            if (planned != &field(journal.plan,"root")) {
                const auto found = std::find(selected.begin(),selected.end(),planned);
                index = static_cast<std::size_t>(found-selected.begin())+1;
            }
            auto retained = snapshots.at(index);
            images.push_back(std::make_unique<ImageSource>(retained->size(),
                std::vector<ImageExtent>{{0,retained->size(),0,retained}}));
        }
    }
};
ReadyMachineCapture::ReadyMachineCapture(const std::filesystem::path& path) : impl_(std::make_unique<Impl>(path)) {}
const CaptureJournal& ReadyMachineCapture::journal() const { return impl_->journal; }
ImageSource& ReadyMachineCapture::source() { return *impl_->images.front(); }
std::size_t ReadyMachineCapture::disk_count() const { return impl_->images.size(); }
ImageSource& ReadyMachineCapture::source(std::size_t disk_index) {
    return *impl_->images.at(disk_index);
}
#else
struct ReadyMachineCapture::Impl {};
ReadyMachineCapture::ReadyMachineCapture(const std::filesystem::path&) { throw Error("machine capture sources require Linux"); }
const CaptureJournal& ReadyMachineCapture::journal() const { throw Error("machine capture sources require Linux"); }
ImageSource& ReadyMachineCapture::source() { throw Error("machine capture sources require Linux"); }
std::size_t ReadyMachineCapture::disk_count() const { throw Error("machine capture sources require Linux"); }
ImageSource& ReadyMachineCapture::source(std::size_t) { throw Error("machine capture sources require Linux"); }
#endif
ReadyMachineCapture::~ReadyMachineCapture() = default;

#ifdef __linux__
namespace {
CaptureJournal release_state(Storage& storage, const CaptureJournal& journal) {
    if (!fs::exists(storage.path/"release.pstream")) return journal;
    auto released = capture_journal_from_value(storage.load_value("release.pstream"));
    auto original = released;
    auto& extras = mutable_array(original.reservation,"extras");
    const auto& saved = array(journal.reservation,"extras");
    if (extras.size() != saved.size())
        throw Error("snapshot release journal reservation count differs from its capture");
    const auto restore_flag = [](Value& reservation, const Value& saved, const char* key) {
        const auto before = number(saved,key), after = number(reservation,key);
        if (before > 1 || after > 1 || after < before)
            throw Error("snapshot release journal has an invalid release transition");
        std::get<Value::Object>(reservation.data)[key] = field(saved,key);
    };
    restore_flag(original.reservation,journal.reservation,"snapshot_released");
    for (std::size_t index = 0; index < extras.size(); ++index)
        restore_flag(extras[index],saved[index],"released");
    if (capture_journal_value(original) != capture_journal_value(journal))
        throw Error("snapshot release journal differs from its capture");
    return released;
}
}
#endif

void finish_machine_capture(const std::filesystem::path& path) {
#ifdef __linux__
    Storage storage(path);
    auto journal = storage.load();
    if (journal.phase != CapturePhase::ready)
        throw Error("only a ready direct capture can finish snapshot reads");
    storage.journal_name = "release.pstream";
    journal = release_state(storage,journal);
    LinuxCapture operations(storage,journal);
    operations.recover_snapshot(journal);
#else
    (void)path;
    throw Error("machine snapshot completion requires Linux");
#endif
}

void prune_machine_capture(const CaptureJournal& expected) {
#ifdef __linux__
    Storage storage(text(expected.reservation,"directory"));
    const auto journal = storage.load();
    if (capture_journal_value(journal) != capture_journal_value(expected) ||
        text(journal.reservation,"directory") != storage.path.string() ||
        storage.path.filename() != "capture-"+journal.id ||
        (journal.phase != CapturePhase::ready && journal.phase != CapturePhase::aborted) ||
        (journal.phase == CapturePhase::aborted && !capture_failure_reportable(journal)))
        throw Error("capture pruning requires its exact released journal");
    const auto released = journal.phase == CapturePhase::ready ?
        release_state(storage,journal) : journal;
    if (journal.phase == CapturePhase::ready &&
        (number(released.reservation,"snapshot_released") != 1 ||
         std::any_of(optional_array(released.reservation,"extras").begin(),
                     optional_array(released.reservation,"extras").end(),
                     [](const Value& extra) { return number(extra,"released") != 1; })))
        throw Error("capture pruning requires every owned snapshot to be released");
    struct stat marker_stat{};
    const bool resuming = fstatat(storage.directory.fd,"retention.pstream",&marker_stat,AT_SYMLINK_NOFOLLOW) == 0;
    if (!resuming && errno != ENOENT) throw Error("cannot inspect capture retention marker");
    if (resuming) {
        const auto marker = storage.load_value("retention.pstream");
        if (number(marker,"format") != 1 || text(marker,"capture_id") != journal.id ||
            (text(marker,"state") != "delete-pending" && text(marker,"state") != "deleted"))
            throw Error("capture retention marker differs from its journal");
        if (text(marker,"state") == "deleted") return;
    }
    const bool tracking = std::get<Value::Object>(journal.reservation.data).contains("cow_path");
    if (tracking) {
        prune_machine_tracking_history(journal.reservation,field(journal.plan,"root"),
            storage.path.parent_path());
        const auto selected = selected_partitions(journal.plan);
        const auto& extras = optional_array(journal.reservation,"extras");
        for (std::size_t index = 0; index < extras.size(); ++index)
            prune_machine_tracking_history(extras[index],*selected.at(index),storage.path.parent_path());
    }
    struct Candidate {
        std::string name;
        Value identity;
        bool cow;
        int directory;
        std::unique_ptr<File> file;
    };
    std::vector<Candidate> files;
    const auto add = [&](std::string name, bool cow) {
        if (fs::path(name).filename() != name || name == "." || name == "..")
            throw Error("capture retention filename is not a reserved basename");
        const auto target = cow ? storage.directory.fd : storage.raw_fd();
        const int fd = openat(target,name.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
        // An already absent reserved artifact needs no unlink, including on
        // the first cleanup pass before a retention marker exists.
        if (fd < 0 && errno == ENOENT) return;
        auto file = std::make_unique<File>(fd);
        private_file(file->fd,false);
        const auto identity = file_identity(file->fd);
        files.push_back({std::move(name),identity,cow,target,std::move(file)});
    };
    if (!std::holds_alternative<std::monostate>(field(journal.reservation,"output").data))
        add("raw.cache",false);
    if (!tracking) add("root.cow",true);
    const auto& disks = optional_array(journal.reservation,"disks");
    for (std::size_t index = 0; index < disks.size(); ++index)
        if (!std::holds_alternative<std::monostate>(field(disks[index],"output").data))
            add(additional_image_name(index+1),false);
    if (!tracking)
        for (const auto& extra : optional_array(journal.reservation,"extras"))
            add(extra_cow_name(extra),true);
    Value marker{Value::Object{{"format",Value{std::uint64_t{1}}},
        {"capture_id",Value{journal.id}},{"state",Value{std::string("delete-pending")}}}};
    storage.save_value(marker,"retention.pstream");
    for (const auto& file : files) {
        const auto remove = [&] {
            struct stat named{};
            if (fstatat(file.directory,file.name.c_str(),&named,AT_SYMLINK_NOFOLLOW)) {
                if (errno == ENOENT) return;
                throw Error("cannot inspect retired capture file: "+std::string(std::strerror(errno)));
            }
            if (named.st_dev != number(file.identity,"device") || named.st_ino != number(file.identity,"inode") ||
                !S_ISREG(named.st_mode) || named.st_nlink != 1)
                throw Error("capture retention file changed before deletion");
            if (unlinkat(file.directory,file.name.c_str(),0) && errno != ENOENT)
                throw Error("cannot delete retired capture file: "+std::string(std::strerror(errno)));
        };
        if (file.cow)
            with_unused_snapshot_cow((storage.path/file.name).string(),number(file.identity,"device"),
                                     number(file.identity,"inode"),remove);
        else remove();
    }
    if (fsync(storage.raw_fd()) || fsync(storage.directory.fd)) throw Error("cannot persist capture file deletion");
    std::get<Value::Object>(marker.data)["state"] = Value{std::string("deleted")};
    storage.save_value(marker,"retention.pstream");
#else
    (void)expected;
    throw Error("capture pruning requires Linux");
#endif
}

CaptureJournal inspect_machine_capture(const std::filesystem::path& directory, bool recover,
                                      const CaptureJournal* expected) {
#ifdef __linux__
    Storage storage(directory);
    auto journal = storage.load();
    if (expected && capture_journal_value(journal) != capture_journal_value(*expected))
        throw Error("capture changed before recovery acquired its lock");
    if (recover && journal.phase == CapturePhase::ready) {
        auto released = release_state(storage,journal);
        storage.journal_name = "release.pstream";
        LinuxCapture operations(storage,released);
        operations.recover_snapshot(released);
    }
    if (recover && journal.phase != CapturePhase::ready && journal.phase != CapturePhase::aborted) {
        LinuxCapture operations(storage,journal);
        recover_machine_capture(journal,operations);
    }
    return journal;
#else
    (void)directory; (void)recover; (void)expected;
    throw Error("machine capture requires Linux");
#endif
}
CaptureJournal resume_machine_capture(const std::filesystem::path& directory, const CaptureJournal& expected,
                                      const std::function<bool()>& cancelled, const std::function<bool()>& stopping) {
#ifdef __linux__
    Storage storage(directory);
    auto journal = storage.load();
    if (capture_journal_value(journal) != capture_journal_value(expected))
        throw Error("capture changed before snapshot reuse acquired its lock");
    LinuxCapture operations(storage,journal,cancelled,stopping);
    operations.open_sources();
    resume_machine_capture(journal,operations);
    return journal;
#else
    (void)directory; (void)expected; (void)cancelled; (void)stopping;
    throw Error("machine capture requires Linux");
#endif
}
CaptureJournal create_machine_capture_from_plan(Value plan, const Value& task,
    std::uint64_t mib, const std::function<void(const CaptureJournal&)>& reserved,
    const std::function<bool()>& cancelled, const std::function<void(const Value&)>& validate_plan,
    const SnapshotBoundaryHooks& hooks, bool persistent_tracking,
    const std::vector<std::filesystem::path>& cache_exclusions, const std::function<bool()>& stopping) {
#ifdef __linux__
    if ((!mib && !persistent_tracking) || mib > (UINT64_MAX>>20))
        throw Error("invalid capture allocation");
    const auto disk = std::get<Value::Object>(plan.data).contains("disk") ? text(plan,"disk") : std::string{};
    const auto selected_mounts = opensabba::selected_mounts(plan);
    const auto bare_metal = machine_bare_metal(plan);
    if (validate_plan) validate_plan(plan);
    const auto origin = snapshot_origin_identity(text(field(plan,"root"),"device"));
    if (!persistent_tracking)
        snapshot_driver_require_untracked(text(origin,"origin_path"),number(origin,"origin_device"));
    const auto driver = snapshot_driver_status();
    if (text(driver,"status") != "control-available" &&
        !(persistent_tracking && text(driver,"status") == "no-free-minor"))
        throw Error("capture requires an already loaded driver with usable slots");
    std::ifstream parameters("/sys/module/synosnap/parameters/max_snap_devices");
    unsigned slot_count{};
    if (!(parameters >> slot_count) || !slot_count || slot_count > 255)
        throw Error("cannot establish driver slot count for machine capture");
    const auto snapshot_count = 1+selected_partitions(plan).size();
    std::vector<std::uint32_t> slots;
    for (std::uint32_t slot = 0; slot < slot_count && slots.size() < snapshot_count; ++slot)
        if (!snapshot_driver_information(slot)) slots.push_back(slot);
    if (!persistent_tracking && slots.size() != snapshot_count)
        throw Error("not enough free synosnap slots for all selected machine volumes");
    const auto cache_policy = backup_cache_policy(task);
    Value::Object cache_fields{{"cached_enabled",Value{std::uint64_t{cache_policy.enabled}}}};
    if (cache_policy.enabled)
        for (const auto key : {"task_uuid","is_paused","cached_volume_name","cached_mount_path",
                              "cached_volume_space_lower_bound_unit","cached_volume_space_lower_bound_value"})
            cache_fields.emplace(key,field(task,key));
    const Value raw_policy{std::move(cache_fields)};
    const auto raw_task_uuid = cache_policy.enabled ? text(task,"task_uuid") : std::string{};
    File parent(open(text(plan,"cow_directory").c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    private_file(parent.fd,true);
    const auto id = random_id(), name = "capture-"+id;
    if (mkdirat(parent.fd,name.c_str(),0700))
        throw Error(std::string("cannot reserve capture directory: ")+std::strerror(errno));
    Storage storage(fs::path(text(plan,"cow_directory"))/name);
    Value root_tracking;
    Value::Array tracking_files;
    auto journal = [&]() {
        try {
            bool raw_ready = true;
            std::string raw_error;
            try {
                const auto raw_parent = cache_policy.enabled ?
                    backup_cache_directory(cache_policy,raw_task_uuid,false) : storage.path.parent_path();
                if (raw_parent != storage.path.parent_path()) {
                    if (mkdir((raw_parent/name).c_str(),0700))
                        throw Error("cannot reserve task raw interval storage: "+std::string(std::strerror(errno)));
                    storage.open_raw_directory(raw_parent/name);
                }
            } catch (const Error& error) {
                // Static-cache creation failure leaves the
                // affected small intervals as direct type2 reads,.
                raw_ready = false;
                raw_error = error.what();
            } catch (const fs::filesystem_error& error) {
                raw_ready = false;
                raw_error = error.what();
            }
            if (fsync(parent.fd)) throw Error(std::string("cannot persist capture directory: ")+std::strerror(errno));
            if (inspect(storage.directory.fd).st_dev != inspect(parent.fd).st_dev)
                throw Error("capture directory differs from its reserved state filesystem");
            std::get<Value::Object>(plan.data)["cow_directory"] = Value{storage.path.string()};
            const auto rechecked = std::get<Value::Object>(plan.data).contains("selection") ?
                rediscover_machine_plan(plan) : select_machine_extra_volumes(
                inspect_machine(disk,storage.path.string()),selected_mounts,bare_metal);
            if (rechecked != plan) {
                const auto& expected = std::get<Value::Object>(plan.data);
                const auto& actual = std::get<Value::Object>(rechecked.data);
                for (const auto& [key, value] : expected)
                    if (!actual.contains(key) || actual.at(key) != value)
                        throw Error("capture topology changed while reserving storage: "+key);
                throw Error("capture topology gained an unexpected field while reserving storage");
            }
            Value cow_identity, output_identity;
            Value::Array extras, disk_reservations;
            const auto omit_raw_cache = [&](Value& disk, const std::string& reason) {
                machine_cache_raw_regions(disk,[](const MachineVolumeRegion&) {
                    throw MachineRawCacheCopyError("static copy destination unavailable");
                },[] {},[] {});
                std::get<Value::Object>(disk.data)["raw_copy_error"] = Value{reason};
            };
            const auto reserve_raw = [&](Value& disk,const std::string& filename) {
                std::unique_ptr<File> output;
                if (raw_ready) {
                    const auto fd = openat(storage.raw_fd(),filename.c_str(),O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
                    if (fd >= 0) {
                        output = std::make_unique<File>(fd);
                        const auto length = number(field(disk,"layout"),"length");
                        if (!length || length > INT64_MAX) throw Error("raw interval geometry exceeds supported range");
                        if (!ftruncate(fd,static_cast<off_t>(length)) && !fsync(fd)) return output;
                        raw_error = std::strerror(errno);
                        output.reset();
                        if (unlinkat(storage.raw_fd(),filename.c_str(),0))
                            throw Error("cannot remove failed static-copy reservation");
                    } else {
                        if (errno == EEXIST) throw CaptureUncertain("raw interval reservation path already exists");
                        raw_error = std::strerror(errno);
                    }
                }
                omit_raw_cache(disk,raw_error);
                return output;
            };
            {
                if (persistent_tracking) {
                    slots.clear();
                    root_tracking = reserve_machine_tracking(field(plan,"root"),storage.path.parent_path(),id,slots);
                    slots.push_back(static_cast<std::uint32_t>(number(root_tracking,"minor")));
                    tracking_files.push_back(root_tracking);
                }
                File cow(persistent_tracking ?
                    open(text(root_tracking,"cow_path").c_str(),O_RDWR|O_NOFOLLOW|O_CLOEXEC) :
                    openat(storage.directory.fd,"root.cow",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
                auto output = std::get<Value::Object>(plan.data).contains("layout") ?
                    reserve_raw(plan,"raw.cache") : std::unique_ptr<File>{};
                std::vector<std::unique_ptr<File>> other_outputs;
                cow_identity = file_identity(cow.fd);
                if (output) output_identity = file_identity(output->fd);
                Value::Object marker{
                    {"format",Value{std::string("opensabba-unpublished-reservation-v3")}},
                    {"id",Value{id}},{"directory",Value{storage.path.string()}},
                    {"directory_inode",Value{std::uint64_t{inspect(storage.directory.fd).st_ino}}},
                    {"filesystem_uuid",field(plan,"cow_filesystem_uuid")},
                    {"raw_directory",Value{storage.raw_path.string()}},
                    {"raw_directory_inode",Value{std::uint64_t{inspect(storage.raw_fd()).st_ino}}},
                    {"raw_cache_policy",raw_policy},{"raw_storage_ready",Value{std::uint64_t{raw_ready}}},
                    {"root.cow",cow_identity},{"raw.cache",output_identity}};
                for (std::size_t index = 0;
                     index < optional_array(plan,"additional_disks").size(); ++index) {
                    auto& disk_plan = mutable_array(plan,"additional_disks")[index];
                    const auto name = additional_image_name(index+1);
                    auto image = reserve_raw(disk_plan,name);
                    const auto identity = image ? file_identity(image->fd) : Value{};
                    marker.emplace(name,identity);
                    other_outputs.push_back(std::move(image));
                    disk_reservations.push_back(Value{Value::Object{
                        {"disk_index",Value{std::uint64_t{index+1}}},
                        {"output",identity}}});
                }
                for (const auto* selected_ptr : selected_partitions(plan)) {
                    const auto& selected = *selected_ptr;
                    const auto name = extra_cow_name(selected);
                    Value extra_tracking;
                    if (persistent_tracking) {
                        extra_tracking = reserve_machine_tracking(selected,storage.path.parent_path(),id,slots);
                        slots.push_back(static_cast<std::uint32_t>(number(extra_tracking,"minor")));
                        tracking_files.push_back(extra_tracking);
                    }
                    File extra(persistent_tracking ?
                        open(text(extra_tracking,"cow_path").c_str(),O_RDWR|O_NOFOLLOW|O_CLOEXEC) :
                        openat(storage.directory.fd,name.c_str(),O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
                    const auto identity = file_identity(extra.fd);
                    if (fsync(extra.fd)) throw Error("cannot persist extra capture COW file");
                    marker.emplace(name,identity);
                    Value::Object extra_reservation{
                        {"minor",Value{std::uint64_t{slots.at(extras.size()+1)}}},
                        {"partition",field(selected,"partition")},
                        {"disk_index",field(selected,"disk_index")},
                        {"mount_path",field(selected,"mount_path")},
                        {"cow",identity},{"attempted",Value{std::uint64_t{0}}},
                        {"released",Value{std::uint64_t{0}}},{"snapshot",Value{}}};
                    if (std::get<Value::Object>(selected.data).contains("lv_uuid"))
                        extra_reservation.emplace("lv_uuid",field(selected,"lv_uuid"));
                    if (persistent_tracking)
                        for (const auto& [key,value] : std::get<Value::Object>(extra_tracking.data))
                            extra_reservation[key] = value;
                    extras.push_back(Value{std::move(extra_reservation)});
                }
                if (fsync(cow.fd) || fsync(storage.raw_fd()))
                    throw Error(std::string("cannot persist capture files: ")+std::strerror(errno));
                marker["raw_storage_ready"] = Value{std::uint64_t{raw_ready}};
                if (persistent_tracking) marker["tracking"] = Value{tracking_files};
                storage.save_value(Value{std::move(marker)},"reservation.pstream");
            }
            CaptureJournal prepared{id,boot_id(),CapturePhase::prepared,plan,Value{Value::Object{
                {"directory",Value{storage.path.string()}},{"cow",cow_identity},{"output",output_identity},
                {"raw_directory",Value{storage.raw_path.string()}},
                {"raw_directory_inode",Value{std::uint64_t{inspect(storage.raw_fd()).st_ino}}},
                {"raw_cache_policy",raw_policy},{"raw_storage_ready",Value{std::uint64_t{raw_ready}}},
                {"minor",Value{std::uint64_t{slots.front()}}},
                {"cow_mib",Value{persistent_tracking ? std::uint64_t{0} : mib}},
                {"snapshot_attempted",Value{std::uint64_t{0}}},{"snapshot_released",Value{std::uint64_t{0}}},
                {"snapshot_time",Value{std::uint64_t{0}}},
                {"disks",Value{std::move(disk_reservations)}},
                {"extras",Value{std::move(extras)}}}}, {},{},{},5,{},{}};
            if (persistent_tracking)
                for (const auto& [key,value] : std::get<Value::Object>(root_tracking.data))
                    std::get<Value::Object>(prepared.reservation.data)[key] = value;
            storage.save(prepared);
            if (unlinkat(storage.directory.fd,"reservation.pstream",0) || fsync(storage.directory.fd))
                throw Error(std::string("cannot retire unpublished capture reservation: ")+std::strerror(errno));
            return prepared;
        } catch (const std::exception& failure) {
            try {
                struct stat published{};
                if (fstatat(storage.directory.fd,"capture.pstream",&published,AT_SYMLINK_NOFOLLOW) &&
                    errno == ENOENT)
                    for (const auto& file : tracking_files) prune_machine_tracking(file);
                storage.discard_unpublished(parent.fd,name);
            }
            catch (const std::exception& cleanup) {
                throw Error(std::string(failure.what())+"; reservation cleanup failed: "+cleanup.what()+
                            "; inspect "+storage.path.string());
            }
            throw;
        }
    }();
    Value::Array files;
    for (const auto& path : cache_exclusions) files.push_back(Value{path.string()});
    std::get<Value::Object>(journal.reservation.data)["cache_exclusions"] = Value{std::move(files)};
    storage.save(journal);
    reserved(journal); // Caller persists ownership before any host mutation.
    LinuxCapture operations(storage,journal,cancelled,stopping);
    operations.open_sources();
    run_machine_capture(journal,operations,hooks);
    return journal;
#else
    (void)plan; (void)task; (void)mib; (void)reserved; (void)cancelled; (void)validate_plan; (void)hooks; (void)persistent_tracking; (void)cache_exclusions; (void)stopping;
    throw Error("machine capture requires Linux");
#endif
}

CaptureJournal create_machine_capture(const std::string& disk, const std::string& directory,
    std::uint64_t mib, const std::function<void(const CaptureJournal&)>& reserved,
    const std::function<bool()>& cancelled, const std::function<void(const Value&)>& validate_plan,
    const std::vector<std::string>& selected_mounts, bool bare_metal, const SnapshotBoundaryHooks& hooks,
    bool persistent_tracking, const std::vector<std::filesystem::path>& cache_exclusions,
    const std::function<bool()>& stopping) {
    auto plan = select_machine_extra_volumes(inspect_machine(disk,directory),selected_mounts,bare_metal);
    return create_machine_capture_from_plan(std::move(plan),Value{Value::Object{}},mib,reserved,cancelled,
        validate_plan,hooks,persistent_tracking,cache_exclusions,stopping);
}

void discard_machine_reservation(const std::filesystem::path& path) {
#ifdef __linux__
    Storage storage(path);
    storage.discard_reservation();
#else
    (void)path;
    throw Error("capture reservation cleanup requires Linux");
#endif
}

}
