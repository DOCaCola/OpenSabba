#include "opensabba/machine_tracking.hpp"
#include "opensabba/machine.hpp"
#include "opensabba/snapshot_driver.hpp"
#include "opensabba/image.hpp"
#include "opensabba/tracking_record.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/rand.h>
#include <array>
#include <set>
#include <utility>
#ifdef __linux__
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/ioctl.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <unistd.h>
#endif

namespace opensabba {
using pstream::Value;
using pstream::Error;
namespace {
namespace fs = std::filesystem;
const Value::Object& object(const Value& value) { return std::get<Value::Object>(value.data); }
const Value& field(const Value& value, const char* key) { return object(value).at(key); }
std::uint64_t number(const Value& value, const char* key) {
    return std::get<std::uint64_t>(field(value,key).data);
}
std::string text(const Value& value, const char* key) { return std::get<std::string>(field(value,key).data); }
const Value::Array& array(const Value& value, const char* key) {
    static const Value::Array empty;
    return object(value).contains(key) ? std::get<Value::Array>(field(value,key).data) : empty;
}
bool logical(const Value& volume) { return object(volume).contains("lv_uuid"); }
std::vector<const Value*> volumes(const Value& plan) {
    std::vector<const Value*> result{&field(plan,"root")};
    for (const auto& entry : array(plan,"selected_extra")) result.push_back(&entry);
    for (const auto& disk : array(plan,"additional_disks"))
        for (const auto& entry : array(disk,"selected_extra")) result.push_back(&entry);
    return result;
}
const Value& reservation(const CaptureJournal& journal, std::size_t index) {
    return index ? array(journal.reservation,"extras").at(index-1) : journal.reservation;
}
const Value& snapshot(const CaptureJournal& journal, std::size_t index) {
    return index ? field(reservation(journal,index),"snapshot") : journal.snapshot;
}
bool same_generation(const Value& a, const Value& b) {
    if (!std::holds_alternative<Value::Object>(a.data) ||
        !std::holds_alternative<Value::Object>(b.data)) return false;
    if (capture_snapshot_omitted(a) || capture_snapshot_omitted(b)) return false;
    return field(a,"uuid") == field(b,"uuid") && field(a,"sequence") == field(b,"sequence");
}
void set(Value& value, const char* key, Value next) { std::get<Value::Object>(value.data)[key] = std::move(next); }
#ifdef __linux__
struct File {
    int fd;
    explicit File(int value) : fd(value) {
        if (fd < 0) throw Error("cannot open machine tracking storage: "+std::string(std::strerror(errno)));
    }
    ~File() { close(fd); }
    File(const File&) = delete;
};
struct stat inspect(int fd) {
    struct stat st{};
    if (fstat(fd,&st)) throw Error("cannot inspect tracking storage");
    if (st.st_uid != geteuid() || (st.st_mode & 0077) ||
        (!S_ISDIR(st.st_mode) && (!S_ISREG(st.st_mode) || st.st_nlink != 1)))
        throw Error("machine tracking storage must be private and owned");
    return st;
}
Value identity(int fd) {
    const auto st = inspect(fd);
    return Value{Value::Object{{"device",Value{std::uint64_t{st.st_dev}}},
                               {"inode",Value{std::uint64_t{st.st_ino}}}}};
}
void check_file(const Value& reserved, int fd) {
    const auto observed = identity(fd);
    const auto& expected = field(reserved,"cow");
    if (field(observed,"inode") != field(expected,"inode"))
        throw Error("machine tracking COW inode changed");
    const auto st = inspect(fd);
    if (machine_filesystem_uuid({major(st.st_dev),minor(st.st_dev)}) != text(reserved,"tracking_filesystem_uuid"))
        throw Error("machine tracking COW filesystem changed");
}
pstream::Bytes read_at(int fd, std::uint64_t at, std::size_t length) {
    pstream::Bytes result(length);
    std::size_t done = 0;
    while (done < length) {
        const auto count = pread(fd,result.data()+done,length-done,static_cast<off_t>(at+done));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw Error("cannot read machine tracking history");
        done += static_cast<std::size_t>(count);
    }
    return result;
}
CaptureJournal load_capture(const fs::path& directory) {
    File dir(open(directory.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    inspect(dir.fd);
    if (flock(dir.fd,LOCK_SH|LOCK_NB)) throw Error("machine tracking history is still being changed");
    File file(openat(dir.fd,"capture.pstream",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));
    const auto st = inspect(file.fd);
    constexpr pstream::Limits limits{24*1024*1024,1000000,20};
    if (st.st_size <= 0 || st.st_size > static_cast<off_t>(limits.max_bytes))
        throw Error("invalid machine tracking history size");
    auto journal = capture_journal_from_value(pstream::decode(
        read_at(file.fd,0,static_cast<std::size_t>(st.st_size)),limits));
    if (text(journal.reservation,"directory") != directory.string() ||
        directory.filename() != "capture-"+journal.id)
        throw Error("tracking history is outside its capture reservation");
    return journal;
}
std::string tracking_executable() {
    std::string executable(4096,'\0');
    const auto count = readlink("/proc/self/exe",executable.data(),executable.size());
    if (count <= 0 || count == static_cast<ssize_t>(executable.size()))
        throw Error("cannot locate executable for synosnap reload record");
    executable.resize(static_cast<std::size_t>(count));
    return executable;
}
void write_hook(const Value& volume, const Value& reserved, const Value& snapshot, bool active_snapshot) {
    MachineTrackingRecords("/etc/synosnap/dla").publish(
        volume,reserved,snapshot,tracking_executable(),active_snapshot);
}
void remove_hook(const Value& volume) {
    MachineTrackingRecords("/etc/synosnap/dla").retire(volume);
}
void remove_history_cows(const Value::Array& removed) {
    // Both Snapshot deletion and Bad-state cleanup
    // commit DB deletion before unlinking COW names; remove failures do not
    // prevent the remaining COW/hook/driver cleanup.
    for (const auto& row : removed) {
        try { MachineTrackingHistory(text(row,"directory")).retire(row); }
        catch (const std::exception& error) {
            std::cerr << "Snapshot retirement bookkeeping failed: " << error.what() << std::endl;
        }
        const auto path = text(row,"cow_path");
        if (access(path.c_str(),F_OK) == 0) std::remove(path.c_str());
    }
}
void remove_history_hook(const Value& volume) {
    try { remove_hook(volume); }
    catch (const std::exception& error) {
        std::cerr << "Snapshot reload cleanup failed: " << error.what() << std::endl;
    }
}
void retire_history_chain(const Value& volume, const Value& reserved) {
    // the official agent deletes rows by saved bdev and monotonically ordered history ID,
    // independently of immutable transfer journals and of kernel occupancy.
    if (object(reserved).contains("history_id")) {
        MachineTrackingDatabaseStore store(fs::path(text(reserved,"directory")).parent_path()/"tracking-history.pstream");
        auto history = store.load();
        const auto removed = history.remove_before(reserved);
        store.save(history);
        remove_history_cows(removed);
    } else prune_machine_tracking(reserved);
    remove_history_hook(object(reserved).contains("device") ? reserved : volume);
}
void validate_snapshot(const Value& current, const Value& reserved, const Value& volume) {
    if (number(current,"minor") != number(reserved,"minor") ||
        text(current,"origin_path") != text(volume,"device") ||
        text(current,"cow_path") != text(reserved,"cow_relative"))
        throw Error("machine tracking slot differs from its on-origin reservation");
}
Value closed_changes(const Value& prior, const Value&, const Value& volume) {
    const int descriptor = open(text(prior,"cow_path").c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if (descriptor < 0) {
        const auto error = errno;
        throw SnapshotPreviousCowError("cannot open previous machine tracking COW: "+
            std::string(std::strerror(error)),error);
    }
    File file(descriptor);
    check_file(prior,file.fd);
    const auto before = inspect(file.fd);
    const auto bitmap = compact_cow_index([&](auto at,auto size) { return read_at(file.fd,at,size); },
        static_cast<std::uint64_t>(before.st_size),number(volume,"length"));
    const auto after = inspect(file.fd);
    if (before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec)
        throw Error("closed machine tracking COW changed while reading");
    return Value{bitmap};
}
Value cow_file_extents(const Value& volume) {
    const auto directory = fs::path(text(volume,"mount_path"))/".synosnap_data";
    File dir(open(directory.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    inspect(dir.fd);
    std::vector<ChangedExtent> extents;
    for (const auto& entry : fs::directory_iterator(directory)) {
        File file(openat(dir.fd,entry.path().filename().c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));
        const auto st = inspect(file.fd);
        if (!st.st_size) continue;
        std::uint64_t at = 0;
        while (at < static_cast<std::uint64_t>(st.st_size)) {
            constexpr std::size_t capacity = 128;
            std::vector<std::uint64_t> buffer((sizeof(fiemap)+capacity*sizeof(fiemap_extent)+7)/8,0);
            auto* map = reinterpret_cast<fiemap*>(buffer.data());
            map->fm_start = at;
            map->fm_length = UINT64_MAX-at;
            // COW files are preallocated before tracing starts. Request only
            // their allocation map: syncing the actively written COW here
            // would wait on the same filesystem journal the COW worker serves.
            map->fm_flags = 0;
            map->fm_extent_count = capacity;
            if (ioctl(file.fd,FS_IOC_FIEMAP,map)) throw Error("cannot locate internal synosnap COW data blocks");
            if (!map->fm_mapped_extents) break;
            for (unsigned i = 0; i < map->fm_mapped_extents; ++i) {
                const auto& extent = map->fm_extents[i];
                if (extent.fe_flags & (FIEMAP_EXTENT_UNKNOWN|FIEMAP_EXTENT_DELALLOC|FIEMAP_EXTENT_ENCODED|
                    FIEMAP_EXTENT_DATA_ENCRYPTED|FIEMAP_EXTENT_NOT_ALIGNED|FIEMAP_EXTENT_DATA_INLINE))
                    throw Error("internal synosnap COW has unsupported physical extent flags");
                extents.push_back({extent.fe_physical,extent.fe_length});
                at = extent.fe_logical+extent.fe_length;
            }
            if (map->fm_extents[map->fm_mapped_extents-1].fe_flags & FIEMAP_EXTENT_LAST) break;
        }
    }
    Value::Array result;
    for (const auto& extent : union_unused_ranges(number(volume,"length"),std::move(extents)))
        result.push_back(Value{Value::Object{{"offset",Value{extent.offset}},{"length",Value{extent.length}}}});
    return Value{std::move(result)};
}
struct TrackingControl final : MachineTrackingControl {
    std::optional<Value> information(std::uint32_t minor) override {
        return snapshot_driver_information(minor);
    }
    void verify_prior_cow(const Value& prior) override {
        const int descriptor = open(text(prior,"cow_path").c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
        if (descriptor < 0 && errno == ENOENT && object(prior).contains("cow_missing")) return;
        File cow(descriptor);
        check_file(prior,cow.fd);
    }
    Value close_prior(const Value& prior, const Value& current, const Value& volume) override {
        return closed_changes(prior,current,volume);
    }
    void release(const Value& observed) override {
        snapshot_driver_bad_state(observed);
    }
    void retire_record(const Value& volume, const Value& reserved) override {
        retire_history_chain(volume,reserved);
    }
    void create(std::uint32_t minor, const std::string& origin,
                const std::string& cow, std::uint64_t mib) override {
        snapshot_driver_setup(minor,origin,cow,mib);
    }
    void renew(const Value& observed, const std::string& cow, std::uint64_t mib) override {
        snapshot_driver_renew(observed,cow,mib);
    }
};
#else
CaptureJournal load_capture(const fs::path&) { throw Error("machine tracking history requires Linux"); }
#endif
}

std::string machine_tracking_cow_name(std::uint64_t seconds) {
    std::array<unsigned char,16> bytes{};
    if (RAND_bytes(bytes.data(),static_cast<int>(bytes.size())) != 1)
        throw Error("cannot generate snapshot COW UUID");
    bytes[6] = static_cast<unsigned char>((bytes[6] & 15U) | 0x40U);
    bytes[8] = static_cast<unsigned char>((bytes[8] & 63U) | 0x80U);
    constexpr char hex[] = "0123456789abcdef";
    auto name = std::to_string(seconds)+"_";
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) name += '-';
        name += hex[bytes[i] >> 4]; name += hex[bytes[i] & 15];
    }
    return name;
}

Value reserve_machine_tracking(const Value& volume, const fs::path& captures,
    std::string_view id, std::span<const std::uint32_t> reserved_minors) {
#ifdef __linux__
    const auto mount = fs::path(text(volume,"mount_path"));
    const auto directory = mount/".synosnap_data";
    if (mkdir(directory.c_str(),0700) && errno != EEXIST)
        throw Error("cannot create on-origin synosnap data directory");
    File dir(open(directory.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    const auto st = inspect(dir.fd);
    const auto& device = text(volume,"device_number");
    if (std::to_string(major(st.st_dev))+":"+std::to_string(minor(st.st_dev)) != device)
        throw Error("synosnap COW directory does not reside on its origin");
    MachineTrackingDatabaseStore store(captures/"tracking-history.pstream");
    auto history = store.load();
    TrackingControl control;
    auto prior = prepare_machine_tracking(history,volume,control);
    if (prior) {
        const int descriptor = open(text(*prior,"cow_path").c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
        const bool missing_cow = descriptor < 0 && errno == ENOENT;
        if (!missing_cow) {
            File cow(descriptor);
            check_file(*prior,cow.fd);
        } else set(*prior,"cow_missing",Value{std::uint64_t{1}});
    }
    auto allocated = history.minors();
    allocated.insert(allocated.end(),reserved_minors.begin(),reserved_minors.end());
    const auto selected = prior ? static_cast<std::uint32_t>(number(*prior,"minor")) :
        static_cast<std::uint32_t>(machine_tracking_free_minor(allocated));
    const auto name = machine_tracking_cow_name(static_cast<std::uint64_t>(std::time(nullptr)));
    File cow(openat(dir.fd,name.c_str(),O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
    if (fsync(cow.fd) || fsync(dir.fd)) throw Error("cannot persist on-origin COW reservation");
    Value::Object result{{"minor",Value{std::uint64_t{selected}}},{"cow",identity(cow.fd)},
        {"cow_path",Value{(directory/name).string()}},{"cow_relative",Value{"/.synosnap_data/"+name}},
        {"tracking_filesystem_uuid",field(volume,"filesystem_uuid")},
        {"directory",Value{(captures/("capture-"+std::string(id))).string()}},
        {"capture_id",Value{std::string(id)}}};
    if (prior) result["prior"] = std::move(*prior);
    return Value{std::move(result)};
#else
    (void)volume; (void)captures; (void)id; (void)reserved_minors;
    throw Error("persistent machine tracking requires Linux");
#endif
}

Value acquire_machine_tracking(Value& reserved, const Value& volume, std::uint64_t mib,
                               const std::function<void(const Value&)>& persist) {
#ifdef __linux__
    File cow(open(text(reserved,"cow_path").c_str(),O_RDWR|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));
    check_file(reserved,cow.fd);
    TrackingControl control;
    const auto current = transition_machine_tracking(reserved,volume,mib,control);
    set(reserved,"cow_unused",cow_file_extents(volume));
    Value::Object row{{"device",Value{machine_tracking_device(volume)}},{"snapshot",current}};
    for (const auto key : {"minor","cow_relative","cow_path","cow","tracking_filesystem_uuid",
                            "directory","capture_id","cow_unused"})
        row[key] = field(reserved,key);
    MachineTrackingDatabaseStore store(fs::path(text(reserved,"directory")).parent_path()/"tracking-history.pstream");
    auto history = store.load();
    history.add(Value{std::move(row)}); // setup / transition.
    store.save(history); // the official agent inserts successful history before Reload-record creation.
    persist(current);
    write_hook(volume,reserved,current,true);
    return current;
#else
    (void)reserved; (void)volume; (void)mib; (void)persist;
    throw Error("persistent machine tracking requires Linux");
#endif
}

void finish_machine_tracking(const Value& reserved, const Value& volume, const Value& saved) {
#ifdef __linux__
    const auto observed = snapshot_driver_information(static_cast<std::uint32_t>(number(reserved,"minor")));
    if (!observed) throw Error("machine snapshot disappeared before tracking transition");
    validate_snapshot(*observed,reserved,volume);
    if (!same_generation(*observed,saved)) throw Error("machine snapshot generation changed before tracking");
    if (number(*observed,"snapshot_mode")) snapshot_driver_track(*observed);
    else if (!number(*observed,"active") || number(*observed,"unverified") ||
             number(*observed,"cancelled") || text(*observed,"error_code") != "0")
        throw Error("machine snapshot did not enter healthy tracking mode");
    write_hook(volume,reserved,*observed,false);
#else
    (void)reserved; (void)volume; (void)saved;
    throw Error("persistent machine tracking requires Linux");
#endif
}
void discard_machine_tracking(const Value& reserved, const Value& volume, const Value& saved) {
#ifdef __linux__
    const auto observed = snapshot_driver_information(static_cast<std::uint32_t>(number(reserved,"minor")));
    if (observed) {
        validate_snapshot(*observed,reserved,volume);
        if (!number(*observed,"unverified") &&
            std::holds_alternative<Value::Object>(saved.data) && !same_generation(*observed,saved))
            throw Error("unhealthy machine tracking generation changed");
        snapshot_driver_release(*observed);
    }
    remove_hook(volume);
#else
    (void)reserved; (void)volume; (void)saved;
    throw Error("persistent machine tracking requires Linux");
#endif
}

namespace {
void remove_tracking_cow(const Value& reserved, bool require_unused) {
#ifdef __linux__
    const auto path = text(reserved,"cow_path");
    const auto& expected = field(reserved,"cow");
    const auto parent = fs::path(path).parent_path();
    if (parent.filename() != ".synosnap_data") throw Error("invalid on-origin tracking path");
    const int directory = open(parent.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    // A missing origin has no mounted COW pathname to unlink.
    if (directory < 0 && errno == ENOENT) return;
    File dir(directory);
    const auto st = inspect(dir.fd);
    if (machine_filesystem_uuid({major(st.st_dev),minor(st.st_dev)}) != text(reserved,"tracking_filesystem_uuid"))
        throw Error("machine tracking COW filesystem changed");
    const auto remove = [&] {
        const auto name = fs::path(path).filename().string();
        const int descriptor = openat(dir.fd,name.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
        if (descriptor < 0 && errno == ENOENT) return;
        File file(descriptor);
        check_file(reserved,file.fd);
        // History pruning is independent of boot commands. Snapshot deletion
        // removes the reload only once no history for its bdev remains.
        if (unlinkat(dir.fd,name.c_str(),0) || fsync(dir.fd)) throw Error("cannot prune tracking history");
    };
    if (require_unused)
        with_unused_snapshot_cow(path,static_cast<std::uint64_t>(st.st_dev),number(expected,"inode"),remove);
    else remove();
#else
    (void)reserved; (void)require_unused;
    throw Error("persistent machine tracking requires Linux");
#endif
}
}
void prune_machine_tracking(const Value& reserved) {
    remove_tracking_cow(reserved,true);
}
void prune_failed_machine_tracking(const Value& reserved) {
    remove_tracking_cow(reserved,false);
}
void prune_machine_tracking_history(const Value& reserved, const Value& volume,
                                    const fs::path& captures) {
#ifdef __linux__
    if (number(reserved,"minor") == machine_tracking_no_minor) {
        // Exhausted setup never added a history or published a boot command.
        prune_machine_tracking(reserved);
        return;
    }
    MachineTrackingDatabaseStore store(captures/"tracking-history.pstream");
    auto history = store.load();
    const auto removed = history.delete_snapshot(reserved);
    store.save(history);
    remove_history_cows(removed);
    if (removed.empty()) return;
    if (!history.last(volume)) {
        remove_history_hook(volume);
        const auto observed = snapshot_driver_information(static_cast<std::uint32_t>(number(removed.front(),"minor")));
        if (observed) snapshot_driver_release(*observed);
    }
#else
    (void)reserved; (void)volume; (void)captures;
    throw Error("persistent machine tracking requires Linux");
#endif
}
void verify_machine_tracking_cow(const Value& reserved) {
#ifdef __linux__
    File file(open(text(reserved,"cow_path").c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));
    check_file(reserved,file.fd);
#else
    (void)reserved;
    throw Error("persistent machine tracking requires Linux");
#endif
}

DeltaPlan machine_tracking_delta(const CaptureJournal& current, const CaptureJournal& base,
                                std::size_t image_index, std::span<const std::string> current_images,
                                std::span<const std::string> base_images,
                                std::vector<ChangedExtent>* reread, bool require_cbt, Value* interval_policy) {
    const bool allocation = capture_snapshot_omitted(current.snapshot) ||
        object(current.reservation).contains("filesystem_unused");
    const auto planned = volumes(current.plan);
    const auto base_volumes = volumes(base.plan);
    const auto physical_count = machine_physical_image_count(current.plan);
    std::uint64_t size = image_index < physical_count ?
        number(field(image_index ? array(current.plan,"additional_disks").at(image_index-1) : current.plan,
                     "layout"),"length") : 0;
    const auto image_of = [](const auto& selected, std::size_t origin, std::size_t physical) {
        if (!logical(*selected[origin])) return origin ? number(*selected[origin],"disk_index") : 0;
        for (std::size_t i = 0; i < origin; ++i) if (logical(*selected[i])) ++physical;
        return static_cast<std::uint64_t>(physical);
    };
    const auto base_physical = machine_physical_image_count(base.plan);
    const auto count_images = [](const auto& selected, std::size_t physical) {
        return physical+static_cast<std::size_t>(std::count_if(selected.begin(),selected.end(),
            [](const auto* volume) { return logical(*volume); }));
    };
    if (current_images.size() != count_images(planned,physical_count) ||
        base_images.size() != count_images(base_volumes,base_physical) || image_index >= current_images.size())
        throw Error("machine transfer image inventory differs from its capture");
    const auto& image_name = current_images[image_index];
    const bool new_image = std::find(base_images.begin(),base_images.end(),image_name) == base_images.end();
    Value::Array origins;
    bool complete_cbt = true;
    std::vector<ChangedExtent> inherited;
    std::size_t logical_index = physical_count;
    for (std::size_t index = 0; index < planned.size(); ++index) {
        const auto& volume = *planned[index];
        const auto logical_image = logical(volume) ? logical_index++ : 0;
        if ((logical(volume) && logical_image != image_index) ||
            (!logical(volume) && (index ? number(volume,"disk_index") : 0) != image_index)) continue;
        const auto length = number(volume,"length");
        const auto offset = logical(volume) ? 0 : number(volume,"offset");
        if (logical(volume)) size = length;
        Value origin_policy{Value::Object{
            {"filesystem_uuid",field(volume,"filesystem_uuid")},{"offset",Value{offset}},
            {"length",Value{length}},{"logical",Value{std::uint64_t{logical(volume)}}},
            {"omitted",Value{std::uint64_t{capture_snapshot_omitted(snapshot(current,index))}}},
            {"is_cbt",Value{std::uint64_t{0}}},{"base_image_name",Value{std::string{}}}}};
        if (capture_snapshot_omitted(snapshot(current,index))) {
            origins.push_back(std::move(origin_policy));
            continue;
        }
        const auto found = std::find_if(base_volumes.begin(),base_volumes.end(),[&](const Value* other) {
            return field(*other,"filesystem_uuid") == field(volume,"filesystem_uuid");
        });
        bool coordinates = false;
        if (found != base_volumes.end()) {
            const auto base_index = static_cast<std::size_t>(found-base_volumes.begin());
            const auto& old = **found;
            const auto old_image = image_of(base_volumes,base_index,base_physical);
            if (old_image >= base_images.size()) throw Error("machine base image inventory differs from its origins");
            set(origin_policy,"base_image_name",Value{base_images[old_image]});
            coordinates = logical(old) == logical(volume) && base_images[old_image] == image_name &&
                (logical(old) ? 0 : number(old,"offset")) == offset;
        }
        if (!coordinates) {
            complete_cbt = false;
            origins.push_back(std::move(origin_policy));
            if (require_cbt) throw Error("cache capture has no filesystem CBT base (7035)");
            if (reread) reread->push_back({offset,length});
            continue;
        }
        const auto base_index = static_cast<std::size_t>(found-base_volumes.begin());
        const auto blocks = (length+65535)/65536;
        std::vector<pstream::Bytes> bitmaps;
        CaptureJournal generation = current;
        std::size_t generation_index = index;
        std::set<std::string> visited;
        bool continuous = false;
        while (visited.insert(generation.id).second) {
            const auto& reserved = reservation(generation,generation_index);
            if (!object(reserved).contains("previous_capture_id") ||
                !object(reserved).contains("changes")) break;
            auto changes = std::get<pstream::Bytes>(field(reserved,"changes").data);
            // A retained pre-allocation capture has a saved wire policy which
            // forced its COW extents changed. Reproduce that exact plan on
            // resume; allocation-aware captures use official agent's independent flags.
            if (!allocation)
                for (const auto* source : {&reserved,&field(reserved,"prior")})
                    for (const auto& extent : array(*source,"cow_unused")) {
                        const auto begin = number(extent,"offset"), count = number(extent,"length");
                        if (begin > length || count > length-begin)
                            throw Error("internal COW extent exceeds its filesystem");
                        changes.resize(std::max(changes.size(),static_cast<std::size_t>((blocks+7)/8)),0);
                        for (auto block = begin/65536; block < (begin+count+65535)/65536; ++block)
                            changes.at(static_cast<std::size_t>(block/8)) |= std::uint8_t{1} << (block%8);
                    }
            bitmaps.push_back(std::move(changes));
            if (text(reserved,"previous_capture_id") == base.id) {
                const auto& previous = field(field(reserved,"prior"),"snapshot");
                continuous = same_generation(previous,snapshot(base,base_index));
                break;
            }
            auto previous = load_capture(text(reserved,"previous_directory"));
            if (previous.id != text(reserved,"previous_capture_id"))
                throw Error("machine CBT history points at a different capture");
            const auto prior_volumes = volumes(previous.plan);
            const auto prior = std::find_if(prior_volumes.begin(),prior_volumes.end(),[&](const Value* item) {
                return field(*item,"filesystem_uuid") == field(volume,"filesystem_uuid");
            });
            if (prior == prior_volumes.end()) break;
            generation_index = static_cast<std::size_t>(prior-prior_volumes.begin());
            generation = std::move(previous);
        }
        // Changed-map lookup visits stored history in chronological
        // order. Each subsequent map sets the accumulator's length; bytes
        // newly exposed by a longer map start at 0xff, then the maps are ORed.
        pstream::Bytes bitmap;
        for (auto changes = bitmaps.rbegin(); changes != bitmaps.rend(); ++changes) {
            if (bitmap.empty()) bitmap = *changes;
            else {
                bitmap.resize(changes->size(),255);
                for (std::size_t byte = 0; byte < bitmap.size(); ++byte) bitmap[byte] |= (*changes)[byte];
            }
        }
        if (!continuous || bitmap.empty()) {
            complete_cbt = false;
            origins.push_back(std::move(origin_policy));
            if (require_cbt) throw Error("cache capture lost its filesystem CBT chain (7035)");
            if (reread) reread->push_back({offset,length});
            continue; // Missing ancestry or empty Changed-map lookup means a full interval.
        }
        set(origin_policy,"is_cbt",Value{std::uint64_t{1}});
        origins.push_back(std::move(origin_policy));
        std::uint64_t at = 0;
        for (std::uint64_t block = 0; block < blocks; ++block) {
            if (block/8 < bitmap.size() &&
                !(bitmap[static_cast<std::size_t>(block/8)] & (1 << (block%8)))) continue;
            const auto start = block*65536;
            if (start > at) inherited.push_back({offset+at,start-at});
            at = std::min(length,start+65536);
        }
        if (at < length) inherited.push_back({offset+at,length-at});
    }
    if (new_image) {
        inherited.clear();
        if (reread) *reread = {{0,size}};
    }
    if (interval_policy) *interval_policy = Value{Value::Object{
        {"format",Value{std::uint64_t{1}}},{"image_name",Value{image_name}},
        {"base_image_name",Value{new_image ? std::string{} : image_name}},
        {"is_cbt",Value{std::uint64_t{complete_cbt}}},{"origins",Value{std::move(origins)}}}};
    // CBT covers the complete filesystem interval, including its first and
    // last queries. Physical headers/gaps remain separate raw intervals.
    DeltaPlan result{size,0,{}};
    result.filesystem_allocation = allocation;
    std::uint64_t at = 0;
    const auto append = [&](std::uint64_t end, bool changed) {
        if (end == at) return;
        result.ranges.push_back({at,end-at,changed});
        if (changed) result.transfer_bytes += end-at;
        at = end;
    };
    for (const auto& extent : union_changed_extents(size,std::move(inherited))) {
        append(extent.offset,true);
        append(extent.offset+extent.length,false);
    }
    append(size,true);
    validate_delta_plan(result,size);
    return result;
}

std::vector<ChangedExtent> machine_tracking_unused(const CaptureJournal& journal, std::size_t image_index,
                                                 bool incremental, std::span<const ChangedExtent> reread) {
    const auto planned = volumes(journal.plan);
    const auto physical_count = machine_physical_image_count(journal.plan);
    std::size_t logical_index = physical_count;
    std::vector<ChangedExtent> result;
    std::uint64_t size = image_index < physical_count ?
        number(field(image_index ? array(journal.plan,"additional_disks").at(image_index-1) : journal.plan,
                     "layout"),"length") : 0;
    for (std::size_t index = 0; index < planned.size(); ++index) {
        const auto& volume = *planned[index];
        const auto logical_image = logical(volume) ? logical_index++ : 0;
        if ((logical(volume) && logical_image != image_index) ||
            (!logical(volume) && (index ? number(volume,"disk_index") : 0) != image_index)) continue;
        const auto length = number(volume,"length");
        const auto offset = logical(volume) ? 0 : number(volume,"offset");
        if (logical(volume)) size = length;
        if (capture_snapshot_omitted(snapshot(journal,index))) {
            result.push_back({offset,length});
            continue;
        }
        const auto& reserved = reservation(journal,index);
        std::vector<ChangedExtent> unused;
        for (const auto* key : {"cow_unused","filesystem_unused"})
        for (const auto& extent : array(reserved,key)) {
            const auto at = number(extent,"offset"), count = number(extent,"length");
            if (at > length || count > length-at) throw Error("unused extent exceeds its filesystem");
            unused.push_back({at,count});
        }
        const bool raw = std::any_of(reread.begin(),reread.end(),[&](const auto& range) {
            return range.offset <= offset && range.offset+range.length >= offset+length;
        });
        const std::uint64_t granularity = incremental && !raw ? 65536 : 1024*1024;
        for (const auto& extent : union_unused_ranges(length,std::move(unused))) {
            const auto at = (extent.offset+granularity-1)/granularity*granularity;
            const auto extent_end = extent.offset+extent.length;
            const auto end = extent_end == length ? length/4096*4096 : extent_end/granularity*granularity;
            if (end > at) result.push_back({offset+at,end-at});
        }
    }
    return union_unused_ranges(size,std::move(result));
}
std::vector<ChangedExtent> machine_snapshot_omissions(const CaptureJournal& journal, std::size_t image_index) {
    const auto planned = volumes(journal.plan);
    const auto physical_count = machine_physical_image_count(journal.plan);
    std::size_t logical_index = physical_count;
    std::vector<ChangedExtent> result;
    for (std::size_t index = 0; index < planned.size(); ++index) {
        const auto& volume = *planned[index];
        const auto logical_image = logical(volume) ? logical_index++ : 0;
        if ((logical(volume) && logical_image != image_index) ||
            (!logical(volume) && (index ? number(volume,"disk_index") : 0) != image_index)) continue;
        if (capture_snapshot_omitted(snapshot(journal,index)))
            result.push_back({logical(volume) ? 0 : number(volume,"offset"),number(volume,"length")});
    }
    return result;
}
}
