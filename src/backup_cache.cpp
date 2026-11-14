#include "opensabba/backup_cache.hpp"
#include "opensabba/capture.hpp"
#include "opensabba/machine_capture.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#endif

namespace opensabba {
using pstream::Value;
using pstream::Error;
namespace {
const Value::Object& object(const Value& v) {
    const auto* p = std::get_if<Value::Object>(&v.data);
    if (!p) throw Error("invalid backup cache object");
    return *p;
}
std::uint64_t number(const Value& v, const char* key) {
    const auto& o = object(v);
    const auto found = o.find(key);
    if (found == o.end()) throw Error(std::string("missing backup cache setting: ")+key);
    const auto* n = std::get_if<std::uint64_t>(&found->second.data);
    if (!n) throw Error(std::string("invalid backup cache number: ")+key);
    return *n;
}
bool flag(const Value& v, const char* key) {
    if (!object(v).contains(key)) return false;
    const auto n = number(v,key);
    if (n > 1) throw Error(std::string("invalid backup cache flag: ")+key);
    return n != 0;
}
std::string text(const Value& v, const char* key) {
    const auto found = object(v).find(key);
    if (found == object(v).end()) throw Error(std::string("missing backup cache text: ")+key);
    const auto* s = std::get_if<std::string>(&found->second.data);
    if (!s) throw Error(std::string("invalid backup cache text: ")+key);
    return *s;
}
void basename(std::string_view name) {
    if (name.empty() || name == "." || name == ".." ||
        name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") != name.npos)
        throw Error("invalid backup cache filename");
}
void persist_directory(const std::filesystem::path& directory) {
#ifdef __linux__
    const auto fd = open(directory.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (fd < 0) throw Error("cannot open backup cache directory for persistence");
    const auto result = fsync(fd);
    close(fd);
    if (result) throw Error("cannot persist backup cache directory");
#else
    (void)directory;
#endif
}
void seek(std::FILE* f, std::uint64_t offset) {
    if (offset > INT64_MAX) throw Error("backup cache offset is too large");
#ifdef _WIN32
    const auto result = _fseeki64(f,static_cast<__int64>(offset),SEEK_SET);
#else
    const auto result = fseeko(f,static_cast<off_t>(offset),SEEK_SET);
#endif
    if (result) throw Error("cannot seek backup cache file");
}
struct CacheFile {
    std::FILE* file;
    std::filesystem::path path;
    std::uint64_t size = 0;
    std::int64_t modified = 0;
    std::int64_t modified_ns = 0;
    explicit CacheFile(const std::filesystem::path& p, bool create) : path(p) {
#ifdef _WIN32
        file = std::fopen(p.string().c_str(),create ? "wbx+" : "rb");
#else
        const auto fd = open(p.c_str(),(create ? O_RDWR|O_CREAT|O_EXCL : O_RDONLY)|
            O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0600);
        file = fd < 0 ? nullptr : fdopen(fd,create ? "wb+" : "rb");
        if (fd >= 0 && !file) close(fd);
#endif
        if (!file) throw Error(create ? "cannot create backup cache file" : "cannot open backup cache file");
#ifndef _WIN32
        if (create && fchmod(fileno(file),0600)) { std::fclose(file); throw Error("cannot protect backup cache file"); }
#endif
        try { remember(); } catch (...) { std::fclose(file); throw; }
    }
    ~CacheFile() { std::fclose(file); }
    void remember() {
#ifdef _WIN32
        struct _stat64 st{};
        if (_fstat64(_fileno(file),&st) || (st.st_mode & _S_IFMT) != _S_IFREG)
#else
        struct stat st{};
        if (fstat(fileno(file),&st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
            st.st_uid != getuid() || (st.st_mode & 0077))
#endif
            throw Error("invalid backup cache file ownership or type");
        size = static_cast<std::uint64_t>(st.st_size);
        modified = static_cast<std::int64_t>(st.st_mtime);
#ifdef __linux__
        modified_ns = st.st_mtim.tv_nsec;
#endif
    }
    void verify() {
        const auto previous_size = size;
        const auto previous_modified = modified;
        const auto previous_ns = modified_ns;
        remember();
        if (size != previous_size || modified != previous_modified || modified_ns != previous_ns)
            throw Error("backup cache file changed");
    }
    void write(std::span<const std::uint8_t> bytes) {
        if (std::fwrite(bytes.data(),1,bytes.size(),file) != bytes.size())
            throw Error("cannot write backup cache file");
    }
    void read(std::span<std::uint8_t> bytes) {
        if (std::fread(bytes.data(),1,bytes.size(),file) != bytes.size())
            throw Error("short read from backup cache file");
    }
    void sync() {
        if (std::fflush(file)) throw Error("cannot flush backup cache file");
#ifdef _WIN32
        if (_commit(_fileno(file)))
#else
        if (fsync(fileno(file)))
#endif
            throw Error("cannot persist backup cache file");
        remember();
    }
    std::string digest() {
        seek(file,0);
        std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free);
        if (!ctx || EVP_DigestInit_ex(ctx.get(),EVP_md5(),nullptr) != 1)
            throw Error("cannot initialize backup cache digest");
        std::array<std::uint8_t,65536> buffer{};
        for (std::uint64_t at = 0; at < size;) {
            const auto length = static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(),size-at));
            read(std::span(buffer).first(length));
            if (EVP_DigestUpdate(ctx.get(),buffer.data(),length) != 1) throw Error("cannot hash backup cache");
            at += length;
        }
        std::array<unsigned char,16> bytes{};
        unsigned length = 0;
        if (EVP_DigestFinal_ex(ctx.get(),bytes.data(),&length) != 1 || length != bytes.size())
            throw Error("cannot finalize backup cache digest");
        std::string result;
        constexpr char hex[] = "0123456789abcdef";
        for (auto byte : bytes) { result += hex[byte >> 4]; result += hex[byte & 15]; }
        return result;
    }
};
using Header = std::array<std::uint64_t,5>;
std::array<std::uint8_t,40> encode(const Header& h) {
    std::array<std::uint8_t,40> result{};
    for (std::size_t n = 0; n < h.size(); ++n)
        for (unsigned byte = 0; byte < 8; ++byte)
            result[n*8+byte] = static_cast<std::uint8_t>(h[n] >> (byte*8));
    return result;
}
Header read_header(CacheFile& file, std::uint64_t index) {
    seek(file.file,index*40);
    std::array<std::uint8_t,40> bytes{};
    file.read(bytes);
    Header result{};
    for (std::size_t n = 0; n < result.size(); ++n)
        for (unsigned byte = 0; byte < 8; ++byte)
            result[n] |= std::uint64_t{bytes[n*8+byte]} << (byte*8);
    return result;
}
std::pair<std::string,std::string> filenames(const Value& manifest) {
    if (number(manifest,"format") != 1) throw Error("unsupported backup cache file format");
    const auto header = text(manifest,"header"), data = text(manifest,"data");
    basename(header); basename(data);
    if (header == data) throw Error("backup cache file pair is not distinct");
    return {header,data};
}
std::string policy_digest(const BackupImage& image, const IncrementalBackup& incremental,
    TransferCompression compression) {
    const auto ranges = [](std::span<const ChangedExtent> entries) {
        Value::Array result;
        for (const auto& range : entries) result.push_back(Value{Value::Object{
            {"offset",Value{range.offset}},{"length",Value{range.length}}}});
        return Value{std::move(result)};
    };
    const auto bytes = pstream::encode(Value{Value::Object{{"name",Value{image.name}},
        {"size",Value{image.source->size()}},{"ranges",delta_plan_value(incremental.plan)},
        {"allocation",Value{std::uint64_t{incremental.plan.filesystem_allocation}}},
        {"unused",ranges(image.unused_ranges)},{"reread",ranges(image.reread_ranges)},
        {"compression",Value{std::uint64_t{compression == TransferCompression::lz4}}}}});
    std::array<unsigned char,16> digest{};
    unsigned length = 0;
    if (EVP_Digest(bytes.data(),bytes.size(),digest.data(),&length,EVP_md5(),nullptr) != 1 ||
        length != digest.size()) throw Error("cannot hash backup cache interval policy");
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (auto byte : digest) { result += hex[byte>>4]; result += hex[byte&15]; }
    return result;
}
}
bool backup_cache_capture_partial(const CaptureJournal& capture) {
    if (capture_snapshot_omitted(capture.snapshot)) return true;
    const auto& reserved = object(capture.reservation);
    if (!reserved.contains("extras")) return false;
    const auto& extras = std::get<Value::Array>(reserved.at("extras").data);
    return std::any_of(extras.begin(),extras.end(),[](const auto& extra) {
        return capture_snapshot_omitted(object(extra).at("snapshot"));
    });
}
bool backup_cache_base_eligible(const CaptureJournal& capture, const Value& configured_target) {
    if (capture.phase != CapturePhase::ready || !capture.failure.empty() ||
        backup_cache_capture_partial(capture) ||
        machine_incremental_target(capture.plan) != machine_incremental_target(configured_target))
        return false;
    const auto& plan = object(capture.plan);
    const auto& target = object(configured_target);
    if (plan.contains("cow_filesystem_uuid") != target.contains("cow_filesystem_uuid") ||
        (plan.contains("cow_filesystem_uuid") &&
         plan.at("cow_filesystem_uuid") != target.at("cow_filesystem_uuid")))
        return false;
    const std::filesystem::path directory{text(capture.reservation,"directory")};
    if (directory.parent_path() != std::filesystem::path{text(configured_target,"cow_directory")} ||
        directory.filename() != "capture-"+capture.id || !std::filesystem::exists(directory))
        return false;
    const auto marker = directory/"retention.pstream";
    if (std::filesystem::symlink_status(marker).type() == std::filesystem::file_type::not_found)
        return true;
    CacheFile file(marker,false);
    if (file.size > 65536) throw Error("capture retention marker exceeds size limit");
    pstream::Bytes bytes(static_cast<std::size_t>(file.size));
    file.read(bytes);
    const auto retention = pstream::decode(bytes,{65536,4096,16});
    if (number(retention,"format") != 1 || text(retention,"capture_id") != capture.id ||
        (text(retention,"state") != "delete-pending" && text(retention,"state") != "deleted"))
        throw Error("capture retention marker differs from its cached base");
    return false;
}
Value backup_cache_write_event(const Value& request, const Value& owner,
    const Value& policy_record, std::string event_id, std::uint64_t now) {
    const auto& record = object(policy_record);
    const auto& task = record.at("task");
    if (record.at("task_owner") != owner || !number(policy_record,"assigned") ||
        number(request,"task_id") != number(owner,"task_id") ||
        number(task,"id") != number(owner,"task_id") ||
        text(request,"task_uuid") != text(task,"task_uuid"))
        throw Error("local cache event belongs to another assigned NAS task");
    if (text(request,"event_type") != "cache_write")
        throw Error("unsupported local backup event type");
    if (!backup_cache_policy(task).enabled) throw Error("backup caching is disabled");
    basename(event_id);
    return Value{Value::Object{{"task_owner",owner},{"task_id",Value{number(request,"task_id")}},
        {"task_uuid",Value{text(task,"task_uuid")}},
        {"event_id",Value{std::move(event_id)}},{"event_type",Value{std::string("cache_write")}},
        {"trigger_type",Value{std::uint64_t{2}}},{"due",Value{now}}}};
}
BackupCachePolicy backup_cache_policy(const Value& task) {
    BackupCachePolicy result;
    result.enabled = flag(task,"cached_enabled");
    if (!result.enabled) return result;
    result.paused = flag(task,"is_paused");
    result.volume_uuid = text(task,"cached_volume_name");
    result.mount_path = text(task,"cached_mount_path");
    result.floor_unit = number(task,"cached_volume_space_lower_bound_unit");
    result.floor_value = number(task,"cached_volume_space_lower_bound_value");
    if (result.volume_uuid.empty() || result.floor_unit > 1 ||
        (result.floor_unit == 0 && result.floor_value > 100))
        throw Error("invalid NAS backup cache location or free-space floor");
    return result;
}
Value translate_backup_cache_task(Value task, const Value::Array& mounted) {
    const auto policy = backup_cache_policy(task);
    if (!policy.enabled || (policy.volume_uuid != "{SystemVolume}" && policy.volume_uuid != "{DataVolume}"))
        return task;
    const Value* selected = nullptr;
    for (const auto& volume : mounted) {
        const auto system = flag(volume,"is_system_drive");
        if (system != (policy.volume_uuid == "{SystemVolume}")) continue;
        if (!selected || number(volume,"free_size") > number(*selected,"free_size")) selected = &volume;
    }
    auto& fields = std::get<Value::Object>(task.data);
    if (!selected) {
        fields["cached_enabled"] = Value{std::uint64_t{0}};
        fields["cached_mount_path"] = Value{std::string{}};
        fields["cached_volume_name"] = Value{std::string{}};
        fields["cached_volume_space_lower_bound_unit"] = Value{std::uint64_t{0}};
        fields["cached_volume_space_lower_bound_value"] = Value{std::uint64_t{0}};
        fields["is_paused"] = Value{std::uint64_t{0}};
    } else {
        fields["cached_mount_path"] = Value{text(*selected,"path")};
        fields["cached_volume_name"] = Value{text(*selected,"volume_name")};
    }
    return task;
}
bool backup_cache_space_enough(const BackupCachePolicy& policy, std::uint64_t capacity, std::uint64_t free) {
    if (policy.floor_unit > 1 || (policy.floor_unit == 0 && policy.floor_value > 100))
        throw Error("invalid backup cache free-space floor");
    if (free > capacity) throw Error("invalid backup cache free-space measurement");
    if (policy.floor_unit == 0) {
        const auto floor = capacity/100*policy.floor_value + capacity%100*policy.floor_value/100;
        return free > floor;
    }
    return policy.floor_value <= UINT64_MAX/(std::uint64_t{1}<<30) &&
        free > policy.floor_value*(std::uint64_t{1}<<30);
}
std::filesystem::path backup_cache_directory(const BackupCachePolicy& policy, std::string_view uuid, bool admission) {
    if (!policy.enabled) throw Error("backup caching is disabled");
    basename(uuid);
#ifdef _WIN32
    (void)admission;
    throw Error("backup cache volume resolution requires Linux");
#else
    basename(policy.volume_uuid);
    const auto device = std::filesystem::canonical(std::filesystem::path("/dev/disk/by-uuid")/policy.volume_uuid);
    struct stat st{};
    if (stat(device.c_str(),&st) || !S_ISBLK(st.st_mode)) throw Error("backup cache UUID is not a block device");
    const auto id = std::to_string(major(st.st_rdev))+":"+std::to_string(minor(st.st_rdev));
    std::ifstream mounts("/proc/self/mountinfo");
    std::string line;
    while (std::getline(mounts,line)) {
        std::istringstream input(line);
        std::string mount_id, parent, dev, root, mount;
        if (!(input >> mount_id >> parent >> dev >> root >> mount) || dev != id || root != "/") continue;
        std::string path;
        for (std::size_t n = 0; n < mount.size(); ++n) {
            if (mount[n] == '\\' && n+3 < mount.size() &&
                mount[n+1] >= '0' && mount[n+1] <= '7' &&
                mount[n+2] >= '0' && mount[n+2] <= '7' &&
                mount[n+3] >= '0' && mount[n+3] <= '7') {
                path += static_cast<char>((mount[n+1]-'0')*64+(mount[n+2]-'0')*8+mount[n+3]-'0');
                n += 3;
            } else path += mount[n];
        }
        const auto space = std::filesystem::space(path);
        if (admission && !backup_cache_space_enough(policy,space.capacity,space.free))
            throw Error("backup cache free-space floor reached (7066)");
        const auto directory = std::filesystem::path(path)/uuid;
        if (mkdir(directory.c_str(),0700) && errno != EEXIST) throw Error("cannot create task backup cache directory");
        if (lstat(directory.c_str(),&st) || !S_ISDIR(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 0077))
            throw Error("task backup cache directory must be private and owned");
        persist_directory(path);
        return directory;
    }
    throw Error("backup cache filesystem UUID is not mounted");
#endif
}
Value write_backup_cache_image(const std::filesystem::path& directory, std::string_view name,
    const BackupImage& image, const IncrementalBackup& incremental, TransferCompression compression,
    const std::function<bool()>& cancelled) {
    basename(name);
    const auto header_name = std::string(name)+".header", data_name = std::string(name)+".data";
    // A failed attempt owns only the files it managed to create.
    std::vector<std::filesystem::path> owned;
    try {
        CacheFile header(directory/header_name,true);
        owned.push_back(directory/header_name);
        CacheFile data(directory/data_name,true);
        owned.push_back(directory/data_name);
        std::uint64_t position = 0, count = 0;
        stream_image(*image.source,image.name,1024*1024,[&](const Value& block) {
            const auto& fields = object(block);
            std::uint64_t size = 0;
            if (const auto found = fields.find("buffer"); found != fields.end()) {
                const auto& bytes = std::get<pstream::Bytes>(found->second.data);
                size = bytes.size();
                data.write(bytes);
            }
            const auto flags = std::uint64_t{flag(block,"used")} |
                std::uint64_t{flag(block,"changed")}<<1 |
                std::uint64_t{flag(block,"compressed")}<<2 |
                std::uint64_t{flag(block,"is_interval_cbt")}<<3;
            header.write(encode({number(block,"offset"),number(block,"length"),position,size,flags}));
            position += size;
            ++count;
        },cancelled,0,compression,&incremental.plan,image.unused_ranges,image.reread_ranges);
        data.sync(); header.sync();
        persist_directory(directory);
        image.source->verify_unchanged();
        return Value{Value::Object{{"format",Value{std::uint64_t{1}}},{"name",Value{image.name}},
            {"size",Value{image.source->size()}},{"records",Value{count}},
            {"header",Value{header_name}},{"data",Value{data_name}},
            {"policy_md5",Value{policy_digest(image,incremental,compression)}},
            {"header_md5",Value{header.digest()}},{"data_md5",Value{data.digest()}}}};
    } catch (...) {
        for (const auto& path : owned) std::filesystem::remove(path);
        throw;
    }
}
void validate_backup_cache_image_policy(const Value& manifest, const BackupImage& image,
    const IncrementalBackup& incremental, TransferCompression compression) {
    if (text(manifest,"policy_md5") != policy_digest(image,incremental,compression))
        throw Error("backup cache interval policy differs from its captured blocks");
}
struct CachedBackupImage::Impl {
    std::unique_ptr<CacheFile> header, data;
    std::unique_ptr<ImageSource> source;
    std::uint64_t count, size;
    std::string name;
    Impl(const std::filesystem::path& directory, const Value& manifest)
        : count(number(manifest,"records")), size(number(manifest,"size")), name(text(manifest,"name")) {
        const auto files = filenames(manifest);
        header = std::make_unique<CacheFile>(directory/files.first,false);
        data = std::make_unique<CacheFile>(directory/files.second,false);
        if (!count || count > UINT64_MAX/40 || header->size != count*40 ||
            header->digest() != text(manifest,"header_md5") || data->digest() != text(manifest,"data_md5"))
            throw Error("backup cache file integrity check failed");
        std::uint64_t at = 0, payload = 0;
        for (std::uint64_t index = 0; index < count; ++index) {
            const auto h = read_header(*header,index);
            if (h[0] != at || !h[1] || h[1]%512 || h[1] > size-at ||
                h[2] != payload || h[3] > data->size-payload || h[3] > 2*1024*1024 ||
                h[1] > 1024*1024 || h[4] > 15 || (((h[4]&3) == 3) != (h[3] != 0)) ||
                ((h[4]&4) && !h[3]) || (h[3] && !(h[4]&4) && h[3] != h[1]))
                throw Error("invalid backup cache record coverage or payload");
            at += h[1]; payload += h[3];
        }
        if (at != size || payload != data->size) throw Error("incomplete backup cache image");
        source = std::make_unique<ImageSource>(size,ImageSource::PreparedStream{
            [this](auto image, auto offset, const auto& send, const auto& cancelled) {
                if (image != name) throw Error("backup cache image name differs from upload");
                auto low = std::uint64_t{0}, high = count;
                while (low < high) {
                    const auto mid = low+(high-low)/2;
                    if (read_header(*header,mid)[0] < offset) low = mid+1;
                    else high = mid;
                }
                if (offset == size) return;
                if (low == count || read_header(*header,low)[0] != offset)
                    throw Error("NAS cache checkpoint is not an exact cached record boundary");
                for (auto index = low; index < count; ++index) {
                    if (cancelled && cancelled()) throw Cancelled();
                    const auto h = read_header(*header,index);
                    Value::Object block{{"image_name",Value{name}},{"offset",Value{h[0]}},
                        {"length",Value{h[1]}},{"used",Value{h[4]&1}},
                        {"changed",Value{(h[4]>>1)&1}},{"is_interval_cbt",Value{(h[4]>>3)&1}}};
                    if (h[3]) {
                        pstream::Bytes bytes(static_cast<std::size_t>(h[3]));
                        seek(data->file,h[2]); data->read(bytes);
                        block["buffer"] = Value{std::move(bytes)};
                        if (h[4]&4) block["compressed"] = Value{std::uint64_t{1}};
                    } else block["changed_length"] = Value{std::uint64_t{0}};
                    send(Value{std::move(block)});
                }
            }},[this] { header->verify(); data->verify(); });
    }
};
CachedBackupImage::CachedBackupImage(const std::filesystem::path& directory, const Value& manifest)
    : impl_(std::make_unique<Impl>(directory,manifest)) {}
CachedBackupImage::~CachedBackupImage() = default;
ImageSource& CachedBackupImage::source() { return *impl_->source; }
void remove_backup_cache_image(const std::filesystem::path& directory, const Value& manifest) {
    const auto files = filenames(manifest);
    for (const auto& [name,key] : {std::pair{files.first,"header_md5"},std::pair{files.second,"data_md5"}}) {
        const auto path = directory/name;
        if (!std::filesystem::exists(path)) continue;
        {
            CacheFile file(path,false);
            if (file.digest() != text(manifest,key)) throw Error("refusing to delete changed backup cache file");
        }
        std::filesystem::remove(path);
    }
    persist_directory(directory);
}
void remove_backup_cache_attempt(const std::filesystem::path& directory, std::string_view name) {
    basename(name);
    for (const auto suffix : {".header",".data"}) {
        const auto path = directory/(std::string(name)+suffix);
        if (std::filesystem::symlink_status(path).type() == std::filesystem::file_type::not_found) continue;
        { CacheFile owned(path,false); }
        std::filesystem::remove(path);
    }
    persist_directory(directory);
}
std::vector<ChangedExtent> backup_cache_exclusions(std::string_view origin, std::uint64_t length,
    std::span<const std::filesystem::path> files) {
    std::vector<ChangedExtent> result;
    if (files.empty()) return result;
#ifdef __linux__
    struct stat device{};
    if (stat(std::string(origin).c_str(),&device) || !S_ISBLK(device.st_mode))
        throw Error("cannot identify cache exclusion origin");
    for (const auto& path : files) {
        CacheFile file(path,false);
        struct stat st{};
        if (fstat(fileno(file.file),&st)) throw Error("cannot identify cache exclusion file");
        if (st.st_dev != device.st_rdev) continue;
        std::uint64_t at = 0;
        while (at < file.size) {
            constexpr std::size_t capacity = 128;
            std::vector<std::uint64_t> buffer((sizeof(fiemap)+capacity*sizeof(fiemap_extent)+7)/8,0);
            auto* map = reinterpret_cast<fiemap*>(buffer.data());
            map->fm_start = at; map->fm_length = UINT64_MAX-at;
            map->fm_flags = FIEMAP_FLAG_SYNC; map->fm_extent_count = capacity;
            if (ioctl(fileno(file.file),FS_IOC_FIEMAP,map)) throw Error("cannot map backup cache exclusions");
            if (!map->fm_mapped_extents) break;
            for (unsigned n = 0; n < map->fm_mapped_extents; ++n) {
                const auto& extent = map->fm_extents[n];
                if (extent.fe_flags & (FIEMAP_EXTENT_UNKNOWN|FIEMAP_EXTENT_DELALLOC|FIEMAP_EXTENT_ENCODED|
                    FIEMAP_EXTENT_DATA_ENCRYPTED|FIEMAP_EXTENT_NOT_ALIGNED|FIEMAP_EXTENT_DATA_INLINE))
                    throw Error("backup cache exclusion has unsupported physical extent flags");
                result.push_back({extent.fe_physical,extent.fe_length});
                at = extent.fe_logical+extent.fe_length;
            }
            if (map->fm_extents[map->fm_mapped_extents-1].fe_flags & FIEMAP_EXTENT_LAST) break;
        }
    }
#else
    (void)origin; (void)files;
#endif
    return union_unused_ranges(length,std::move(result));
}
}
