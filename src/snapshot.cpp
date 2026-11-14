#include "opensabba/snapshot.hpp"
#include "opensabba/machine_boot.hpp"
#include "opensabba/machine.hpp"
#include "opensabba/filesystem.hpp"
#include <algorithm>
#include <memory>
#include <map>
#include <set>
#include <sstream>

namespace opensabba {
namespace {
using pstream::Error;
using pstream::Bytes;
std::uint32_t le32(const Bytes& bytes, std::size_t at) {
    return std::uint32_t(bytes[at]) | (std::uint32_t(bytes[at+1]) << 8) |
           (std::uint32_t(bytes[at+2]) << 16) | (std::uint32_t(bytes[at+3]) << 24);
}
std::uint16_t le16(const Bytes& bytes, std::size_t at) {
    return static_cast<std::uint16_t>(bytes[at] | (unsigned(bytes[at+1]) << 8));
}
struct Volume {
    ImagePartition partition;
    std::string uuid, device, filesystem;
    std::string mount_path;
    bool excluded = false;
    std::vector<MachineVolumeRegion> regions{};
    const pstream::Value* planned = nullptr;
};
const pstream::Value& field(const pstream::Value& value, const char* key) {
    const auto* object = std::get_if<pstream::Value::Object>(&value.data);
    if (!object || !object->contains(key)) throw Error(std::string("machine metadata is missing ")+key);
    return object->at(key);
}
std::uint64_t number(const pstream::Value& value, const char* key) {
    const auto* result = std::get_if<std::uint64_t>(&field(value,key).data);
    if (!result) throw Error(std::string("invalid machine metadata number: ")+key);
    return *result;
}
std::string text(const pstream::Value& value, const char* key) {
    const auto* result = std::get_if<std::string>(&field(value,key).data);
    if (!result) throw Error(std::string("invalid machine metadata text: ")+key);
    return *result;
}
std::string json_string(std::string_view value) {
    std::string result{"\""};
    constexpr char hex[] = "0123456789abcdef";
    for (unsigned char ch : value) {
        if (ch == '"' || ch == '\\') { result += '\\'; result += static_cast<char>(ch); }
        else if (ch < 0x20) {
            result += "\\u00"; result += hex[ch >> 4]; result += hex[ch & 15];
        } else result += static_cast<char>(ch);
    }
    return result+'"';
}
struct FatIdentity { std::string uuid; bool fat32; };
FatIdentity fat_identity(ImageSource& source, const ImagePartition& part, std::uint32_t sector) {
    if (part.length < sector) throw Error("FAT partition is too small");
    const auto bpb = source.read_metadata(part.offset, 512);
    if (bpb[510] != 0x55 || bpb[511] != 0xaa || le16(bpb, 11) != sector ||
        (bpb[0] != 0xe9 && !(bpb[0] == 0xeb && bpb[2] == 0x90)))
        throw Error("invalid FAT boot sector or sector size");
    const std::uint64_t spc = bpb[13], reserved = le16(bpb, 14), fats = bpb[16];
    const std::uint64_t roots = le16(bpb, 17), total16 = le16(bpb, 19), total32 = le32(bpb, 32);
    const std::uint64_t fat16 = le16(bpb, 22), fat_sectors = fat16 ? fat16 : le32(bpb, 36);
    if (!spc || (spc & (spc-1)) || spc > 128 || spc*sector > 32768 ||
        !reserved || !fats || fats > 2 || !fat_sectors || (total16 && total32) ||
        (bpb[21] != 0xf0 && bpb[21] < 0xf8))
        throw Error("invalid or unsupported FAT geometry");
    const auto sectors = total16 ? total16 : total32;
    const auto metadata = reserved + fats*fat_sectors + (roots*32+sector-1)/sector;
    if (sectors > part.length/sector || sectors <= metadata)
        throw Error("FAT geometry exceeds its partition or has no data region");
    const auto clusters = (sectors-metadata)/spc;
    if (clusters < 4085) throw Error("FAT12 boot partitions are not supported");
    const bool fat32 = clusters >= 65525;
    const auto width = fat32 ? 4U : 2U;
    if (clusters > 0x0ffffff5 || fat_sectors*sector/width < clusters+2)
        throw Error("FAT table cannot address the data region");
    if (fat32 ? (fat16 || roots || total16 || le16(bpb, 42)) :
                (!fat16 || !roots || roots*32 % sector))
        throw Error("FAT variant disagrees with its cluster geometry");
    const auto signature = fat32 ? 66U : 38U, serial = fat32 ? 67U : 39U;
    if (bpb[signature] != 0x29 || !le32(bpb, serial))
        throw Error("FAT volume has no extended serial identity");
    unsigned active = 0;
    bool mirrored = true;
    if (fat32) {
        const auto flags = le16(bpb, 40);
        if (flags & 0xff70) throw Error("unsupported FAT32 flags");
        mirrored = !(flags & 0x80);
        if (!mirrored) active = flags & 15;
        if (active >= fats) throw Error("FAT32 active table is outside its table count");
        const auto root = le32(bpb, 44);
        if (root < 2 || root > clusters+1) throw Error("FAT32 root cluster exceeds the data region");
        const auto fsinfo = le16(bpb, 48), backup = le16(bpb, 50);
        if ((fsinfo != 0xffff && fsinfo >= reserved) ||
            (backup != 0xffff && backup >= reserved))
            throw Error("FAT32 reserved metadata exceeds its reserved region");
        if (backup && backup != 0xffff) {
            const auto other = source.read_metadata(part.offset+std::uint64_t(backup)*sector, 512);
            // Linux updates the primary FAT_STATE_DIRTY bit independently of
            // the backup BPB. It is runtime state, not filesystem geometry.
            if (other[510] != 0x55 || other[511] != 0xaa ||
                !std::equal(bpb.begin()+11, bpb.begin()+65, other.begin()+11) ||
                ((bpb[65] ^ other[65]) & ~1U) ||
                !std::equal(bpb.begin()+66, bpb.begin()+90, other.begin()+66))
                throw Error("FAT32 backup boot metadata differs from its primary");
        }
        const auto entry = source.read_metadata(part.offset+(reserved+active*fat_sectors)*sector+root*4, 4);
        const auto next = le32(entry, 0) & 0x0fffffff;
        if (next < 0x0ffffff8 && (next < 2 || next > clusters+1))
            throw Error("FAT32 root directory is unallocated or invalid");
    }
    Bytes first;
    for (unsigned table = 0; table < fats; ++table) {
        if (!mirrored && table != active) continue;
        auto entries = source.read_metadata(part.offset+(reserved+table*fat_sectors)*sector, 2*width);
        const auto media = fat32 ? (le32(entries, 0) & 0x0fffffff) : le16(entries, 0);
        const auto clean = fat32 ? (le32(entries, 4) & 0x0fffffff) : le16(entries, 2);
        const auto mask = fat32 ? 0x0fffff00U : 0xff00U;
        if (media != (mask | bpb[21]) || clean != (fat32 ? 0x0fffffffU : 0xffffU))
            throw Error("FAT filesystem is dirty, reports I/O errors, or has invalid reserved entries");
        if (!first.empty() && first != entries) throw Error("FAT mirrored reserved entries differ");
        first = std::move(entries);
    }
    constexpr char hex[] = "0123456789ABCDEF";
    const auto id = le32(bpb, serial);
    std::string uuid;
    for (int digit = 7; digit >= 0; --digit) {
        if (digit == 3) uuid += '-';
        uuid += hex[(id >> (digit*4)) & 15];
    }
    return {uuid, fat32};
}
void interval(std::ostream& out, std::uint64_t start, std::uint64_t end,
              std::string_view name, const Volume* volume,
              const MachineVolumeRegion* region = nullptr, bool upload = true) {
    out << "{\"device_name\":" << json_string(volume ? volume->device : std::string(name))
        << ",\"mount_path\":" << json_string(volume ? volume->mount_path : "")
        << ",\"volume_name\":" << json_string(volume ? volume->uuid : "")
        << ",\"alias_name\":" << json_string(volume ? volume->device : std::string(name))
        << ",\"path\":" << json_string(!upload || (region && region->type == 4) ? "" : name)
        << ",\"snapshot_id\":\"\",\"file_system\":"
        << json_string(region && !region->label.empty() ? region->label :
            volume ? volume->filesystem : "") << ",\"disk_start\":\"" << start
        << "\",\"disk_end\":\"" << end << "\",\"source_start\":\"" << (!upload && volume ? 0 : start)
        << "\",\"source_end\":\"" << (!upload && volume ? end-start : end) << "\",\"destination_start\":\"" << start
        << "\",\"destination_end\":\"" << end << "\",\"type\":"
        << (region ? region->type : volume ? (volume->excluded ? 5 : 1) : 3)
        << ",\"is_system\":" << ((region && region->system) || (volume && !volume->mount_path.empty() &&
            (volume->mount_path == "/" || volume->mount_path == "/boot" ||
             volume->mount_path.starts_with("/boot/"))) ? "true" : "false")
        << ",\"is_system_drive\":" << (volume && volume->mount_path == "/" ? "true" : "false")
        << ",\"is_primary_partition\":"
        << (volume ? "true" : "false") << '}';
}
}

namespace {
bool system_path(std::string_view path) {
    return path == "/" || path == "/boot" || path.starts_with("/boot/");
}
struct VolumeMount {
    std::string path, image, device, alias;
    std::int64_t disk, partition;
    bool system, primary, mbr;
    std::uint64_t offset, length;
};
std::string mount_json(const VolumeMount& mount) {
    std::ostringstream out;
    out << "{\"mount_path\":" << json_string(mount.path)
        << ",\"object_id\":0,\"image_path\":" << json_string(mount.image)
        << ",\"device_name\":" << json_string(mount.device)
        << ",\"alias_name\":" << json_string(mount.alias)
        << ",\"disk_number\":" << mount.disk << ",\"partition_number\":" << mount.partition
        << ",\"target_partition_number\":-1,\"volume_uuid\":\"\",\"fs_type\":\"\","
           "\"valid_offset_length\":true,\"is_system\":" << (mount.system ? "true" : "false")
        << ",\"is_primary_partition\":" << (mount.primary ? "true" : "false")
        << ",\"offset\":\"" << mount.offset << "\",\"length\":\"" << mount.length
        << "\",\"is_mbr\":" << (mount.mbr ? "true" : "false") << '}';
    return out.str();
}
struct DiskMetadata {
    std::string image, layout, disk_image;
    std::map<std::string,VolumeMount> mounts;
    bool system_mount_required = false;
    std::int64_t disk_number = -1;
};
std::string metadata_json(const pstream::Value& value) {
    if (const auto* text = std::get_if<std::string>(&value.data)) return json_string(*text);
    if (const auto* number = std::get_if<std::uint64_t>(&value.data)) return std::to_string(*number);
    if (const auto* entries = std::get_if<pstream::Value::Array>(&value.data)) {
        std::string out = "[";
        for (const auto& entry : *entries) {
            if (out.size() != 1) out += ',';
            out += metadata_json(entry);
        }
        return out+']';
    }
    if (const auto* entries = std::get_if<pstream::Value::Object>(&value.data)) {
        std::string out = "{";
        for (const auto& [key,entry] : *entries) {
            if (out.size() != 1) out += ',';
            out += json_string(key)+':'+metadata_json(entry);
        }
        return out+'}';
    }
    throw Error("unsupported LVM metadata value");
}
DiskMetadata logical_volume_metadata(ImageSource& source, std::string_view name,
    const pstream::Value& plan, const DeltaPlan* delta, bool omitted, bool upload = true) {
    const auto size = number(plan,"length");
    if (size != source.size() || !size || size % 512 || name != text(plan,"image_name"))
        throw Error("captured logical volume image differs from its plan");
    if (delta) validate_delta_plan(*delta,size);
    const auto fs = omitted || !upload ? LinuxFilesystem{} : inspect_linux_filesystem(size,[&](std::uint64_t at,std::size_t count) {
        return source.read_metadata(at,count);
    },false);
    const auto mounted = text(plan,"filesystem");
    if (upload && !omitted && (fs.uuid != text(plan,"filesystem_uuid") ||
        (fs.type != mounted && !(mounted == "ext4" && (fs.type == "ext2" || fs.type == "ext3")))))
        throw Error("captured logical volume filesystem identity differs from machine plan");
    const auto path = text(plan,"mount_path");
    if ((upload && (path.empty() || path.front() != '/')) || text(plan,"lv_uuid").empty() ||
        text(plan,"vg_uuid").empty()) throw Error("invalid selected logical volume identity");
    std::ostringstream image;
    image << "{\"image_name\":" << json_string(name);
    for (const auto* key : {"length","used_length","original_used_length"})
        image << ",\"" << key << "\":\"" << (omitted && std::string_view(key) != "length" ? 0 : size) << '"';
    for (const auto* key : {"changed_length","transfer_length","transfer_length_4k"})
        image << ",\"" << key << "\":\"" << (delta ? delta->transfer_bytes : size) << '"';
    image << ",\"excluded_length\":\"" << (omitted ? size : 0) << "\"}";
    const bool system = path == "/" || path == "/boot" || path.starts_with("/boot/");
    std::ostringstream interval;
    interval << "{\"device_name\":" << json_string(text(plan,"logical_path"))
             << ",\"mount_path\":" << json_string(path)
             << ",\"volume_name\":" << json_string(text(plan,"filesystem_uuid"))
             << ",\"alias_name\":" << json_string(path.empty() ? text(plan,"logical_path") : path)
             << ",\"path\":" << json_string(omitted || !upload ? "" : name)
             << ",\"snapshot_id\":\"\",\"file_system\":" << json_string(mounted);
    for (const auto* key : {"disk_start","source_start","destination_start"})
        interval << ",\"" << key << "\":\"0\"";
    for (const auto* key : {"disk_end","source_end","destination_end"})
        interval << ",\"" << key << "\":\"" << size << '"';
    interval << ",\"type\":" << (upload ? (omitted ? 4 : 1) : 5) << ",\"is_system\":" << (system ? "true" : "false")
             << ",\"is_system_drive\":" << (path == "/" ? "true" : "false")
             << ",\"is_primary_partition\":false}";
    std::ostringstream disk;
    disk << "{\"disk_number\":\"-1\",\"disk_layout\":\"GPT\",\"image_name\":"
         << json_string(name) << ",\"need_upload\":" << (upload ? "true" : "false") << ",\"intervals\":[" << interval.str() << "]}";
    source.verify_unchanged();
    // the official agent device metadata construction admits mounts only from interval types outside 4/5.
    // An omitted image still belongs to the layout and upload list.
    DiskMetadata result{upload ? image.str() : std::string{},{},disk.str(),{}};
    if (upload && !omitted) {
        result.mounts.emplace(path,VolumeMount{path,std::string(name),text(plan,"logical_path"),"",
            -1,-1,system,false,true,0,size});
        result.system_mount_required = system && path != "/";
    }
    return result;
}
DiskMetadata disk_metadata(ImageSource& source, std::uint32_t sector,
                           std::string_view name, std::uint64_t snapshot_time, const DeltaPlan* delta,
                           const pstream::Value* machine_plan, std::size_t disk_number,
                           std::span<const ChangedExtent> omitted_snapshots, bool upload = true) {
    validate_image_options(name, 1024*1024);
    if (!snapshot_time) throw Error("snapshot time must be a positive Unix timestamp");
    if (!omitted_snapshots.empty() && !machine_plan)
        throw Error("snapshot omission requires a captured machine plan");
    if (machine_plan && std::get<pstream::Value::Object>(machine_plan->data).contains("lv_uuid")) {
        if (!omitted_snapshots.empty() && (omitted_snapshots.size() != 1 ||
            omitted_snapshots.front().offset != 0 || omitted_snapshots.front().length != source.size()))
            throw Error("snapshot omission differs from its logical-volume image");
        return logical_volume_metadata(source,name,*machine_plan,delta,!omitted_snapshots.empty());
    }
    auto layout = [&] {
        if (upload) return inspect_image_layout(source,sector);
        const auto& saved = field(*machine_plan,"layout");
        ImageLayout result{text(saved,"scheme") == "MBR" ? ImageLayout::Scheme::mbr : ImageLayout::Scheme::gpt,
            sector,number(saved,"length"),text(saved,"disk_id"),{}};
        for (const auto& part : std::get<pstream::Value::Array>(field(saved,"partitions").data))
            result.partitions.push_back({static_cast<std::uint32_t>(number(part,"number")),
                number(part,"offset"),number(part,"length"),number(part,"attributes"),
                static_cast<std::uint8_t>(number(part,"mbr_type")),number(part,"bootable") != 0,
                text(part,"type_guid"),text(part,"uuid")});
        return result;
    }();
    std::set<std::uint32_t> omitted_partitions;
    for (const auto& range : omitted_snapshots) {
        const auto found = std::find_if(layout.partitions.begin(),layout.partitions.end(),
            [&](const auto& part) { return part.offset == range.offset && part.length == range.length; });
        if (found == layout.partitions.end() || !omitted_partitions.insert(found->number).second)
            throw Error("snapshot omission differs from its physical partition");
    }
    if (machine_plan && layout_value(layout) != field(*machine_plan,"layout"))
        throw Error("captured image layout differs from machine plan");
    if (delta) validate_delta_plan(*delta, source.size());
    if (layout.partitions.empty()) throw Error("fixed-image metadata requires at least one supported partition");
    std::sort(layout.partitions.begin(), layout.partitions.end(),
              [](const auto& a, const auto& b) { return a.offset < b.offset; });
    std::vector<Volume> volumes;
    std::set<std::string> identifiers;
    std::uint64_t excluded_length = 0;
    bool found_root = false, found_boot = false;
    std::size_t found_excluded = 0, found_selected = 0;
    for (const auto& part : layout.partitions) {
        const pstream::Value* planned = nullptr;
        bool excluded = false;
        if (machine_plan) {
            const auto& machine_fields = std::get<pstream::Value::Object>(machine_plan->data);
            for (const auto* role : {"root","boot"}) {
                if (!machine_fields.contains(role)) continue;
                const auto& entry = machine_fields.at(role);
                if (std::get<pstream::Value::Object>(entry.data).contains("lv_uuid")) continue;
                if (number(entry,"partition") == part.number) {
                    if (planned) throw Error("machine root and boot identify the same partition");
                    planned = &entry;
                    if (std::string_view(role) == "root") found_root = true;
                    else found_boot = true;
                }
            }
            const pstream::Value::Array empty;
            const auto* entries = machine_fields.contains("excluded") ?
                std::get_if<pstream::Value::Array>(&machine_fields.at("excluded").data) : &empty;
            if (!entries) throw Error("invalid excluded machine metadata");
            for (const auto& entry : *entries) if (number(entry,"partition") == part.number) {
                if (planned) throw Error("machine partition has conflicting selection");
                planned = &entry;
                excluded = true;
                ++found_excluded;
            }
            const auto* selected = machine_fields.contains("selected_extra") ?
                std::get_if<pstream::Value::Array>(&machine_fields.at("selected_extra").data) : &empty;
            if (!selected) throw Error("invalid selected machine metadata");
            for (const auto& entry : *selected) if (
                    !std::get<pstream::Value::Object>(entry.data).contains("lv_uuid") &&
                    number(entry,"partition") == part.number) {
                if (planned) throw Error("machine partition has conflicting selection");
                planned = &entry;
                ++found_selected;
            }
            if (!planned || number(*planned,"offset") != part.offset ||
                number(*planned,"length") != part.length)
                throw Error("machine partition selection differs from captured layout");
        }
        const bool omitted = omitted_partitions.contains(part.number);
        if (omitted) {
            if (!planned || excluded || text(*planned,"mount_path").empty())
                throw Error("snapshot omission does not identify a selected mounted partition");
            const auto uuid = text(*planned,"filesystem_uuid");
            if (!identifiers.insert(uuid).second) throw Error("duplicate filesystem UUID in image");
            volumes.push_back({part,uuid,std::string(name)+"p"+std::to_string(part.number),
                text(*planned,"filesystem"),text(*planned,"mount_path"),false,
                {{part.offset,part.length,4,"",false}},planned});
            excluded_length += part.length;
            continue;
        }
        if (excluded) {
            const auto& properties = std::get<pstream::Value::Object>(planned->data);
            const bool pv = properties.contains("pv_uuid");
            const auto metadata = pv && upload ? number(*planned,"pv_metadata_length") : 0;
            const auto tail = pv && upload ? number(*planned,"pv_tail_length") : 0;
            if (pv && upload && (!properties.contains("pv_wire_policy") ||
                       text(*planned,"pv_wire_policy") != "whole-partition-zero"))
                throw Error("captured LVM physical volume has no whole-partition-zero wire policy");
            if (pv && upload && (metadata < 4096 || metadata > part.length ||
                       metadata % sector || tail > part.length-metadata || tail % sector))
                throw Error("captured LVM physical-volume partition has invalid geometry");
            if (pv && upload && number(*planned,"pv_extent_length") != part.length-metadata-tail)
                throw Error("captured LVM physical-volume extent geometry differs from machine plan");
            const auto regions = machine_partition_regions(*machine_plan,*planned);
            bool wholly_excluded = true;
            for (const auto& region : regions) {
                if (region.type != 5) { wholly_excluded = false; continue; }
                excluded_length += region.length;
                for (std::uint64_t at = 0; upload && !source.direct_intervals() && at < region.length;) {
                    const auto bytes = source.read(region.offset+at,
                        static_cast<std::size_t>(std::min<std::uint64_t>(1024*1024,region.length-at)));
                    if (std::any_of(bytes.begin(),bytes.end(),[](auto byte) { return byte != 0; }))
                        throw Error("excluded machine partition contains nonzero bytes");
                    at += bytes.size();
                }
            }
            volumes.push_back({part, {}, pv || !upload ? text(*planned,"device") :
                                   std::string(name)+"p"+std::to_string(part.number),
                               pv ? "LVM2_member" : text(*planned,"filesystem"),
                               text(*planned,"mount_path"), wholly_excluded,regions,planned});
            continue;
        }
        const bool mbr = layout.scheme == ImageLayout::Scheme::mbr;
        const bool linux_partition = mbr ? part.mbr_type == 0x83 :
            part.type_guid == "0fc63daf-8483-4772-8e79-3d69d8477de4";
        const bool fat = mbr ? (part.mbr_type == 0x04 || part.mbr_type == 0x06 ||
            part.mbr_type == 0x0e || part.mbr_type == 0x0b || part.mbr_type == 0x0c || part.mbr_type == 0xef) :
            (part.type_guid == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" ||
             part.type_guid == "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7");
        if (!linux_partition && !fat) throw Error("unsupported partition type; expected Linux data or FAT16/FAT32");
        const auto linux_fs = linux_partition ? inspect_linux_filesystem(part.length,
            [&](std::uint64_t offset, std::size_t length) {
                return source.read_metadata(part.offset+offset,length);
            }, !machine_plan) : LinuxFilesystem{};
        auto uuid = linux_fs.uuid;
        if (fat) {
            const auto identity = fat_identity(source, part, sector);
            if (mbr && part.mbr_type != 0xef &&
                identity.fat32 != (part.mbr_type == 0x0b || part.mbr_type == 0x0c))
                throw Error("MBR partition type disagrees with the FAT variant");
            uuid = identity.uuid;
        }
        if (!identifiers.insert(uuid).second) throw Error("duplicate filesystem UUID in image");
        std::string filesystem = linux_partition ? linux_fs.type : "vfat";
        if (planned) {
            const auto mounted = text(*planned,"filesystem");
            const bool compatible = mounted == filesystem ||
                (linux_partition && mounted == "ext4" &&
                 (linux_fs.type == "ext2" || linux_fs.type == "ext3"));
            if (uuid != text(*planned,"filesystem_uuid") || !compatible)
                throw Error("captured filesystem identity differs from machine plan");
            // The official Linux agent metadata uses the mounted filesystem name reported
            // by libmount. Ext4 can mount compatible ext2/ext3 on-disk formats.
            filesystem = mounted;
        }
        volumes.push_back({part, std::move(uuid), std::string(name) + "p" + std::to_string(part.number),
                           std::move(filesystem),
                           planned ? text(*planned,"mount_path") : std::string{}, false,{},planned});
        if (machine_plan && machine_bare_metal(*machine_plan) && fat)
            volumes.back().regions = machine_partition_regions(*machine_plan,*planned);
    }
    if (machine_plan) {
        const auto& machine_fields = std::get<pstream::Value::Object>(machine_plan->data);
        const auto excluded_count = machine_fields.contains("excluded") ?
            std::get<pstream::Value::Array>(machine_fields.at("excluded").data).size() : 0;
        const bool logical_root = machine_fields.contains("root") &&
            std::get<pstream::Value::Object>(machine_fields.at("root").data).contains("lv_uuid");
        const auto physical_selected = machine_fields.contains("selected_extra") ?
            std::count_if(std::get<pstream::Value::Array>(machine_fields.at("selected_extra").data).begin(),
                std::get<pstream::Value::Array>(machine_fields.at("selected_extra").data).end(),
                [](const auto& entry) {
                    return !std::get<pstream::Value::Object>(entry.data).contains("lv_uuid");
                }) : 0;
        if ((machine_fields.contains("root") && !logical_root && !found_root) ||
            (machine_fields.contains("boot") && !found_boot) ||
            found_excluded != excluded_count ||
            found_selected != static_cast<std::size_t>(physical_selected))
            throw Error("machine plan does not cover every captured partition exactly once");
    }
    const auto layout_regions = machine_plan ?
        machine_layout_regions(*machine_plan) : std::vector<MachineVolumeRegion>{};
    std::vector<ChangedExtent> unused_layout;
    for (const auto& region : layout_regions)
        if (region.type == 5) {
            unused_layout.push_back({region.offset,region.length});
            excluded_length += region.length;
        }
    if (upload) verify_unused_source(source,unused_layout);
    const char* scheme = layout.scheme == ImageLayout::Scheme::mbr ? "MBR" : "GPT";
    // Machine plans supply exact mount paths and exclusions; ordinary fixed
    // images remain unmounted data images with no host claims.
    std::ostringstream image;
    image << "{\"image_name\":" << json_string(name);
    for (auto key : {"length", "used_length", "original_used_length"})
        image << ",\"" << key << "\":\""
            << (std::string_view(key) == "length" ? layout.length : layout.length-excluded_length) << '"';
    for (auto key : {"changed_length", "transfer_length", "transfer_length_4k"})
        image << ",\"" << key << "\":\"" << (delta ? delta->transfer_bytes : layout.length) << '"';
    image << ",\"excluded_length\":\"" << excluded_length << "\"}";
    std::ostringstream disk_layout;
    disk_layout << '[';
    bool first = true;
    for (const auto& volume : volumes) {
        if (!first) disk_layout << ',';
        first = false;
        const auto& p = volume.partition;
        const bool system = std::any_of(volume.regions.begin(),volume.regions.end(),
            [](const auto& region) { return region.system; }) ||
            (machine_plan && machine_bare_metal(*machine_plan) &&
                (volume.mount_path == "/" || volume.mount_path == "/boot" ||
                 volume.mount_path.starts_with("/boot/")));
        disk_layout << "{\"attribute\":" << (system ? 1 : 0)
            << ",\"device_name\":" << json_string(volume.device)
            << ",\"volume_name\":" << json_string(volume.uuid)
            << ",\"mount_path\":" << json_string(volume.mount_path)
            << ",\"file_system\":" << json_string(volume.filesystem)
            << ",\"alias_name\":" << json_string(volume.device)
            << ",\"dummy_disk_length\":\"0\",\"is_primary_partition\":true,"
               "\"disk_number\":" << disk_number << ",\"partition_number\":" << p.number << ",\"offset\":\"" << p.offset
            << "\",\"length\":\"" << p.length << "\",\"is_excluded\":"
            << (volume.excluded ? "true" : "false") << ",\"exclude_reason\":0,"
               "\"bytes_per_sector\":" << sector << '}';
    }
    disk_layout << ']';
    std::ostringstream disk_image;
    disk_image << "{\"disk_number\":\"" << disk_number << "\","
           "\"disk_layout\":\"" << scheme << "\",\"image_name\":" << json_string(name)
        << ",\"need_upload\":" << (upload ? "true" : "false") << ",\"intervals\":[";
    std::uint64_t at = 0;
    first = true;
    auto append = [&](std::uint64_t end, const Volume* volume) {
        if (end == at) return;
        if (!first) disk_image << ',';
        first = false;
        interval(disk_image, at, end, name, volume,nullptr,upload);
        at = end;
    };
    const auto append_layout = [&](std::uint64_t end) {
        if (layout_regions.empty()) { append(end,nullptr); return; }
        while (at < end) {
            const auto found = std::find_if(layout_regions.begin(),layout_regions.end(),
                [&](const auto& region) { return region.offset == at && region.length <= end-at; });
            if (found == layout_regions.end()) throw Error("machine layout metadata has incomplete intervals");
            if (!first) disk_image << ',';
            first = false;
            interval(disk_image,at,at+found->length,name,nullptr,&*found,upload);
            at += found->length;
        }
    };
    for (const auto& volume : volumes) {
        append_layout(volume.partition.offset);
        if (volume.regions.empty())
            append(volume.partition.offset + volume.partition.length, &volume);
        else for (const auto& region : volume.regions) {
            if (!first) disk_image << ',';
            first = false;
            interval(disk_image,region.offset,region.offset+region.length,name,&volume,&region,upload);
            at = region.offset+region.length;
        }
    }
    append_layout(layout.length);
    disk_image << "]}";
    source.verify_unchanged();
    DiskMetadata result{upload ? image.str() : std::string{},disk_layout.str(),disk_image.str(),{}};
    result.disk_number = static_cast<std::int64_t>(disk_number);
    for (const auto& volume : volumes) {
        const bool retained = volume.regions.empty() ? !volume.excluded :
            std::any_of(volume.regions.begin(),volume.regions.end(),[](const auto& region) {
                return region.type != 4 && region.type != 5;
            });
        if (!volume.planned || volume.mount_path.empty() || !retained) continue;
        result.system_mount_required |= system_path(volume.mount_path) && volume.mount_path != "/";
        // the official agent requires the discovered volume metadata volume name as well as a
        // mounted retained interval. Partition discovery only obtains that
        // name for ext2/3/4, XFS and FAT, independently of raw eligibility.
        if (!supported_linux_filesystem(volume.filesystem) && volume.filesystem != "vfat") continue;
        const auto& properties = std::get<pstream::Value::Object>(volume.planned->data);
        const bool named = !volume.uuid.empty() || (properties.contains("filesystem_uuid") &&
            !text(*volume.planned,"filesystem_uuid").empty());
        if (!named) continue;
        const auto& part = volume.partition;
        const bool system = part.bootable ||
            part.type_guid == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" ||
            part.type_guid == "21686148-6449-6e6f-744e-656564454649" ||
            system_path(volume.mount_path) || volume.filesystem == "swap";
        const bool mbr = layout.scheme == ImageLayout::Scheme::mbr;
        result.mounts.insert_or_assign(volume.mount_path,VolumeMount{
            volume.mount_path,std::string(name),text(*volume.planned,"device"),volume.mount_path,
            static_cast<std::int64_t>(disk_number),part.number,system,mbr && part.number <= 4,mbr,
            part.offset,part.length});
    }
    return result;
}
}
Bytes fixed_machine_metadata(std::span<const MetadataDisk> disks, std::uint64_t snapshot_time) {
    if (disks.empty()) throw Error("machine metadata requires at least one disk");
    std::vector<DiskMetadata> parts;
    parts.reserve(disks.size());
    std::set<std::string> names;
    bool cbt = false;
    for (std::size_t index = 0; index < disks.size(); ++index) {
        const auto& disk = disks[index];
        if (!names.insert(disk.image_name).second) throw Error("duplicate machine image name");
        parts.push_back(disk_metadata(*disk.source,disk.sector_size,disk.image_name,
            snapshot_time,disk.delta,disk.machine_plan,
            disk.machine_plan && std::get<pstream::Value::Object>(disk.machine_plan->data).contains("disk_number") ?
                number(*disk.machine_plan,"disk_number") : index,disk.omitted_snapshots));
        cbt |= disk.delta != nullptr;
    }
    if (cbt && std::any_of(disks.begin(),disks.end(),
                           [](const MetadataDisk& disk) { return disk.delta == nullptr; }))
        throw Error("incremental machine metadata requires a delta plan for every disk");
    const auto* plan = disks.front().machine_inventory ? disks.front().machine_inventory : disks.front().machine_plan;
    if (plan) {
        const auto& machine = std::get<pstream::Value::Object>(plan->data);
        if (machine.contains("root") &&
            std::get<pstream::Value::Object>(field(*plan,"root").data).contains("lv_uuid")) {
            const auto& primary = field(*plan,"root");
            const auto image = std::find_if(disks.begin(),disks.end(),[&](const MetadataDisk& disk) {
                return disk.machine_plan && *disk.machine_plan == primary &&
                    disk.image_name == text(primary,"image_name");
            });
            if (image == disks.end()) throw Error("machine plan is missing its root logical-volume image");
        }
    }
    std::map<std::string,VolumeMount> mounts;
    bool system_mount_required = false;
    // the official agent fills simple-volume entries before dynamic/LV entries, assigning
    // by mount path. Its std::map also determines serialized key order.
    for (const bool logical : {false,true})
        for (std::size_t index = 0; index < disks.size(); ++index) {
            const auto* plan = disks[index].machine_plan;
            const bool is_logical = plan && std::get<pstream::Value::Object>(plan->data).contains("lv_uuid");
            if (logical != is_logical) continue;
            system_mount_required |= parts[index].system_mount_required;
            for (const auto& [path,mount] : parts[index].mounts)
                mounts.insert_or_assign(path,mount);
        }
    const bool bootable = mounts.contains("/") && (!system_mount_required ||
        std::any_of(mounts.begin(),mounts.end(),[](const auto& entry) {
            return entry.first != "/" && system_path(entry.first);
        }));
    if (plan) {
        const auto& machine = std::get<pstream::Value::Object>(plan->data);
        if (machine.contains("unselected_disks"))
            for (const auto& disk : std::get<pstream::Value::Array>(field(*plan,"unselected_disks").data)) {
                ImageSource unread(number(field(disk,"layout"),"length"),
                    [](auto,auto,auto*) -> Bytes { throw Error("unselected physical image was read"); },[] {});
                parts.push_back(disk_metadata(unread,static_cast<std::uint32_t>(number(field(disk,"layout"),"sector_size")),
                    text(disk,"image_name"),snapshot_time,nullptr,&disk,number(disk,"disk_number"),{},false));
            }
        if (machine.contains("unselected_logical"))
            for (const auto& volume : std::get<pstream::Value::Array>(field(*plan,"unselected_logical").data)) {
                ImageSource unread(number(volume,"length"),
                    [](auto,auto,auto*) -> Bytes { throw Error("unselected logical image was read"); },[] {});
                parts.push_back(logical_volume_metadata(unread,text(volume,"image_name"),volume,nullptr,false,false));
            }
    }
    std::vector<const DiskMetadata*> inventory;
    for (const auto& part : parts) inventory.push_back(&part);
    std::stable_sort(inventory.begin(),inventory.end(),[](const auto* a,const auto* b) {
        return (a->disk_number < 0 ? INT64_MAX : a->disk_number) <
            (b->disk_number < 0 ? INT64_MAX : b->disk_number);
    });
    std::ostringstream out;
    out << "{\"agent_version\":\"5059\"";
    if (std::none_of(disks.begin(),disks.end(),[](const auto& disk) { return disk.machine_plan != nullptr; }))
        out << ",\"is_cbt\":" << (cbt ? "true" : "false");
    out << ",\"device_spec\":{\"is_volume\":false,"
           "\"is_bootable\":" << (bootable ? "true" : "false")
        << ",\"is_system_mbr\":false,\"cpu_number\":0,\"memory_size\":0,"
           "\"snapshot_start_time\":\"" << snapshot_time << "\",\"images\":[";
    for (std::size_t index = 0; index < disks.size(); ++index) {
        if (index) out << ',';
        out << parts[index].image;
    }
    out << "],\"mount_map\":{";
    bool first_mount = true;
    for (const auto& [path,mount] : mounts) {
        if (!first_mount) out << ',';
        first_mount = false;
        out << json_string(path) << ':' << mount_json(mount);
    }
    out << "},\"disk_layout\":{";
    bool first_layout = true;
    for (const auto* part : inventory) {
        if (part->layout.empty()) continue;
        if (!first_layout) out << ',';
        first_layout = false;
        out << json_string(std::to_string(part->disk_number)) << ':' << part->layout;
    }
    out << "},\"volume_groups\":";
    if (plan && std::get<pstream::Value::Object>(plan->data).contains("lvm"))
        out << metadata_json(field(field(*plan,"lvm"),"volume_groups"));
    else out << "[]";
    out << ",\"unsupported_volumes\":[]},\"disk_images\":[";
    for (std::size_t index = 0; index < parts.size(); ++index) {
        if (index) out << ',';
        out << inventory[index]->disk_image;
    }
    out << "]}";
    auto json = out.str();
    if (json.size() > 8*1024*1024) throw Error("snapshot metadata exceeds size limit");
    return Bytes(json.begin(), json.end());
}
Bytes fixed_image_metadata(ImageSource& source, std::uint32_t sector,
                           std::string_view name, std::uint64_t snapshot_time, const DeltaPlan* delta,
                           const pstream::Value* machine_plan) {
    const MetadataDisk disk{&source,sector,std::string(name),machine_plan,delta};
    return fixed_machine_metadata(std::span(&disk,1),snapshot_time);
}
}
