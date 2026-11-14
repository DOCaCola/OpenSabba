#include "opensabba/machine.hpp"
#include "opensabba/machine_boot.hpp"
#include "opensabba/filesystem.hpp"
#include "opensabba/lvm.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <charconv>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#ifdef __linux__
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/fs.h>
#include <spawn.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace opensabba {
using pstream::Bytes;
using pstream::Error;
using pstream::Value;
namespace {
std::uint64_t number(std::string_view text) {
    std::uint64_t n{};
    const auto [end, error] = std::from_chars(text.data(), text.data()+text.size(), n);
    if (error != std::errc{} || end != text.data()+text.size() || text.empty())
        throw Error("invalid number in machine inventory");
    return n;
}
MachineDevice device_number(std::string_view text) {
    const auto colon = text.find(':');
    if (colon == text.npos) throw Error("missing major:minor device number");
    const auto major = number(text.substr(0, colon)), minor = number(text.substr(colon+1));
    if (major > UINT32_MAX || minor > UINT32_MAX) throw Error("device number exceeds supported range");
    return {static_cast<std::uint32_t>(major), static_cast<std::uint32_t>(minor)};
}
std::string unescape(std::string_view input) {
    std::string result;
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (input[i] != '\\') { result += input[i]; continue; }
        const auto code = input.substr(i, 4);
        if (code == "\\040") result += ' ';
        else if (code == "\\011") result += '\t';
        else if (code == "\\012") result += '\n';
        else if (code == "\\134") result += '\\';
        else throw Error("invalid mountinfo path escape");
        i += 3;
    }
    return result;
}
#ifdef __linux__
bool option(std::string_view list, std::string_view value) {
    while (!list.empty()) {
        const auto comma = list.find(',');
        if (list.substr(0, comma) == value) return true;
        if (comma == list.npos) break;
        list.remove_prefix(comma+1);
    }
    return false;
}
#endif
#ifdef __linux__
pstream::Value inspect_selected_external_disk(const std::string& disk,
    const std::string& cow_directory, const std::vector<std::string>& paths,
    const LvmInventory* lvm = nullptr);
std::string text_file(const std::filesystem::path&);
std::string scalar(const std::filesystem::path&);
bool has_lvm_devices();
Value logical_volume_value(const LvmLv&, const MachineMount&);
Value lvm_selected_identity(const Value&);
Value lvm_group_value(const LvmInventory&, const LvmVg&, const std::vector<MachineMount>&);
#endif
}

bool machine_bare_metal(const Value& plan) {
    const auto& fields = std::get<Value::Object>(plan.data);
    const auto found = fields.find("volume_policy");
    if (found == fields.end()) return false;
    if (found->second != Value{std::string("linux-bare-metal-v1")})
        throw Error("unsupported machine volume policy");
    return true;
}
void record_machine_raw_volume_uuid(Value& volume, const std::function<std::string()>& probe_uuid) {
    auto& fields = std::get<Value::Object>(volume.data);
    if (std::get<std::string>(fields.at("mount_path").data).empty() ||
        std::get<std::string>(fields.at("filesystem").data) != "vfat") return;
    const auto uuid = probe_uuid();
    if (!uuid.empty()) fields["filesystem_uuid"] = Value{uuid};
}
namespace {
bool official_layout_policy(const Value& disk) {
    const auto& fields = std::get<Value::Object>(disk.data);
    const auto found = fields.find("layout_policy");
    if (found == fields.end()) return false; // Historical captures copied every gap.
    if (found->second != Value{std::string("linux-layout-v1")})
        throw Error("unsupported machine layout policy");
    return true;
}
void apply_raw_cache_failures(const Value& disk, std::vector<MachineVolumeRegion>& regions) {
    const auto& fields = std::get<Value::Object>(disk.data);
    if (!fields.contains("raw_cache_failures")) return;
    for (const auto& failure : std::get<Value::Array>(fields.at("raw_cache_failures").data)) {
        const auto& record = std::get<Value::Object>(failure.data);
        for (auto& region : regions)
            if (region.type == 3 && record.at("offset") == Value{region.offset} &&
                record.at("length") == Value{region.length})
                region.type = region.label == "swap_partition_body" ? 5U : 2U;
    }
}
std::vector<MachineVolumeRegion> gap_regions(std::uint64_t begin, std::uint64_t end,
                                           bool official, bool tail = false) {
    if (begin == end) return {};
    std::vector<MachineVolumeRegion> result;
    if (official && begin == 0) {
        const auto header = std::min(end,std::uint64_t{1024*1024});
        result.push_back({0,header,3,"",false});
        begin = header;
    }
    const auto body_end = official && tail ? end-std::min(end-begin,std::uint64_t{1024*1024}) : end;
    if (begin != body_end) {
        const auto length = body_end-begin;
        const auto type = !official || length < 16*1024*1024 ? 3U :
            length > 1024*1024*1024ULL ? 5U : 2U;
        result.push_back({begin,length,type,"",false});
    }
    if (body_end != end) result.push_back({body_end,end-body_end,3,"",false});
    return result;
}
}
std::vector<MachineVolumeRegion> machine_layout_regions(const Value& disk) {
    if (!std::get<Value::Object>(disk.data).contains("layout") || !official_layout_policy(disk)) return {};
    const auto& fields = std::get<Value::Object>(disk.data);
    const auto& layout = std::get<Value::Object>(fields.at("layout").data);
    const auto length = std::get<std::uint64_t>(layout.at("length").data);
    auto partitions = std::get<Value::Array>(layout.at("partitions").data);
    const auto number = [](const Value& entry,const char* key) {
        return std::get<std::uint64_t>(std::get<Value::Object>(entry.data).at(key).data);
    };
    std::sort(partitions.begin(),partitions.end(),[&](const Value& a,const Value& b) {
        return number(a,"offset") < number(b,"offset");
    });
    std::vector<MachineVolumeRegion> result;
    std::uint64_t at = 0;
    const auto append = [&](std::uint64_t end, bool tail = false) {
        const auto regions = gap_regions(at,end,true,tail);
        result.insert(result.end(),regions.begin(),regions.end());
    };
    for (const auto& partition : partitions) {
        const auto offset = number(partition,"offset"), size = number(partition,"length");
        if (!size || offset < at || offset > length || size > length-offset)
            throw Error("invalid machine layout interval geometry");
        append(offset);
        at = offset+size;
    }
    append(length,true);
    apply_raw_cache_failures(disk,result);
    return result;
}
std::vector<MachineVolumeRegion> machine_partition_regions(
        const Value& disk, const Value& partition) {
    const auto& fields = std::get<Value::Object>(partition.data);
    const auto numeric = [](const Value::Object& object, const char* key) {
        return std::get<std::uint64_t>(object.at(key).data);
    };
    const auto offset = numeric(fields,"offset"), length = numeric(fields,"length");
    if (!length || offset > UINT64_MAX-length) throw Error("invalid machine volume range");
    const bool selected_raw = fields.contains("selected_raw") &&
        std::get<std::uint64_t>(fields.at("selected_raw").data) != 0;
    if (!machine_bare_metal(disk) && !selected_raw) return {{offset,length,5,"",false}};
    const auto& layout = std::get<Value::Object>(
        std::get<Value::Object>(disk.data).at("layout").data);
    const auto& parts = std::get<Value::Array>(layout.at("partitions").data);
    const auto found = std::find_if(parts.begin(),parts.end(),[&](const Value& part) {
        return numeric(std::get<Value::Object>(part.data),"number") == numeric(fields,"partition");
    });
    if (found == parts.end()) throw Error("machine volume is absent from disk layout");
    const auto& table = std::get<Value::Object>(found->data);
    if (numeric(table,"offset") != offset || numeric(table,"length") != length ||
        offset > numeric(layout,"length") || length > numeric(layout,"length")-offset)
        throw Error("machine volume geometry differs from disk layout");
    const auto& mount = std::get<std::string>(fields.at("mount_path").data);
    const auto& filesystem = std::get<std::string>(fields.at("filesystem").data);
    const auto& guid = std::get<std::string>(table.at("type_guid").data);
    const bool system = numeric(table,"bootable") != 0 ||
        guid == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" ||
        guid == "21686148-6449-6e6f-744e-656564454649" ||
        mount == "/" || mount == "/boot" || mount.starts_with("/boot/") ||
        filesystem == "swap";
    if (filesystem == "swap") {
        const auto page = numeric(std::get<Value::Object>(disk.data),"swap_page_size");
        if (page < 4096 || page > 1024*1024 || (page & (page-1)))
            throw Error("invalid machine swap page size");
        std::vector<MachineVolumeRegion> result;
        const auto header = length >= page ? page : 0;
        if (header) result.push_back({offset,header,3,"swap_partition_header",true});
        if (length > header) result.push_back({offset+header,length-header,
            length-header < 16*1024*1024 ? 3U : 5U,"swap_partition_body",true});
        apply_raw_cache_failures(disk,result);
        return result;
    }
    const bool omitted = !system || filesystem == "LVM2_member" ||
        filesystem == "linux_raid_member" ||
        (length > 1024*1024*1024ULL && filesystem.empty());
    return {{offset,length,omitted ? 5U : 2U,"",system}};
}
std::vector<MachineVolumeRegion> machine_cached_regions(const Value& disk) {
    auto regions = machine_layout_regions(disk);
    const auto& fields = std::get<Value::Object>(disk.data);
    if (fields.contains("excluded"))
        for (const auto& partition : std::get<Value::Array>(fields.at("excluded").data)) {
            const auto parts = machine_partition_regions(disk,partition);
            regions.insert(regions.end(),parts.begin(),parts.end());
        }
    std::erase_if(regions,[](const auto& region) { return region.type != 3 || region.length >= 16*1024*1024; });
    std::sort(regions.begin(),regions.end(),[](const auto& a,const auto& b) { return a.offset < b.offset; });
    return regions;
}
void validate_machine_raw_cache_failures(const Value& disk) {
    const auto& fields = std::get<Value::Object>(disk.data);
    if (!fields.contains("raw_cache_failures")) return;
    const auto* failures = std::get_if<Value::Array>(&fields.at("raw_cache_failures").data);
    if (!failures || failures->empty()) throw Error("invalid raw cache failure records");
    auto original = disk;
    std::get<Value::Object>(original.data).erase("raw_cache_failures");
    const auto candidates = machine_cached_regions(original);
    std::uint64_t end = 0;
    for (const auto& failure : *failures) {
        const auto* record = std::get_if<Value::Object>(&failure.data);
        if (!record || record->size() != 2 || !record->contains("offset") || !record->contains("length"))
            throw Error("invalid raw cache failure record");
        const auto found = std::find_if(candidates.begin(),candidates.end(),[&](const auto& region) {
            return record->at("offset") == Value{region.offset} && record->at("length") == Value{region.length};
        });
        if (found == candidates.end() || found->offset < end)
            throw Error("raw cache failure does not match a planned cache interval");
        end = found->offset+found->length;
    }
}
void machine_cache_raw_regions(Value& disk,
        const std::function<void(const MachineVolumeRegion&)>& copy,
        const std::function<void()>& verify, const std::function<void()>& persist) {
    validate_machine_raw_cache_failures(disk);
    for (const auto& region : machine_cached_regions(disk)) {
        verify();
        bool failed = false;
        try { copy(region); }
        catch (const MachineRawCacheCopyError&) { failed = true; }
        // A copy failure must not conceal a changed source or lost boot lease.
        verify();
        if (!failed) continue;
        auto& fields = std::get<Value::Object>(disk.data);
        if (!fields.contains("raw_cache_failures")) fields["raw_cache_failures"] = Value{Value::Array{}};
        auto& failures = std::get<Value::Array>(fields.at("raw_cache_failures").data);
        failures.push_back(Value{Value::Object{{"offset",Value{region.offset}},{"length",Value{region.length}}}});
        std::sort(failures.begin(),failures.end(),[](const auto& a,const auto& b) {
            return std::get<std::uint64_t>(std::get<Value::Object>(a.data).at("offset").data) <
                std::get<std::uint64_t>(std::get<Value::Object>(b.data).at("offset").data);
        });
        persist();
    }
}
std::vector<ChangedExtent> machine_unused_extents(const Value& disk) {
    std::vector<ChangedExtent> result;
    const auto& fields = std::get<Value::Object>(disk.data);
    if (!fields.contains("layout")) return result;
    if (!fields.contains("excluded")) return result;
    for (const auto& part : std::get<Value::Array>(fields.at("excluded").data))
        for (const auto& region : machine_partition_regions(disk,part))
            if (region.type == 5) result.push_back({region.offset,region.length});
    for (const auto& region : machine_layout_regions(disk))
        if (region.type == 5) result.push_back({region.offset,region.length});
    std::sort(result.begin(),result.end(),[](const auto& a,const auto& b) {
        return a.offset < b.offset;
    });
    validate_unused_ranges(result,std::get<std::uint64_t>(
        std::get<Value::Object>(fields.at("layout").data).at("length").data));
    return result;
}
bool machine_disk_need_upload(const Value& disk) {
    const auto& fields = std::get<Value::Object>(disk.data);
    if (fields.contains("root") || fields.contains("boot") ||
        !std::get<Value::Array>(fields.at("selected_extra").data).empty()) return true;
    for (const auto& part : std::get<Value::Array>(fields.at("excluded").data))
        for (const auto& region : machine_partition_regions(disk,part))
            if (region.type != 5) return true;
    return false;
}

std::vector<MachineMount> parse_machine_mounts(std::string_view text) {
    std::istringstream input{std::string(text)};
    std::string line;
    std::vector<MachineMount> result;
    std::set<std::uint64_t> ids;
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        std::vector<std::string> tokens;
        std::string token;
        while (fields >> token) tokens.push_back(token);
        if (tokens.size() < 10) throw Error("incomplete mountinfo record");
        const auto separator = std::find(tokens.begin()+6, tokens.end(), "-");
        if (separator == tokens.end() || tokens.end()-separator != 4)
            throw Error("invalid mountinfo field separator");
        const auto id = number(tokens[0]);
        const auto parent_id = number(tokens[1]);
        if (!id || !ids.insert(id).second) throw Error("duplicate or zero mount ID");
        auto root = unescape(tokens[3]), path = unescape(tokens[4]);
        if (root.empty() || root.front() != '/' || path.empty() || path.front() != '/')
            throw Error("mountinfo requires absolute paths");
        std::vector<std::string> optional_fields(tokens.begin()+6,separator);
        std::sort(optional_fields.begin(),optional_fields.end());
        result.push_back({id, device_number(tokens[2]), std::move(root), std::move(path),
                          *(separator+1), tokens[5], *(separator+3),
                          parent_id, *(separator+2), std::move(optional_fields)});
    }
    if (result.empty()) throw Error("mount inventory is empty");
    return result;
}

bool machine_relevant_mounts_equal(const std::vector<MachineMount>& before,
                                   const std::vector<MachineMount>& after,
                                   const std::vector<MachineDevice>& block_devices,
                                   std::string_view boot_path,
                                   std::string_view cow_path) {
    const auto contains = [](std::string_view parent, std::string_view child) {
        return parent == "/" || child == parent ||
            (child.size() > parent.size() && child.starts_with(parent) &&
             child[parent.size()] == '/');
    };
    const auto ephemeral = [](const MachineMount& mount) {
        return mount.filesystem == "tmpfs" || mount.filesystem == "ramfs";
    };
    const auto block_backed = [&](const MachineMount& mount) {
        return std::find(block_devices.begin(),block_devices.end(),mount.device) !=
            block_devices.end();
    };
    std::vector<std::string_view> stable_paths;
    for (const auto* mounts : {&before,&after})
        for (const auto& mount : *mounts)
            if (block_backed(mount) && mount.path != "/")
                stable_paths.push_back(mount.path);
    const auto relevant = [&](const MachineMount& mount) {
        if (!ephemeral(mount)) return true;
        if (contains(mount.path,boot_path) || contains("/boot",mount.path) ||
            contains(mount.path,cow_path) || contains(cow_path,mount.path))
            return true;
        return std::any_of(stable_paths.begin(),stable_paths.end(),
            [&](std::string_view path) {
                return contains(mount.path,path) || contains(path,mount.path);
            });
    };
    const auto selected = [&](const std::vector<MachineMount>& mounts) {
        std::vector<MachineMount> result;
        for (const auto& mount : mounts)
            if (relevant(mount)) result.push_back(mount);
        std::sort(result.begin(),result.end(),
            [](const MachineMount& a, const MachineMount& b) { return a.id < b.id; });
        return result;
    };
    return selected(before) == selected(after);
}

static std::vector<MachineCopyRegion> static_regions(const Value& plan, bool include_root) {
    const auto object = [](const Value& value) -> const Value::Object& {
        const auto* result = std::get_if<Value::Object>(&value.data);
        if (!result) throw Error("invalid machine copy plan object");
        return *result;
    };
    const auto numeric = [&](const Value& value, const char* key) {
        const auto& entry = object(value).at(key);
        const auto* result = std::get_if<std::uint64_t>(&entry.data);
        if (!result) throw Error(std::string("invalid machine copy plan ")+key);
        return *result;
    };
    if (!object(plan).contains("layout")) return {};
    const auto length = numeric(object(plan).at("layout"),"length");
    const bool official_layout = official_layout_policy(plan);
    struct Partition { std::uint64_t offset, length; bool excluded, snapshot; };
    std::vector<Partition> partitions;
    if (include_root) {
        const auto& root = object(plan).at("root");
        if (!object(root).contains("lv_uuid"))
            partitions.push_back({numeric(root,"offset"),numeric(root,"length"),false,true});
        if (official_layout && object(plan).contains("boot")) {
            const auto& boot = object(plan).at("boot");
            partitions.push_back({numeric(boot,"offset"),numeric(boot,"length"),false,false});
        }
    }
    const auto* selected = std::get_if<Value::Array>(&object(plan).at("selected_extra").data);
    if (!selected) throw Error("invalid selected machine copy partitions");
    for (const auto& entry : *selected)
        if (!object(entry).contains("lv_uuid"))
            partitions.push_back({numeric(entry,"offset"),numeric(entry,"length"),false,true});
    const auto* excluded = std::get_if<Value::Array>(&object(plan).at("excluded").data);
    if (!excluded) throw Error("invalid excluded machine copy partitions");
    for (const auto& entry : *excluded) {
        if (object(entry).contains("pv_uuid") &&
            (!object(entry).contains("pv_wire_policy") ||
             object(entry).at("pv_wire_policy") !=
                 Value{std::string("whole-partition-zero")}))
            throw Error("LVM physical-volume capture requires whole-partition-zero wire policy");
        for (const auto& region : machine_partition_regions(plan,entry))
            partitions.push_back({region.offset,region.length,region.type == 5,false});
    }
    std::sort(partitions.begin(),partitions.end(),
        [](const auto& a, const auto& b) { return a.offset < b.offset; });
    std::vector<MachineCopyRegion> result;
    std::uint64_t at = 0;
    for (const auto& part : partitions) {
        if (!part.length || part.offset < at || part.offset > length ||
            part.length > length-part.offset)
            throw Error("invalid excluded partition geometry in capture plan");
        if (part.offset > at)
            for (const auto& region : gap_regions(at,part.offset,official_layout))
                result.push_back({region.offset,region.length,region.type != 5});
        if (part.excluded) result.push_back({part.offset,part.length,false});
        else if (!part.snapshot) result.push_back({part.offset,part.length,true});
        at = part.offset+part.length;
    }
    if (at < length)
        for (const auto& region : gap_regions(at,length,official_layout,true))
            result.push_back({region.offset,region.length,region.type != 5});
    return result;
}
std::vector<MachineCopyRegion> machine_static_regions(const Value& plan) {
    return static_regions(plan,true);
}
std::vector<MachineCopyRegion> machine_additional_static_regions(const Value& disk) {
    return static_regions(disk,false);
}

std::vector<ChangedExtent> machine_reread_ranges(const Value& disk, std::uint64_t image_size) {
    if (!machine_bare_metal(disk) && !official_layout_policy(disk)) return {};
    const auto& fields = std::get<Value::Object>(disk.data);
    std::vector<ChangedExtent> raw;
    for (const auto& region : static_regions(disk,fields.contains("root")))
        if (region.read_source) {
            const auto begin = region.offset/4096*4096;
            const auto end = std::min(image_size,
                (region.offset+region.length+4095)/4096*4096);
            raw.push_back({begin,end-begin});
        }
    return union_changed_extents(image_size,std::move(raw));
}
void machine_force_raw_changes(DeltaPlan& delta, const Value& disk) {
    auto changed = machine_reread_ranges(disk,delta.image_size);
    if (delta.filesystem_allocation) {
        for (const auto& range : machine_unused_extents(disk)) {
            const auto begin = range.offset/4096*4096;
            const auto end = (range.offset+range.length+4095)/4096*4096;
            changed.push_back({begin,end-begin});
        }
    }
    if (changed.empty()) return;
    for (const auto& range : delta.ranges)
        if (range.changed) changed.push_back({range.offset,range.length});
    const auto united = union_changed_extents(delta.image_size,std::move(changed));
    delta.ranges.clear();
    delta.transfer_bytes = 0;
    std::uint64_t at = 0;
    for (const auto& range : united) {
        if (range.offset > at) delta.ranges.push_back({at,range.offset-at,false});
        delta.ranges.push_back({range.offset,range.length,true});
        delta.transfer_bytes += range.length;
        at = range.offset+range.length;
    }
    if (at < delta.image_size) delta.ranges.push_back({at,delta.image_size-at,false});
    validate_delta_plan(delta,delta.image_size);
}

Value select_machine_extra_volumes(Value plan, const std::vector<std::string>& mount_paths,
                                   bool bare_metal) {
    auto& fields = std::get<Value::Object>(plan.data);
    fields["layout_policy"] = Value{std::string("linux-layout-v1")};
    if (bare_metal) {
        fields["volume_policy"] = Value{std::string("linux-bare-metal-v1")};
#ifdef __linux__
        fields["swap_page_size"] = Value{static_cast<std::uint64_t>(getpagesize())};
#else
        fields["swap_page_size"] = Value{std::uint64_t{4096}};
#endif
    }
    auto& excluded = std::get<Value::Array>(fields.at("excluded").data);
    auto& selected = std::get<Value::Array>(fields.at("selected_extra").data);
    if (!selected.empty()) throw Error("machine plan already has selected extra volumes");
    std::set<std::string> requested(mount_paths.begin(),mount_paths.end());
    if (requested.size() != mount_paths.size()) throw Error("duplicate selected machine volume");
    Value::Array remaining;
    for (auto& entry : excluded) {
        auto& partition = std::get<Value::Object>(entry.data);
        const auto& path = std::get<std::string>(partition.at("mount_path").data);
        if (!requested.erase(path)) {
            remaining.push_back(std::move(entry));
            continue;
        }
        if (path.empty() || !supported_linux_filesystem(
                std::get<std::string>(partition.at("filesystem").data)) ||
            !partition.contains("mount_id") || !partition.contains("filesystem_uuid"))
            throw Error("selected extra volume requires a directly mounted supported Linux partition");
        const auto& layout = std::get<Value::Object>(fields.at("layout").data);
        const auto& scheme = std::get<std::string>(layout.at("scheme").data);
        const auto& parts = std::get<Value::Array>(layout.at("partitions").data);
        const auto part_number = std::get<std::uint64_t>(partition.at("partition").data);
        const auto layout_part = std::find_if(parts.begin(),parts.end(),[&](const Value& entry) {
            return std::get<std::uint64_t>(
                std::get<Value::Object>(entry.data).at("number").data) == part_number;
        });
        if (layout_part == parts.end()) throw Error("selected extra partition is absent from the disk table");
        const auto& type = std::get<Value::Object>(layout_part->data);
        const bool linux_type = scheme == "MBR" ?
            std::get<std::uint64_t>(type.at("mbr_type").data) == 0x83 :
            std::get<std::string>(type.at("type_guid").data) ==
                "0fc63daf-8483-4772-8e79-3d69d8477de4";
        if (!linux_type) throw Error("selected extra partition has a non-Linux disk type");
        partition["required_capture"] = Value{std::string("synosnap-with-driver-managed-freeze")};
        partition["disk_index"] = Value{std::uint64_t{0}};
        selected.push_back(std::move(entry));
    }
    Value::Array additional;
    if (!requested.empty()) {
#ifdef __linux__
        std::map<std::string,std::vector<std::string>> groups;
        std::map<std::string,std::vector<std::string>> lv_groups;
        const auto& inventory = std::get<Value::Array>(fields.at("external_volumes").data);
        for (const auto& entry : inventory) {
            const auto& item = std::get<Value::Object>(entry.data);
            const auto& path = std::get<std::string>(item.at("mount_path").data);
            if (!requested.erase(path)) continue;
            const auto disk = std::get<std::string>(item.at("disk").data);
            (item.contains("lv_uuid") ? lv_groups : groups)[disk].push_back(path);
        }
        if (!requested.empty()) throw Error("selected machine volume is absent from the configured disks");
        std::optional<LvmInventory> lvm;
        if (!lv_groups.empty() || has_lvm_devices()) lvm = inspect_lvm();
        std::set<std::string> selected_disks;
        for (const auto& [disk, paths] : groups) selected_disks.insert(disk);
        for (const auto& disk : selected_disks) {
            const bool primary = std::filesystem::canonical(disk) ==
                std::filesystem::canonical(std::get<std::string>(fields.at("disk").data));
            if (primary) continue;
            auto pv_disk = inspect_selected_external_disk(disk,
                std::get<std::string>(fields.at("cow_directory").data),
                groups.contains(disk) ? groups.at(disk) : std::vector<std::string>{},
                lvm ? &*lvm : nullptr);
            additional.push_back(std::move(pv_disk));
        }
        if (!lv_groups.empty()) {
            const auto mounts = parse_machine_mounts(text_file("/proc/self/mountinfo"));
            Value::Array volume_groups, selected_lvs;
            if (fields.contains("lvm")) {
                volume_groups = std::get<Value::Array>(
                    std::get<Value::Object>(fields.at("lvm").data).at("volume_groups").data);
                selected_lvs = std::get<Value::Array>(
                    std::get<Value::Object>(fields.at("lvm").data).at("selected_lvs").data);
            }
            for (const auto& [disk, paths] : lv_groups) {
                for (const auto& path : paths) {
                    const auto mount = std::find_if(mounts.begin(),mounts.end(),
                        [&](const MachineMount& item) { return item.path == path; });
                    if (mount == mounts.end()) throw Error("selected LVM mount disappeared");
                    const auto lv = std::find_if(lvm->logical_volumes.begin(),lvm->logical_volumes.end(),
                        [&](const LvmLv& item) {
                            return item.public_device && item.device.major == mount->device.major &&
                                   item.device.minor == mount->device.minor;
                        });
                    if (lv == lvm->logical_volumes.end())
                        throw Error("selected mount has no supported LVM logical volume");
                    const auto pv = std::find_if(lvm->physical_volumes.begin(),lvm->physical_volumes.end(),
                        [&](const LvmPv& item) { return item.vg_uuid == lv->vg_uuid; });
                    if (pv == lvm->physical_volumes.end() ||
                        std::filesystem::canonical(pv->parent_disk) != std::filesystem::canonical(disk))
                        throw Error("selected LVM volume changed its physical disk");
                    auto value = logical_volume_value(*lv,*mount);
                    std::get<Value::Object>(value.data)["disk_index"] = Value{std::uint64_t{0}};
                    selected_lvs.push_back(lvm_selected_identity(value));
                    selected.push_back(std::move(value));
                    if (std::none_of(volume_groups.begin(),volume_groups.end(),
                        [&](const Value& group) {
                            return std::get<std::string>(
                                std::get<Value::Object>(group.data).at("uuid").data) == lv->vg_uuid;
                        })) {
                        const auto vg = std::find_if(lvm->volume_groups.begin(),lvm->volume_groups.end(),
                            [&](const LvmVg& item) { return item.uuid == lv->vg_uuid; });
                        if (vg == lvm->volume_groups.end()) throw Error("selected LVM volume group is absent");
                        volume_groups.push_back(lvm_group_value(*lvm,*vg,mounts));
                    }
                }
            }
            fields["lvm"] = Value{Value::Object{
                {"volume_groups",Value{std::move(volume_groups)}},
                {"selected_lvs",Value{std::move(selected_lvs)}}}};
        }
        std::sort(additional.begin(),additional.end(),[](const Value& a, const Value& b) {
            const auto key = [](const Value& disk) {
                const auto& item = std::get<Value::Object>(disk.data);
                if (item.contains("selection_key"))
                    return std::get<std::string>(item.at("selection_key").data);
                const auto& selected = std::get<Value::Array>(item.at("selected_extra").data);
                return std::get<std::string>(
                    std::get<Value::Object>(selected.front().data).at("mount_path").data);
            };
            return key(a) < key(b);
        });
        for (std::size_t index = 0; index < additional.size(); ++index)
            for (auto& entry : std::get<Value::Array>(
                     std::get<Value::Object>(additional[index].data).at("selected_extra").data))
                std::get<Value::Object>(entry.data)["disk_index"] = Value{std::uint64_t{index+1}};
#else
        throw Error("selected external machine volumes require Linux");
#endif
    }
#ifdef __linux__
    std::optional<LvmInventory> selected_lvm;
#endif
    excluded = std::move(remaining);
#ifdef __linux__
    if (bare_metal) {
        if (!selected_lvm && has_lvm_devices()) selected_lvm = inspect_lvm();
        const auto primary = std::filesystem::canonical(
            "/sys/dev/block/"+std::get<std::string>(fields.at("device_number").data));
        for (const auto& entry : std::filesystem::directory_iterator("/sys/block")) {
            const auto path = std::filesystem::canonical(entry.path());
            if (path == primary || path.string().find("/virtual/") != std::string::npos ||
                std::filesystem::exists(path/"loop") ||
                !std::filesystem::exists(path/"diskseq") || !number(scalar(path/"size")))
                continue;
            const auto disk = "/dev/"+path.filename().string();
            if (std::any_of(additional.begin(),additional.end(),[&](const Value& value) {
                return std::get<Value::Object>(value.data).at("disk") == Value{disk};
            })) continue;
            bool partitioned = false, has_holders = false;
            for (const auto& child : std::filesystem::directory_iterator(path)) {
                if (!std::filesystem::exists(child.path()/"partition")) continue;
                partitioned = true;
                has_holders |= !std::filesystem::is_empty(child.path()/"holders");
            }
            if (!partitioned) continue;
            if (has_holders && !selected_lvm) selected_lvm = inspect_lvm();
            auto candidate = inspect_selected_external_disk(disk,
                std::get<std::string>(fields.at("cow_directory").data),{},selected_lvm ? &*selected_lvm : nullptr);
            auto& properties = std::get<Value::Object>(candidate.data);
            properties["volume_policy"] = fields.at("volume_policy");
            properties["swap_page_size"] = fields.at("swap_page_size");
            // Layout bytes alone do not make an otherwise omitted disk an image.
            if (machine_disk_need_upload(candidate)) additional.push_back(std::move(candidate));
        }
        for (auto& disk : additional) {
            auto& properties = std::get<Value::Object>(disk.data);
            properties["volume_policy"] = fields.at("volume_policy");
            properties["swap_page_size"] = fields.at("swap_page_size");
        }
        std::sort(additional.begin(),additional.end(),[](const Value& a,const Value& b) {
            const auto& left = std::get<Value::Object>(std::get<Value::Object>(a.data).at("layout").data);
            const auto& right = std::get<Value::Object>(std::get<Value::Object>(b.data).at("layout").data);
            return std::get<std::string>(left.at("disk_id").data) <
                std::get<std::string>(right.at("disk_id").data);
        });
        for (std::size_t index = 0; index < additional.size(); ++index)
            for (auto& volume : std::get<Value::Array>(
                 std::get<Value::Object>(additional[index].data).at("selected_extra").data))
                std::get<Value::Object>(volume.data)["disk_index"] = Value{std::uint64_t{index+1}};
    }
#endif
    for (auto& disk : additional)
        std::get<Value::Object>(disk.data)["layout_policy"] = fields.at("layout_policy");
    fields["additional_disks"] = Value{std::move(additional)};
    return plan;
}

namespace {
void validate_machine_partition_inventory(const ImageLayout& layout,
        const std::vector<MachinePartition>& partitions) {
    if (layout.partitions.size() < 2 || layout.partitions.size() != partitions.size())
        throw Error("machine capture requires a root and boot partition and matching kernel inventory");
    std::set<std::uint32_t> numbers;
    for (const auto& p : partitions) {
        if (!numbers.insert(p.number).second || p.path.empty() || !p.length)
            throw Error("invalid or duplicate kernel partition identity");
        const auto it = std::find_if(layout.partitions.begin(), layout.partitions.end(),
            [&](const auto& entry) { return entry.number == p.number; });
        if (it == layout.partitions.end() || it->offset != p.offset || it->length != p.length)
            throw Error("kernel partition geometry differs from the on-disk partition table");
    }
    std::set<std::pair<std::uint32_t,std::uint32_t>> devices;
    for (const auto& part : partitions)
        if (!devices.insert({part.device.major,part.device.minor}).second)
            throw Error("partitions have the same device number");
}
const MachineMount& unique_machine_mount(const std::vector<MachineMount>& mounts,
                                        std::string_view path) {
    const MachineMount* found = nullptr;
    for (const auto& mount : mounts) if (mount.path == path) {
        if (found) throw Error("stacked mounts prevent unambiguous machine capture");
        found = &mount;
    }
    if (!found) throw Error("required machine mount is missing");
    return *found;
}
struct MachineBootChoice {
    const MachinePartition* partition;
    const MachineMount* mount;
};
MachineBootChoice validated_machine_boot(const ImageLayout& layout,
        const std::vector<MachinePartition>& partitions,
        const std::vector<MachineMount>& mounts,
        std::optional<std::uint32_t> root_partition) {
    const MachineMount* boot_mount = nullptr;
    const MachinePartition* boot = nullptr;
    for (const auto& mount : mounts) {
        if (!supported_machine_boot_mount(mount.path)) continue;
        const auto part = std::find_if(partitions.begin(),partitions.end(),
            [&](const auto& entry) { return entry.device == mount.device; });
        if (part == partitions.end()) continue;
        if (boot_mount) throw Error("boot partition has multiple mounts; capture needs one unambiguous mount");
        boot_mount = &mount;
        boot = &*part;
    }
    if (!boot || (root_partition && boot->number == *root_partition) ||
        boot_mount->root != "/" || boot_mount->filesystem != "vfat")
        throw Error("boot partition must be directly mounted as vfat at /boot, /boot/efi, or /boot/firmware");
    for (const auto& mount : mounts)
        if (mount.device == boot->device && mount.id != boot_mount->id)
            throw Error("boot partition has multiple mounts; capture needs one unambiguous mount");
    (void)unique_machine_mount(mounts,boot_mount->path);
    for (const auto& mount : mounts) {
        if (mount.id == boot_mount->id) continue;
        if (mount.path == "/boot" || mount.path.starts_with("/boot/"))
            throw Error("additional boot mounts are not supported");
    }
    const auto part = std::find_if(layout.partitions.begin(),layout.partitions.end(),
        [&](const auto& entry) { return entry.number == boot->number; });
    if (part == layout.partitions.end()) throw Error("boot partition differs from disk layout");
    const bool boot_type = layout.scheme == ImageLayout::Scheme::mbr ?
        (part->mbr_type == 0x04 || part->mbr_type == 0x06 || part->mbr_type == 0x0e ||
         part->mbr_type == 0x0b || part->mbr_type == 0x0c || part->mbr_type == 0xef) :
        (part->type_guid == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" ||
         part->type_guid == "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7");
    if (!boot_type) throw Error("partition types disagree with the mounted root/boot filesystems");
    return {boot,boot_mount};
}
}
MachinePlan plan_machine_capture(const ImageLayout& layout,
                                 const std::vector<MachinePartition>& partitions,
                                 const std::vector<MachineMount>& mounts) {
    validate_machine_partition_inventory(layout,partitions);
    const auto& root_mount = unique_machine_mount(mounts,"/");
    if (root_mount.root != "/" || !supported_linux_filesystem(root_mount.filesystem))
        throw Error("machine root must be a directly mounted supported Linux filesystem");
    const auto root = std::find_if(partitions.begin(), partitions.end(),
        [&](const auto& p) { return p.device == root_mount.device; });
    if (root == partitions.end()) throw Error("selected disk does not contain the mounted root filesystem");
    const auto choice = validated_machine_boot(layout,partitions,mounts,root->number);
    const auto root_part = std::find_if(layout.partitions.begin(),layout.partitions.end(),
        [&](const auto& entry) { return entry.number == root->number; });
    const bool linux_type = layout.scheme == ImageLayout::Scheme::mbr ?
        root_part->mbr_type == 0x83 :
        root_part->type_guid == "0fc63daf-8483-4772-8e79-3d69d8477de4";
    if (!linux_type) throw Error("partition types disagree with the mounted root/boot filesystems");
    MachinePlan result{*choice.partition, *root, *choice.mount, root_mount, {}};
    for (const auto& part : partitions)
        if (part.number != choice.partition->number && part.number != root->number)
            result.excluded.push_back(part);
    return result;
}
MachineLvmBoot plan_lvm_machine_boot(const ImageLayout& layout,
        const std::vector<MachinePartition>& partitions,
        const std::vector<MachineMount>& mounts,
        std::uint32_t pv_partition, MachineDevice root_lv_device) {
    validate_machine_partition_inventory(layout,partitions);
    const auto& root = unique_machine_mount(mounts,"/");
    if (root.device != root_lv_device || root.root != "/" ||
        !supported_linux_filesystem(root.filesystem))
        throw Error("LVM root must be a directly mounted supported Linux filesystem");
    const auto pv = std::find_if(partitions.begin(),partitions.end(),
        [&](const auto& part) { return part.number == pv_partition; });
    if (pv == partitions.end())
        throw Error("LVM root physical volume is absent from selected disk");
    const auto boot = validated_machine_boot(layout,partitions,mounts,pv_partition);
    return {*boot.partition,*boot.mount};
}

void validate_machine_cow_storage(MachineDevice source, MachineDevice cow,
                                  const std::vector<MachineStorage>& storage) {
    std::vector<MachineDevice> active;
    const std::function<void(MachineDevice)> visit = [&](MachineDevice current) {
        if (current == source)
            throw Error("COW directory resides on the source disk; choose independent storage");
        if (std::find(active.begin(), active.end(), current) != active.end())
            throw Error("cyclic COW storage topology");
        const MachineStorage* node = nullptr;
        for (const auto& candidate : storage) if (candidate.device == current) {
            if (node) throw Error("duplicate COW storage identity");
            node = &candidate;
        }
        if (!node || (node->backing.empty() && !node->physical_leaf))
            throw Error("COW storage independence cannot be proved from its backing devices");
        active.push_back(current);
        for (const auto& backing : node->backing) visit(backing);
        active.pop_back();
    };
    visit(cow);
}

#ifdef __linux__
namespace {
namespace fs = std::filesystem;
class File {
public:
    int fd;
    explicit File(const fs::path& path, int flags) : fd(open(path.c_str(), flags | O_CLOEXEC | O_NOFOLLOW)) {
        if (fd < 0) throw Error("cannot open machine inventory path: "+path.string()+": "+std::strerror(errno));
    }
    ~File() { close(fd); }
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    struct stat stat() const {
        struct stat result{};
        if (fstat(fd, &result)) throw Error("cannot inspect machine inventory descriptor");
        return result;
    }
};
std::string text_file(const fs::path& path) {
    std::ifstream input(path);
    if (!input) throw Error("cannot read machine inventory: "+path.string());
    std::string result, line;
    while (std::getline(input, line)) {
        if (result.size()+line.size() > 4*1024*1024) throw Error("machine inventory exceeds size limit");
        result += line+'\n';
    }
    if (!input.eof()) throw Error("machine inventory read failed");
    return result;
}
std::string scalar(const fs::path& path) {
    auto text = text_file(path);
    if (text.empty() || text.back() != '\n') throw Error("empty machine inventory value");
    text.pop_back();
    return text;
}
std::string device_text(MachineDevice device) {
    return std::to_string(device.major)+":"+std::to_string(device.minor);
}
MachineDevice device(dev_t value) { return {major(value), minor(value)}; }
fs::path sys_device(MachineDevice value) {
    return fs::canonical("/sys/dev/block/"+device_text(value));
}
std::string filesystem_uuid(MachineDevice value) {
    std::string result;
    for (const auto& entry : fs::directory_iterator("/dev/disk/by-uuid")) {
        struct stat st{};
        if (stat(entry.path().c_str(), &st) == 0 && S_ISBLK(st.st_mode) &&
            device(st.st_rdev) == value) {
            if (!result.empty()) throw Error("ambiguous filesystem UUID in machine inventory");
            result = entry.path().filename().string();
        }
    }
    if (result.empty()) throw Error("machine filesystem needs a persistent /dev/disk/by-uuid identity");
    return result;
}
std::uint64_t sector_bytes(const fs::path& path) {
    const auto sectors = number(scalar(path));
    if (sectors > UINT64_MAX/512) throw Error("kernel partition extent overflows");
    return sectors*512; // sysfs uses 512-byte units even on 4Kn devices.
}
bool has_lvm_devices() {
    for (const auto& entry : fs::directory_iterator("/sys/block")) {
        const auto uuid = entry.path()/"dm"/"uuid";
        if (fs::exists(uuid) && scalar(uuid).starts_with("LVM-")) return true;
    }
    return false;
}
std::vector<MachinePartition> kernel_partitions(const fs::path& disk,
                                                const LvmInventory* lvm = nullptr) {
    std::vector<MachinePartition> result;
    for (const auto& child : fs::directory_iterator(disk)) {
        if (!fs::exists(child.path()/"partition")) continue;
        const auto n = number(scalar(child.path()/"partition"));
        if (!n || n > UINT32_MAX) throw Error("invalid kernel partition number");
        const auto dev = device_number(scalar(child.path()/"dev"));
        for (const auto& holder : fs::directory_iterator(child.path()/"holders")) {
            const auto held = device_number(scalar(fs::canonical(holder.path())/"dev"));
            const bool recognized = lvm && std::any_of(lvm->physical_volumes.begin(),
                lvm->physical_volumes.end(),[&](const LvmPv& pv) {
                    if (pv.device.major != dev.major || pv.device.minor != dev.minor) return false;
                    return std::any_of(lvm->kernel_nodes.begin(),lvm->kernel_nodes.end(),
                        [&](const auto& node) {
                            return node.device.major == held.major && node.device.minor == held.minor;
                        });
                });
            if (!recognized) throw Error("source partition has unsupported stacked-device holders");
        }
        const auto name = fs::canonical(child.path()).filename().string();
        const auto path = "/dev/"+name;
        File partition(path, O_RDONLY | O_NONBLOCK);
        const auto st = partition.stat();
        if (!S_ISBLK(st.st_mode) || device(st.st_rdev) != dev)
            throw Error("partition path differs from its kernel registration");
        result.push_back({static_cast<std::uint32_t>(n), dev, path,
                          sector_bytes(child.path()/"start"), sector_bytes(child.path()/"size")});
    }
    std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) { return a.number < b.number; });
    return result;
}
Value partition_value(const MachinePartition& part, const MachineMount& mount, std::string strategy) {
    return Value{Value::Object{
        {"partition", Value{std::uint64_t{part.number}}}, {"device", Value{part.path}},
        {"device_number", Value{device_text(part.device)}}, {"offset", Value{part.offset}},
        {"length", Value{part.length}}, {"mount_id", Value{mount.id}},
        {"mount_path", Value{mount.path}}, {"filesystem", Value{mount.filesystem}},
        {"filesystem_uuid", Value{filesystem_uuid(part.device)}},
        {"mount_options", Value{mount.options}}, {"super_options", Value{mount.super_options}},
        {"read_only_mount", Value{std::uint64_t{option(mount.options, "ro")}}},
        {"required_capture", Value{std::move(strategy)}}}};
}
// Low-level probing reads the signature even for unmounted volumes and
// bypasses blkid's persistent cache. A missing signature is an empty fs.
std::string probe_filesystem_tag(const std::string& path, const std::string& tag) {
    std::string executable;
    for (const auto* directory : {"/sbin/","/usr/sbin/"}) {
        const auto candidate = std::string(directory)+"blkid";
        if (access(candidate.c_str(),X_OK) == 0) {
            executable = fs::canonical(candidate).string();
            break;
        }
    }
    if (executable.empty()) throw Error("machine inspection requires installed blkid");
    int descriptors[2];
    if (pipe2(descriptors,O_CLOEXEC)) throw Error("cannot create filesystem probe pipe");
    File output("/dev/null",O_RDWR); // Child stdin and diagnostics.
    struct Pipe {
        int read, write;
        ~Pipe() { close(read); if (write >= 0) close(write); }
    } pipe{descriptors[0],descriptors[1]};
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions)) throw Error("cannot initialize filesystem probe");
    struct Actions {
        posix_spawn_file_actions_t* value;
        ~Actions() { posix_spawn_file_actions_destroy(value); }
    } cleanup{&actions};
    if (posix_spawn_file_actions_adddup2(&actions,output.fd,STDIN_FILENO) ||
        posix_spawn_file_actions_adddup2(&actions,output.fd,STDERR_FILENO) ||
        posix_spawn_file_actions_adddup2(&actions,pipe.write,STDOUT_FILENO) ||
        posix_spawn_file_actions_addclosefrom_np(&actions,3))
        throw Error("cannot configure filesystem probe");
    std::vector<std::string> arguments{executable,"-p","-s",tag,"-o","value",path};
    std::vector<char*> argv;
    for (auto& argument : arguments) argv.push_back(argument.data());
    argv.push_back(nullptr);
    char locale[] = "LC_ALL=C";
    char* environment[]{locale,nullptr};
    pid_t child{};
    if (posix_spawn(&child,executable.c_str(),&actions,nullptr,argv.data(),environment))
        throw Error("cannot execute filesystem probe");
    struct Child {
        pid_t pid; bool waited = false;
        ~Child() {
            if (!waited) {
                kill(pid,SIGKILL);
                while (waitpid(pid,nullptr,0) < 0 && errno == EINTR) {}
            }
        }
    } process{child};
    close(pipe.write); pipe.write = -1;
    std::string result;
    char buffer[128];
    for (;;) {
        const auto count = read(pipe.read,buffer,sizeof buffer);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) throw Error("cannot read filesystem probe");
        if (!count) break;
        if (result.size()+static_cast<std::size_t>(count) > 128)
            throw Error("filesystem probe output exceeds limit");
        result.append(buffer,static_cast<std::size_t>(count));
    }
    int status{};
    while (waitpid(child,&status,0) < 0)
        if (errno != EINTR) throw Error("cannot wait for filesystem probe");
    process.waited = true;
    if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 2))
        throw Error("filesystem signature probe failed");
    if (WEXITSTATUS(status) == 2) return std::string{};
    if (!result.empty() && result.back() == '\n') result.pop_back();
    return result;
}
Value excluded_value(const MachinePartition& part, const std::vector<MachineMount>& mounts) {
    const MachineMount* found = nullptr;
    for (const auto& mount : mounts) if (mount.device == part.device) {
        if (found || mount.root != "/")
            throw Error("excluded partition has ambiguous or non-direct mounts");
        found = &mount;
    }
    if (found && supported_linux_filesystem(found->filesystem)) {
        auto selected = partition_value(part,*found,"excluded-zero-fill");
        return selected;
    }
    Value result{Value::Object{
        {"partition", Value{std::uint64_t{part.number}}}, {"device", Value{part.path}},
        {"device_number", Value{device_text(part.device)}}, {"offset", Value{part.offset}},
        {"length", Value{part.length}}, {"mount_path", Value{found ? found->path : std::string{}}},
        {"filesystem", Value{found ? found->filesystem : probe_filesystem_tag(part.path,"TYPE")}},
        {"required_capture", Value{std::string("excluded-zero-fill")}}}};
    record_machine_raw_volume_uuid(result,[&] { return probe_filesystem_tag(part.path,"UUID"); });
    return result;
}
std::string pv_metadata_sha256(const LvmPv& pv, std::uint64_t offset,
                               std::uint64_t length) {
    if (!length || length > 16*1024*1024 || offset > pv.device_size ||
        length > pv.device_size-offset || offset % 512 || length % 512)
        throw Error("LVM physical-volume metadata extent is unsupported");
    File source(pv.name,O_RDONLY|O_NONBLOCK);
    std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> digest(EVP_MD_CTX_new(),EVP_MD_CTX_free);
    if (!digest || EVP_DigestInit_ex(digest.get(),EVP_sha256(),nullptr) != 1)
        throw Error("cannot initialize LVM metadata fingerprint");
    Bytes bytes(1024*1024);
    for (std::uint64_t at = 0; at < length;) {
        const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(bytes.size(),length-at));
        if (pread(source.fd,bytes.data(),count,static_cast<off_t>(offset+at)) != static_cast<ssize_t>(count) ||
            EVP_DigestUpdate(digest.get(),bytes.data(),count) != 1)
            throw Error("cannot fingerprint LVM physical-volume metadata");
        at += count;
    }
    unsigned char hash[32]; unsigned digest_length{};
    if (EVP_DigestFinal_ex(digest.get(),hash,&digest_length) != 1 || digest_length != 32)
        throw Error("cannot fingerprint LVM physical-volume metadata");
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (const auto byte : hash) { result += hex[byte>>4]; result += hex[byte&15]; }
    return result;
}
Value pv_excluded_value(const MachinePartition& part, const LvmPv& pv,
                        const std::vector<MachineMount>& mounts) {
    if (part.device.major != pv.device.major || part.device.minor != pv.device.minor ||
        part.offset != pv.partition_offset || part.length != pv.partition_length ||
        part.number != pv.partition_number)
        throw Error("LVM physical volume differs from the disk partition table");
    auto value = excluded_value(part,mounts);
    auto& fields = std::get<Value::Object>(value.data);
    fields["filesystem"] = Value{std::string("LVM2_member")};
    fields["pv_wire_policy"] = Value{std::string("whole-partition-zero")};
    fields["pv_uuid"] = Value{pv.uuid};
    fields["vg_uuid"] = Value{pv.vg_uuid};
    if (pv.pe_start < 4096 || pv.pe_start > 16*1024*1024 ||
        pv.pe_start % 512 || pv.size > pv.device_size-pv.pe_start)
        throw Error("LVM physical-volume metadata extent is unsupported");
    const auto tail_offset = pv.pe_start+pv.size;
    const auto tail_length = pv.device_size-tail_offset;
    if (tail_length > 16*1024*1024)
        throw Error("LVM physical-volume tail extent is unsupported");
    fields["pv_metadata_length"] = Value{pv.pe_start};
    fields["pv_extent_length"] = Value{pv.size};
    fields["pv_mda_size"] = Value{pv.mda_size};
    fields["pv_mda_count"] = Value{pv.mda_count};
    fields["pv_metadata_sha256"] = Value{pv_metadata_sha256(pv,0,pv.pe_start)};
    fields["pv_tail_length"] = Value{tail_length};
    if (tail_length)
        fields["pv_tail_sha256"] = Value{pv_metadata_sha256(pv,tail_offset,tail_length)};
    return value;
}
Value logical_volume_value(const LvmLv& lv, const MachineMount& mount) {
    if (mount.device.major != lv.device.major || mount.device.minor != lv.device.minor ||
        mount.root != "/" || !supported_linux_filesystem(mount.filesystem))
        throw Error("selected LVM logical volume requires a direct supported filesystem mount");
    Value::Array segments;
    for (const auto& part : lv.segments)
        segments.push_back(Value{Value::Object{
            {"logical_offset",Value{part.logical_offset}},
            {"length",Value{part.length}},{"pv_uuid",Value{part.pv_uuid}},
            {"pv_offset",Value{part.pv_offset}},{"type",Value{part.type}},
            {"mapping",Value{part.mapping}},{"kernel_topology",Value{lv.kernel_table}}}});
    const auto& vg = lv.path.substr(5,lv.path.find('/',5)-5);
    return Value{Value::Object{
        {"lv_name",Value{lv.name}},{"lv_uuid",Value{lv.uuid}},
        {"vg_uuid",Value{lv.vg_uuid}},{"logical_path",Value{lv.path}},
        {"device",Value{fs::canonical(lv.dm_path).string()}},
        {"device_number",Value{device_text(mount.device)}},
        {"length",Value{lv.size}},{"offset",Value{std::uint64_t{0}}},
        {"partition",Value{std::uint64_t{0}}},{"disk_index",Value{std::uint64_t{0}}},
        {"mount_id",Value{mount.id}},{"mount_path",Value{mount.path}},
        {"mount_options",Value{mount.options}},{"super_options",Value{mount.super_options}},
        {"read_only_mount",Value{std::uint64_t{option(mount.options,"ro")}}},
        {"filesystem",Value{mount.filesystem}},
        {"filesystem_uuid",Value{filesystem_uuid(mount.device)}},
        {"image_name",Value{lvm_image_name(vg,lv.name)}},
        {"segments",Value{std::move(segments)}},
        {"required_capture",Value{std::string("synosnap-lvm")}}}};
}
Value lvm_group_value(const LvmInventory& inventory, const LvmVg& vg,
                      const std::vector<MachineMount>& mounts) {
    Value::Array pvs, lvs;
    for (const auto& pv : inventory.physical_volumes) if (pv.vg_uuid == vg.uuid)
        pvs.push_back(Value{Value::Object{
            {"name",Value{pv.name}},{"uuid",Value{pv.uuid}},{"size",Value{pv.size}}}});
    for (const auto& lv : inventory.logical_volumes) if (lv.vg_uuid == vg.uuid) {
        std::string filesystem;
        for (const auto& mount : mounts)
            if (mount.device.major == lv.device.major && mount.device.minor == lv.device.minor) {
                if (!lv.public_device) continue;
                if (mount.root != "/") throw Error("LVM logical volume has an ambiguous mount");
                if (!filesystem.empty()) throw Error("LVM logical volume has multiple mounts");
                filesystem = mount.filesystem;
            }
        if (filesystem.empty() && lv.public_device) filesystem = probe_filesystem_tag(lv.path,"TYPE");
        lvs.push_back(Value{Value::Object{
            {"name",Value{lv.name}},{"uuid",Value{lv.uuid}},
            {"file_system",Value{filesystem}},{"size",Value{lv.size}}}});
    }
    return Value{Value::Object{
        {"name",Value{vg.name}},{"uuid",Value{vg.uuid}},
        {"extent_size",Value{vg.extent_size}},{"mda_size",Value{vg.mda_size}},
        {"total_size",Value{vg.total_size}},
        {"physical_volumes",Value{std::move(pvs)}},
        {"logical_volumes",Value{std::move(lvs)}}}};
}
Value lvm_selected_identity(const Value& selected) {
    Value::Object identity;
    for (const auto* key : {"lv_name","lv_uuid","vg_uuid","image_name","length",
                            "mount_path","filesystem","filesystem_uuid","segments"})
        identity.emplace(key,std::get<Value::Object>(selected.data).at(key));
    return Value{std::move(identity)};
}
pstream::Value inspect_selected_external_disk(const std::string& disk_path,
    const std::string& cow_directory, const std::vector<std::string>& paths,
    const LvmInventory* lvm) {
    const auto disk = fs::canonical(disk_path);
    File source(disk,O_RDONLY|O_NONBLOCK);
    const auto st = source.stat();
    if (!S_ISBLK(st.st_mode)) throw Error("selected external source is not a whole disk");
    const auto sysfs = sys_device(device(st.st_rdev));
    if (fs::exists(sysfs/"partition") || fs::exists(sysfs/"loop") ||
        !fs::is_empty(sysfs/"holders") || !fs::is_empty(sysfs/"slaves"))
        throw Error("selected external source must be a direct physical disk");
    std::uint64_t size{};
    int sector{};
    if (ioctl(source.fd,BLKGETSIZE64,&size) || ioctl(source.fd,BLKSSZGET,&sector) ||
        !size || size > INT64_MAX || (sector != 512 && sector != 4096))
        throw Error("selected external disk has unsupported geometry");
    const auto read = [&](std::uint64_t offset, std::size_t count) {
        Bytes bytes(count);
        std::size_t done = 0;
        while (done < count) {
            const auto n = pread(source.fd,bytes.data()+done,count-done,static_cast<off_t>(offset+done));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) throw Error("selected external disk table read failed");
            done += static_cast<std::size_t>(n);
        }
        return bytes;
    };
    const auto layout = inspect_disk_layout(size,static_cast<std::uint32_t>(sector),read);
    const auto parts = kernel_partitions(sysfs,lvm);
    if (parts.size() != layout.partitions.size())
        throw Error("selected external disk partition inventory differs from its table");
    const auto mounts = parse_machine_mounts(text_file("/proc/self/mountinfo"));
    const std::set<std::string> requested(paths.begin(),paths.end());
    if (requested.size() != paths.size()) throw Error("duplicate selected external volume");
    Value::Array selected, excluded;
    for (const auto& layout_part : layout.partitions) {
        const auto found = std::find_if(parts.begin(),parts.end(),[&](const auto& part) {
            return part.number == layout_part.number;
        });
        if (found == parts.end() || found->offset != layout_part.offset ||
            found->length != layout_part.length)
            throw Error("selected external disk partition geometry differs from kernel inventory");
        const MachineMount* mounted = nullptr;
        for (const auto& mount : mounts) if (mount.device == found->device) {
            if (mounted || mount.root != "/")
                throw Error("selected external partition has ambiguous mounts");
            mounted = &mount;
        }
        if (mounted && requested.contains(mounted->path)) {
            const bool linux_type = layout.scheme == ImageLayout::Scheme::mbr ?
                layout_part.mbr_type == 0x83 :
                layout_part.type_guid == "0fc63daf-8483-4772-8e79-3d69d8477de4";
            if (!linux_type || !supported_linux_filesystem(mounted->filesystem))
                throw Error("selected external volume requires a supported Linux partition");
            selected.push_back(partition_value(*found,*mounted,"synosnap-with-driver-managed-freeze"));
        } else {
            const LvmPv* pv = nullptr;
            if (lvm) for (const auto& candidate : lvm->physical_volumes)
                if (candidate.device.major == found->device.major &&
                    candidate.device.minor == found->device.minor) {
                    if (pv) throw Error("ambiguous LVM physical volume on external disk");
                    pv = &candidate;
                }
            if (pv) {
                excluded.push_back(pv_excluded_value(*found,*pv,mounts));
            } else if (mounted && mounted->filesystem == "vfat") {
                excluded.push_back(partition_value(*found,*mounted,"buffered-raw-read"));
            } else excluded.push_back(excluded_value(*found,mounts));
        }
    }
    if (selected.size() != requested.size())
        throw Error("selected external volume no longer matches its disk partition");
    (void)cow_directory;
    return Value{Value::Object{
        {"disk",Value{disk.string()}},{"device_number",Value{device_text(device(st.st_rdev))}},
        {"disk_sequence",Value{number(scalar(sysfs/"diskseq"))}},
        {"layout",layout_value(layout)},
        {"selected_extra",Value{std::move(selected)}},{"excluded",Value{std::move(excluded)}}}};
}
}
#endif

Value inspect_machine(const std::string& disk_path, const std::string& cow_directory) {
#ifndef __linux__
    (void)disk_path; (void)cow_directory;
    throw Error("machine inspection requires Linux");
#else
    const auto disk = fs::canonical(disk_path), cow = fs::canonical(cow_directory);
    File source(disk, O_RDONLY | O_NONBLOCK);
    const auto st = source.stat();
    if (!S_ISBLK(st.st_mode)) throw Error("machine source must be an explicit whole block device");
    const auto sysfs = sys_device(device(st.st_rdev));
    const auto disk_sequence = number(scalar(sysfs/"diskseq"));
    if (fs::exists(sysfs/"partition") || !fs::is_empty(sysfs/"holders") ||
        !fs::is_empty(sysfs/"slaves") || fs::exists(sysfs/"loop"))
        throw Error("machine source must be a direct disk without stacked devices");
    std::uint64_t size{};
    int sector{};
    if (ioctl(source.fd, BLKGETSIZE64, &size) || ioctl(source.fd, BLKSSZGET, &sector) ||
        !size || size > INT64_MAX || (sector != 512 && sector != 4096))
        throw Error("cannot determine supported machine disk geometry");
    const auto read = [&](std::uint64_t offset, std::size_t count) {
        Bytes bytes(count);
        std::size_t done = 0;
        while (done < count) {
            const auto n = pread(source.fd, bytes.data()+done, count-done, static_cast<off_t>(offset+done));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) throw Error("machine partition table read failed");
            done += static_cast<std::size_t>(n);
        }
        return bytes;
    };
    struct ReadRecord { std::uint64_t offset; Bytes bytes; };
    std::vector<ReadRecord> records;
    const auto layout = inspect_disk_layout(size, static_cast<std::uint32_t>(sector),
        [&](auto offset, auto count) {
            auto bytes = read(offset, count);
            records.push_back({offset, bytes});
            return bytes;
        });
    const auto mounts = parse_machine_mounts(text_file("/proc/self/mountinfo"));
    std::vector<MachineDevice> block_mount_devices;
    const auto record_block_mounts = [&](const std::vector<MachineMount>& observed) {
        for (const auto& mount : observed)
            if (fs::exists("/sys/dev/block/"+device_text(mount.device)) &&
                std::find(block_mount_devices.begin(),block_mount_devices.end(),
                          mount.device) == block_mount_devices.end())
                block_mount_devices.push_back(mount.device);
    };
    record_block_mounts(mounts);
    std::optional<LvmInventory> lvm;
    if (has_lvm_devices()) lvm = inspect_lvm();
    const auto parts = kernel_partitions(sysfs,lvm ? &*lvm : nullptr);
    const auto& mounted_root = unique_machine_mount(mounts,"/");
    const LvmLv* root_lv = nullptr;
    if (lvm) for (const auto& lv : lvm->logical_volumes)
        if (lv.public_device && lv.device.major == mounted_root.device.major &&
            lv.device.minor == mounted_root.device.minor) root_lv = &lv;
    Value root_value, boot_value;
    Value::Array excluded;
    Value::Array groups, selected_lvs;
    if (root_lv) {
        const auto pv = std::find_if(lvm->physical_volumes.begin(),lvm->physical_volumes.end(),
            [&](const LvmPv& candidate) { return candidate.vg_uuid == root_lv->vg_uuid &&
                fs::canonical(candidate.parent_disk) == disk; });
        if (pv == lvm->physical_volumes.end() || fs::canonical(pv->parent_disk) != disk)
            throw Error("selected disk does not contain the mounted LVM root physical volume");
        const auto boot = plan_lvm_machine_boot(layout,parts,mounts,pv->partition_number,
            {root_lv->device.major,root_lv->device.minor});
        for (const auto& part : parts) {
            if (part.number == boot.partition.number) continue;
            const auto physical = std::find_if(lvm->physical_volumes.begin(),lvm->physical_volumes.end(),
                [&](const auto& item) { return item.device.major == part.device.major &&
                    item.device.minor == part.device.minor; });
            if (physical != lvm->physical_volumes.end())
                excluded.push_back(pv_excluded_value(part,*physical,mounts));
            else excluded.push_back(excluded_value(part,mounts));
        }
        boot_value = partition_value(boot.partition,boot.mount,
            "immutable-copy-under-supervised-read-only-remount");
        root_value = logical_volume_value(*root_lv,mounted_root);
        selected_lvs.push_back(lvm_selected_identity(root_value));
        const auto vg = std::find_if(lvm->volume_groups.begin(),lvm->volume_groups.end(),
            [&](const LvmVg& item) { return item.uuid == root_lv->vg_uuid; });
        if (vg == lvm->volume_groups.end()) throw Error("mounted LVM root volume group is missing");
        groups.push_back(lvm_group_value(*lvm,*vg,mounts));
    } else {
        const auto plan = plan_machine_capture(layout, parts, mounts);
        boot_value = partition_value(plan.boot, plan.boot_mount,
            "immutable-copy-under-supervised-read-only-remount");
        root_value = partition_value(plan.root, plan.root_mount,
            "synosnap-with-driver-managed-freeze");
        for (const auto& part : plan.excluded) {
            const LvmPv* pv = nullptr;
            if (lvm) for (const auto& candidate : lvm->physical_volumes)
                if (candidate.device.major == part.device.major &&
                    candidate.device.minor == part.device.minor) {
                    if (pv) throw Error("ambiguous LVM physical volume on source disk");
                    pv = &candidate;
                }
            if (pv) {
                excluded.push_back(pv_excluded_value(part,*pv,mounts));
            } else excluded.push_back(excluded_value(part,mounts));
        }
    }
    Value::Array external_volumes;
    for (const auto& mount : mounts) {
        if (mount.root != "/" || !supported_linux_filesystem(mount.filesystem)) continue;
        const auto mounted = sys_device(mount.device);
        if (!fs::exists(mounted/"partition") || mounted.parent_path() == sysfs) continue;
        const auto parent_disk = mounted.parent_path();
        if (fs::exists(parent_disk/"loop") || !fs::is_empty(parent_disk/"holders") ||
            !fs::is_empty(parent_disk/"slaves")) continue;
        external_volumes.push_back(Value{Value::Object{
            {"mount_path",Value{mount.path}},
            {"filesystem",Value{mount.filesystem}},
            {"disk",Value{"/dev/"+parent_disk.filename().string()}}}});
    }
    if (lvm) for (const auto& mount : mounts) {
        if (mount.path == "/" || mount.root != "/" ||
            !supported_linux_filesystem(mount.filesystem)) continue;
        const auto lv = std::find_if(lvm->logical_volumes.begin(),lvm->logical_volumes.end(),
            [&](const LvmLv& candidate) {
                return candidate.public_device && candidate.device.major == mount.device.major &&
                       candidate.device.minor == mount.device.minor;
            });
        if (lv == lvm->logical_volumes.end()) continue;
        const auto pv = std::find_if(lvm->physical_volumes.begin(),lvm->physical_volumes.end(),
            [&](const LvmPv& candidate) { return candidate.vg_uuid == lv->vg_uuid; });
        if (pv == lvm->physical_volumes.end()) throw Error("mounted LVM volume has no physical volume");
        external_volumes.push_back(Value{Value::Object{
            {"mount_path",Value{mount.path}},{"disk",Value{pv->parent_disk}},
            {"filesystem",Value{mount.filesystem}},
            {"lv_uuid",Value{lv->uuid}}}});
    }
    const auto count_other_disks = [&] {
        std::uint64_t count = 0;
        for (const auto& entry : fs::directory_iterator("/sys/block")) {
            const auto path = fs::canonical(entry.path());
            if (path == sysfs || path.string().find("/virtual/") != std::string::npos ||
                fs::exists(path/"loop") || !fs::exists(path/"diskseq") ||
                !number(scalar(path/"size"))) continue;
            ++count;
        }
        return count;
    };
    const auto other_disks = count_other_disks();
    File cow_fd(cow, O_RDONLY | O_DIRECTORY);
    const auto cow_stat = cow_fd.stat();
    if (cow_stat.st_uid != geteuid() || (cow_stat.st_mode & 0077))
        throw Error("COW directory must be private and owned by the current user");
    const MachineMount* cow_mount = nullptr;
    for (const auto& mount : mounts) {
        if (cow == mount.path || mount.path == "/" || cow.string().starts_with(mount.path+"/")) {
            if (cow_mount && cow_mount->path == mount.path)
                throw Error("stacked mounts prevent unambiguous COW storage inspection");
            if (!cow_mount || mount.path.size() > cow_mount->path.size()) cow_mount = &mount;
        }
    }
    if (!cow_mount || cow_mount->device != device(cow_stat.st_dev) || !option(cow_mount->options, "rw"))
        throw Error("capture working storage must be on an identifiable writable filesystem");
    // Detect ordinary hotplug/repartition/remount races. This is an observation,
    // not a lease: capture must revalidate its own pinned descriptors later.
    const auto after_parts = kernel_partitions(sysfs,lvm ? &*lvm : nullptr);
    if (after_parts.size() != parts.size()) throw Error("disk partitions changed during inspection");
    for (std::size_t i = 0; i < parts.size(); ++i)
        if (parts[i].device != after_parts[i].device || parts[i].offset != after_parts[i].offset ||
            parts[i].length != after_parts[i].length || parts[i].number != after_parts[i].number)
            throw Error("disk partitions changed during inspection");
    for (const auto& record : records)
        if (read(record.offset, record.bytes.size()) != record.bytes)
            throw Error("disk partition table changed during inspection");
    File named_disk(disk, O_RDONLY | O_NONBLOCK), named_cow(cow, O_RDONLY | O_DIRECTORY);
    const auto named_disk_stat = named_disk.stat(), named_cow_stat = named_cow.stat();
    if (named_disk_stat.st_rdev != st.st_rdev || named_disk_stat.st_ino != st.st_ino ||
        named_disk_stat.st_dev != st.st_dev || !S_ISBLK(named_disk_stat.st_mode) ||
        named_cow_stat.st_dev != cow_stat.st_dev || named_cow_stat.st_ino != cow_stat.st_ino ||
        named_cow_stat.st_uid != cow_stat.st_uid || named_cow_stat.st_mode != cow_stat.st_mode ||
        number(scalar(sysfs/"diskseq")) != disk_sequence ||
        sys_device(device(st.st_rdev)) != sysfs)
        throw Error("machine device or COW directory identity changed during inspection");
    std::uint64_t after_size{};
    int after_sector{};
    const auto boot_path = std::get<std::string>(
        std::get<Value::Object>(boot_value.data).at("mount_path").data);
    const auto after_mounts = parse_machine_mounts(text_file("/proc/self/mountinfo"));
    record_block_mounts(after_mounts);
    if (!machine_relevant_mounts_equal(mounts,after_mounts,block_mount_devices,
            boot_path,cow.string()))
        throw Error("machine capture-relevant mounts changed during inspection");
    if (ioctl(source.fd, BLKGETSIZE64, &after_size) || ioctl(source.fd, BLKSSZGET, &after_sector) ||
        after_size != size || after_sector != sector ||
        count_other_disks() != other_disks || fs::canonical(disk_path) != disk ||
        fs::canonical(cow_directory) != cow)
        throw Error("machine geometry or device changed during inspection");
    Value::Object result{
        {"mode", Value{std::string("read-only-plan")}},
        {"capture_implemented", Value{std::uint64_t{1}}},
        {"disk", Value{disk.string()}}, {"device_number", Value{device_text(device(st.st_rdev))}},
        {"disk_sequence", Value{disk_sequence}},
        {"other_disk_count", Value{other_disks}},
        {"boot_id", Value{scalar("/proc/sys/kernel/random/boot_id")}},
        {"layout", layout_value(layout)}, {"cow_directory", Value{cow.string()}},
        {"cow_device", Value{device_text(device(cow_stat.st_dev))}},
        {"cow_filesystem_uuid", Value{filesystem_uuid(device(cow_stat.st_dev))}},
        {"boot", std::move(boot_value)},
        {"root", std::move(root_value)},
        {"selected_extra", Value{Value::Array{}}},
        {"additional_disks",Value{Value::Array{}}},
        {"external_volumes",Value{std::move(external_volumes)}},
        {"excluded", Value{std::move(excluded)}},
        {"remaining", Value{std::string("live capture validation, persistent whole-machine driver tracking and NAS recovery validation")}}
    };
    if (root_lv) result.emplace("lvm",Value{Value::Object{
        {"volume_groups",Value{std::move(groups)}},
        {"selected_lvs",Value{std::move(selected_lvs)}}}});
    return Value{std::move(result)};
#endif
}
std::string machine_filesystem_uuid(MachineDevice value) {
#ifdef __linux__
    return filesystem_uuid(value);
#else
    (void)value;
    throw Error("machine filesystem identity requires Linux");
#endif
}
Value inspect_running_machine(const std::string& cow_directory) {
#ifndef __linux__
    (void)cow_directory;
    throw Error("machine inspection requires Linux");
#else
    const auto mounts = parse_machine_mounts(text_file("/proc/self/mountinfo"));
    const auto root = std::find_if(mounts.begin(), mounts.end(), [](const auto& m) { return m.path == "/"; });
    if (root == mounts.end()) throw Error("cannot locate mounted root for machine recovery");
    const auto partition = sys_device(root->device);
    if (fs::exists(partition/"partition"))
        return inspect_machine("/dev/"+partition.parent_path().filename().string(), cow_directory);
    if (!fs::exists(partition/"dm"))
        throw Error("machine root must be a direct partition or supported LVM logical volume");
    const auto inventory = inspect_lvm();
    const auto lv = std::find_if(inventory.logical_volumes.begin(),inventory.logical_volumes.end(),
        [&](const LvmLv& candidate) {
            return candidate.public_device && candidate.device.major == root->device.major &&
                   candidate.device.minor == root->device.minor;
        });
    if (lv == inventory.logical_volumes.end())
        throw Error("mounted root has no supported LVM logical volume identity");
    const auto pv = std::find_if(inventory.physical_volumes.begin(),inventory.physical_volumes.end(),
        [&](const LvmPv& candidate) {
            if (candidate.vg_uuid != lv->vg_uuid) return false;
            return std::any_of(mounts.begin(),mounts.end(),[&](const auto& mount) {
                if (mount.filesystem != "vfat" || (mount.path != "/boot" &&
                    mount.path != "/boot/efi" && mount.path != "/boot/firmware")) return false;
                const auto node = sys_device(mount.device);
                return fs::exists(node/"partition") &&
                    node.parent_path().filename() == fs::path(candidate.parent_disk).filename();
            });
        });
    if (pv == inventory.physical_volumes.end()) throw Error("mounted LVM root has no physical volume on its boot disk");
    return inspect_machine(pv->parent_disk,cow_directory);
#endif
}
Value discover_machine_inventory(const std::string& working_directory) {
#ifndef __linux__
    (void)working_directory;
    throw Error("machine inventory requires Linux");
#else
    const auto directory = fs::canonical(working_directory);
    File storage(directory,O_RDONLY|O_DIRECTORY);
    const auto stored = storage.stat();
    if (stored.st_uid != geteuid() || (stored.st_mode & 0077))
        throw Error("machine working directory must be private and owned");
    const auto mounts = parse_machine_mounts(text_file("/proc/self/mountinfo"));
    std::optional<LvmInventory> lvm;
    if (has_lvm_devices()) lvm = inspect_lvm();
    Value::Array disks, logical, groups, failures;
    std::vector<fs::path> candidates;
    for (const auto& entry : fs::directory_iterator("/sys/block")) {
        const auto path = fs::canonical(entry.path());
        if (path.string().find("/virtual/") != std::string::npos ||
            fs::exists(path/"loop") || !fs::exists(path/"diskseq") ||
            !number(scalar(path/"size")) || number(scalar(path/"removable"))) continue;
        candidates.push_back(path);
    }
    std::sort(candidates.begin(),candidates.end());
    for (const auto& path : candidates) {
        const auto disk = "/dev/"+path.filename().string();
        try {
            // Inventory every partition; selection is a separate NAS-policy
            // operation. Mounted ext/XFS entries already carry live identities.
            disks.push_back(inspect_selected_external_disk(disk,directory.string(),{},lvm ? &*lvm : nullptr));
        } catch (const Error& error) {
            failures.push_back(Value{Value::Object{{"disk",Value{disk}},
                {"message",Value{std::string(error.what())}}}}); // the official agent discovery detail7110.
        }
    }
    if (lvm) {
        for (const auto& vg : lvm->volume_groups) groups.push_back(lvm_group_value(*lvm,vg,mounts));
        for (const auto& mount : mounts) {
            if (mount.root != "/" || !supported_linux_filesystem(mount.filesystem)) continue;
            const auto lv = std::find_if(lvm->logical_volumes.begin(),lvm->logical_volumes.end(),[&](const LvmLv& item) {
                return item.public_device && item.device.major == mount.device.major && item.device.minor == mount.device.minor;
            });
            if (lv != lvm->logical_volumes.end()) logical.push_back(logical_volume_value(*lv,mount));
        }
        for (const auto& lv : lvm->logical_volumes) {
            if (!lv.public_device || std::any_of(logical.begin(),logical.end(),[&](const Value& volume) {
                return std::get<Value::Object>(volume.data).at("lv_uuid") == Value{lv.uuid};
            })) continue;
            const auto vg = std::find_if(lvm->volume_groups.begin(),lvm->volume_groups.end(),
                [&](const LvmVg& group) { return group.uuid == lv.vg_uuid; });
            logical.push_back(Value{Value::Object{
                {"lv_uuid",Value{lv.uuid}},{"vg_uuid",Value{lv.vg_uuid}},
                {"logical_path",Value{lv.path}},{"length",Value{lv.size}},
                {"image_name",Value{lvm_image_name(vg->name,lv.name)}},
                {"mount_path",Value{std::string{}}},
                {"filesystem",Value{probe_filesystem_tag(lv.path,"TYPE")}},
                {"filesystem_uuid",Value{probe_filesystem_tag(lv.path,"UUID")}}}});
        }
    }
    Value::Object inventory{{"disks",Value{std::move(disks)}},{"logical_volumes",Value{std::move(logical)}},
        {"discovery_errors",Value{std::move(failures)}},
        {"boot_id",Value{scalar("/proc/sys/kernel/random/boot_id")}},
        {"cow_directory",Value{directory.string()}},{"cow_device",Value{device_text(device(stored.st_dev))}},
        {"cow_filesystem_uuid",Value{filesystem_uuid(device(stored.st_dev))}},
        {"other_disk_count",Value{static_cast<std::uint64_t>(candidates.size())}},
        {"swap_page_size",Value{static_cast<std::uint64_t>(getpagesize())}}};
    if (lvm) inventory.emplace("lvm",Value{Value::Object{{"volume_groups",Value{std::move(groups)}}}});
    return Value{std::move(inventory)};
#endif
}

}
