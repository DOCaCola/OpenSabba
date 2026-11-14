#include "opensabba/lvm.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#ifdef __linux__
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <linux/fs.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace opensabba {
using pstream::Error;
namespace {
constexpr std::size_t report_limit = 4*1024*1024;
std::string trim(std::string_view value) {
    const auto first = value.find_first_not_of(" \t\r");
    if (first == value.npos) return {};
    const auto last = value.find_last_not_of(" \t\r");
    return std::string(value.substr(first,last-first+1));
}
std::vector<std::vector<std::string>> rows(std::string_view report, std::size_t columns) {
    if (report.size() > report_limit || report.find('\0') != report.npos)
        throw Error("LVM report exceeds limits or contains NUL");
    std::istringstream input{std::string(report)};
    std::string line;
    std::vector<std::vector<std::string>> result;
    while (std::getline(input,line)) {
        if (trim(line).empty()) continue;
        std::vector<std::string> row;
        std::string_view remaining(line);
        for (;;) {
            const auto at = remaining.find('|');
            row.push_back(trim(remaining.substr(0,at)));
            if (at == remaining.npos) break;
            remaining.remove_prefix(at+1);
        }
        if (row.size() != columns || result.size() >= 4096)
            throw Error("invalid LVM report column count or row limit");
        result.push_back(std::move(row));
    }
    return result;
}
std::uint64_t numeric(std::string_view text) {
    std::uint64_t value{};
    const auto [end,error] = std::from_chars(text.data(),text.data()+text.size(),value);
    if (text.empty() || error != std::errc{} || end != text.data()+text.size())
        throw Error("invalid unsigned integer in LVM report");
    return value;
}
std::uint32_t small(std::string_view text) {
    const auto value = numeric(text);
    if (value > UINT32_MAX) throw Error("LVM device or partition number exceeds range");
    return static_cast<std::uint32_t>(value);
}
std::uint64_t multiply(std::uint64_t a, std::uint64_t b) {
    if (b && a > UINT64_MAX/b) throw Error("LVM extent arithmetic overflow");
    return a*b;
}
std::uint64_t add(std::uint64_t a, std::uint64_t b) {
    if (a > UINT64_MAX-b) throw Error("LVM extent arithmetic overflow");
    return a+b;
}
bool alnum(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}
std::string compact_uuid(std::string_view uuid) {
    constexpr std::array<std::size_t,6> hyphens{6,11,16,21,26,31};
    if (uuid.size() != 38) throw Error("invalid LVM UUID");
    std::string result;
    for (std::size_t i = 0; i < uuid.size(); ++i) {
        if (std::find(hyphens.begin(),hyphens.end(),i) != hyphens.end()) {
            if (uuid[i] != '-') throw Error("invalid LVM UUID separator");
        } else {
            if (!alnum(uuid[i])) throw Error("invalid LVM UUID character");
            result += uuid[i];
        }
    }
    return result;
}
void name(std::string_view text) {
    if (text.empty() || text.size() > 127 || text.front() == '-' || text == "." || text == ".." ||
        !std::all_of(text.begin(),text.end(),[](char c) { return alnum(c) || c == '.' || c == '_' || c == '-' || c == '+'; }))
        throw Error("invalid LVM name");
}
}
std::string lvm_image_name(std::string_view vg, std::string_view lv) {
    name(vg); name(lv);
    if (vg.size()+lv.size()+5 > 128)
        throw Error("LVM image name exceeds supported length");
    return std::string(vg)+"="+std::string(lv)+".img";
}
namespace {
void device_path(std::string_view path) {
    if (!path.starts_with("/dev/") || path.size() <= 5 || path.size() > 1024 ||
        path.find("//") != path.npos || path.find("/../") != path.npos ||
        path.ends_with("/..") || path.find("/./") != path.npos ||
        !std::all_of(path.begin(),path.end(),[](char c) { return alnum(c) || c == '/' || c == '.' || c == '_' || c == '-' || c == '+'; }))
        throw Error("invalid LVM device path");
}
std::string escaped(std::string_view text) {
    std::string result;
    for (char c : text) { result += c; if (c == '-') result += '-'; }
    return result;
}
const LvmVg& vg_for(const LvmInventory& inventory, std::string_view uuid) {
    const auto found = std::find_if(inventory.volume_groups.begin(),inventory.volume_groups.end(),
        [&](const auto& vg) { return vg.uuid == uuid; });
    if (found == inventory.volume_groups.end()) throw Error("LVM volume references an absent VG");
    return *found;
}
const LvmPv& pv_for(const LvmInventory& inventory, std::string_view uuid) {
    const auto found = std::find_if(inventory.physical_volumes.begin(),inventory.physical_volumes.end(),
        [&](const auto& pv) { return pv.uuid == uuid; });
    if (found == inventory.physical_volumes.end()) throw Error("LVM segment references an absent PV");
    return *found;
}
LvmDevice dev_number(std::string_view text) {
    const auto at = text.find(':');
    if (at == text.npos) throw Error("invalid LVM major:minor device number");
    return {small(text.substr(0,at)),small(text.substr(at+1))};
}
bool nonzero(LvmDevice device) { return device.major != 0; }
std::uint32_t le32(std::span<const std::uint8_t> bytes, std::size_t at) {
    return std::uint32_t(bytes[at]) | (std::uint32_t(bytes[at+1])<<8) |
        (std::uint32_t(bytes[at+2])<<16) | (std::uint32_t(bytes[at+3])<<24);
}
std::uint64_t le64(std::span<const std::uint8_t> bytes, std::size_t at) {
    return std::uint64_t(le32(bytes,at)) | (std::uint64_t(le32(bytes,at+4))<<32);
}
std::uint32_t label_crc(std::span<const std::uint8_t> bytes) {
    std::uint32_t result = 0xf597a6cfU;
    for (auto byte : bytes) {
        result ^= byte;
        for (unsigned bit = 0; bit < 8; ++bit)
            result = (result>>1) ^ ((result&1) ? 0xedb88320U : 0U);
    }
    return result;
}
}

LvmInventory parse_lvm_reports(std::string_view vgs, std::string_view pvs, std::string_view lvs) {
    LvmInventory inventory;
    for (const auto& row : rows(vgs,12)) {
        if (row[2].size() != 6 || (row[2][0] != 'w' && row[2][0] != 'r') ||
            row[2][2] != '-' || row[2][3] != '-' || row[2][5] != '-' ||
            numeric(row[9]) || (!row[10].empty() && row[10] != "none") || !row[11].empty())
            throw Error("LVM requires a complete local unexported non-shared VG");
        inventory.volume_groups.push_back({row[0],row[1],numeric(row[3]),numeric(row[5]),
            numeric(row[4]),numeric(row[6]),numeric(row[7]),numeric(row[8])});
    }
    for (const auto& row : rows(pvs,10)) {
        if (row[6] != "a--" || row[2].empty())
            throw Error("LVM requires a complete allocated PV without missing/exported flags");
        LvmPv pv;
        pv.name = row[0]; pv.uuid = row[1]; pv.vg_uuid = row[2];
        pv.size = numeric(row[3]); pv.pe_start = numeric(row[4]); pv.mda_size = numeric(row[5]);
        pv.extent_count = numeric(row[7]); pv.mda_count = numeric(row[8]); pv.device_size = numeric(row[9]);
        inventory.physical_volumes.push_back(std::move(pv));
    }
    for (const auto& row : rows(lvs,13)) {
        const auto& attr = row[5];
        if (attr.size() != 10) throw Error("invalid LVM LV attributes");
        const auto& vg = vg_for(inventory,row[2]);
        std::string lv_name = row[0];
        if (lv_name.starts_with('[') && lv_name.ends_with(']'))
            lv_name = lv_name.substr(1,lv_name.size()-2);
        name(lv_name);
        LvmSegment segment{numeric(row[8]),numeric(row[9]),0,{},"linear",{}};
        segment.type = row[7];
        segment.mapping = row[10];
        if (segment.type == "linear") {
            const auto at = row[10].rfind(':');
            if (at == row[10].npos) throw Error("invalid LVM PV segment range");
            const auto path = row[10].substr(0,at);
            const auto pv = std::find_if(inventory.physical_volumes.begin(),inventory.physical_volumes.end(),
                [&](const auto& entry) { return entry.name == path && entry.vg_uuid == vg.uuid; });
            if (pv == inventory.physical_volumes.end()) throw Error("LVM segment references an absent PV path");
            const auto range = std::string_view(row[10]).substr(at+1);
            const auto dash = range.find('-');
            if (dash == range.npos) throw Error("invalid LVM linear extent range");
            const auto start = numeric(range.substr(0,dash)), end = numeric(range.substr(dash+1));
            if (end < start || end >= pv->extent_count) throw Error("LVM extent range exceeds its PV");
            if (multiply(add(end-start,1),vg.extent_size) != segment.length)
                throw Error("LVM segment size disagrees with its PE range");
            segment.pv_offset = add(pv->pe_start,multiply(start,vg.extent_size));
            segment.pv_uuid = pv->uuid;
        }
        const LvmDevice device = row[11] == "-1" && row[12] == "-1" ?
            LvmDevice{} : LvmDevice{small(row[11]),small(row[12])};
        if (nonzero(device) != (attr[4] == 'a'))
            throw Error("LVM active state disagrees with kernel device identity");
        auto lv = std::find_if(inventory.logical_volumes.begin(),inventory.logical_volumes.end(),
            [&](const auto& entry) { return entry.uuid == row[1]; });
        const auto path = "/dev/"+vg.name+"/"+lv_name;
        const auto dm_path = "/dev/mapper/"+escaped(vg.name)+"-"+escaped(lv_name);
        if ((!row[3].empty() && row[3] != path) || (!row[4].empty() && row[4] != dm_path))
            throw Error("inconsistent LVM LV identity");
        if (lv == inventory.logical_volumes.end()) {
            LvmLv item{lv_name,row[1],row[2],path,dm_path,device,numeric(row[6]),{segment},{},{}};
            item.attributes = attr;
            item.public_device = !row[3].empty() && nonzero(device);
            item.visible = !row[0].starts_with('[');
            inventory.logical_volumes.push_back(std::move(item));
        } else {
            if (lv->name != lv_name || lv->vg_uuid != row[2] || lv->device != device ||
                lv->size != numeric(row[6]) || lv->attributes != attr)
                throw Error("LVM segment rows disagree on LV identity");
            lv->segments.push_back(std::move(segment));
        }
    }
    for (auto& lv : inventory.logical_volumes)
        std::sort(lv.segments.begin(),lv.segments.end(),[](const auto& a,const auto& b) {
            return a.logical_offset < b.logical_offset;
        });
    const auto by_uuid = [](const auto& a,const auto& b) { return a.uuid < b.uuid; };
    std::sort(inventory.volume_groups.begin(),inventory.volume_groups.end(),by_uuid);
    std::sort(inventory.physical_volumes.begin(),inventory.physical_volumes.end(),by_uuid);
    std::sort(inventory.logical_volumes.begin(),inventory.logical_volumes.end(),by_uuid);
    validate_lvm_inventory(inventory);
    return inventory;
}

void validate_lvm_inventory(const LvmInventory& inventory) {
    std::set<std::string> uuids, vg_names, pv_names, lv_paths;
    std::set<std::pair<std::uint32_t,std::uint32_t>> lv_devices;
    for (const auto& vg : inventory.volume_groups) {
        name(vg.name); (void)compact_uuid(vg.uuid);
        if (!uuids.insert(vg.uuid).second || !vg_names.insert(vg.name).second)
            throw Error("duplicate LVM VG identity");
        if (!vg.pv_count || !vg.extent_size || vg.extent_size%512 ||
            !vg.sequence || !vg.total_size || vg.total_size%vg.extent_size ||
            !vg.mda_size || vg.mda_size%512)
            throw Error("LVM requires complete PV inventory with valid extent geometry");
        const auto pvs = std::count_if(inventory.physical_volumes.begin(),inventory.physical_volumes.end(),
            [&](const auto& pv) { return pv.vg_uuid == vg.uuid; });
        const auto lvs = std::count_if(inventory.logical_volumes.begin(),inventory.logical_volumes.end(),
            [&](const auto& lv) { return lv.vg_uuid == vg.uuid && lv.visible; });
        std::uint64_t total = 0;
        for (const auto& pv : inventory.physical_volumes)
            if (pv.vg_uuid == vg.uuid) total = add(total,pv.size);
        if (static_cast<std::uint64_t>(pvs) != vg.pv_count ||
            static_cast<std::uint64_t>(lvs) != vg.lv_count || total != vg.total_size)
            throw Error("LVM VG report does not cover all PVs and LVs");
    }
    for (const auto& pv : inventory.physical_volumes) {
        device_path(pv.name); (void)compact_uuid(pv.uuid);
        const auto& vg = vg_for(inventory,pv.vg_uuid);
        if (!uuids.insert(pv.uuid).second || !pv_names.insert(pv.name).second)
            throw Error("duplicate LVM PV identity");
        if (!pv.size || !pv.pe_start || pv.pe_start%512 || !pv.device_size ||
            pv.device_size%512 || pv.mda_size%512 ||
            (pv.mda_count == 0) != (pv.mda_size == 0) || pv.mda_count > 2 ||
            multiply(pv.extent_count,vg.extent_size) != pv.size ||
            pv.pe_start > pv.device_size || pv.size > pv.device_size-pv.pe_start ||
            pv.mda_size > pv.device_size)
            throw Error("invalid LVM PV extent or metadata geometry");
    }
    struct Allocation { std::string pv; std::uint64_t start, end; };
    std::vector<Allocation> allocations;
    for (const auto& lv : inventory.logical_volumes) {
        name(lv.name); (void)compact_uuid(lv.uuid);
        const auto& vg = vg_for(inventory,lv.vg_uuid);
        if (lv.public_device) (void)lvm_image_name(vg.name,lv.name);
        device_path(lv.path); device_path(lv.dm_path);
        if (!uuids.insert(lv.uuid).second || !lv_paths.insert(lv.path).second ||
            (nonzero(lv.device) && !lv_devices.insert({lv.device.major,lv.device.minor}).second) || lv.path != "/dev/"+vg.name+"/"+lv.name ||
            lv.dm_path != "/dev/mapper/"+escaped(vg.name)+"-"+escaped(lv.name))
            throw Error("duplicate or inconsistent LVM LV identity");
        if (!lv.size || lv.size%vg.extent_size || lv.segments.empty())
            throw Error("invalid LVM LV geometry");
        std::uint64_t at = 0;
        for (const auto& segment : lv.segments) {
            if (segment.logical_offset != at || !segment.length || segment.length%vg.extent_size ||
                segment.type.empty()) throw Error("invalid or incomplete LVM segment mapping");
            at = add(at,segment.length);
            if (segment.type != "linear") continue;
            const auto& pv = pv_for(inventory,segment.pv_uuid);
            if (pv.vg_uuid != vg.uuid ||
                segment.pv_offset < pv.pe_start ||
                (segment.pv_offset-pv.pe_start)%vg.extent_size ||
                segment.pv_offset > pv.pe_start+pv.size ||
                segment.length > pv.pe_start+pv.size-segment.pv_offset)
                throw Error("invalid or incomplete LVM linear segment mapping");
            allocations.push_back({pv.uuid,segment.pv_offset,add(segment.pv_offset,segment.length)});
        }
        if (at != lv.size) throw Error("LVM segment coverage differs from LV size");
    }
    std::sort(allocations.begin(),allocations.end(),[](const auto& a,const auto& b) {
        return a.pv != b.pv ? a.pv < b.pv : a.start < b.start;
    });
    for (std::size_t i = 1; i < allocations.size(); ++i)
        if (allocations[i].pv == allocations[i-1].pv && allocations[i].start < allocations[i-1].end)
            throw Error("LVM LV extents overlap on a PV");
}

std::vector<LvmDmTarget> parse_lvm_dm_table(std::string_view report) {
    if (report.size() > report_limit || report.find('\0') != report.npos)
        throw Error("invalid LVM DM table size");
    std::istringstream input{std::string(report)};
    std::string line;
    std::vector<LvmDmTarget> targets;
    std::uint64_t at = 0;
    while (std::getline(input,line)) {
        if (trim(line).empty()) continue;
        std::istringstream fields(line);
        std::string start, length, type, parameters;
        if (!(fields>>start>>length>>type) || targets.size() >= 4096 || type == "crypt")
            throw Error("LVM DM table contains unsupported targets");
        std::getline(fields,parameters);
        LvmDmTarget target{{},multiply(numeric(start),512),multiply(numeric(length),512),0,"linear",{}};
        target.type = type;
        target.parameters = trim(parameters);
        if (type == "linear") {
            std::istringstream args(target.parameters);
            std::string device, offset, extra;
            if (!(args>>device>>offset) || (args>>extra))
                throw Error("LVM DM table must contain only complete linear targets");
            target.device = dev_number(device);
            target.device_offset = multiply(numeric(offset),512);
            if (!nonzero(target.device)) throw Error("invalid LVM DM linear device");
        }
        if (target.logical_offset != at || !target.length)
            throw Error("LVM DM table has missing/overlapping logical ranges");
        at = add(at,target.length);
        targets.push_back(target);
    }
    if (targets.empty()) throw Error("LVM DM table is empty");
    return targets;
}
LvmDmIdentity parse_lvm_dm_identity(std::string_view report) {
    const auto parsed = rows(report,7);
    if (parsed.size() != 1) throw Error("LVM DM info must identify exactly one device");
    const auto& row = parsed.front();
    if (row[6].size() != 4 || row[6][0] != 'L' || row[6][1] != '-' ||
        row[6][2] != '-' || (row[6][3] != 'w' && row[6][3] != 'r'))
        throw Error("LVM DM device is suspended or has an inactive table");
    return {row[0],row[1],{small(row[2]),small(row[3])},numeric(row[4]),numeric(row[5])};
}
void validate_lvm_mapping(const LvmInventory& inventory, const LvmLv& lv,
                          const LvmDmIdentity& identity, const std::vector<LvmDmTarget>& table) {
    validate_lvm_inventory(inventory);
    const auto& vg = vg_for(inventory,lv.vg_uuid);
    if (std::find(inventory.logical_volumes.begin(),inventory.logical_volumes.end(),lv) == inventory.logical_volumes.end() ||
        identity.device != lv.device || identity.name != escaped(vg.name)+"-"+escaped(lv.name) ||
        identity.uuid != "LVM-"+compact_uuid(vg.uuid)+compact_uuid(lv.uuid) ||
        identity.segments != table.size())
        throw Error("LVM live DM identity differs from report");
    if (table.empty() || add(table.back().logical_offset,table.back().length) != lv.size)
        throw Error("LVM live DM table size differs from LV");
    if (std::any_of(lv.segments.begin(),lv.segments.end(),[](const auto& segment) {
        return segment.type != "linear";
    })) return; // Kernel graph validates nonlinear dependencies, not physical reconstruction.
    if (table.size() != lv.segments.size()) throw Error("LVM live DM segment count differs");
    for (std::size_t i = 0; i < table.size(); ++i) {
        const auto& segment = lv.segments[i];
        const auto& pv = pv_for(inventory,segment.pv_uuid);
        const auto& target = table[i];
        if (!nonzero(pv.device) || !nonzero(pv.parent_device) ||
            !pv.partition_number || pv.partition_length != pv.device_size ||
            pv.partition_offset%512 || pv.parent_disk.empty() || !pv.disk_sequence ||
            target.type != "linear" || target.device != pv.device || target.logical_offset != segment.logical_offset ||
            target.length != segment.length || target.device_offset != segment.pv_offset)
            throw Error("LVM live DM mapping or PV partition geometry differs from report");
    }
}

void validate_lvm_kernel_graph(const LvmInventory& inventory) {
    std::set<std::pair<std::uint32_t,std::uint32_t>> devices;
    const auto vg_of = [&](const LvmInventory::KernelNode& node) -> const LvmVg& {
        for (const auto& vg : inventory.volume_groups)
            if (node.uuid.starts_with("LVM-"+compact_uuid(vg.uuid))) return vg;
        throw Error("LVM kernel node belongs to an absent VG");
    };
    for (const auto& node : inventory.kernel_nodes) {
        const auto& vg = vg_of(node);
        if (!devices.insert({node.device.major,node.device.minor}).second)
            throw Error("duplicate LVM kernel device");
        const auto owner = std::find_if(inventory.logical_volumes.begin(),inventory.logical_volumes.end(),
            [&](const auto& lv) {
                const auto uuid = "LVM-"+compact_uuid(vg.uuid)+compact_uuid(lv.uuid);
                return lv.vg_uuid == vg.uuid && (node.uuid == uuid || node.uuid.starts_with(uuid+"-"));
            });
        if (owner == inventory.logical_volumes.end()) throw Error("LVM kernel node has no LV identity");
        (void)parse_lvm_dm_table(node.table);
        for (const auto& dependency : node.dependencies) {
            const auto pv = std::find_if(inventory.physical_volumes.begin(),inventory.physical_volumes.end(),
                [&](const auto& item) { return item.device == dependency && item.vg_uuid == vg.uuid; });
            if (pv != inventory.physical_volumes.end()) continue;
            const auto child = std::find_if(inventory.kernel_nodes.begin(),inventory.kernel_nodes.end(),
                [&](const auto& item) { return item.device == dependency && vg_of(item).uuid == vg.uuid; });
            if (child == inventory.kernel_nodes.end()) throw Error("LVM kernel dependency is outside its VG");
        }
    }
    std::set<std::pair<std::uint32_t,std::uint32_t>> active, visited;
    const std::function<void(const LvmInventory::KernelNode&)> visit = [&](const auto& node) {
        const auto key = std::pair{node.device.major,node.device.minor};
        if (active.contains(key)) throw Error("cyclic LVM kernel mapping");
        if (!visited.insert(key).second) return;
        active.insert(key);
        for (const auto& device : node.dependencies)
            for (const auto& child : inventory.kernel_nodes)
                if (child.device == device) visit(child);
        active.erase(key);
    };
    for (const auto& node : inventory.kernel_nodes) visit(node);
    for (const auto& lv : inventory.logical_volumes) if (lv.public_device) {
        const auto found = std::find_if(inventory.kernel_nodes.begin(),inventory.kernel_nodes.end(),
            [&](const auto& node) { return node.device == lv.device; });
        const auto& vg = vg_for(inventory,lv.vg_uuid);
        if (found == inventory.kernel_nodes.end() ||
            found->uuid != "LVM-"+compact_uuid(vg.uuid)+compact_uuid(lv.uuid) ||
            found->name != escaped(vg.name)+"-"+escaped(lv.name))
            throw Error("LVM public device differs from LV identity");
        const auto table = parse_lvm_dm_table(found->table);
        if (add(table.back().logical_offset,table.back().length) != lv.size)
            throw Error("LVM public device size differs from LV");
    }
}

std::string lvm_kernel_topology(const LvmInventory& inventory, std::string_view vg_uuid) {
    const auto device_text = [](LvmDevice device) {
        return std::to_string(device.major)+":"+std::to_string(device.minor);
    };
    std::map<std::string,std::string> identities;
    for (const auto& pv : inventory.physical_volumes)
        identities.emplace(device_text(pv.device),"PV-"+pv.uuid);
    for (const auto& node : inventory.kernel_nodes)
        identities.emplace(device_text(node.device),node.uuid);
    std::map<std::string,std::string> nodes;
    const auto prefix = "LVM-"+compact_uuid(vg_uuid);
    for (const auto& node : inventory.kernel_nodes) if (node.uuid.starts_with(prefix)) {
        std::istringstream lines(node.table);
        std::string line, normalized;
        while (std::getline(lines,line)) {
            std::istringstream tokens(line);
            std::string token;
            bool first = true;
            while (tokens >> token) {
                if (!first) normalized += ' ';
                first = false;
                const auto found = identities.find(token);
                normalized += found == identities.end() ? token : found->second;
            }
            normalized += '\n';
        }
        std::set<std::string> dependencies;
        for (const auto& device : node.dependencies)
            dependencies.insert(identities.at(device_text(device)));
        for (const auto& identity : dependencies) normalized += "dependency "+identity+"\n";
        nodes.emplace(node.uuid,std::move(normalized));
    }
    std::string result;
    for (const auto& [uuid,table] : nodes) result += uuid+"\n"+table;
    return result;
}

void validate_lvm_pv_header(const LvmPv& pv, std::span<const std::uint8_t> bytes) {
    if (bytes.size() != 2048) throw Error("LVM PV label inspection requires four sectors");
    if (!pv.size || !pv.device_size || pv.pe_start > pv.device_size ||
        pv.size > pv.device_size-pv.pe_start)
        throw Error("invalid LVM PV header geometry");
    std::span<const std::uint8_t> label;
    for (std::size_t sector = 0; sector < 4; ++sector) {
        const auto candidate = bytes.subspan(sector*512,512);
        if (!std::equal(candidate.begin(),candidate.begin()+8,"LABELONE")) continue;
        if (!label.empty()) throw Error("LVM PV contains multiple labels");
        if (le64(candidate,8) != sector || label_crc(candidate.subspan(20)) != le32(candidate,16) ||
            !std::equal(candidate.begin()+24,candidate.begin()+32,"LVM2 001"))
            throw Error("invalid LVM2 PV label or CRC");
        label = candidate;
    }
    if (label.empty()) throw Error("LVM2 PV label is absent");
    const auto header = le32(label,20);
    if (header < 32 || header > 512-104) throw Error("invalid LVM2 PV header offset");
    const auto uuid = compact_uuid(pv.uuid);
    // The label records the device size when LVM wrote it. Growing the
    // containing partition without pvresize does not change the PV extents.
    // the official agent lvm2app reads this value without equating it to dev_get_size.
    if (!std::equal(uuid.begin(),uuid.end(),label.begin()+header))
        throw Error("LVM PV header UUID differs from report");
    std::size_t at = header+40;
    if (le64(label,at) != pv.pe_start ||
        (le64(label,at+8) && le64(label,at+8) != pv.size) ||
        le64(label,at+16) || le64(label,at+24))
        throw Error("LVM PV data area differs from report");
    at += 32;
    std::vector<std::pair<std::uint64_t,std::uint64_t>> areas;
    for (;;) {
        if (at > 512-16) throw Error("unterminated LVM PV metadata areas");
        const auto offset = le64(label,at), size = le64(label,at+8);
        at += 16;
        if (!offset && !size) break;
        if (!offset || offset%512 || !size || size%512 ||
            offset > pv.device_size || size > pv.device_size-offset || areas.size() >= 2)
            throw Error("invalid LVM PV metadata area");
        const auto end = offset+size;
        if (offset < pv.pe_start+pv.size && end > pv.pe_start)
            throw Error("LVM PV metadata overlaps data extents");
        for (const auto& previous : areas)
            if (offset < previous.first+previous.second && previous.first < end)
                throw Error("LVM PV metadata areas overlap");
        areas.push_back({offset,size});
    }
    if (areas.size() != pv.mda_count ||
        (!areas.empty() && std::min_element(areas.begin(),areas.end(),[](const auto& a,const auto& b) {
            return a.second < b.second;
        })->second != pv.mda_size))
        throw Error("LVM PV metadata size/count differs from report");
    std::size_t prefix = 0, tail = 0;
    for (const auto& [offset,size] : areas) {
        if (offset < pv.pe_start && size <= pv.pe_start-offset) ++prefix;
        else if (offset >= pv.pe_start+pv.size) ++tail;
        else throw Error("LVM PV metadata area is outside preserved extents");
    }
    if (prefix+tail != pv.mda_count || prefix > 1 || tail > 1)
        throw Error("LVM PV metadata area placement is unsupported");
}

#ifdef __linux__
namespace {
namespace fs = std::filesystem;
struct Fd {
    int value;
    explicit Fd(int fd) : value(fd) { if (fd < 0) throw Error("cannot open LVM inventory descriptor: "+std::string(std::strerror(errno))); }
    ~Fd() { close(value); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};
std::string executable(const char* basename) {
    for (const auto* directory : {"/sbin/","/usr/sbin/"}) {
        const auto path = std::string(directory)+basename;
        if (access(path.c_str(),X_OK) == 0) return fs::canonical(path).string();
    }
    throw Error(std::string("LVM inspection requires installed ")+basename);
}
std::string command(const std::string& executable, std::vector<std::string> arguments) {
    int pipes[2];
    if (pipe2(pipes,O_CLOEXEC|O_NONBLOCK)) throw Error("cannot create LVM report pipe");
    Fd output(pipes[0]), writer(pipes[1]);
    Fd null(open("/dev/null",O_RDONLY|O_CLOEXEC));
    posix_spawn_file_actions_t actions;
    const auto initial = posix_spawn_file_actions_init(&actions);
    if (initial) throw Error("cannot initialize LVM report process actions");
    struct Actions { posix_spawn_file_actions_t* value; ~Actions() { posix_spawn_file_actions_destroy(value); } } cleanup{&actions};
    if (posix_spawn_file_actions_adddup2(&actions,null.value,STDIN_FILENO) ||
        posix_spawn_file_actions_adddup2(&actions,writer.value,STDOUT_FILENO) ||
        posix_spawn_file_actions_adddup2(&actions,writer.value,STDERR_FILENO) ||
        posix_spawn_file_actions_addclosefrom_np(&actions,3))
        throw Error("cannot configure LVM report process");
    // A service may have live network sockets while discovery runs. The report
    // child owns only stdin/stdout/stderr, including when inherited descriptors
    // were opened without CLOEXEC. LVM warns about leaks on its report stream.
    // The child must have blocking stdout, while the parent uses poll/read.
    if (fcntl(writer.value,F_SETFL,0)) throw Error("cannot configure LVM report output");
    arguments.insert(arguments.begin(),executable);
    std::vector<char*> argv;
    for (auto& argument : arguments) argv.push_back(argument.data());
    argv.push_back(nullptr);
    char locale[] = "LC_ALL=C";
    char path[] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
    char* environment[]{locale,path,nullptr};
    pid_t child{};
    const int spawned = posix_spawn(&child,executable.c_str(),&actions,nullptr,argv.data(),environment);
    if (spawned) throw Error("cannot execute LVM report tool: "+std::string(std::strerror(spawned)));
    struct Child {
        pid_t pid; bool waited = false;
        ~Child() { if (!waited) { kill(pid,SIGKILL); while (waitpid(pid,nullptr,0) < 0 && errno == EINTR) {} } }
    } process{child};
    close(writer.value); writer.value = -1;
    std::string result;
    const auto deadline = std::chrono::steady_clock::now()+std::chrono::seconds(20);
    for (;;) {
        if (std::chrono::steady_clock::now() >= deadline) throw Error("LVM report tool timed out");
        pollfd descriptor{output.value,POLLIN|POLLHUP,0};
        const int polled = poll(&descriptor,1,100);
        if (polled < 0 && errno == EINTR) continue;
        if (polled < 0) throw Error("LVM report pipe polling failed");
        if (!polled) continue;
        std::array<char,8192> buffer{};
        const auto count = read(output.value,buffer.data(),buffer.size());
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count < 0) throw Error("LVM report pipe read failed");
        if (!count) break;
        if (result.size()+static_cast<std::size_t>(count) > report_limit)
            throw Error("LVM report tool output exceeds limit");
        result.append(buffer.data(),static_cast<std::size_t>(count));
    }
    int status{};
    for (;;) {
        const auto waited = waitpid(child,&status,WNOHANG);
        if (waited == child) break;
        if (waited < 0 && errno != EINTR) throw Error("cannot wait for LVM report process");
        if (std::chrono::steady_clock::now() >= deadline) throw Error("LVM report tool exit timed out");
        poll(nullptr,0,10);
    }
    process.waited = true;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        throw Error("LVM report tool failed: "+trim(result));
    return result;
}
std::string scalar(const fs::path& path) {
    std::ifstream input(path);
    if (!input) throw Error("cannot read LVM kernel inventory: "+path.string());
    std::string line, extra;
    if (!std::getline(input,line) || std::getline(input,extra) || line.size() > 1024)
        throw Error("invalid LVM kernel inventory value");
    return line;
}
std::string dev_text(LvmDevice device) { return std::to_string(device.major)+":"+std::to_string(device.minor); }
LvmDevice dev(dev_t device) { return {major(device),minor(device)}; }
struct stat stat_fd(int fd) {
    struct stat result{};
    if (fstat(fd,&result)) throw Error("cannot inspect LVM block descriptor");
    return result;
}
std::uint64_t block_size(int fd) {
    std::uint64_t size{};
    if (ioctl(fd,BLKGETSIZE64,&size) || !size) throw Error("cannot inspect LVM block size");
    return size;
}
LvmInventory reports(const std::string& tool) {
    const auto report = [&](std::string command_name, std::string columns, bool segments) {
        std::vector<std::string> args{std::move(command_name),"--noheadings","--separator","|",
            "--units","b","--nosuffix","--nohints","--nolocking","--config",
            "devices { write_cache_state=0 } backup { backup=0 archive=0 }",
            "-o",std::move(columns)};
        if (segments) { args.push_back("--segments"); args.push_back("--all"); }
        else args.push_back("--readonly");
        return command(tool,std::move(args));
    };
    const auto vgs = report("vgs","vg_name,vg_uuid,vg_attr,vg_extent_size,vg_size,vg_mda_size,vg_seqno,pv_count,lv_count,vg_missing_pv_count,vg_lock_type,vg_sysid",false);
    const auto pvs = report("pvs","pv_name,pv_uuid,vg_uuid,pv_size,pe_start,pv_mda_size,pv_attr,pv_pe_count,pv_mda_count,dev_size",false);
    const auto lvs = report("lvs","lv_name,lv_uuid,vg_uuid,lv_path,lv_dm_path,lv_attr,lv_size,segtype,seg_start,seg_size,seg_pe_ranges,lv_kernel_major,lv_kernel_minor",true);
    return parse_lvm_reports(vgs,pvs,lvs);
}
LvmDmIdentity dm_identity(const std::string& dmsetup, const LvmLv& lv) {
    return parse_lvm_dm_identity(command(dmsetup,{"info","-c","--noheadings","--separator","|","-o","name,uuid,major,minor,segments,events,attr","--major",std::to_string(lv.device.major),"--minor",std::to_string(lv.device.minor)}));
}
std::vector<LvmDmTarget> dm_table(const std::string& dmsetup, const LvmLv& lv) {
    return parse_lvm_dm_table(command(dmsetup,{"table","--major",std::to_string(lv.device.major),"--minor",std::to_string(lv.device.minor)}));
}
std::vector<LvmInventory::KernelNode> kernel_graph(const std::string& dmsetup,
                                                  const LvmInventory& inventory) {
    std::vector<LvmInventory::KernelNode> nodes;
    for (const auto& entry : fs::directory_iterator("/sys/block")) {
        const auto path = fs::canonical(entry.path());
        if (!fs::exists(path/"dm")) continue;
        const auto uuid = scalar(path/"dm"/"uuid");
        if (std::none_of(inventory.volume_groups.begin(),inventory.volume_groups.end(),
            [&](const auto& vg) { return uuid.starts_with("LVM-"+compact_uuid(vg.uuid)); })) continue;
        LvmLv probe;
        probe.device = dev_number(scalar(path/"dev"));
        const auto identity = dm_identity(dmsetup,probe);
        if (identity.uuid != uuid || identity.name != scalar(path/"dm"/"name"))
            throw Error("LVM DM sysfs identity differs from live device");
        LvmInventory::KernelNode node{probe.device,identity.name,uuid,{},{}};
        const auto table = command(dmsetup,{"table","--major",std::to_string(probe.device.major),
            "--minor",std::to_string(probe.device.minor)});
        if (parse_lvm_dm_table(table).size() != identity.segments)
            throw Error("LVM kernel table segment count differs");
        std::istringstream lines(table);
        std::string line;
        while (std::getline(lines,line)) if (!trim(line).empty()) node.table += trim(line)+"\n";
        for (const auto& dependency : fs::directory_iterator(path/"slaves"))
            node.dependencies.push_back(dev_number(scalar(dependency.path()/"dev")));
        std::sort(node.dependencies.begin(),node.dependencies.end(),[](const auto& a,const auto& b) {
            return std::pair{a.major,a.minor} < std::pair{b.major,b.minor};
        });
        nodes.push_back(std::move(node));
    }
    std::sort(nodes.begin(),nodes.end(),[](const auto& a,const auto& b) { return a.uuid < b.uuid; });
    return nodes;
}
}
#endif

LvmInventory inspect_lvm() {
#ifndef __linux__
    throw Error("LVM inspection requires Linux");
#else
    const auto lvm = executable("lvm"), dmsetup = executable("dmsetup");
    auto inventory = reports(lvm);
    const auto reported = inventory;
    struct PvObservation {
        struct stat source, parent;
        pstream::Bytes label;
    };
    std::vector<PvObservation> pv_observations;
    for (auto& pv : inventory.physical_volumes) {
        const auto path = fs::canonical(pv.name);
        Fd source(open(path.c_str(),O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));
        const auto before = stat_fd(source.value);
        if (!S_ISBLK(before.st_mode) || block_size(source.value) != pv.device_size)
            throw Error("LVM PV device identity or size differs from report");
        pv.device = dev(before.st_rdev);
        const auto sysfs = fs::canonical("/sys/dev/block/"+dev_text(pv.device));
        if (!fs::exists(sysfs/"partition") ||
            (fs::exists(sysfs/"slaves") && !fs::is_empty(sysfs/"slaves")))
            throw Error("LVM PV must be a direct physical-disk partition; stacked/crypt PVs are unsupported");
        const auto parent = sysfs.parent_path();
        if (parent.string().find("/virtual/") != std::string::npos ||
            fs::exists(parent/"partition") || fs::exists(parent/"loop") ||
            !fs::is_empty(parent/"slaves") || !fs::is_empty(parent/"holders"))
            throw Error("LVM PV parent must be a direct physical disk");
        pv.parent_device = dev_number(scalar(parent/"dev"));
        pv.parent_disk = "/dev/"+parent.filename().string();
        pv.partition_number = small(scalar(sysfs/"partition"));
        pv.partition_offset = multiply(numeric(scalar(sysfs/"start")),512);
        pv.partition_length = multiply(numeric(scalar(sysfs/"size")),512);
        pv.disk_sequence = numeric(scalar(parent/"diskseq"));
        Fd parent_fd(open(pv.parent_disk.c_str(),O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));
        const auto parent_stat = stat_fd(parent_fd.value);
        const auto length = block_size(parent_fd.value);
        if (!S_ISBLK(parent_stat.st_mode) || dev(parent_stat.st_rdev) != pv.parent_device ||
            pv.partition_length != pv.device_size || pv.partition_offset > length ||
            pv.partition_length > length-pv.partition_offset || !pv.partition_number || !pv.disk_sequence)
            throw Error("LVM PV partition geometry differs from kernel registration");
        pstream::Bytes header(2048);
        std::size_t at = 0;
        while (at < header.size()) {
            const auto count = pread(source.value,header.data()+at,header.size()-at,static_cast<off_t>(at));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) throw Error("cannot read LVM PV label");
            at += static_cast<std::size_t>(count);
        }
        validate_lvm_pv_header(pv,header);
        Fd named(open(fs::canonical(pv.name).c_str(),O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));
        const auto after = stat_fd(named.value);
        if (before.st_rdev != after.st_rdev || before.st_ino != after.st_ino ||
            before.st_dev != after.st_dev || fs::canonical(pv.name) != path ||
            numeric(scalar(parent/"diskseq")) != pv.disk_sequence)
            throw Error("LVM PV changed during discovery");
        pv_observations.push_back({before,parent_stat,std::move(header)});
    }
    // the official agent logs absent /dev/VG/LV nodes and keeps those LVs metadata-only.
    for (auto& lv : inventory.logical_volumes)
        if (lv.public_device && !fs::exists(lv.path)) lv.public_device = false;
    inventory.kernel_nodes = kernel_graph(dmsetup,inventory);
    validate_lvm_kernel_graph(inventory);
    const auto check_holders = [&](LvmDevice device) {
        const auto path = fs::canonical("/sys/dev/block/"+dev_text(device));
        for (const auto& holder : fs::directory_iterator(path/"holders")) {
            const auto held = dev_number(scalar(holder.path()/"dev"));
            if (std::none_of(inventory.kernel_nodes.begin(),inventory.kernel_nodes.end(),
                [&](const auto& node) { return node.device == held; }))
                throw Error("LVM device has unsupported non-LVM holders");
        }
    };
    for (const auto& pv : inventory.physical_volumes) check_holders(pv.device);
    for (const auto& node : inventory.kernel_nodes) check_holders(node.device);
    for (auto& lv : inventory.logical_volumes) {
        if (!lv.public_device) continue;
        const auto path = fs::canonical(lv.path);
        if (fs::canonical(lv.dm_path) != path) throw Error("LVM LV mapper path differs from LV path");
        Fd source(open(path.c_str(),O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));
        const auto st = stat_fd(source.value);
        if (!S_ISBLK(st.st_mode) || dev(st.st_rdev) != lv.device || block_size(source.value) != lv.size)
            throw Error("LVM LV path or size differs from report");
        validate_lvm_mapping(inventory,lv,dm_identity(dmsetup,lv),dm_table(dmsetup,lv));
        lv.kernel_table = lvm_kernel_topology(inventory,lv.vg_uuid);
    }
    if (reports(lvm) != reported) throw Error("LVM topology changed during discovery");
    for (std::size_t index = 0; index < inventory.logical_volumes.size(); ++index) {
        const auto& lv = inventory.logical_volumes[index];
        if (reported.logical_volumes[index].public_device &&
            fs::exists(lv.path) != lv.public_device)
            throw Error("LVM public device presence changed during discovery");
    }
    for (std::size_t i = 0; i < inventory.physical_volumes.size(); ++i) {
        const auto& pv = inventory.physical_volumes[i];
        const auto& previous = pv_observations[i];
        Fd source(open(fs::canonical(pv.name).c_str(),O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));
        Fd parent_fd(open(pv.parent_disk.c_str(),O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));
        const auto current = stat_fd(source.value), parent_stat = stat_fd(parent_fd.value);
        const auto sysfs = fs::canonical("/sys/dev/block/"+dev_text(pv.device));
        const auto parent = sysfs.parent_path();
        if (current.st_rdev != previous.source.st_rdev || current.st_ino != previous.source.st_ino ||
            current.st_dev != previous.source.st_dev || !S_ISBLK(current.st_mode) ||
            parent_stat.st_rdev != previous.parent.st_rdev || parent_stat.st_ino != previous.parent.st_ino ||
            parent_stat.st_dev != previous.parent.st_dev || !S_ISBLK(parent_stat.st_mode) ||
            block_size(source.value) != pv.device_size ||
            dev_number(scalar(sysfs/"dev")) != pv.device ||
            dev_number(scalar(parent/"dev")) != pv.parent_device ||
            "/dev/"+parent.filename().string() != pv.parent_disk ||
            small(scalar(sysfs/"partition")) != pv.partition_number ||
            multiply(numeric(scalar(sysfs/"start")),512) != pv.partition_offset ||
            multiply(numeric(scalar(sysfs/"size")),512) != pv.partition_length ||
            numeric(scalar(parent/"diskseq")) != pv.disk_sequence)
            throw Error("LVM PV kernel identity changed during discovery");
        pstream::Bytes header(2048);
        std::size_t at = 0;
        while (at < header.size()) {
            const auto count = pread(source.value,header.data()+at,header.size()-at,static_cast<off_t>(at));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) throw Error("cannot recheck LVM PV label");
            at += static_cast<std::size_t>(count);
        }
        if (header != previous.label) throw Error("LVM PV label changed during discovery");
    }
    if (kernel_graph(dmsetup,inventory) != inventory.kernel_nodes)
        throw Error("LVM live DM table changed during discovery");
    return inventory;
#endif
}
}
