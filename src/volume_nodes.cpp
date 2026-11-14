#include "opensabba/volume_nodes.hpp"
#include "opensabba/filesystem.hpp"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <set>
#ifdef __linux__
#include <cerrno>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#endif

namespace opensabba {
namespace {
using pstream::Error;
using pstream::Value;
#ifdef __linux__
std::uint64_t bytes(unsigned long blocks, unsigned long size) {
    if (size && blocks > UINT64_MAX/size) throw Error("mounted volume size overflows");
    return std::uint64_t{blocks}*size;
}
bool dm_device(const MachineDevice& device) {
    return std::filesystem::exists("/sys/dev/block/"+std::to_string(device.major)+":"+
                                   std::to_string(device.minor)+"/dm/name");
}
#endif
}
Value::Array volume_node_values(const std::vector<VolumeNode>& volumes) {
    Value::Array result;
    for (const auto& volume : volumes) {
        if (volume.path.empty() || volume.path.front() != '/' ||
            volume.used_size > volume.total_size ||
            volume.free_size > volume.total_size)
            throw Error("invalid mounted volume node");
        result.push_back(Value{Value::Object{
            {"name",Value{volume.path}}, {"path",Value{volume.path}},
            {"is_dir",Value{std::uint64_t{1}}},
            {"file_system",Value{volume.filesystem}},
            {"is_dynamic_volume",Value{std::uint64_t{0}}},
            {"is_system_drive",Value{std::uint64_t{volume.path == "/"}}},
            {"volume_name",Value{volume.uuid}},
            {"total_size",Value{volume.total_size}},
            {"used_size",Value{volume.used_size}},
            {"free_size",Value{volume.free_size}}}});
    }
    return result;
}
Value::Array mounted_volume_nodes() {
#ifndef __linux__
    throw Error("mounted volume discovery requires Linux");
#else
    std::ifstream input("/proc/self/mountinfo");
    if (!input) throw Error("cannot read mounted volume inventory");
    const std::string mountinfo(std::istreambuf_iterator<char>{input},{});
    auto mounts = parse_machine_mounts(mountinfo);
    std::stable_sort(mounts.begin(),mounts.end(),[](const MachineMount& a,const MachineMount& b) {
        return dm_device(a.device) < dm_device(b.device);
    });
    std::vector<VolumeNode> volumes;
    std::set<std::string> paths;
    for (const auto& mount : mounts) {
        if (mount.root != "/" || !mount.device.major ||
            !paths.insert(mount.path).second)
            continue;
        const auto uuid = supported_linux_filesystem(mount.filesystem) ?
            machine_filesystem_uuid(mount.device) : std::string{};
        struct statvfs space{};
        if (statvfs(mount.path.c_str(),&space) != 0)
            throw Error("cannot inspect mounted volume space");
        const auto unit = space.f_frsize ? space.f_frsize : space.f_bsize;
        const auto total = bytes(space.f_blocks,unit);
        const auto free = bytes(space.f_bfree,unit);
        if (free > total) throw Error("mounted volume free space exceeds total size");
        volumes.push_back({mount.path,mount.filesystem,uuid,total,total-free,free});
    }
    if (std::none_of(volumes.begin(),volumes.end(),[](const VolumeNode& v) { return v.path == "/"; }))
        throw Error("mounted volume inventory has no root filesystem");
    return volume_node_values(volumes);
#endif
}
Value::Array directory_node_values(const std::string& path, bool dir_only,
                                  const std::vector<DirectoryNode>& entries) {
    if (path.empty() || path.find('\0') != std::string::npos)
        throw Error("invalid directory-list path");
    Value::Array result;
    for (const auto& entry : entries) {
        const auto directory = entry.directory || entry.symlink;
        if (entry.name == "." || entry.name == ".." || (dir_only && !directory))
            continue;
        result.push_back(Value{Value::Object{
            {"name",Value{entry.name}},
            {"path",Value{path + (path == "/" ? "" : "/") + entry.name}},
            {"is_dir",Value{std::uint64_t{directory}}}}});
    }
    return result;
}
DirectoryNodes directory_nodes(const std::string& path, bool dir_only) {
    if (path.empty() || path.find('\0') != std::string::npos)
        throw Error("invalid directory-list path");
#ifndef __linux__
    (void)dir_only;
    throw Error("directory discovery requires Linux");
#else
    std::unique_ptr<DIR,decltype(&closedir)> directory(opendir(path.c_str()),closedir);
    if (!directory)
        return {{},static_cast<std::uint64_t>(-static_cast<std::int64_t>(errno))};
    std::vector<DirectoryNode> entries;
    while (const auto* entry = readdir(directory.get())) {
        // Directory enumeration lstat-checks each entry before applying its
        // d_type mapping. ENOENT is treated as a missing regular-file record.
        struct stat info{};
        const auto child = path + "/" + entry->d_name;
        if (lstat(child.c_str(),&info) != 0 && errno != ENOENT) break;
        entries.push_back({entry->d_name,entry->d_type == DT_DIR,entry->d_type == DT_LNK});
    }
    // Directory listing returns success even after directory enumeration failure, retaining the
    // already-enumerated prefix. opendir failure is the only -errno result.
    return {directory_node_values(path,dir_only,entries),0};
#endif
}
void validate_client_node_result(const Value& result) {
    const auto* fields = std::get_if<Value::Object>(&result.data);
    if (!fields || !fields->contains("event_id") || !fields->contains("error_code"))
        throw Error("invalid client node-list result");
    const auto* id = std::get_if<std::uint64_t>(&fields->at("event_id").data);
    const auto* error = std::get_if<std::uint64_t>(&fields->at("error_code").data);
    const auto has_nodes = fields->contains("node_list");
    if (!id || !*id || !error ||
        (*error != 0 && (*error < UINT64_MAX - INT32_MAX || has_nodes)) ||
        (has_nodes && !std::holds_alternative<Value::Array>(fields->at("node_list").data)))
        throw Error("invalid client node-list result");
}
}
