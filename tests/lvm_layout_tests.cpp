#include "opensabba/lvm.hpp"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>

using namespace opensabba;
using pstream::Error;
namespace {
void check(bool value) { if (!value) throw Error("LVM layout fixture assertion failed"); }
std::string read(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file) throw Error("cannot open LVM layout fixture: "+path.string());
    return {std::istreambuf_iterator<char>(file),{}};
}
std::vector<std::string> split(const std::string& value, char separator) {
    std::istringstream input(value);
    std::vector<std::string> fields;
    std::string field;
    while (std::getline(input,field,separator)) fields.push_back(field);
    return fields;
}
template<class F> void reject(F action) {
    try { action(); } catch (const Error&) { return; }
    throw Error("invalid LVM graph accepted");
}
LvmDevice device(const std::string& value) {
    const auto parts = split(value,':');
    check(parts.size() == 2);
    return {static_cast<std::uint32_t>(std::stoul(parts[0])),
            static_cast<std::uint32_t>(std::stoul(parts[1]))};
}
}
int main(int argc, char** argv) {
    try {
        if (argc != 2) throw Error("usage: lvm_layout_tests FIXTURE_DIRECTORY");
        const std::filesystem::path directory(argv[1]);
        auto inventory = parse_lvm_reports(read(directory/"vgs.txt"),read(directory/"pvs.txt"),
                                            read(directory/"lvs.txt"));
        check(inventory.volume_groups.size() == 1 && inventory.physical_volumes.size() == 4);
        // Reports are sorted by UUID; labels are keyed by their PV device.
        for (const auto& pv : inventory.physical_volumes) {
            const auto label = directory/("pv-label-"+std::filesystem::path(pv.name).filename().string()+".bin");
            if (!std::filesystem::exists(label)) continue; // Native collector owns these labels.
            std::ifstream input(label,std::ios::binary);
            const pstream::Bytes bytes{std::istreambuf_iterator<char>(input),{}};
            validate_lvm_pv_header(pv,bytes);
        }
        std::set<std::string> types;
        for (const auto& lv : inventory.logical_volumes)
            for (const auto& segment : lv.segments) types.insert(segment.type);
        for (const auto* type : {"linear","striped","raid1","mirror","thin","thin-pool","cache","cache-pool"})
            check(types.contains(type));
        for (const auto& line : split(read(directory/"devices.txt"),'\n')) {
            const auto fields = split(line,'|');
            check(fields.size() == 3);
            auto pv = std::find_if(inventory.physical_volumes.begin(),inventory.physical_volumes.end(),
                [&](const auto& item) { return item.name == fields[0]; });
            check(pv != inventory.physical_volumes.end());
            pv->device = device(fields[1]+":"+fields[2]);
            pv->parent_device = {240,pv->device.minor+1};
            pv->parent_disk = "/dev/fixture"+std::to_string(pv->device.minor);
            pv->partition_number = 1; pv->partition_offset = 1024*1024;
            pv->partition_length = pv->device_size; pv->disk_sequence = 1;
        }
        std::size_t index = 0;
        for (const auto& line : split(read(directory/"nodes.txt"),'\n')) {
            const auto fields = split(line,'|');
            check(fields.size() == 5);
            LvmInventory::KernelNode node{device(fields[0]+":"+fields[1]),fields[2],fields[3],
                read(directory/("node-"+std::to_string(index++)+".txt")),{}};
            for (const auto& dependency : split(fields[4],',')) node.dependencies.push_back(device(dependency));
            inventory.kernel_nodes.push_back(std::move(node));
        }
        validate_lvm_kernel_graph(inventory);
        std::size_t public_count = 0;
        for (const auto& lv : inventory.logical_volumes) {
            if (!lv.public_device) continue;
            ++public_count;
            const auto node = std::find_if(inventory.kernel_nodes.begin(),inventory.kernel_nodes.end(),
                [&](const auto& item) { return item.device == lv.device; });
            check(node != inventory.kernel_nodes.end());
            const auto table = parse_lvm_dm_table(node->table);
            validate_lvm_mapping(inventory,lv,{node->name,node->uuid,node->device,table.size(),0},table);
        }
        check(public_count == 6);
        const auto pool = std::find_if(inventory.logical_volumes.begin(),inventory.logical_volumes.end(),
            [](const auto& lv) { return lv.name == "pool"; });
        check(pool != inventory.logical_volumes.end() && !pool->public_device && pool->visible);
        check(std::any_of(inventory.logical_volumes.begin(),inventory.logical_volumes.end(),
            [](const auto& lv) { return !lv.visible && !lv.public_device; }));
        const auto& vg_uuid = inventory.volume_groups.front().uuid;
        const auto topology = lvm_kernel_topology(inventory,vg_uuid);
        auto renumbered = inventory;
        const auto old_device = renumbered.kernel_nodes.front().device;
        const auto old_number = std::to_string(old_device.major)+":"+std::to_string(old_device.minor);
        const LvmDevice new_device{253,345};
        renumbered.kernel_nodes.front().device = new_device;
        for (auto& node : renumbered.kernel_nodes) {
            for (auto& dependency : node.dependencies)
                if (dependency == old_device) dependency = new_device;
            std::istringstream lines(node.table);
            std::string line, rebuilt;
            while (std::getline(lines,line)) {
                std::istringstream tokens(line);
                std::string token;
                bool first = true;
                while (tokens >> token) {
                    if (!first) rebuilt += ' ';
                    first = false;
                    rebuilt += token == old_number ? "253:345" : token;
                }
                rebuilt += '\n';
            }
            node.table = std::move(rebuilt);
        }
        check(lvm_kernel_topology(renumbered,vg_uuid) == topology);
        auto invalid = inventory;
        invalid.kernel_nodes.front().dependencies.push_back({999,999});
        reject([&] { validate_lvm_kernel_graph(invalid); });
        invalid = inventory;
        invalid.kernel_nodes.front().dependencies.push_back(invalid.kernel_nodes.front().device);
        reject([&] { validate_lvm_kernel_graph(invalid); });
        invalid = inventory;
        invalid.kernel_nodes.front().uuid = "LVM-foreign";
        reject([&] { validate_lvm_kernel_graph(invalid); });
        std::cout << "LVM layouts and kernel graph passed: " << public_count << " public LVs\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
