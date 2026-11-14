#include "opensabba/machine.hpp"
#include "opensabba/filesystem.hpp"
#include "opensabba/task_policy.hpp"
#include <algorithm>
#include <filesystem>
#include <set>

namespace opensabba {
using pstream::Value;
using pstream::Error;
namespace {
const Value::Object& object(const Value& value) { return std::get<Value::Object>(value.data); }
Value::Object& object(Value& value) { return std::get<Value::Object>(value.data); }
const Value::Array& array(const Value& value,const char* key) { return std::get<Value::Array>(object(value).at(key).data); }
std::string text(const Value& value,const char* key) { return std::get<std::string>(object(value).at(key).data); }
std::uint64_t number(const Value& value,const char* key) { return std::get<std::uint64_t>(object(value).at(key).data); }
bool system_path(const std::string& path) { return path == "/" || path == "/boot" || path.starts_with("/boot/"); }
}
std::string machine_disk_image_name(const std::string& disk) {
    // Discovery supplies a whole physical device. Image naming
    // strips /dev/ and its partition suffix before appending.img.
    if (!disk.starts_with("/dev/") || disk.size() == 5 || disk.find('/',5) != std::string::npos)
        throw Error("physical image requires a whole device path");
    return disk.substr(5)+".img";
}
Value select_machine_inventory(Value inventory,const Value& task) {
    const auto type = number(task,"source_type");
    if (type < 1 || type > 3) throw Error("NAS task has an unsupported source selection");
    std::set<std::string> custom;
    if (type == 3)
        for (const auto& value : array(task,"custom_volume")) custom.insert(std::get<std::string>(value.data));
    const auto selected_path = [&](const std::string& path) {
        if (path.empty()) return false;
        return type == 1 || (type == 2 && system_path(path)) ||
            (type == 3 && (custom.contains(path) || (custom.contains("/") && system_path(path))));
    };
    Value::Array selected_disks, logical;
    Value::Array unselected_logical, unselected_disks;
    for (const auto& volume : array(inventory,"logical_volumes"))
        (selected_path(text(volume,"mount_path")) && supported_linux_filesystem(text(volume,"filesystem")) ?
            logical : unselected_logical).push_back(volume);
    std::uint64_t disk_number = 0;
    for (auto disk : array(inventory,"disks")) {
        object(disk)["disk_number"] = Value{disk_number++};
        Value::Array selected, excluded;
        for (const auto& volume : array(disk,"excluded")) {
            const auto path = text(volume,"mount_path");
            const auto filesystem = text(volume,"filesystem");
            if (selected_path(path) && supported_linux_filesystem(filesystem) &&
                object(volume).contains("mount_id")) {
                auto snapshot = volume;
                object(snapshot)["required_capture"] = Value{std::string("synosnap-with-driver-managed-freeze")};
                selected.push_back(std::move(snapshot));
            }
            else {
                auto retained = volume;
                if (selected_path(path) && filesystem == "vfat" && system_path(path))
                    object(retained)["selected_raw"] = Value{std::uint64_t{1}};
                excluded.push_back(std::move(retained));
            }
        }
        object(disk)["selected_extra"] = Value{std::move(selected)};
        object(disk)["excluded"] = Value{std::move(excluded)};
        object(disk)["layout_policy"] = Value{std::string("linux-layout-v1")};
        object(disk)["image_name"] = Value{machine_disk_image_name(text(disk,"disk"))};
        if (type == 1) {
            object(disk)["volume_policy"] = Value{std::string("linux-bare-metal-v1")};
            object(disk)["swap_page_size"] = object(inventory).at("swap_page_size");
        }
        (machine_disk_need_upload(disk) ? selected_disks : unselected_disks).push_back(std::move(disk));
    }
    // A real selected filesystem supplies the primary snapshot slot. This is
    // capture ownership only; the primary origin need not be mounted at /.
    auto primary_disk = selected_disks.end();
    Value primary;
    for (auto disk = selected_disks.begin(); disk != selected_disks.end(); ++disk) {
        auto& selected = std::get<Value::Array>(object(*disk).at("selected_extra").data);
        if (!selected.empty()) {
            primary_disk = disk;
            primary = selected.front();
            break;
        }
    }
    if (primary_disk == selected_disks.end()) {
        if (logical.empty()) throw Error("snapshot selection has no supported mounted origin");
        primary = logical.front();
        logical.erase(logical.begin());
        if (!selected_disks.empty()) primary_disk = selected_disks.begin();
    }
    Value plan{Value::Object{{"selected_extra",Value{Value::Array{}}},
        {"excluded",Value{Value::Array{}}}}};
    if (primary_disk != selected_disks.end()) {
        plan = *primary_disk;
        selected_disks.erase(primary_disk);
    }
    auto& selected = std::get<Value::Array>(object(plan).at("selected_extra").data);
    if (!object(primary).contains("lv_uuid"))
        std::erase_if(selected,[&](const Value& volume) { return text(volume,"device") == text(primary,"device"); });
    object(primary)["disk_index"] = Value{std::uint64_t{0}};
    object(plan)["root"] = std::move(primary);
    for (const auto& volume : logical) selected.push_back(volume);
    const auto index_volumes = [](Value& disk,std::uint64_t index) {
        for (auto& volume : std::get<Value::Array>(object(disk).at("selected_extra").data))
            object(volume)["disk_index"] = Value{index};
    };
    index_volumes(plan,0);
    for (std::size_t index = 0; index < selected_disks.size(); ++index) index_volumes(selected_disks[index],index+1);
    object(plan)["additional_disks"] = Value{std::move(selected_disks)};
    Value::Array discovered_mounts;
    for (const auto& disk : array(inventory,"disks"))
        for (const auto& volume : array(disk,"excluded"))
            discovered_mounts.push_back(Value{text(volume,"mount_path")});
    for (const auto& volume : array(inventory,"logical_volumes"))
        discovered_mounts.push_back(Value{text(volume,"mount_path")});
    object(plan)["unselected_disks"] = Value{std::move(unselected_disks)};
    object(plan)["unselected_logical"] = Value{std::move(unselected_logical)};
    object(plan)["discovered_mounts"] = Value{std::move(discovered_mounts)};
    object(plan)["discovery_errors"] = object(inventory).at("discovery_errors");
    for (const auto key : {"boot_id","cow_directory","cow_device","cow_filesystem_uuid","other_disk_count"})
        object(plan)[key] = object(inventory).at(key);
    object(plan)["selection"] = Value{Value::Object{{"source_type",object(task).at("source_type")}}};
    if (type == 3) object(object(plan).at("selection"))["custom_volume"] = object(task).at("custom_volume");
    if (object(inventory).contains("lvm")) {
        object(plan)["lvm"] = object(inventory).at("lvm");
        Value::Array identities;
        const auto add = [&](const Value& volume) {
            if (object(volume).contains("lv_uuid")) identities.push_back(volume);
        };
        add(object(plan).at("root"));
        for (const auto& volume : selected) add(volume);
        object(object(plan).at("lvm"))["selected_lvs"] = Value{std::move(identities)};
    }
    return plan;
}
std::size_t machine_physical_image_count(const Value& plan) {
    return (object(plan).contains("layout") ? 1U : 0U)+
        (object(plan).contains("additional_disks") ? array(plan,"additional_disks").size() : 0U);
}
std::vector<const Value*> machine_image_plans(const Value& plan) {
    std::vector<const Value*> result;
    if (object(plan).contains("layout")) result.push_back(&plan);
    if (object(plan).contains("additional_disks"))
        for (const auto& disk : array(plan,"additional_disks")) result.push_back(&disk);
    const auto add = [&](const Value& volume) {
        if (object(volume).contains("lv_uuid")) result.push_back(&volume);
    };
    add(object(plan).at("root"));
    if (object(plan).contains("selected_extra"))
        for (const auto& volume : array(plan,"selected_extra")) add(volume);
    return result;
}
Value rediscover_machine_plan(const Value& plan) {
    return select_machine_inventory(discover_machine_inventory(text(plan,"cow_directory")),
        object(plan).at("selection"));
}
}
