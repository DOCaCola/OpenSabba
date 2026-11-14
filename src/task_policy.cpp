#include "opensabba/task_policy.hpp"
#include "opensabba/machine_boot.hpp"
#include "opensabba/filesystem.hpp"
#include "opensabba/backup_cache.hpp"
#include <algorithm>
#include <set>

namespace opensabba {
using pstream::Value;
using pstream::Error;
namespace {
const Value::Object& fields(const Value& value) {
    const auto* result = std::get_if<Value::Object>(&value.data);
    if (!result) throw Error("invalid NAS task policy object");
    return *result;
}
std::uint64_t number(const Value::Object& object, const char* key) {
    const auto found = object.find(key);
    if (found == object.end()) throw Error(std::string("NAS task is missing policy field: ")+key);
    const auto* result = std::get_if<std::uint64_t>(&found->second.data);
    if (!result) throw Error(std::string("invalid numeric NAS task policy: ")+key);
    return *result;
}
bool flag(const Value::Object& object, const char* key) {
    if (!object.contains(key)) return false;
    const auto value = number(object,key);
    if (value > 1) throw Error(std::string("invalid NAS task policy flag: ")+key);
    return value != 0;
}
}
bool task_transfer_encrypted(const Value& task) {
    const auto& object = fields(task);
    return object.contains("encryption") && number(object,"encryption") != 0;
}
bool task_app_aware(const Value& task) {
    const auto& object = fields(task);
    return object.contains("app_aware_bkp") && number(object,"app_aware_bkp") != 0;
}
Value::Object task_script_policy(const Value& task) {
    const auto& object = fields(task);
    const auto found = object.find("pre_post_script_setting");
    if (found == object.end()) return {};
    const auto& scripts = fields(found->second);
    Value::Object policy;
    for (auto key : {"pre_script_enabled","post_script_enabled"}) {
        if (!scripts.contains(key)) throw Error(std::string("NAS script policy is missing ")+key);
        policy.emplace(key,Value{std::uint64_t{flag(scripts,key)}});
    }
    if (scripts.contains("script_exec_mode"))
        policy.emplace("script_exec_mode",Value{number(scripts,"script_exec_mode")});
    return policy;
}
TransferCompression validate_task_policy(const Value& task, bool script_boundary) {
    const auto& object = fields(task);
    const auto compression = number(object,"compression");
    if (compression > 1) throw Error("NAS selected an unsupported transfer compression mode");
    for (auto key : {"pre_script_enabled","post_script_enabled"})
        if (flag(object,key) && !script_boundary)
            throw Error(std::string("NAS task requires ")+key+
                " at snapshot creation; use automatic machine capture");
    (void)backup_cache_policy(task);
    return compression ? TransferCompression::lz4 : TransferCompression::none;
}
std::vector<std::string> machine_task_extra_mounts(const Value& task, const Value& plan, bool script_boundary) {
    (void)validate_task_policy(task,script_boundary);
    const auto& object = fields(task);
    const auto& planned = fields(plan);
    const auto* boot_mount = std::get_if<std::string>(&fields(planned.at("boot")).at("mount_path").data);
    if (!boot_mount) throw Error("invalid machine boot mount for task selection");
    Value::Array all;
    if (const auto found = planned.find("excluded"); found != planned.end()) {
        const auto* excluded = std::get_if<Value::Array>(&found->second.data);
        if (!excluded) throw Error("invalid excluded machine partitions");
        for (const auto& entry : *excluded)
            if (!fields(entry).contains("pv_uuid")) all.push_back(entry);
    }
    if (const auto found = planned.find("selected_extra"); found != planned.end()) {
        const auto* selected = std::get_if<Value::Array>(&found->second.data);
        if (!selected) throw Error("invalid selected machine partitions");
        all.insert(all.end(),selected->begin(),selected->end());
    }
    if (const auto found = planned.find("external_volumes"); found != planned.end()) {
        const auto* external = std::get_if<Value::Array>(&found->second.data);
        if (!external) throw Error("invalid external machine volume inventory");
        std::set<std::string> known;
        for (const auto& entry : all)
            known.insert(std::get<std::string>(fields(entry).at("mount_path").data));
        for (const auto& entry : *external) {
            const auto& path = std::get<std::string>(fields(entry).at("mount_path").data);
            if (known.insert(path).second) all.push_back(entry);
        }
    }
    if (const auto found = planned.find("additional_disks"); found != planned.end()) {
        const auto* disks = std::get_if<Value::Array>(&found->second.data);
        if (!disks) throw Error("invalid selected external machine disks");
        std::set<std::string> known;
        for (const auto& entry : all)
            known.insert(std::get<std::string>(fields(entry).at("mount_path").data));
        for (const auto& disk : *disks)
            for (const auto& entry : std::get<Value::Array>(fields(disk).at("selected_extra").data)) {
                const auto& path = std::get<std::string>(fields(entry).at("mount_path").data);
                if (known.insert(path).second) all.push_back(entry);
            }
    }
    if (!supported_machine_boot_mount(*boot_mount))
        throw Error("unsupported machine boot mount for task selection");
    // The official Linux agent selects by source_type/custom_volume. Its external-disk
    // filter is a no-op; this flag never expands the requested mount list.
    (void)flag(object,"backup_external");
    std::vector<std::string> requested;
    switch (number(object,"source_type")) {
    case 1: // Entire device: the current discovered disks and mounted volumes.
        for (const auto& entry : all) {
            const auto& mount = fields(entry).at("mount_path");
            const auto* path = std::get_if<std::string>(&mount.data);
            if (!path) throw Error("invalid machine mount path");
            if (path->empty()) continue;
            if (fields(entry).contains("filesystem") && !supported_linux_filesystem(
                    std::get<std::string>(fields(entry).at("filesystem").data))) continue;
            requested.push_back(*path);
        }
        break;
    case 2: // the official agent system paths: /, /boot, and descendants of /boot/.
        for (const auto& entry : all) {
            const auto* mount = std::get_if<std::string>(&fields(entry).at("mount_path").data);
            if (!mount) throw Error("invalid excluded machine mount path");
            if (*mount == "/" || *mount == "/boot" || mount->starts_with("/boot/"))
                requested.push_back(*mount);
        }
        break;
    case 3: {
        const auto entry = object.find("custom_volume");
        if (entry == object.end()) throw Error("NAS custom selection is missing custom_volume");
        const auto* volumes = std::get_if<Value::Array>(&entry->second.data);
        if (!volumes) throw Error("invalid NAS custom volume selection");
        bool root = false;
        for (const auto& volume : *volumes) {
            const auto* mount = std::get_if<std::string>(&volume.data);
            if (!mount) throw Error("invalid NAS custom volume selection");
            for (const auto& entry : all) {
                const auto* extra = std::get_if<std::string>(&fields(entry).at("mount_path").data);
                if (!extra) throw Error("invalid excluded machine mount path");
                if (!extra->empty() && *mount == *extra) {
                    requested.push_back(*mount);
                }
            }
            root |= *mount == "/";
        }
        if (!root) throw Error("NAS custom selection excludes root; partial-volume machine images are not implemented");
        for (const auto& entry : all) {
            const auto& mount = std::get<std::string>(fields(entry).at("mount_path").data);
            if ((mount == "/boot" || mount.starts_with("/boot/")) &&
                std::find(requested.begin(),requested.end(),mount) == requested.end())
                requested.push_back(mount);
        }
        break;
    }
    default: throw Error("NAS task has an unsupported source selection");
    }
    std::sort(requested.begin(),requested.end());
    if (std::adjacent_find(requested.begin(),requested.end()) != requested.end())
        throw Error("NAS task repeats a selected extra volume");
    return requested;
}
std::vector<std::string> machine_task_missing_mounts(const Value& task, const Value& plan) {
    const auto& object = fields(task);
    if (number(object,"source_type") != 3) return {};
    std::set<std::string> present;
    const auto add = [&](const Value& volume) {
        present.insert(std::get<std::string>(fields(volume).at("mount_path").data));
    };
    const auto inventory = [&](const Value& disk) {
        const auto& properties = fields(disk);
        for (const auto key : {"root","boot"})
            if (properties.contains(key)) add(properties.at(key));
        for (const auto key : {"selected_extra","excluded"})
            if (properties.contains(key))
                for (const auto& volume : std::get<Value::Array>(properties.at(key).data)) add(volume);
    };
    inventory(plan);
    const auto& planned = fields(plan);
    if (planned.contains("discovered_mounts"))
        for (const auto& mount : std::get<Value::Array>(planned.at("discovered_mounts").data))
            present.insert(std::get<std::string>(mount.data));
    if (planned.contains("additional_disks"))
        for (const auto& disk : std::get<Value::Array>(planned.at("additional_disks").data)) inventory(disk);
    std::vector<std::string> missing;
    for (const auto& volume : std::get<Value::Array>(object.at("custom_volume").data)) {
        const auto& mount = std::get<std::string>(volume.data);
        if (!present.contains(mount)) missing.push_back(mount);
    }
    return missing;
}
TransferCompression validate_machine_transfer_policy(const Value& task) {
    return validate_task_policy(task,true);
}
TransferCompression validate_machine_task_policy(const Value& task, const Value& plan, bool script_boundary) {
    const auto compression = validate_task_policy(task,script_boundary);
    if (fields(plan).contains("selection")) {
        Value::Object expected{{"source_type",fields(task).at("source_type")}};
        if (number(fields(task),"source_type") == 3)
            expected.emplace("custom_volume",fields(task).at("custom_volume"));
        if (fields(plan).at("selection") != Value{std::move(expected)})
            throw Error("machine capture selection differs from the current NAS task");
        return compression;
    }
    const auto requested = machine_task_extra_mounts(task,plan,script_boundary);
    const auto& fields_plan = fields(plan);
    std::vector<std::string> selected;
    if (const auto found = fields_plan.find("selected_extra"); found != fields_plan.end()) {
        const auto* entries = std::get_if<Value::Array>(&found->second.data);
        if (!entries) throw Error("invalid selected machine partitions");
        for (const auto& entry : *entries) {
            const auto* mount = std::get_if<std::string>(&fields(entry).at("mount_path").data);
            if (!mount) throw Error("invalid selected machine mount");
            selected.push_back(*mount);
        }
    }
    if (const auto found = fields_plan.find("additional_disks"); found != fields_plan.end()) {
        const auto* disks = std::get_if<Value::Array>(&found->second.data);
        if (!disks) throw Error("invalid selected external machine disks");
        for (const auto& disk : *disks)
            for (const auto& entry : std::get<Value::Array>(fields(disk).at("selected_extra").data))
                selected.push_back(std::get<std::string>(fields(entry).at("mount_path").data));
    }
    std::sort(selected.begin(),selected.end());
    if (requested != selected)
        throw Error("machine capture selection differs from the current NAS task");
    return compression;
}
}
