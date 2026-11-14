#include "opensabba/task_policy.hpp"
#include <iostream>
using namespace opensabba;
using namespace opensabba::pstream;
namespace {
Value n(std::uint64_t v) { return Value{v}; }
void check(bool v) { if (!v) throw Error("task policy invariant failed"); }
template<class F> void rejects(F f, std::string_view text) {
    try { f(); } catch (const Error& error) {
        check(std::string_view(error.what()).find(text) != std::string_view::npos);
        return;
    }
    throw Error("unsupported task policy accepted");
}
}
int main() {
    try {
        const auto machine = [](std::string_view boot, Value::Array excluded = {},
                                std::uint64_t other_disks = 0) {
            return Value{Value::Object{{"boot",Value{Value::Object{{"mount_path",Value{std::string(boot)}}}}},
                {"root",Value{Value::Object{{"mount_path",Value{std::string("/")}}}}},
                {"excluded",Value{std::move(excluded)}},{"selected_extra",Value{Value::Array{}}},
                {"other_disk_count",n(other_disks)}}};
        };
        const auto basic = machine("/boot/firmware");
        Value::Object policy{{"compression",n(1)},{"source_type",n(1)}};
        check(!task_app_aware(Value{policy}));
        check(!task_transfer_encrypted(Value{policy}));
        for (const auto encrypted : {0U,1U,2U}) {
            auto transfer = policy; transfer["encryption"] = n(encrypted);
            check(task_transfer_encrypted(Value{transfer}) == bool(encrypted));
        }
        for (const auto value : {0U,1U,2U}) {
            auto selected = policy;
            selected["app_aware_bkp"] = n(value);
            check(task_app_aware(Value{selected}) == (value != 0));
        }
        auto malformed_app_aware = policy;
        malformed_app_aware["app_aware_bkp"] = Value{std::string("yes")};
        rejects([&] { task_app_aware(Value{malformed_app_aware}); }, "numeric");
        check(validate_machine_task_policy(Value{policy},basic) == TransferCompression::lz4);
        policy["compression"] = n(0);
        check(validate_task_policy(Value{policy}) == TransferCompression::none);
        for (auto key : {"pre_script_enabled","post_script_enabled"}) {
            auto changed = policy; changed[key] = n(1);
            rejects([&] { validate_machine_task_policy(Value{changed},basic); },
                    std::string_view(key) == "cached_enabled" ? "caching" : "script");
            if (std::string_view(key) != "cached_enabled")
                check(validate_machine_task_policy(Value{changed},basic,true) == TransferCompression::none);
            changed[key] = n(2);
            rejects([&] { validate_machine_task_policy(Value{changed},basic); }, "flag");
        }
        for (auto type : {0,3,99}) {
            auto changed = policy; changed["source_type"] = n(type);
            rejects([&] { validate_machine_task_policy(Value{changed},basic); }, "selection");
        }
        for (const auto boot : {"/boot", "/boot/efi", "/boot/firmware"}) {
            auto selected = policy; selected["source_type"] = n(2);
            check(validate_machine_task_policy(Value{selected},machine(boot)) == TransferCompression::none);
            selected["source_type"] = n(3);
            for (auto volumes : {Value::Array{Value{std::string("/")}},
                                 Value::Array{Value{std::string("/")},Value{std::string(boot)}}}) {
                selected["custom_volume"] = Value{volumes};
                check(validate_machine_task_policy(Value{selected},machine(boot)) == TransferCompression::none);
            }
            for (auto volumes : {Value::Array{}, Value::Array{Value{std::string(boot)}},
                    Value::Array{Value{std::string("/dev/sda2")}}, Value::Array{n(1)}}) {
                selected["custom_volume"] = Value{volumes};
                rejects([&] { validate_machine_task_policy(Value{selected},machine(boot)); }, "selection");
            }
        }
        // Fresh discovery carries the actual NAS selection; no / or boot role
        // is required for a selected nonroot origin. Acquisition-time validation
        // and retained-snapshot transfer policy are separate boundaries.
        auto nonroot_task = policy;
        nonroot_task["source_type"] = n(3);
        nonroot_task["custom_volume"] = Value{Value::Array{Value{std::string("/data")}}};
        Value nonroot{Value::Object{{"selection",Value{Value::Object{
            {"source_type",n(3)},{"custom_volume",nonroot_task.at("custom_volume")}}}},
            {"root",Value{Value::Object{{"mount_path",Value{std::string("/data")}}}}}}};
        check(validate_machine_task_policy(Value{nonroot_task},nonroot,true) == TransferCompression::none);
        auto changed_selection = nonroot_task;
        changed_selection["custom_volume"] = Value{Value::Array{Value{std::string("/other")}}};
        rejects([&] { validate_machine_task_policy(Value{changed_selection},nonroot,true); }, "selection differs");
        // Dispatch preserves the old selected bytes while applying refreshed
        // transfer settings. Newly enabled scripts cannot replay a boundary.
        changed_selection["compression"] = n(1);
        changed_selection["pre_script_enabled"] = n(1);
        changed_selection["post_script_enabled"] = n(1);
        check(validate_machine_transfer_policy(Value{changed_selection}) == TransferCompression::lz4);
        changed_selection["compression"] = n(0);
        changed_selection["source_type"] = n(1);
        check(validate_machine_transfer_policy(Value{changed_selection}) == TransferCompression::none);
        auto missing = policy; missing.erase("source_type");
        rejects([&] { validate_machine_task_policy(Value{missing},basic); }, "source_type");
        const auto extra = machine("/boot/firmware", {Value{Value::Object{{"mount_path",Value{std::string("/data")}}}}});
        rejects([&] { validate_machine_task_policy(Value{policy},extra); }, "selection differs");
        check(validate_machine_task_policy(Value{policy},machine("/boot/firmware",{},1)) ==
              TransferCompression::none);
        const auto omitted = machine("/boot/firmware", {
            Value{Value::Object{{"mount_path",Value{std::string{}}},
                               {"filesystem",Value{std::string("ext4")}}}},
            Value{Value::Object{{"mount_path",Value{std::string("/archive")}},
                               {"filesystem",Value{std::string("btrfs")}}}},
            Value{Value::Object{{"mount_path",Value{std::string{}}},
                               {"filesystem",Value{std::string("swap")}}}}});
        check(machine_task_extra_mounts(Value{policy},omitted).empty());
        check(validate_machine_task_policy(Value{policy},omitted) == TransferCompression::none);
        auto system = policy; system["source_type"] = n(2);
        check(validate_machine_task_policy(Value{system},extra) == TransferCompression::none);
        auto custom = policy; custom["source_type"] = n(3);
        custom["custom_volume"] = Value{Value::Array{Value{std::string("/")},Value{std::string("/data")}}};
        rejects([&] { validate_machine_task_policy(Value{custom},extra); }, "selection differs");
        const auto boot_extra = machine("/boot/firmware",
            {Value{Value::Object{{"mount_path",Value{std::string("/boot/efi")}}}}});
        check(machine_task_extra_mounts(Value{system},boot_extra) ==
              std::vector<std::string>{"/boot/efi"});
        rejects([&] { validate_machine_task_policy(Value{system},boot_extra); }, "selection differs");
        auto wrong_boot = machine("/boot/efi-extra");
        rejects([&] { validate_machine_task_policy(Value{system},wrong_boot); },
                "unsupported machine boot mount");
        auto external = machine("/boot/firmware",{},1);
        auto& external_fields = std::get<Value::Object>(external.data);
        external_fields["external_volumes"] = Value{Value::Array{Value{Value::Object{
            {"mount_path",Value{std::string("/data")}},
            {"disk",Value{std::string("/dev/sdc")}}}}}};
        check(machine_task_extra_mounts(Value{policy},external) == std::vector<std::string>{"/data"});
        check(machine_task_extra_mounts(Value{custom},external) == std::vector<std::string>{"/data"});
        external_fields["additional_disks"] = Value{Value::Array{Value{Value::Object{
            {"selected_extra",Value{Value::Array{Value{Value::Object{
                {"mount_path",Value{std::string("/data")}}}}}}}}}}};
        check(validate_machine_task_policy(Value{custom},external) == TransferCompression::none);
        external_fields.erase("external_volumes"); // A persisted target keeps the selected disk, not discovery inventory.
        check(validate_machine_task_policy(Value{custom},external) == TransferCompression::none);
        check(validate_machine_task_policy(Value{policy},external) == TransferCompression::none);
        for (const auto& selected : {policy,system,custom}) {
            auto disabled = selected, enabled = selected;
            disabled["backup_external"] = n(0);
            enabled["backup_external"] = n(1);
            check(machine_task_extra_mounts(Value{disabled},external) ==
                  machine_task_extra_mounts(Value{enabled},external));
            enabled["backup_external"] = n(2);
            rejects([&] { machine_task_extra_mounts(Value{enabled},external); }, "flag");
        }
        // Rebuild the request for every job rather than replaying a configured
        // target. The second disk is visible only to entire-device selection.
        auto added_disk = external;
        auto& added_fields = std::get<Value::Object>(added_disk.data);
        added_fields["other_disk_count"] = n(2);
        added_fields["external_volumes"] = Value{Value::Array{Value{Value::Object{
            {"mount_path",Value{std::string("/new-disk")}},
            {"filesystem",Value{std::string("ext4")}},
            {"disk",Value{std::string("/dev/sdd")}}}}}};
        check(machine_task_extra_mounts(Value{custom},added_disk) ==
              machine_task_extra_mounts(Value{custom},external));
        check(machine_task_extra_mounts(Value{system},added_disk).empty());
        check(machine_task_extra_mounts(Value{policy},added_disk) ==
              std::vector<std::string>({"/data","/new-disk"}));
        auto removed = machine("/boot/firmware",{},2);
        check(machine_task_extra_mounts(Value{custom},removed).empty());
        check(validate_machine_task_policy(Value{custom},removed) == TransferCompression::none);
        check(machine_task_missing_mounts(Value{custom},removed) == std::vector<std::string>{"/data"});
        check(machine_task_extra_mounts(Value{policy},removed).empty());
        // Remounting/replacing an extra source uses its current path and task
        // membership; an old selected path never silently selects the new one.
        check(machine_task_extra_mounts(Value{custom},machine("/boot/firmware",{
            Value{Value::Object{{"mount_path",Value{std::string("/renamed")}}}}})).empty());
        auto lvm = machine("/boot/firmware", {Value{Value::Object{
            {"mount_path",Value{std::string{}}},
            {"pv_uuid",Value{std::string("pv-identity")}}}}});
        auto& lvm_fields = std::get<Value::Object>(lvm.data);
        lvm_fields["external_volumes"] = Value{Value::Array{Value{Value::Object{
            {"mount_path",Value{std::string("/data")}},
            {"disk",Value{std::string("/dev/sdc")}},
            {"lv_uuid",Value{std::string("lv-identity")}}}}}};
        check(machine_task_extra_mounts(Value{policy},lvm) == std::vector<std::string>{"/data"});
        lvm_fields["selected_extra"] = Value{Value::Array{Value{Value::Object{
            {"mount_path",Value{std::string("/data")}},
            {"lv_uuid",Value{std::string("lv-identity")}}}}}};
        check(validate_machine_task_policy(Value{policy},lvm) == TransferCompression::none);
        auto selected_lv = custom;
        selected_lv["backup_external"] = n(1);
        check(validate_machine_task_policy(Value{selected_lv},lvm) == TransferCompression::none);
        selected_lv["custom_volume"] = Value{Value::Array{
            Value{std::string("/")},Value{std::string("/data")},Value{std::string("/lab")}}};
        check(validate_machine_task_policy(Value{selected_lv},lvm) == TransferCompression::none);
        check(machine_task_missing_mounts(Value{selected_lv},lvm) == std::vector<std::string>{"/lab"});
        check(validate_task_policy(Value{missing}) == TransferCompression::none);
        missing.erase("compression");
        rejects([&] { validate_task_policy(Value{missing}); }, "compression");
        Value::Object scripts{{"pre_script_enabled",n(1)},{"post_script_enabled",n(0)},
            {"script_exec_mode",n(0)},{"pre_script_content",Value{std::string("SECRET")}},
            {"pre_script_path",Value{std::string("/private/script")}}};
        Value raw{Value::Object{{"pre_post_script_setting",Value{scripts}},
            {"pre_script_enabled",n(0)}}};
        auto decoded = task_script_policy(raw);
        check(decoded.size() == 3 && decoded.at("pre_script_enabled") == n(1));
        policy.merge(decoded);
        rejects([&] { validate_task_policy(Value{policy}); }, "pre_script_enabled");
        scripts.erase("post_script_enabled");
        raw = Value{Value::Object{{"pre_post_script_setting",Value{scripts}}}};
        rejects([&] { task_script_policy(raw); }, "post_script_enabled");
        raw = Value{Value::Object{{"pre_post_script_setting",Value{std::string("invalid")}}}};
        rejects([&] { task_script_policy(raw); }, "object");
        check(task_script_policy(Value{Value::Object{}}).empty());
        std::cout << "NAS task policy tests passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
