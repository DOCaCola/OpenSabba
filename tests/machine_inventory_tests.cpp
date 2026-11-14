#include "opensabba/machine.hpp"
#include "opensabba/task_policy.hpp"
#include <algorithm>
#include <iostream>
using namespace opensabba;
using pstream::Value;
using pstream::Error;
namespace {
Value n(std::uint64_t value) { return Value{value}; }
Value s(const char* value) { return Value{std::string(value)}; }
const Value& field(const Value& v,const char* key) { return std::get<Value::Object>(v.data).at(key); }
const Value::Array& array(const Value& v,const char* key) { return std::get<Value::Array>(field(v,key).data); }
void check(bool value) { if (!value) throw Error("inventory selection mismatch"); }
Value volume(unsigned number,const char* device,const char* mount,const char* filesystem) {
    return Value{Value::Object{{"partition",n(number)},{"offset",n(number*1024*1024)},{"length",n(1024*1024)},
        {"device",s(device)},{"mount_path",s(mount)},{"filesystem",s(filesystem)},
        {"filesystem_uuid",s(device)},{"mount_id",n(number)}}};
}
Value disk(const char* device,Value::Array volumes) {
    Value::Array parts;
    for (const auto& v : volumes) parts.push_back(Value{Value::Object{
        {"number",field(v,"partition")},{"offset",field(v,"offset")},{"length",field(v,"length")},
        {"type_guid",s("0fc63daf-8483-4772-8e79-3d69d8477de4")},{"bootable",n(0)}}});
    return Value{Value::Object{{"disk",s(device)},{"selected_extra",Value{Value::Array{}}},
        {"excluded",Value{std::move(volumes)}},{"layout",Value{Value::Object{
            {"length",n(16*1024*1024)},{"partitions",Value{std::move(parts)}}}}}}};
}
Value inventory() {
    return Value{Value::Object{{"disks",Value{Value::Array{
        disk("/dev/sda",{volume(1,"/dev/sda1","/boot/efi","vfat"),volume(2,"/dev/sda2","/","ext4")}),
        disk("/dev/nvme0n1",{volume(1,"/dev/nvme0n1p1","/data","xfs"),volume(2,"/dev/nvme0n1p2","/home","ext4")})}}},
        {"logical_volumes",Value{Value::Array{}}},{"discovery_errors",Value{Value::Array{}}},
        {"boot_id",s("boot")},{"cow_directory",s("/state")},{"cow_device",s("8:9")},
        {"cow_filesystem_uuid",s("state")},{"other_disk_count",n(2)},{"swap_page_size",n(4096)}}};
}
Value task(unsigned type,Value::Array paths = {}) {
    return Value{Value::Object{{"source_type",n(type)},{"custom_volume",Value{std::move(paths)}}}};
}
}
int main() {
    const auto all = select_machine_inventory(inventory(),task(1));
    check(field(field(all,"root"),"mount_path") == s("/"));
    check(field(all,"image_name") == s("sda.img"));
    check(array(all,"additional_disks").size() == 1);
    check(field(array(all,"additional_disks")[0],"image_name") == s("nvme0n1.img"));
    check(array(array(all,"additional_disks")[0],"selected_extra").size() == 2);
    check(machine_partition_regions(all,array(all,"excluded")[0])[0].type == 2);
    auto reversed = inventory();
    std::reverse(std::get<Value::Array>(std::get<Value::Object>(reversed.data).at("disks").data).begin(),
        std::get<Value::Array>(std::get<Value::Object>(reversed.data).at("disks").data).end());
    const auto data_first = select_machine_inventory(reversed,task(1));
    check(field(field(data_first,"root"),"mount_path") == s("/data"));
    check(field(array(data_first,"additional_disks")[0],"disk") == s("/dev/sda"));
    const auto system = select_machine_inventory(inventory(),task(2));
    check(array(system,"additional_disks").empty());
    check(machine_partition_regions(system,array(system,"excluded")[0])[0].type == 2);
    check(!std::get<Value::Object>(system.data).contains("boot"));
    const auto custom = task(3,{s("/data"),s("/gone")});
    const auto nonroot = select_machine_inventory(inventory(),custom);
    check(field(nonroot,"disk") == s("/dev/nvme0n1"));
    check(field(field(nonroot,"root"),"mount_path") == s("/data"));
    check(array(nonroot,"additional_disks").empty());
    check(machine_task_missing_mounts(custom,nonroot) == std::vector<std::string>{"/gone"});
    check(machine_partition_regions(nonroot,array(nonroot,"excluded")[0])[0].type == 5);
    const auto root = select_machine_inventory(inventory(),task(3,{s("/")}));
    check(machine_partition_regions(root,array(root,"excluded")[0])[0].type == 2);
    auto changed = inventory();
    auto& disks = std::get<Value::Array>(std::get<Value::Object>(changed.data).at("disks").data);
    disks.erase(disks.begin()); // Current root disk disappeared; custom /data still works.
    check(field(select_machine_inventory(changed,task(3,{s("/data")})),"disk") == s("/dev/nvme0n1"));
    bool no_origin = false;
    try { (void)select_machine_inventory(inventory(),task(3,{s("/boot/efi")})); }
    catch (const Error&) { no_origin = true; }
    check(no_origin);
    auto lvm_inventory = inventory();
    auto& inv = std::get<Value::Object>(lvm_inventory.data);
    auto pv = volume(1,"/dev/sdc1","","LVM2_member");
    std::get<Value::Object>(pv.data)["vg_uuid"] = s("vg");
    std::get<Value::Object>(pv.data)["pv_uuid"] = s("pv");
    std::get<Value::Array>(inv.at("disks").data).push_back(disk("/dev/sdc",{pv}));
    inv["logical_volumes"] = Value{Value::Array{Value{Value::Object{
        {"lv_uuid",s("lv")},{"vg_uuid",s("vg")},{"mount_path",s("/archive")},
        {"filesystem",s("ext4")},{"image_name",s("vg=archive.img")},{"device",s("/dev/dm-0")}}}}};
    auto other_pv = pv;
    std::get<Value::Object>(other_pv.data)["pv_uuid"] = s("second-pv");
    std::get<Value::Object>(other_pv.data)["device"] = s("/dev/sdd1");
    std::get<Value::Array>(inv.at("disks").data).push_back(disk("/dev/sdd",{other_pv}));
    Value groups{Value::Array{Value{Value::Object{{"uuid",s("vg")},
        {"physical_volumes",Value{Value::Array{pv,other_pv}}}}},
        Value{Value::Object{{"uuid",s("unrelated-vg")},
        {"physical_volumes",Value{Value::Array{volume(1,"/dev/sde1","","LVM2_member")}}}}}}};
    inv["lvm"] = Value{Value::Object{{"volume_groups",groups}}};
    const auto logical = select_machine_inventory(lvm_inventory,task(3,{s("/archive")}));
    check(!std::get<Value::Object>(logical.data).contains("layout"));
    check(machine_physical_image_count(logical) == 0 && machine_image_plans(logical).size() == 1);
    check(array(logical,"unselected_disks").size() == 4);
    check(field(field(logical,"root"),"image_name") == s("vg=archive.img"));
    check(field(field(logical,"lvm"),"volume_groups") == groups);
    const auto mixed = select_machine_inventory(lvm_inventory,task(3,{s("/"),s("/archive")}));
    check(field(mixed,"disk") == s("/dev/sda") && array(mixed,"additional_disks").empty());
    check(machine_physical_image_count(mixed) == 1 && machine_image_plans(mixed).size() == 2);
    check(field(field(mixed,"lvm"),"volume_groups") == groups);
    std::cout << "NAS inventory selection: system, entire, nonroot custom, removal, missing and LV passed\n";
}
