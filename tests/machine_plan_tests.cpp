#include "opensabba/machine.hpp"
#include "opensabba/task_policy.hpp"
#include <algorithm>
#include <iostream>
#include <source_location>

using namespace opensabba;
using pstream::Error;
namespace {
void check(bool condition, std::source_location at = std::source_location::current()) {
    if (!condition) throw Error("machine plan test failed at line "+std::to_string(at.line()));
}
template<class F> void reject(F action, std::string_view message) {
    try { action(); } catch (const Error& error) {
        if (std::string_view(error.what()).find(message) != std::string_view::npos) return;
        throw Error(std::string("unexpected rejection: ")+error.what());
    }
    throw Error("unsafe machine plan was accepted");
}
constexpr std::uint64_t mib = 1024*1024;
void raw_volume_identity() {
    using pstream::Value;
    const auto volume = [](std::string filesystem, std::string mount) {
        return Value{Value::Object{{"filesystem",Value{filesystem}},{"mount_path",Value{mount}}}};
    };
    auto fat = volume("vfat","/boot/extra");
    int probes = 0;
    record_machine_raw_volume_uuid(fat,[&] { ++probes; return std::string("1A2B-3C4D"); });
    check(probes == 1 && std::get<std::string>(
        std::get<Value::Object>(fat.data).at("filesystem_uuid").data) == "1A2B-3C4D");
    check(pstream::decode(pstream::encode(fat)) == fat);
    for (const auto* filesystem : {"btrfs","ntfs","swap","linux_raid_member","LVM2_member",""}) {
        auto unsupported = volume(filesystem,"/boot/raw");
        record_machine_raw_volume_uuid(unsupported,[]() -> std::string {
            throw Error("unsupported UUID probe was invoked");
        });
        check(!std::get<Value::Object>(unsupported.data).contains("filesystem_uuid"));
    }
    auto unmounted = volume("vfat","");
    record_machine_raw_volume_uuid(unmounted,[]() -> std::string {
        throw Error("unmounted raw UUID probe was invoked");
    });
    auto unnamed = volume("vfat","/boot/raw");
    record_machine_raw_volume_uuid(unnamed,[] { return std::string{}; });
    check(!std::get<Value::Object>(unnamed.data).contains("filesystem_uuid"));
    reject([&] { record_machine_raw_volume_uuid(unnamed,[]() -> std::string {
        throw Error("UUID probe I/O failure");
    }); }, "probe I/O failure");
    check(!std::get<Value::Object>(unnamed.data).contains("filesystem_uuid"));
}
void bare_metal_regions() {
    using pstream::Value;
    ImageLayout table{ImageLayout::Scheme::gpt,512,4096*mib,"disk",{}};
    Value::Array volumes;
    const auto add = [&](std::string filesystem, std::string mount, std::uint64_t length,
                         std::string guid = "", bool active = false) {
        const auto number = static_cast<std::uint32_t>(table.partitions.size()+1);
        const auto offset = table.partitions.empty() ? mib :
            table.partitions.back().offset+table.partitions.back().length;
        table.partitions.push_back({number,offset,length,0,0,active,guid,{}});
        volumes.push_back(Value{Value::Object{
            {"partition",Value{std::uint64_t{number}}},{"offset",Value{offset}},
            {"length",Value{length}},{"filesystem",Value{filesystem}},
            {"mount_path",Value{mount}}}});
    };
    add("ext4","",8*mib);
    add("btrfs","/archive",8*mib);
    add("vfat","",32*mib,"c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
    add("swap","",32*mib);
    add("LVM2_member","",8*mib,"c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
    add("","",1024*mib+512,"21686148-6449-6e6f-744e-656564454649");
    add("swap","",8*mib);
    add("","",1024*mib,"21686148-6449-6e6f-744e-656564454649");
    add("ntfs","",1024*mib+512,"c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
    add("linux_raid_member","",8*mib,"",true);
    Value disk{Value::Object{{"layout",layout_value(table)},
        {"volume_policy",Value{std::string("linux-bare-metal-v1")}},
        {"swap_page_size",Value{std::uint64_t{65536}}},
        {"selected_extra",Value{Value::Array{}}},{"excluded",Value{volumes}}}};
    const auto region = [&](std::size_t index) { return machine_partition_regions(disk,volumes[index]); };
    check(region(0).front().type == 5); // Unmounted supported fs is not a snapshot.
    check(region(1).front().type == 5); // Mounted unsupported fs has no ordinary fallback.
    check(region(2).front().type == 2 && region(2).front().system);
    const auto swap = region(3);
    check(swap.size() == 2 && swap[0].length == 65536 && swap[0].type == 3 &&
          swap[0].label == "swap_partition_header" && swap[1].type == 5 &&
          swap[1].offset == swap[0].offset+65536 && swap[1].length == 32*mib-65536);
    check(region(4).front().type == 5); // Boot-marked PV remains omitted.
    check(region(5).front().type == 5); // Strictly above 1 GiB with empty fs.
    check(region(6)[1].type == 3); // Small swap bodies fit the immutable capture.
    check(region(7).front().type == 2); // Exactly 1 GiB is retained.
    check(region(8).front().type == 2); // Nonempty boot fs has no 1 GiB limit.
    check(region(9).front().type == 5); // Boot-marked RAID is omitted.
    const auto unused = machine_unused_extents(disk);
    check(unused.size() == 6 && unused[2].offset == swap[1].offset &&
          unused[2].length == swap[1].length);
    const auto copies = machine_additional_static_regions(disk);
    for (const auto& range : unused)
        check(std::any_of(copies.begin(),copies.end(),[&](const auto& copy) {
            return copy.offset == range.offset && copy.length == range.length && !copy.read_source;
        }));
    check(std::any_of(copies.begin(),copies.end(),[&](const auto& copy) {
        return copy.offset == swap[0].offset && copy.length == 65536 && copy.read_source;
    }));
    check(machine_disk_need_upload(disk));
    auto omitted_disk = disk;
    auto& fields = std::get<Value::Object>(omitted_disk.data);
    fields["excluded"] = Value{Value::Array{volumes[0],volumes[1]}};
    check(!machine_disk_need_upload(omitted_disk));
    DeltaPlan delta{table.length,0,{{0,table.length,false}}};
    machine_force_raw_changes(delta,disk);
    for (const auto& copy : copies) if (copy.read_source)
        check(std::any_of(delta.ranges.begin(),delta.ranges.end(),[&](const auto& range) {
            return range.changed && range.offset <= copy.offset &&
                range.offset+range.length >= copy.offset+copy.length;
        }));
    check(delta.transfer_bytes < table.length);
    auto normal = disk;
    std::get<Value::Object>(normal.data).erase("volume_policy");
    check(machine_partition_regions(normal,volumes[2]).front().type == 5);
    const auto saved = delta;
    machine_force_raw_changes(delta,normal);
    check(delta_plan_value(delta) == delta_plan_value(saved));
    auto bad = disk;
    std::get<Value::Object>(bad.data)["swap_page_size"] = Value{std::uint64_t{4097}};
    reject([&] { machine_unused_extents(bad); }, "page size");
    std::get<Value::Object>(bad.data)["volume_policy"] = Value{std::string("invalid")};
    reject([&] { machine_unused_extents(bad); }, "volume policy");
}
void official_layout_gaps() {
    using pstream::Value;
    constexpr std::uint64_t gib = 1024*mib;
    ImageLayout table{ImageLayout::Scheme::mbr,512,0,"layout",{}};
    const auto first = gib+mib+4096;
    const auto second = first+mib+gib+4096;
    const auto third = second+mib+gib;
    table.partitions = {{1,first,mib,0,0x83},{2,second,mib,0,0x83},{3,third,mib,0,0x83}};
    table.length = third+mib+gib+mib+4096;
    Value::Array selected;
    for (const auto& part : table.partitions)
        selected.push_back(Value{Value::Object{
            {"offset",Value{part.offset}},{"length",Value{part.length}}}});
    Value disk{Value::Object{{"layout",layout_value(table)},
        {"layout_policy",Value{std::string("linux-layout-v1")}},
        {"selected_extra",Value{selected}},{"excluded",Value{Value::Array{}}}}};
    const auto regions = machine_layout_regions(disk);
    check(regions.size() == 6 && regions[0].offset == 0 && regions[0].length == mib &&
          regions[0].type == 3 && regions[1].length == gib+4096 && regions[1].type == 5 &&
          regions[2].length == gib+4096 && regions[2].type == 5 &&
          regions[3].length == gib && regions[3].type == 2 &&
          regions[4].length == gib+4096 && regions[4].type == 5 &&
          regions[5].length == mib && regions[5].type == 3);
    const auto unused = machine_unused_extents(disk);
    check(unused.size() == 3);
    const auto schedule = machine_additional_static_regions(disk);
    check(schedule.size() == regions.size());
    for (std::size_t index = 0; index < schedule.size(); ++index)
        check(schedule[index].offset == regions[index].offset &&
              schedule[index].length == regions[index].length &&
              schedule[index].read_source == (regions[index].type != 5));
    auto historical = disk;
    std::get<Value::Object>(historical.data).erase("layout_policy");
    check(machine_layout_regions(historical).empty() && machine_unused_extents(historical).empty());
    auto bad = disk;
    std::get<Value::Object>(bad.data)["layout_policy"] = Value{std::string("invalid")};
    reject([&] { machine_layout_regions(bad); }, "layout policy");
    // The final small interval preserves the backup GPT on every tail.
    table.scheme = ImageLayout::Scheme::gpt;
    const auto cursor = third+mib;
    for (const auto tail : {std::uint64_t{4096},mib,mib+4096,gib,gib+mib,gib+mib+4096}) {
        table.length = cursor+tail;
        auto gpt = disk;
        std::get<Value::Object>(gpt.data)["layout"] = layout_value(table);
        const auto split = machine_layout_regions(gpt);
        const auto& final = split.back();
        check(final.type == 3 && final.length == std::min(tail,mib) &&
              final.offset+final.length == table.length);
        const auto copies = machine_additional_static_regions(gpt);
        check(copies.back().read_source && copies.back().offset == final.offset &&
              copies.back().length == final.length);
        if (tail > mib) {
            const auto& body = split[split.size()-2];
            check(body.offset == cursor && body.length == tail-mib &&
                  body.type == (tail-mib > gib ? 5U : tail-mib < 16*mib ? 3U : 2U));
        } else check(final.offset == cursor);
        const auto unused = machine_unused_extents(gpt);
        check(std::none_of(unused.begin(),unused.end(),[&](const auto& range) {
            return range.offset+range.length > final.offset;
        }));
    }
}
const std::string mountinfo =
    "30 1 179:2 / / rw,relatime shared:1 - ext4 /dev/mmcblk0p2 rw\n"
    "31 30 179:1 / /boot/firmware rw,relatime - vfat /dev/mmcblk0p1 rw\n"
    "32 30 8:1 / /media/COW\\040drive rw - ext4 /dev/sda1 rw\n"
    "33 30 0:1 / /proc rw - proc proc rw\n";
ImageLayout layout() {
    return {ImageLayout::Scheme::mbr, 512, 100*mib, "1234", {
        {1, mib, 32*mib, 0, 0x0c, true, {}, {}},
        {2, 33*mib, 66*mib, 0, 0x83, false, {}, {}}}};
}
std::vector<MachinePartition> partitions() {
    return {{1, {179,1}, "/dev/mmcblk0p1", mib, 32*mib},
            {2, {179,2}, "/dev/mmcblk0p2", 33*mib, 66*mib}};
}
}
int main() {
    try {
        raw_volume_identity();
        bare_metal_regions();
        official_layout_gaps();
        const auto mounts = parse_machine_mounts(mountinfo);
        check(mounts.size() == 4 && mounts[2].path == "/media/COW drive");
        check(mounts[1].options == "rw,relatime" && mounts[1].super_options == "rw");
        const auto inventory = parse_machine_mounts(
            "30 1 179:2 / / rw,relatime shared:1 master:2 - ext4 /dev/mmcblk0p2 rw\n"
            "31 30 179:1 / /boot/firmware rw shared:1 - vfat /dev/mmcblk0p1 rw\n"
            "32 30 8:1 / /lab rw shared:3 - ext4 /dev/sda1 rw\n"
            "33 30 8:2 / /data rw shared:4 - ext4 /dev/sdb1 rw\n"
            "34 30 8:2 /subdir /archive rw - ext4 /dev/sdb1 rw\n"
            "35 30 0:5 / /dev rw - devtmpfs devtmpfs rw\n"
            "36 30 0:4 net:[4026532726] /run/docker/netns/5b295500b563 rw shared:6"
            " - nsfs nsfs rw\n"
            "40 30 0:40 / /run/user/1000 rw shared:5 - tmpfs tmpfs rw\n");
        check(inventory[4].parent_id == 30 && inventory[4].source == "/dev/sdb1");
        check(inventory[6].root == "net:[4026532726]" &&
              inventory[6].path == "/run/docker/netns/5b295500b563");
        check(inventory[0].optional_fields ==
              std::vector<std::string>({"master:2","shared:1"}));
        const std::vector<MachineDevice> block_devices{{179,2},{179,1},{8,1},{8,2}};
        auto efi_inventory = inventory;
        efi_inventory[1].path = "/boot/efi";
        check(machine_relevant_mounts_equal(efi_inventory,efi_inventory,block_devices,
            "/boot/efi","/lab/captures"));
        auto moved_efi = efi_inventory;
        moved_efi[1].path = "/boot/firmware";
        check(!machine_relevant_mounts_equal(efi_inventory,moved_efi,block_devices,
            "/boot/efi","/lab/captures"));
        const auto consistent = [&](const auto& later) {
            return machine_relevant_mounts_equal(inventory,later,block_devices,
                "/boot/firmware","/lab/captures");
        };
        auto reordered = inventory;
        std::reverse(reordered.begin(),reordered.end());
        check(consistent(reordered));
        reordered.erase(reordered.begin()); // Unrelated user tmpfs disappeared.
        check(consistent(reordered));
        reordered.push_back({41,{0,41},"/","/run/user/2000","ramfs","rw"});
        check(consistent(reordered));
        reordered.push_back({42,{0,42},"/","/dev/shm","tmpfs","rw"});
        check(consistent(reordered)); // A pseudo mount below devtmpfs is unrelated.
        auto container_churn = inventory;
        container_churn.erase(container_churn.begin()+6); // Container netns removed.
        container_churn.push_back({43,{0,43},"/","/var/lib/docker/overlay2/a1/merged","overlay","rw"});
        container_churn.push_back({44,{0,4},"net:[4026532999]","/run/docker/netns/7c1e","nsfs","rw"});
        container_churn.push_back({45,{0,45},"/","/mnt/remote","nfs4","rw"});
        check(consistent(container_churn)); // Unrelated non-block mounts may come and go.
        container_churn = inventory;
        container_churn[5].options = "ro";
        check(consistent(container_churn)); // devtmpfs is not capture topology.
        auto reordered_tags = inventory;
        reordered_tags[0] = parse_machine_mounts(
            "30 1 179:2 / / rw,relatime master:2 shared:1 - ext4 /dev/mmcblk0p2 rw\n").front();
        check(consistent(reordered_tags)); // Optional-field text order is immaterial.
        reordered_tags = inventory;
        reordered_tags.back().optional_fields = {"shared:99"};
        check(consistent(reordered_tags)); // Unrelated tmpfs propagation may change.
        for (std::size_t index = 0; index < 5; ++index) {
            auto changed = inventory;
            changed[index].options = "ro";
            check(!consistent(changed)); // Root, boot, COW, external and bind options.
            changed = inventory;
            changed[index].optional_fields.push_back("propagate_from:99");
            check(!consistent(changed)); // Relevant propagation is part of mount identity.
            if (index < 4) {
                changed = inventory;
                changed[index].optional_fields.back() = "shared:99";
                check(!consistent(changed)); // Existing propagation group changed.
            }
            changed = inventory;
            changed.erase(changed.begin()+static_cast<std::ptrdiff_t>(index));
            check(!consistent(changed));
        }
        auto changed_mounts = inventory;
        changed_mounts[4].root = "/other-subdir";
        check(!consistent(changed_mounts)); // A bind alias changed its source subtree.
        changed_mounts = inventory;
        changed_mounts[2].parent_id = 99;
        check(!consistent(changed_mounts)); // Mount parentage is topology.
        changed_mounts = inventory;
        changed_mounts[3].source = "/dev/foreign";
        check(!consistent(changed_mounts)); // Block-device alias substitution.
        changed_mounts = inventory;
        changed_mounts.push_back({51,{8,3},"/","/new-disk","ext4","rw"});
        auto observed_devices = block_devices; // Inspection records the later inventory's devices.
        observed_devices.push_back({8,3});
        check(!machine_relevant_mounts_equal(inventory,changed_mounts,observed_devices,
            "/boot/firmware","/lab/captures")); // New block-backed volume topology.
        for (const auto* type : {"tmpfs","overlay","nfs4","fuse.sshfs"})
            for (const auto* path : {"/","/boot","/boot/efi","/boot/firmware","/lab","/lab/captures",
                                     "/data","/data/cache"}) {
                changed_mounts = inventory;
                changed_mounts.push_back({50,{0,50},"/",path,type,"rw"});
                check(!consistent(changed_mounts)); // Relevant pseudo mount or overlay.
            }
        const auto plan = plan_machine_capture(layout(), partitions(), mounts);
        check(plan.root.device == MachineDevice{179,2} && plan.boot.device == MachineDevice{179,1});
        check(plan.root_mount.path == "/" && plan.boot_mount.path == "/boot/firmware");
        for (const auto* type : {"ext2","ext3","xfs"}) {
            auto other = mounts;
            other[0].filesystem = type;
            check(plan_machine_capture(layout(),partitions(),other).root_mount.filesystem == type);
        }
        auto reversed = partitions();
        std::swap(reversed[0], reversed[1]);
        check(plan_machine_capture(layout(), reversed, mounts).boot.number == 1);
        auto old_boot = mounts; old_boot[1].path = "/boot";
        check(plan_machine_capture(layout(), partitions(), old_boot).boot_mount.path == "/boot");
        auto gpt = layout(); gpt.scheme = ImageLayout::Scheme::gpt;
        gpt.partitions[0].type_guid = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
        gpt.partitions[1].type_guid = "0fc63daf-8483-4772-8e79-3d69d8477de4";
        check(plan_machine_capture(gpt, partitions(), mounts).root.number == 2);
        auto efi_mounts = mounts; efi_mounts[1].path = "/boot/efi";
        check(plan_machine_capture(gpt, partitions(), efi_mounts).boot_mount.path == "/boot/efi");
        auto efi_hidden = efi_mounts;
        efi_hidden.push_back({44,{0,44},"/","/boot","tmpfs","rw"});
        reject([&] { plan_machine_capture(gpt,partitions(),efi_hidden); }, "additional boot mounts");
        efi_hidden = efi_mounts;
        efi_hidden.push_back({44,{179,1},"/","/boot/firmware","vfat","rw"});
        reject([&] { plan_machine_capture(gpt,partitions(),efi_hidden); }, "multiple mounts");
        efi_hidden = efi_mounts;
        efi_hidden[1].root = "/subdir";
        reject([&] { plan_machine_capture(gpt,partitions(),efi_hidden); }, "directly mounted");
        efi_hidden = efi_mounts;
        efi_hidden[1].filesystem = "ext4";
        reject([&] { plan_machine_capture(gpt,partitions(),efi_hidden); }, "vfat");
        efi_hidden = efi_mounts;
        efi_hidden[1].device = {179,2};
        reject([&] { plan_machine_capture(gpt,partitions(),efi_hidden); }, "directly mounted");
        efi_hidden = efi_mounts;
        efi_hidden.push_back({44,{179,3},"/","/boot","ext4","rw"});
        reject([&] { plan_machine_capture(gpt,partitions(),efi_hidden); }, "additional boot mounts");
        auto wrong_efi_type = gpt;
        wrong_efi_type.partitions[0].type_guid = "0fc63daf-8483-4772-8e79-3d69d8477de4";
        reject([&] { plan_machine_capture(wrong_efi_type,partitions(),efi_mounts); },
               "partition types");
        auto lvm_layout = layout();
        lvm_layout.partitions[1].mbr_type = 0x8e;
        auto lvm_mounts = mounts;
        lvm_mounts[0].device = {253,0};
        check(plan_lvm_machine_boot(lvm_layout,partitions(),lvm_mounts,2,{253,0})
            .partition.number == 1);
        auto efi_lvm = efi_mounts; efi_lvm[0].device = {253,0};
        auto gpt_lvm = gpt;
        gpt_lvm.partitions[1].type_guid = "e6d6d379-f507-44c2-a23c-238f2a3df928";
        check(plan_lvm_machine_boot(gpt_lvm,partitions(),efi_lvm,2,{253,0})
            .mount.path == "/boot/efi");
        efi_lvm.push_back({44,{0,44},"/","/boot/firmware","tmpfs","rw"});
        reject([&] { plan_lvm_machine_boot(gpt_lvm,partitions(),efi_lvm,2,{253,0}); },
               "additional boot mounts");
        auto wrong_lvm_parts = partitions();
        wrong_lvm_parts[1].offset += 512;
        reject([&] { plan_lvm_machine_boot(lvm_layout,wrong_lvm_parts,lvm_mounts,2,{253,0}); },
            "geometry");
        auto wrong_lvm_layout = lvm_layout;
        wrong_lvm_layout.partitions[0].mbr_type = 0x83;
        reject([&] { plan_lvm_machine_boot(wrong_lvm_layout,partitions(),lvm_mounts,2,{253,0}); },
            "partition types");
        wrong_lvm_layout = lvm_layout;
        wrong_lvm_layout.partitions[1].mbr_type = 0x83;
        // PV identity comes from LVM metadata, independently of table type.
        check(plan_lvm_machine_boot(wrong_lvm_layout,partitions(),lvm_mounts,2,{253,0})
            .partition.number == 1);
        auto generic_gpt_pv = gpt_lvm;
        generic_gpt_pv.partitions[1].type_guid = "0fc63daf-8483-4772-8e79-3d69d8477de4";
        check(plan_lvm_machine_boot(generic_gpt_pv,partitions(),lvm_mounts,2,{253,0})
            .partition.number == 1);
        auto hidden_lvm_boot = lvm_mounts;
        hidden_lvm_boot.push_back({44,{0,44},"/","/boot","tmpfs","rw"});
        reject([&] { plan_lvm_machine_boot(lvm_layout,partitions(),hidden_lvm_boot,2,{253,0}); },
            "additional boot mounts");
        auto repeated_lvm_boot = lvm_mounts;
        repeated_lvm_boot.push_back({44,{179,1},"/","/boot-copy","vfat","rw"});
        reject([&] { plan_lvm_machine_boot(lvm_layout,partitions(),repeated_lvm_boot,2,{253,0}); },
            "multiple mounts");
        reject([&] { plan_lvm_machine_boot(lvm_layout,partitions(),lvm_mounts,2,{253,1}); },
            "LVM root");
        // Kernel stale after repartition, unaccounted partitions, wrong source disk.
        auto parts = partitions(); parts[1].offset += 512;
        reject([&] { plan_machine_capture(layout(), parts, mounts); }, "geometry");
        parts = partitions(); parts.push_back({3, {179,3}, "/dev/mmcblk0p3", 99*mib, mib});
        reject([&] { plan_machine_capture(layout(), parts, mounts); }, "inventory");
        auto extra_layout = layout();
        extra_layout.partitions.push_back({3,99*mib,mib,0,0x82});
        check(plan_machine_capture(extra_layout,parts,mounts).excluded.size() == 1);
        pstream::Value schedule_plan{pstream::Value::Object{
            {"layout",pstream::Value{pstream::Value::Object{{"length",pstream::Value{100*mib}}}}},
            {"root",pstream::Value{pstream::Value::Object{
                {"offset",pstream::Value{33*mib}},{"length",pstream::Value{66*mib}}}}},
            {"boot",pstream::Value{pstream::Value::Object{
                {"offset",pstream::Value{mib}},{"length",pstream::Value{32*mib}}}}},
            {"selected_extra",pstream::Value{pstream::Value::Array{}}},
            {"excluded",pstream::Value{pstream::Value::Array{pstream::Value{
                pstream::Value::Object{{"offset",pstream::Value{99*mib}},
                                        {"length",pstream::Value{mib}}}}}}}}};
        const auto schedule = machine_static_regions(schedule_plan);
        check(schedule.size() == 2 && schedule[0].offset == 0 &&
              schedule[0].length == 33*mib && schedule[0].read_source &&
              schedule[1].offset == 99*mib && schedule[1].length == mib &&
              !schedule[1].read_source);
        auto selected_plan = schedule_plan;
        auto& selected_fields = std::get<pstream::Value::Object>(selected_plan.data);
        selected_fields["layout"] = layout_value(extra_layout);
        auto& selectable = std::get<pstream::Value::Array>(selected_fields.at("excluded").data);
        std::get<pstream::Value::Object>(selectable[0].data)["partition"] =
            pstream::Value{std::uint64_t{3}};
        std::get<pstream::Value::Object>(selectable[0].data)["mount_path"] =
            pstream::Value{std::string("/data")};
        std::get<pstream::Value::Object>(selectable[0].data)["filesystem"] =
            pstream::Value{std::string("ext4")};
        std::get<pstream::Value::Object>(selectable[0].data)["mount_id"] =
            pstream::Value{std::uint64_t{44}};
        std::get<pstream::Value::Object>(selectable[0].data)["filesystem_uuid"] =
            pstream::Value{std::string("11111111-2222-3333-4444-555555555555")};
        reject([&] { select_machine_extra_volumes(selected_plan,{"/data"}); }, "non-Linux disk type");
        auto linux_extra = extra_layout;
        linux_extra.partitions.back().mbr_type = 0x83;
        selected_fields["layout"] = layout_value(linux_extra);
        {
            // Task membership changes the real snapshot/static-copy schedule.
            // An unrelated attached disk cannot change a custom-volume job;
            // disappearance of /data drops that origin and omits its old range.
            using pstream::Value;
            auto inventory = selected_plan;
            auto& inventory_fields = std::get<Value::Object>(inventory.data);
            std::get<Value::Object>(inventory_fields.at("root").data)["mount_path"] = Value{std::string("/")};
            std::get<Value::Object>(inventory_fields.at("boot").data)["mount_path"] = Value{std::string("/boot/firmware")};
            const Value task{Value::Object{{"compression",Value{std::uint64_t{0}}},
                {"source_type",Value{std::uint64_t{3}}},{"custom_volume",Value{Value::Array{
                    Value{std::string("/")},Value{std::string("/data")}}}}}};
            const auto capture = [&](const Value& discovered) {
                return select_machine_extra_volumes(discovered,machine_task_extra_mounts(task,discovered));
            };
            const auto first = capture(inventory);
            inventory_fields["other_disk_count"] = Value{std::uint64_t{2}};
            const auto with_scratch = capture(inventory);
            check(std::get<Value::Object>(first.data).at("selected_extra") ==
                  std::get<Value::Object>(with_scratch.data).at("selected_extra"));
            const auto before = machine_static_regions(first), after = machine_static_regions(with_scratch);
            check(before.size() == after.size());
            for (std::size_t index = 0; index < before.size(); ++index)
                check(before[index].offset == after[index].offset && before[index].length == after[index].length &&
                      before[index].read_source == after[index].read_source);
            auto& absent = std::get<Value::Object>(std::get<Value::Array>(inventory_fields.at("excluded").data).front().data);
            absent["mount_path"] = Value{std::string{}};
            const auto without_data = capture(inventory);
            check(std::get<Value::Array>(std::get<Value::Object>(without_data.data).at("selected_extra").data).empty());
            const auto omitted = machine_static_regions(without_data);
            check(std::any_of(omitted.begin(),omitted.end(),[](const auto& range) {
                return range.offset == 99*mib && range.length == mib && !range.read_source;
            }));
            check(machine_task_missing_mounts(task,without_data) == std::vector<std::string>{"/data"});
        }
        selected_plan = select_machine_extra_volumes(std::move(selected_plan),{"/data"});
        check(std::get<pstream::Value::Array>(
            std::get<pstream::Value::Object>(selected_plan.data).at("selected_extra").data).size() == 1);
        for (const auto* type : {"ext2","ext3","xfs"}) {
            auto alternate = selected_plan;
            auto& fields = std::get<pstream::Value::Object>(alternate.data);
            auto& chosen = std::get<pstream::Value::Array>(fields.at("selected_extra").data);
            std::get<pstream::Value::Object>(chosen[0].data)["filesystem"] =
                pstream::Value{std::string(type)};
            auto excluded_copy = chosen;
            fields["selected_extra"] = pstream::Value{pstream::Value::Array{}};
            fields["excluded"] = pstream::Value{std::move(excluded_copy)};
            check(std::get<pstream::Value::Array>(
                std::get<pstream::Value::Object>(
                    select_machine_extra_volumes(std::move(alternate),{"/data"}).data
                ).at("selected_extra").data).size() == 1);
        }
        const auto selected_regions = machine_static_regions(selected_plan);
        check(selected_regions.size() == 2 && selected_regions[0].read_source &&
              selected_regions[0].length == mib && selected_regions[1].read_source &&
              selected_regions[1].length == 32*mib);
        auto lvm_plan = schedule_plan;
        auto& lvm_fields = std::get<pstream::Value::Object>(lvm_plan.data);
        lvm_fields["root"] = pstream::Value{pstream::Value::Object{
            {"lv_uuid",pstream::Value{std::string("LV")}},
            {"offset",pstream::Value{std::uint64_t{0}}},
            {"length",pstream::Value{32*mib}}}};
        lvm_fields["excluded"] = pstream::Value{pstream::Value::Array{pstream::Value{
            pstream::Value::Object{
                {"offset",pstream::Value{33*mib}},
                {"length",pstream::Value{66*mib}},
                {"pv_uuid",pstream::Value{std::string("pv")}},
                {"pv_wire_policy",pstream::Value{std::string("whole-partition-zero")}},
                {"pv_metadata_length",pstream::Value{mib}}}}}};
        const auto lvm_regions = machine_static_regions(lvm_plan);
        check(lvm_regions.size() == 3 &&
              lvm_regions[0].offset == 0 && lvm_regions[0].length == 33*mib &&
              lvm_regions[0].read_source &&
              lvm_regions[1].offset == 33*mib && lvm_regions[1].length == 66*mib &&
              !lvm_regions[1].read_source &&
              lvm_regions[2].offset == 99*mib && lvm_regions[2].length == mib &&
              lvm_regions[2].read_source);
        auto old_lvm_plan = lvm_plan;
        auto& old_pv = std::get<pstream::Value::Object>(
            std::get<pstream::Value::Array>(
                std::get<pstream::Value::Object>(old_lvm_plan.data).at("excluded").data
            ).front().data);
        old_pv.erase("pv_wire_policy");
        reject([&] { machine_static_regions(old_lvm_plan); }, "wire policy");
        auto direct_root_lvm = schedule_plan;
        auto& direct_fields = std::get<pstream::Value::Object>(direct_root_lvm.data);
        direct_fields["excluded"] = pstream::Value{pstream::Value::Array{pstream::Value{
            pstream::Value::Object{
                {"offset",pstream::Value{std::uint64_t{0}}},
                {"length",pstream::Value{32*mib}},
                {"pv_uuid",pstream::Value{std::string("pv")}},
                {"pv_wire_policy",pstream::Value{std::string("whole-partition-zero")}},
                {"pv_metadata_length",pstream::Value{mib}},
                {"pv_tail_length",pstream::Value{mib}}}}}};
        direct_fields["selected_extra"] = pstream::Value{pstream::Value::Array{
            pstream::Value{pstream::Value::Object{
                {"lv_uuid",pstream::Value{std::string("lv")}},
                {"mount_path",pstream::Value{std::string("/data")}}}}}};
        const auto direct_regions = machine_static_regions(direct_root_lvm);
        check(direct_regions.size() == 3 &&
              direct_regions[0].offset == 0 && direct_regions[0].length == 32*mib &&
              !direct_regions[0].read_source &&
              direct_regions[1].offset == 32*mib && direct_regions[1].length == mib &&
              direct_regions[1].read_source &&
              direct_regions[2].offset == 99*mib && direct_regions[2].length == mib &&
              direct_regions[2].read_source);
        for (auto pe_start : {mib,2*mib}) {
            auto geometry = direct_root_lvm;
            auto& pv = std::get<pstream::Value::Object>(
                std::get<pstream::Value::Array>(
                    std::get<pstream::Value::Object>(geometry.data).at("excluded").data
                ).front().data);
            pv["pv_metadata_length"] = pstream::Value{pe_start};
            const auto regions = machine_static_regions(geometry);
            check(regions.size() == direct_regions.size());
            for (std::size_t index = 0; index < regions.size(); ++index)
                check(regions[index].offset == direct_regions[index].offset &&
                      regions[index].length == direct_regions[index].length &&
                      regions[index].read_source == direct_regions[index].read_source);
        }
        auto& extras = std::get<pstream::Value::Array>(
            std::get<pstream::Value::Object>(schedule_plan.data).at("excluded").data);
        std::get<pstream::Value::Object>(extras[0].data)["offset"] = pstream::Value{98*mib};
        reject([&] { machine_static_regions(schedule_plan); }, "geometry");
        parts = partitions(); parts[1].device = {8,2};
        reject([&] { plan_machine_capture(layout(), parts, mounts); }, "does not contain");
        auto modified = mounts; modified[0].filesystem = "overlay";
        reject([&] { plan_machine_capture(layout(), partitions(), modified); }, "directly mounted supported");
        modified = mounts; modified[0].root = "/subvolume";
        reject([&] { plan_machine_capture(layout(), partitions(), modified); }, "directly mounted supported");
        modified = mounts; modified[1].filesystem = "ext4";
        reject([&] { plan_machine_capture(layout(), partitions(), modified); }, "vfat");
        modified = mounts; modified[1].path = "/hidden-boot";
        reject([&] { plan_machine_capture(layout(), partitions(), modified); }, "vfat");
        modified = mounts; modified.push_back({44, {0,44}, "/", "/", "tmpfs", "rw"});
        reject([&] { plan_machine_capture(layout(), partitions(), modified); }, "stacked");
        modified = mounts; modified.push_back({44, {179,1}, "/", "/boot-copy", "vfat", "rw"});
        reject([&] { plan_machine_capture(layout(), partitions(), modified); }, "multiple mounts");
        modified = mounts; modified.push_back({44, {0,44}, "/", "/boot", "tmpfs", "rw"});
        reject([&] { plan_machine_capture(layout(), partitions(), modified); }, "additional boot");
        auto unsupported = layout(); unsupported.partitions[0].mbr_type = 0x07;
        reject([&] { plan_machine_capture(unsupported, partitions(), mounts); }, "partition types");
        reject([&] { parse_machine_mounts("30 1 179:2 / / rw - ext4\n"); }, "incomplete");
        reject([&] { parse_machine_mounts(mountinfo+mountinfo); }, "duplicate");
        reject([&] { parse_machine_mounts("30 1 179:2 / /bad\\000path rw - ext4 /dev/a rw\n"); }, "escape");
        reject([&] { parse_machine_mounts("30 1 bad / / rw - ext4 /dev/a rw\n"); }, "major:minor");
        reject([&] { parse_machine_mounts("30 1 179:2 / relative rw - ext4 /dev/a rw\n"); },
               "absolute mount point");
        // COW independence includes stacked-device backing and shared physical leaves.
        const MachineDevice disk{179,0}, cow{8,1}, other{8,0}, dm{253,0}, loop{7,0};
        std::vector<MachineStorage> storage{{cow, {other}, false}, {other, {}, true}};
        validate_machine_cow_storage(disk, cow, storage);
        reject([&] { validate_machine_cow_storage(other, cow, storage); }, "source disk");
        storage.push_back({dm, {cow}, false});
        validate_machine_cow_storage(disk, dm, storage);
        storage[2].backing.push_back(disk);
        reject([&] { validate_machine_cow_storage(disk, dm, storage); }, "source disk");
        storage.push_back({loop, {}, false});
        reject([&] { validate_machine_cow_storage(disk, loop, storage); }, "cannot be proved");
        storage[2].backing = {dm};
        reject([&] { validate_machine_cow_storage(disk, dm, storage); }, "cyclic");
        storage[2].backing = {cow, other};
        validate_machine_cow_storage(disk, dm, storage);
        // Layout callback must supply exact extents, even without an ImageSource.
        reject([&] { inspect_disk_layout(4096, 512, [](auto, auto) { return pstream::Bytes(1); }); }, "short");
        std::cout << "Machine topology, mount parsing and COW storage independence passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
