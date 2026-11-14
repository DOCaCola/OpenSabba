#include "opensabba/cow_index.hpp"
#include "opensabba/filesystem.hpp"
#include <algorithm>
#include "opensabba/machine_capture.hpp"
#include "opensabba/machine_snapshot.hpp"
#include "opensabba/tracking_record.hpp"
#include "opensabba/machine.hpp"
#include "opensabba/client.hpp"
#include "opensabba/machine_tracking.hpp"
#include <iostream>
#include <source_location>
#ifdef __linux__
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace opensabba;
using namespace opensabba::pstream;
namespace {
Value n(std::uint64_t value) { return Value{value}; }
void set(Value& v, const char* key, Value value) { std::get<Value::Object>(v.data)[key] = std::move(value); }
void check(bool value, std::source_location at = std::source_location::current()) {
    if (!value) throw Error("machine artifact test failed at "+std::string(at.file_name())+":"+std::to_string(at.line()));
}
template<class F> void rejects(F operation) {
    bool rejected = false;
    try { operation(); } catch (const Error&) { rejected = true; }
    check(rejected);
}
CaptureJournal ready() {
    return {"00112233445566778899aabbccddeeff", "11223344-5566-7788-99aa-bbccddeeff00",
        CapturePhase::ready,
        Value{Value::Object{{"layout",Value{Value::Object{{"length",n(512)},{"sector_size",n(512)}}}}}},
        Value{Value::Object{{"snapshot_released",n(1)},{"snapshot_time",n(123)}}},
        Value{Value::Object{{"released",n(1)}}},
        Value{Value::Object{{"length",n(512)},{"sector_size",n(512)},
            {"sha256",Value{std::string{}}}}}, {}};
}
std::vector<std::string> fixture_image_names(const CaptureJournal& journal) {
    const auto& plan = std::get<Value::Object>(journal.plan.data);
    std::size_t physical = 1;
    if (plan.contains("additional_disks")) physical += std::get<Value::Array>(plan.at("additional_disks").data).size();
    std::vector<std::string> names;
    for (std::size_t i = 0; i < physical; ++i) names.push_back("disk-"+std::to_string(i)+".img");
    const auto append = [&](const Value& volume) {
        const auto& entry = std::get<Value::Object>(volume.data);
        if (entry.contains("lv_uuid")) names.push_back(std::get<std::string>(entry.at("lv_uuid").data)+".img");
    };
    append(plan.at("root"));
    if (plan.contains("selected_extra")) for (const auto& volume : std::get<Value::Array>(plan.at("selected_extra").data)) append(volume);
    return names;
}
DeltaPlan fixture_tracking_delta(const CaptureJournal& current, const CaptureJournal& base, std::size_t index,
    std::vector<ChangedExtent>* reread = nullptr, bool require = false, Value* policy = nullptr) {
    return machine_tracking_delta(current,base,index,fixture_image_names(current),fixture_image_names(base),reread,require,policy);
}
#include "resize_tests.hpp"
void complete_interval_cbt() {
    constexpr std::uint64_t query = 65536, size = 8*query;
    // the official agent queries the complete interval at 64 KiB when CBT is present.
    // Exhaust every change mask, including unchanged edges/all unchanged and
    // changed-only edges, for both logical and physical filesystem images.
    for (const bool logical : {false,true}) for (unsigned mask = 0; mask < 256; ++mask) {
        auto base = ready(), current = ready();
        base.id = std::string(32,'a'); current.id = std::string(32,'b');
        Value volume{Value::Object{{"offset",n(0)},{"length",n(size)},
            {"filesystem_uuid",Value{std::string("edge-fs")}},{"disk_index",n(0)}}};
        if (logical) set(volume,"lv_uuid",Value{std::string("edge-lv")});
        base.plan = Value{Value::Object{{"root",volume}}};
        if (!logical) set(base.plan,"layout",Value{Value::Object{{"length",n(size)}}});
        current.plan = base.plan;
        base.snapshot = Value{Value::Object{{"uuid",Value{std::string(32,'c')}},{"sequence",n(7)}}};
        current.snapshot = base.snapshot; set(current.snapshot,"sequence",n(8));
        current.reservation = Value{Value::Object{
            {"previous_capture_id",Value{base.id}},
            {"prior",Value{Value::Object{{"snapshot",base.snapshot}}}},
            {"changes",Value{Bytes{static_cast<std::uint8_t>(mask)}}},
            {"filesystem_unused",Value{Value::Array{}}}}};
        const std::vector<std::string> names{"edge.img"};
        std::vector<ChangedExtent> reread;
        const auto delta = machine_tracking_delta(current,base,0,names,names,&reread);
        check(reread.empty());
        const auto serialized = delta_plan_value(delta);
        auto roundtrip = delta_plan_from_value(serialized,size);
        roundtrip.filesystem_allocation = true;
        std::uint64_t read = 0, sent = 0;
        ImageSource image(size,[&](auto at,auto count,auto*) {
            check(count == query && (mask & (1U << (at/query))));
            read += count;
            return Bytes(count,0x5a);
        },[] {});
        stream_image(image,"edge.img",1024*1024,[&](const Value& block) {
            const auto& fields = std::get<Value::Object>(block.data);
            check(fields.at("offset") == n(sent) && fields.at("length") == n(query));
            const bool changed = (mask & (1U << (sent/query))) != 0;
            check(fields.at("used") == n(1) && fields.at("changed") == n(changed) &&
                fields.at("is_interval_cbt") == n(1) && fields.contains("buffer") == changed);
            sent += query;
        },{},0,TransferCompression::none,&roundtrip);
        check(sent == size && read == delta.transfer_bytes);
    }
}
void persistent_tracking_ranges() {
    constexpr std::uint64_t mib = 1024*1024;
    auto base = ready(), current = ready();
    base.id = std::string(32,'a'); current.id = std::string(32,'b');
    const Value volume{Value::Object{{"offset",n(2*mib)},{"length",n(12*mib)},
        {"filesystem_uuid",Value{std::string("root-fs")}},{"disk_index",n(0)}}};
    base.plan = Value{Value::Object{{"layout",Value{Value::Object{{"length",n(16*mib)}}}},
                                  {"root",volume}}};
    current.plan = base.plan;
    base.snapshot = Value{Value::Object{{"uuid",Value{std::string(32,'c')}},{"sequence",n(7)}}};
    current.snapshot = base.snapshot;
    set(current.snapshot,"sequence",n(8));
    current.reservation = Value{Value::Object{{"previous_capture_id",Value{base.id}},
        {"prior",Value{Value::Object{{"snapshot",base.snapshot}}}}}};
    Bytes bitmap(24,0);
    bitmap.at(4) = 1; // Source block 32 => image [4 MiB, 4 MiB + 64 KiB).
    set(current.reservation,"changes",Value{bitmap});
    std::vector<ChangedExtent> reread;
    auto delta = fixture_tracking_delta(current,base,0,&reread);
    check(delta.transfer_bytes == 4*mib+65536 && reread.empty());
    check(delta.ranges.size() == 5 && delta.ranges[2].offset == 4*mib &&
          delta.ranges[2].length == 65536 && delta.ranges[2].changed);
    const Value internal{Value::Array{Value{Value::Object{
        {"offset",n(6*mib)},{"length",n(4096)}}}}};
    set(current.reservation,"cow_unused",internal);
    check(fixture_tracking_delta(current,base,0).transfer_bytes == 4*mib+2*65536);
    const auto unused = machine_tracking_unused(current,0);
    check(unused.empty()); // Sub-query-unit holes do not suppress a official agent full-read query.
    set(current.reservation,"filesystem_unused",Value{Value::Array{Value{Value::Object{
        {"offset",n(6*mib+4096)},{"length",n(2*mib-4096)}}}}});
    check(fixture_tracking_delta(current,base,0).transfer_bytes == 4*mib+65536);
    auto free_full = machine_tracking_unused(current,0);
    auto free_cbt = machine_tracking_unused(current,0,true);
    check(free_full.size() == 1 && free_full.front().offset == 8*mib && free_full.front().length == 2*mib);
    check(free_cbt.size() == 1 && free_cbt.front().offset == 8*mib && free_cbt.front().length == 2*mib);
    set(current.reservation,"filesystem_unused",Value{Value::Array{Value{Value::Object{
        {"offset",n(6*mib+4096)},{"length",n(128*1024-4096)}}}}});
    check(machine_tracking_unused(current,0).empty());
    free_cbt = machine_tracking_unused(current,0,true);
    check(free_cbt.size() == 1 && free_cbt.front().length == 128*1024);
    const std::vector<ChangedExtent> full_reread{{2*mib,12*mib}};
    check(machine_tracking_unused(current,0,true,full_reread).empty());
    // Native 1 KiB free/COW extents can jointly make a complete wire query
    // unused. Neither map may be projected to driver-sized units first.
    set(current.reservation,"cow_unused",Value{Value::Array{Value{Value::Object{
        {"offset",n(6*mib)},{"length",n(1024)}}}}});
    set(current.reservation,"filesystem_unused",Value{Value::Array{Value{Value::Object{
        {"offset",n(6*mib+1024)},{"length",n(65536-1024)}}}}});
    free_cbt = machine_tracking_unused(current,0,true);
    check(free_cbt.size() == 1 && free_cbt.front().offset == 8*mib &&
          free_cbt.front().length == 65536);
    auto short_tail = current;
    set(std::get<Value::Object>(short_tail.plan.data).at("root"),"length",n(12*mib+1024));
    set(short_tail.reservation,"cow_unused",Value{Value::Array{}});
    set(short_tail.reservation,"filesystem_unused",Value{Value::Array{Value{Value::Object{
        {"offset",n(0)},{"length",n(12*mib+1024)}}}}});
    const auto tail_unused = machine_tracking_unused(short_tail,0);
    check(tail_unused.size() == 1 && tail_unused.front().offset == 2*mib &&
          tail_unused.front().length == 12*mib); // the official agent retains the sub-4-KiB final read.
    set(current.reservation,"cow_unused",internal);
    std::get<Value::Object>(current.reservation.data).erase("filesystem_unused");
    auto wrong_internal = current;
    set(wrong_internal.reservation,"cow_unused",Value{Value::Array{Value{Value::Object{
        {"offset",n(12*mib)},{"length",n(4096)}}}}});
    rejects([&] { machine_tracking_unused(wrong_internal,0); });
    std::get<Value::Object>(current.reservation.data).erase("cow_unused");
    set(current.reservation,"changes",Value{Bytes(24,0)});
    check(fixture_tracking_delta(current,base,0).transfer_bytes == 4*mib);
    auto lost = current;
    std::get<Value::Object>(lost.reservation.data).erase("changes");
    reread.clear();
    check(fixture_tracking_delta(lost,base,0,&reread).transfer_bytes == 16*mib);
    check(reread.size() == 1 && reread.front().offset == 2*mib && reread.front().length == 12*mib);
    // Offline cache production requires usable CBT; it cannot substitute a
    // new full image when the exact ancestry needed to encode the cache is gone.
    rejects([&] { fixture_tracking_delta(lost,base,0,nullptr,true); });
    // Durable initialized ownership can renew a healthy driver generation
    // without reconstructing independent transfer ancestry. The consecutive
    // UUID/sequence and explicit recovery marker do not authorize inheritance.
    auto owned_without_history = current;
    std::get<Value::Object>(owned_without_history.reservation.data).erase("changes");
    std::get<Value::Object>(owned_without_history.reservation.data).erase("previous_capture_id");
    set(owned_without_history.reservation,"tracking_recovery",
        Value{std::string("durable-owner-renewed-without-history")});
    Value no_history_policy;
    reread.clear();
    check(fixture_tracking_delta(owned_without_history,base,0,&reread,false,&no_history_policy).transfer_bytes == 16*mib);
    check(reread.size() == 1 && reread.front().offset == 2*mib && reread.front().length == 12*mib);
    check(std::get<std::uint64_t>(std::get<Value::Object>(no_history_policy.data).at("is_cbt").data) == 0);
    rejects([&] { fixture_tracking_delta(owned_without_history,base,0,nullptr,true); });
    auto different_base = base;
    set(different_base.snapshot,"uuid",Value{std::string(32,'d')});
    check(fixture_tracking_delta(current,different_base,0).transfer_bytes == 16*mib);
    rejects([&] { fixture_tracking_delta(current,different_base,0,nullptr,true); });
    set(current.reservation,"changes",Value{Bytes(23,0)});
    check(fixture_tracking_delta(current,base,0).transfer_bytes == 4*mib+512*1024);
    set(current.reservation,"changes",Value{bitmap});
    // A root LV occupies its own image and contributes no inherited physical disk bytes.
    auto root = volume;
    set(root,"lv_uuid",Value{std::string("root-lv")});
    set(current.plan,"root",root); set(base.plan,"root",root);
    check(fixture_tracking_delta(current,base,0).transfer_bytes == 16*mib);
    check(fixture_tracking_delta(current,base,1).transfer_bytes == 65536);
    // Snapshot ownership and image zero remain valid with only an LV image.
    // Its CBT ranges use logical offset zero, without a physical predecessor.
    auto logical_current = current, logical_base = base;
    std::get<Value::Object>(logical_current.plan.data).erase("layout");
    std::get<Value::Object>(logical_base.plan.data).erase("layout");
    const std::vector<std::string> only_lv{"root-lv.img"};
    check(machine_image_plans(logical_current.plan).size() == 1);
    check(machine_tracking_delta(logical_current,logical_base,0,only_lv,only_lv).transfer_bytes ==
        65536);
    logical_current.snapshot = Value{Value::Object{{"acquisition_error",n(2)}}};
    const auto logical_omission = machine_snapshot_omissions(logical_current,0);
    check(logical_omission.size() == 1 && logical_omission[0].offset == 0 &&
        logical_omission[0].length == 12*mib);
    check(machine_tracking_unused(logical_current,0,true).front().length == 12*mib);
    // A selected partition on the next disk uses that disk's coordinates.
    set(root,"filesystem_uuid",Value{std::string("second-fs")});
    std::get<Value::Object>(root.data).erase("lv_uuid");
    set(root,"disk_index",n(1));
    const Value disk{Value::Object{{"layout",Value{Value::Object{{"length",n(16*mib)}}}},
                                  {"selected_extra",Value{Value::Array{root}}}}};
    set(current.plan,"additional_disks",Value{Value::Array{disk}});
    set(base.plan,"additional_disks",Value{Value::Array{disk}});
    auto extra = current.reservation;
    set(extra,"snapshot",current.snapshot);
    set(current.reservation,"extras",Value{Value::Array{extra}});
    auto old_extra = Value{Value::Object{{"snapshot",base.snapshot}}};
    set(base.reservation,"extras",Value{Value::Array{old_extra}});
    check(fixture_tracking_delta(current,base,1).transfer_bytes == 4*mib+65536);
    // Omission is exact type-4 coverage, independent of filesystem bitmap
    // rounding or CBT ancestry, and never inherits bytes from the prior image.
    const Value omitted{Value::Object{{"acquisition_error",n(2)}}};
    set(std::get<Value::Array>(std::get<Value::Object>(current.reservation.data).at("extras").data)[0],
        "snapshot",omitted);
    auto omitted_ranges = machine_snapshot_omissions(current,1);
    check(omitted_ranges.size() == 1 && omitted_ranges[0].offset == 2*mib &&
        omitted_ranges[0].length == 12*mib);
    check(machine_tracking_unused(current,1,true).front().length == 12*mib);
    check(fixture_tracking_delta(current,base,1,nullptr,true).transfer_bytes == 16*mib);
    check(machine_snapshot_omissions(current,0).empty());
    auto failed_root = current;
    failed_root.snapshot = omitted;
    check(fixture_tracking_delta(failed_root,base,2,nullptr,true).transfer_bytes == 12*mib);
    check(machine_snapshot_omissions(failed_root,2).front().offset == 0);
    check(machine_tracking_unused(failed_root,2,true).front().length == 12*mib);
    // No attempted type-1 context failed: raw-only and omitted-only images do
    // not clear the snapshot's positive-base completion CBT value.
    const auto omitted_names = fixture_image_names(failed_root), base_names = fixture_image_names(base);
    for (std::size_t image = 0; image < omitted_names.size(); ++image) {
        Value policy;
        (void)machine_tracking_delta(failed_root,base,image,omitted_names,base_names,nullptr,true,&policy);
        check(std::get<std::uint64_t>(std::get<Value::Object>(policy.data).at("is_cbt").data) == 1);
    }
    // A healthy filesystem after an omitted base needs a full interval.
    auto omitted_base = base;
    omitted_base.snapshot = omitted;
    check(fixture_tracking_delta(current,omitted_base,2).transfer_bytes == 12*mib);
    rejects([&] { fixture_tracking_delta(current,omitted_base,2,nullptr,true); });
}
void fresh_interval_coordinates() {
    constexpr std::uint64_t mib = 1024*1024;
    auto base = ready(), current = ready();
    base.id = std::string(32,'a'); current.id = std::string(32,'b');
    Value root{Value::Object{{"offset",n(2*mib)},{"length",n(4*mib)},
        {"filesystem_uuid",Value{std::string("root-fs")}},{"disk_index",n(0)}}};
    auto sibling = root;
    set(sibling,"offset",n(8*mib)); set(sibling,"filesystem_uuid",Value{std::string("sibling-fs")});
    base.plan = Value{Value::Object{{"layout",Value{Value::Object{{"length",n(16*mib)}}}},
        {"root",root},{"selected_extra",Value{Value::Array{sibling}}}}};
    current.plan = base.plan;
    base.snapshot = Value{Value::Object{{"uuid",Value{std::string(32,'c')}},{"sequence",n(7)}}};
    current.snapshot = base.snapshot; set(current.snapshot,"sequence",n(8));
    current.reservation = Value{Value::Object{{"previous_capture_id",Value{base.id}},
        {"filesystem_unused",Value{Value::Array{}}},{"changes",Value{Bytes(8,0)}},
        {"prior",Value{Value::Object{{"snapshot",base.snapshot}}}}}};
    auto extra = current.reservation;
    set(extra,"snapshot",current.snapshot);
    set(current.reservation,"extras",Value{Value::Array{extra}});
    set(base.reservation,"extras",Value{Value::Array{Value{Value::Object{{"snapshot",base.snapshot}}}}});
    const auto changed = [](const DeltaPlan& plan, std::uint64_t at) {
        for (const auto& range : plan.ranges) if (range.offset <= at && at < range.offset+range.length) return range.changed;
        throw Error("fixture has no image coverage");
    };
    const std::vector<std::string> names{"disk.img"};
    std::vector<ChangedExtent> reread;
    Value policy;
    // Valid ancestry alone does not authorize inheritance at a new disk offset.
    set(std::get<Value::Object>(current.plan.data).at("root"),"offset",n(3*mib));
    auto delta = machine_tracking_delta(current,base,0,names,names,&reread,false,&policy);
    check(changed(delta,4*mib) && !changed(delta,9*mib));
    check(reread.size() == 1 && reread[0].offset == 3*mib && reread[0].length == 4*mib);
    check(std::get<std::uint64_t>(std::get<Value::Object>(policy.data).at("is_cbt").data) == 0);
    rejects([&] { machine_tracking_delta(current,base,0,names,names,nullptr,true); });
    current.plan = base.plan;
    // Actual names determine whether the NAS has a clone; every offset of a
    // new image, including boundaries and unused ranges, needs no-CBT coverage.
    const std::vector<std::string> renamed{"renamed.img"};
    reread.clear();
    delta = machine_tracking_delta(current,base,0,renamed,names,&reread,false,&policy);
    check(delta.transfer_bytes == 16*mib && reread.size() == 1 && reread[0].offset == 0 && reread[0].length == 16*mib);
    // Outer disk geometry does not alter the two unchanged filesystem origins.
    for (const auto size : {14*mib,20*mib}) {
        set(std::get<Value::Object>(current.plan.data).at("layout"),"length",n(size));
        reread.clear();
        delta = machine_tracking_delta(current,base,0,names,names,&reread,false,&policy);
        check(delta.image_size == size && reread.empty() && !changed(delta,4*mib) && !changed(delta,9*mib));
    }
    current.plan = base.plan;
    // Physical/LV class is part of the official agent predicate even with the same UUID.
    set(std::get<Value::Object>(current.plan.data).at("root"),"lv_uuid",Value{std::string("root-lv")});
    const std::vector<std::string> logical_names{"disk.img","root-lv.img"};
    reread.clear();
    delta = machine_tracking_delta(current,base,1,logical_names,names,&reread,false,&policy);
    check(delta.transfer_bytes == 4*mib && reread.size() == 1 && reread[0].offset == 0);
    current.plan = base.plan;
    // Reorder/remove logical images using actual names and origin UUIDs.
    auto lv_a = root, lv_b = root;
    set(lv_a,"lv_uuid",Value{std::string("a")}); set(lv_a,"filesystem_uuid",Value{std::string("a-fs")});
    set(lv_b,"lv_uuid",Value{std::string("b")}); set(lv_b,"filesystem_uuid",Value{std::string("b-fs")});
    set(base.plan,"selected_extra",Value{Value::Array{lv_a,lv_b}});
    set(current.plan,"selected_extra",Value{Value::Array{lv_b,lv_a}});
    auto old_b = base.snapshot; set(old_b,"uuid",Value{std::string(32,'d')});
    auto new_b = old_b; set(new_b,"sequence",n(8));
    auto b_reserved = current.reservation;
    set(b_reserved,"snapshot",new_b); set(b_reserved,"prior",Value{Value::Object{{"snapshot",old_b}}});
    set(base.reservation,"extras",Value{Value::Array{Value{Value::Object{{"snapshot",base.snapshot}}},Value{Value::Object{{"snapshot",old_b}}}}});
    set(current.reservation,"extras",Value{Value::Array{b_reserved,extra}});
    const std::vector<std::string> old_names{"disk.img","a.img","b.img"}, reordered{"disk.img","b.img","a.img"};
    reread.clear();
    delta = machine_tracking_delta(current,base,1,reordered,old_names,&reread,false,&policy);
    check(reread.empty() && !changed(delta,2*mib));
    set(current.plan,"selected_extra",Value{Value::Array{lv_b}});
    set(current.reservation,"extras",Value{Value::Array{b_reserved}});
    const std::vector<std::string> removed{"disk.img","b.img"};
    check(machine_tracking_delta(current,base,1,removed,old_names).transfer_bytes == 0);
    // An unrelated new selected origin gets full data while the retained one
    // still inherits; cache cannot turn the missing context into a full point.
    set(base.plan,"selected_extra",Value{Value::Array{lv_a}});
    set(base.reservation,"extras",Value{Value::Array{Value{Value::Object{{"snapshot",base.snapshot}}}}});
    const std::vector<std::string> one_old{"disk.img","a.img"};
    reread.clear();
    delta = machine_tracking_delta(current,base,1,removed,one_old,&reread,false,&policy);
    check(delta.transfer_bytes == 4*mib && reread.size() == 1 && reread[0].length == 4*mib);
    rejects([&] { machine_tracking_delta(current,base,1,removed,one_old,nullptr,true); });
}
void automatic_capture_policy() {
    auto reserved = ready();
    reserved.phase = CapturePhase::prepared;
    set(reserved.reservation,"snapshot_time",n(0));
    set(reserved.reservation,"snapshot_attempted",n(0));
    set(reserved.reservation,"snapshot_released",n(0));
    set(reserved.reservation,"directory",Value{std::string("/private/capture")});
    set(reserved.reservation,"output",Value{Value::Object{{"inode",n(42)}}});
    auto current = reserved;
    verify_machine_reservation(reserved,current);
    {
        auto cache_reserved = reserved;
        const ImageLayout layout{ImageLayout::Scheme::mbr,512,4*1024*1024,"cache",{}};
        const Value disk{Value::Object{{"layout",layout_value(layout)},
            {"layout_policy",Value{std::string("linux-layout-v1")}},
            {"excluded",Value{Value::Array{}}},{"selected_extra",Value{Value::Array{}}}}};
        cache_reserved.plan = disk;
        set(cache_reserved.plan,"additional_disks",Value{Value::Array{disk}});
        auto progress = cache_reserved;
        progress.phase = CapturePhase::static_copy_intent;
        const auto fail = [&](Value& plan) {
            machine_cache_raw_regions(plan,[](const auto&) {
                throw MachineRawCacheCopyError("cache copy");
            },[] {},[] {});
        };
        fail(progress.plan);
        fail(std::get<Value::Array>(std::get<Value::Object>(
            progress.plan.data).at("additional_disks").data).front());
        verify_machine_reservation(cache_reserved,progress);
        auto invalid = progress;
        invalid.phase = CapturePhase::prepared;
        rejects([&] { verify_machine_reservation(cache_reserved,invalid); });
        invalid = progress;
        auto& failures = std::get<Value::Array>(std::get<Value::Object>(
            invalid.plan.data).at("raw_cache_failures").data);
        set(failures.front(),"length",n(512));
        rejects([&] { verify_machine_reservation(cache_reserved,invalid); });
    }
    auto early = current;
    set(early.reservation,"snapshot_time",n(123));
    rejects([&] { verify_machine_reservation(reserved,early); });
    current.phase = CapturePhase::snapshot_active;
    rejects([&] { verify_machine_reservation(reserved,current); });
    set(current.reservation,"snapshot_time",n(123));
    set(current.reservation,"snapshot_attempted",n(1));
    verify_machine_reservation(reserved,current);
    current.phase = CapturePhase::ready;
    set(current.reservation,"snapshot_released",n(1));
    set(current.reservation,"filesystem_unused",Value{Value::Array{}});
    verify_machine_reservation(reserved,current);
    auto early_allocation = current;
    early_allocation.phase = CapturePhase::snapshot_active;
    rejects([&] { verify_machine_reservation(reserved,early_allocation); });
    auto changed = current;
    changed.id[0] = 'f';
    rejects([&] { verify_machine_reservation(reserved,changed); });
    changed = current; changed.boot_id[0] = 'f';
    rejects([&] { verify_machine_reservation(reserved,changed); });
    changed = current; set(changed.plan,"disk",Value{std::string("/foreign")});
    rejects([&] { verify_machine_reservation(reserved,changed); });
    for (auto key : {"directory","output","snapshot_attempted","snapshot_released"}) {
        changed = current; set(changed.reservation,key,n(3));
        rejects([&] { verify_machine_reservation(reserved,changed); });
    }
    changed = current; set(changed.reservation,"snapshot_attempted",n(0));
    rejects([&] { verify_machine_reservation(reserved,changed); });
    const auto job = [](std::uint64_t task, std::uint64_t id, std::uint64_t status, std::uint64_t type = 0) {
        return Value{Value::Object{{"task_id",n(task)},{"id",n(id)},{"status",n(status)},{"type",n(type)}}};
    };
    check(!queued_machine_run({},2));
    check(!queued_machine_run({job(2,7,3)},2)); // Cancellation cannot trigger capture.
    check(queued_machine_run({job(99,8,0),job(2,9,0,1),job(2,10,0)},2) == 10);
    rejects([&] { queued_machine_run({job(2,0,0)},2); });
    rejects([&] { queued_machine_run({job(2,10,0),job(2,11,0)},2); });
    rejects([&] { queued_machine_run({job(2,10,0),job(2,10,0)},2); });
    Value plan{Value::Object{}};
    for (auto key : {"disk","device_number","layout","cow_directory","cow_device","cow_filesystem_uuid"})
        set(plan,key,Value{std::string(key)});
    set(plan,"other_disk_count",n(0));
    for (auto role : {"root","boot"}) {
        Value partition{Value::Object{}};
        for (auto key : {"partition","device","device_number","offset","length","mount_path","filesystem","filesystem_uuid"})
            set(partition,key,Value{std::string(key)});
        set(plan,role,partition);
    }
    Value excluded{Value::Object{
        {"partition",n(3)},{"offset",n(4096)},{"length",n(4096)},
        {"mount_path",Value{std::string("/data")}},
        {"filesystem",Value{std::string("ext4")}},
        {"device",Value{std::string("/dev/sda3")}},
        {"device_number",Value{std::string("8:3")}}}};
    set(plan,"excluded",Value{Value::Array{excluded}});
    const auto target = machine_capture_target(plan);
    auto efi_plan = plan;
    set(std::get<Value::Object>(efi_plan.data).at("boot"),"mount_path",
        Value{std::string("/boot/efi")});
    check(machine_capture_target(efi_plan) != target);
    check(machine_incremental_target(efi_plan) != machine_incremental_target(plan));
    auto efi_journal = ready();
    efi_journal.plan = efi_plan;
    const auto persisted = capture_journal_from_value(
        decode(encode(capture_journal_value(efi_journal))));
    check(persisted.plan == efi_plan);
    check(machine_capture_target(persisted.plan) == machine_capture_target(efi_plan));
    set(plan,"boot_id",Value{std::string("another-boot")});
    set(std::get<Value::Object>(plan.data).at("root"),"mount_id",n(999));
    check(machine_capture_target(plan) == target);
    set(std::get<Value::Object>(plan.data).at("root"),"device",Value{std::string("/other")});
    check(machine_capture_target(plan) == target); // Kernel device names are not persistent identity.
    set(plan,"device_number",Value{std::string("8:16")});
    set(plan,"cow_device",Value{std::string("8:0")});
    check(machine_capture_target(plan) == target);
    auto& extra = std::get<Value::Array>(
        std::get<Value::Object>(plan.data).at("excluded").data).front();
    set(extra,"device",Value{std::string("/dev/vda3")});
    set(extra,"device_number",Value{std::string("252:3")});
    check(machine_capture_target(plan) == target);
    auto changed_plan = plan;
    set(changed_plan,"cow_filesystem_uuid",Value{std::string("foreign")});
    check(machine_capture_target(changed_plan) != target);
    set(std::get<Value::Object>(plan.data).at("root"),"filesystem_uuid",Value{std::string("foreign")});
    check(machine_capture_target(plan) != target);
    set(std::get<Value::Object>(plan.data).at("root"),"filesystem_uuid",Value{std::string("filesystem_uuid")});
    set(extra,"mount_path",Value{std::string("/new-data")});
    check(machine_capture_target(plan) != target);
    set(extra,"mount_path",Value{std::string("/data")});
    set(plan,"other_disk_count",n(1));
    check(machine_capture_target(plan) != target);
    set(extra,"pv_uuid",Value{std::string("pv-uuid")});
    set(extra,"vg_uuid",Value{std::string("vg-uuid")});
    set(extra,"pv_wire_policy",Value{std::string("whole-partition-zero")});
    set(extra,"pv_metadata_length",n(512));
    set(extra,"pv_extent_length",n(1024));
    set(extra,"pv_mda_size",n(512));
    set(extra,"pv_mda_count",n(2));
    set(extra,"pv_metadata_sha256",Value{std::string(64,'a')});
    set(extra,"pv_tail_length",n(512));
    set(extra,"pv_tail_sha256",Value{std::string(64,'b')});
    const auto pv_target = machine_incremental_target(plan);
    auto old_policy = plan;
    auto& old_extra = std::get<Value::Array>(
        std::get<Value::Object>(old_policy.data).at("excluded").data).front();
    std::get<Value::Object>(old_extra.data).erase("pv_wire_policy");
    check(machine_incremental_target(old_policy) != pv_target);
    set(extra,"pv_tail_sha256",Value{std::string(64,'c')});
    check(machine_incremental_target(plan) != pv_target);
    set(extra,"pv_tail_sha256",Value{std::string(64,'b')});
    set(extra,"pv_mda_count",n(1));
    check(machine_incremental_target(plan) != pv_target);
    auto legacy = plan;
    for (auto key : {"other_disk_count","selected_extra","excluded","additional_disks","external_volumes"})
        std::get<Value::Object>(legacy.data).erase(key);
    auto modern = legacy;
    set(modern,"other_disk_count",n(1));
    for (auto key : {"selected_extra","excluded","additional_disks"})
        set(modern,key,Value{Value::Array{}});
    set(modern,"external_volumes",Value{Value::Array{Value{Value::Object{
        {"mount_path",Value{std::string("/lab")}},{"disk",Value{std::string("/dev/sdb")}}}}}});
    check(machine_incremental_target(legacy) == machine_incremental_target(modern));
    set(modern,"selected_extra",Value{Value::Array{excluded}});
    check(machine_incremental_target(legacy) != machine_incremental_target(modern));
    auto added = modern;
    set(added,"additional_disks",Value{Value::Array{Value{Value::Object{
        {"layout",std::get<Value::Object>(plan.data).at("layout")},
        {"selected_extra",Value{Value::Array{excluded}}},
        {"excluded",Value{Value::Array{}}}}}}});
    const auto selected_target = machine_incremental_target(added);
    auto& external = std::get<Value::Object>(
        std::get<Value::Array>(std::get<Value::Object>(added.data).at("additional_disks").data).front().data);
    auto& selected = std::get<Value::Array>(external.at("selected_extra").data);
    set(selected.front(),"mount_path",Value{std::string("/other-data")});
    check(machine_incremental_target(added) != selected_target);
    auto lvm_plan = plan;
    Value segment{Value::Object{
        {"logical_offset",n(0)},{"length",n(512)},
        {"pv_uuid",Value{std::string("pv-uuid")}},{"pv_offset",n(1048576)}}};
    Value lv{Value::Object{
        {"lv_name",Value{std::string("selected")}},
        {"lv_uuid",Value{std::string("lv-uuid")}},
        {"vg_uuid",Value{std::string("vg-uuid")}},
        {"image_name",Value{std::string("vg=selected.img")}},
        {"length",n(512)},
        {"mount_path",Value{std::string("/data")}},
        {"filesystem",Value{std::string("ext4")}},
        {"filesystem_uuid",Value{std::string("fs-uuid")}},
        {"segments",Value{Value::Array{segment}}}}};
    set(lvm_plan,"selected_extra",Value{Value::Array{lv}});
    Value pv{Value::Object{
        {"name",Value{std::string("/dev/sda1")}},
        {"uuid",Value{std::string("pv-uuid")}},{"size",n(8388608)}}};
    Value vg_lv{Value::Object{
        {"name",Value{std::string("selected")}},{"uuid",Value{std::string("lv-uuid")}},
        {"file_system",Value{std::string("ext4")}},{"size",n(512)}}};
    Value vg{Value::Object{
        {"name",Value{std::string("vg")}},{"uuid",Value{std::string("vg-uuid")}},
        {"extent_size",n(4194304)},{"mda_size",n(1044480)},{"total_size",n(8388608)},
        {"physical_volumes",Value{Value::Array{pv}}},
        {"logical_volumes",Value{Value::Array{vg_lv}}}}};
    set(lvm_plan,"lvm",Value{Value::Object{
        {"selected_lvs",Value{Value::Array{lv}}},
        {"volume_groups",Value{Value::Array{vg}}}}});
    const auto lvm_target = machine_incremental_target(lvm_plan);
    const auto lvm_source_target = machine_capture_target(lvm_plan);
    auto discovery = lvm_plan;
    auto& discovered_lv = std::get<Value::Array>(
        std::get<Value::Object>(discovery.data).at("selected_extra").data).front();
    auto& discovered_segment = std::get<Value::Array>(
        std::get<Value::Object>(discovered_lv.data).at("segments").data).front();
    set(discovered_segment,"type",Value{std::string("linear")});
    set(discovered_segment,"mapping",Value{Value::Array{}});
    set(discovered_segment,"kernel_topology",Value{Value::Object{}});
    auto& discovered_lvm = std::get<Value::Object>(
        std::get<Value::Object>(discovery.data).at("lvm").data);
    discovered_lvm["selected_lvs"] = Value{Value::Array{discovered_lv}};
    auto& discovered_group = std::get<Value::Array>(discovered_lvm.at("volume_groups").data).front();
    auto& discovered_inventory = std::get<Value::Array>(
        std::get<Value::Object>(discovered_group.data).at("logical_volumes").data);
    discovered_inventory.push_back(Value{Value::Object{
        {"name",Value{std::string("unselected")}},{"uuid",Value{std::string("other-lv")}},
        {"file_system",Value{std::string{}}},{"size",n(512)}}});
    check(machine_capture_target(discovery) != lvm_source_target);
    check(machine_incremental_target(discovery) == lvm_target);
    // Mapping changes belong to source validation; a logical image's byte
    // coordinates remain the same. Inheritance still needs its exact CBT chain.
    set(discovered_segment,"pv_offset",n(2097152));
    check(machine_capture_target(discovery) != lvm_source_target);
    check(machine_incremental_target(discovery) == lvm_target);
    set(discovered_lv,"length",n(1024));
    check(machine_incremental_target(discovery) != lvm_target);
    set(std::get<Value::Array>(std::get<Value::Object>(
        std::get<Value::Array>(std::get<Value::Object>(
            std::get<Value::Object>(lvm_plan.data).at("lvm").data).at("volume_groups").data
        ).front().data).at("physical_volumes").data).front(),
        "name",Value{std::string("/dev/vdb1")});
    check(machine_incremental_target(lvm_plan) == lvm_target);
    set(std::get<Value::Array>(std::get<Value::Object>(
        lvm_plan.data).at("selected_extra").data).front(),"filesystem_uuid",
        Value{std::string("changed-fs")});
    check(machine_incremental_target(lvm_plan) != lvm_target);
}
void reject_earlier_schema() {
    const auto current = capture_journal_value(ready());
    for (std::uint64_t schema = 1; schema < 5; ++schema) {
        auto old = current;
        set(old,"schema",n(schema));
        rejects([&] { (void)capture_journal_from_value(old); });
        auto journal = ready(); journal.schema = schema;
        rejects([&] { (void)capture_journal_value(journal); });
    }
}
void snapshot_rotation() {
    MachineSnapshotCatalog catalog;
    const auto add = [&](std::uint64_t version, char uuid, std::string task = "task-H") {
        auto capture = ready(); capture.id = std::string(32,uuid);
        // Deliberately decreasing clock: local order is independent of time.
        set(capture.reservation,"snapshot_time",n(1000-version));
        const auto id = catalog.reserve(task == "task-H" ? 2 : 9,task,version);
        catalog.attach(id,capture); catalog.version(capture.id,version);
        return id;
    };
    const auto old = add(102,'a');
    const auto other = add(900,'f',"another-task");
    const auto base = add(103,'b');
    check(catalog.base("task-H",103)->id == base);
    check(!catalog.base("another-task",103));
    const auto obsolete = catalog.rotation("task-H",103);
    check(obsolete.size() == 1 && obsolete.front().id == old);
    check(catalog.rotation("task-H",0).empty());
    check(catalog.rotation("task-H",999).empty()); // No matching local row -> full, no rotation.
    check(catalog.rotation("unknown-task",103).empty());
    // the official agent retries old resource deletion on later rotations, retaining the
    // agent snapshot rows even when cleanup failed on an earlier boot.
    Value persisted;
    std::vector<std::uint64_t> cleaned;
    std::size_t writes = 0;
    std::uint64_t failed = 0;
    rejects([&] {
        failed = catalog.prepare(2,"task-H",104,base,
            [&](const MachineSnapshot& snapshot) { cleaned.push_back(snapshot.id); },
            [&](const MachineSnapshotCatalog& saved) { persisted = decode(encode(saved.value())); ++writes; });
        throw Error("injected snapshot failure after rotation");
    });
    check(writes == 1 && cleaned == std::vector<std::uint64_t>{old});
    catalog = MachineSnapshotCatalog{persisted};
    check(catalog.capture(std::string(32,'a'))->id == old);
    check(catalog.capture(std::string(32,'b'))->id == base);
    check(catalog.capture(std::string(32,'f'))->id == other);
    check(catalog.rotation("task-H",103).size() == 1);
    // A restart before acquiring any capture reuses the durable placeholder.
    check(catalog.prepare(2,"task-H",104,base,
        [&](const MachineSnapshot&) { check(false); },
        [&](const MachineSnapshotCatalog&) { check(false); }) == failed);
    auto failed_capture = ready(); failed_capture.id = std::string(32,'d');
    catalog.attach(failed,failed_capture);
    persisted = catalog.value(); // Capture reservation is durably attached before acquisition.
    // Lost resources with no NAS checkpoint are recaptured under the same
    // official agent DB identity; the old physical attempt still belongs to that row.
    const auto recapture = catalog.prepare(2,"task-H",104,base,
        [&](const MachineSnapshot&) { check(false); },
        [&](const MachineSnapshotCatalog& saved) { persisted = saved.value(); });
    // Cancellation after preparation is equally unable to undo rotation.
    catalog = MachineSnapshotCatalog{persisted};
    check(recapture == failed);
    auto replacement = ready(); replacement.id = std::string(32,'c');
    catalog.attach(recapture,replacement); catalog.version(replacement.id,104);
    const auto successor = catalog.base("task-H",104)->id;
    check(successor == failed && catalog.base("task-H",104)->capture->id == replacement.id);
    check(catalog.base("task-H",104)->superseded.size() == 1 &&
        catalog.base("task-H",104)->superseded.front().id == failed_capture.id);
    check(catalog.rotation("task-H",103).size() == 1); // Resource cleanup remains repeatable.
    const auto later = catalog.rotation("task-H",104);
    check(later.size() == 2 && later.front().id == old && later.back().id == base);
    const std::vector<std::string> present{"task-H","another-task"};
    check(catalog.removed_tasks(present).empty()); // Selection never enters this predicate.
    const std::vector<std::string> removed{"another-task"};
    const auto removed_rows = catalog.removed_tasks(removed);
    check(removed_rows.size() == 3);
    for (const auto& snapshot : removed_rows) catalog.erase(snapshot.id);
    const auto fresh = catalog.reserve(2,"task-H",105);
    check(fresh > successor); // AUTOINCREMENT survives DB row deletion.
    MachineSnapshotCatalog empty;
    check(!empty.base("task-H",103) && empty.rotation("task-H",103).empty());
    std::size_t full_writes = 0;
    empty.prepare(2,"task-H",106,0,[&](const MachineSnapshot&) { check(false); },
        [&](const MachineSnapshotCatalog&) { ++full_writes; });
    check(full_writes == 1 && !empty.base("task-H",103));
}
#ifdef __linux__
void base_rotation_keeps_absent_origins() {
    char pattern[] = "/tmp/opensabba-rotation-XXXXXX";
    const auto made = mkdtemp(pattern);
    if (!made) throw Error("cannot create rotation fixture");
    const std::filesystem::path directory(made);
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::filesystem::remove_all(path); }
    } cleanup{directory};
    MachineTrackingRecords records(directory/"records");
    MachineSnapshotCatalog catalog;
    auto old = ready(), base = ready();
    old.id = std::string(32,'a'); base.id = std::string(32,'b');
    const auto old_id = catalog.reserve(2,"task-H",102);
    catalog.attach(old_id,old); catalog.version(old.id,102);
    const auto base_id = catalog.reserve(2,"task-H",103);
    catalog.attach(base_id,base); catalog.version(base.id,103);
    std::filesystem::create_directory(directory/old.id);
    std::filesystem::create_directory(directory/base.id);
    MachineTrackingHistory old_history(directory/old.id), base_history(directory/base.id);
    for (const auto minor : {3,4}) {
        const auto volume = Value{Value::Object{{"device",Value{"/dev/dm-"+std::to_string(minor)}},
            {"filesystem_uuid",Value{"scratch-"+std::to_string(minor)}}}};
        const auto reserved = [&](std::uint64_t inode) {
            return Value{Value::Object{{"minor",n(minor)},{"tracking_filesystem_uuid",Value{"scratch-"+std::to_string(minor)}},
                {"cow_relative",Value{"/.synosnap_data/"+std::to_string(inode)}},
                {"cow",Value{Value::Object{{"device",n(253)},{"inode",n(inode)}}}}}};
        };
        const auto old_cow = reserved(1020+minor), base_cow = reserved(1030+minor);
        const auto generation = Value{Value::Object{{"uuid",Value{std::string(32,'c')}},{"sequence",n(2)}}};
        records.publish(volume,base_cow,generation,"/usr/bin/opensabba",false);
        const auto reload = directory/"records"/("reload_dm-"+std::to_string(minor));
        struct stat before{}, after{};
        check(stat(reload.c_str(),&before) == 0);
        // v104 has deselected both scratch origins. Rotation uses the task's
        // DB IDs, so those absent origins still retain their selected-base row.
        const auto obsolete = catalog.rotation("task-H",103);
        check(obsolete.size() == 1 && obsolete.front().id == old_id);
        old_history.retire(old_cow);
        check(old_history.retired(old_cow) && !base_history.retired(base_cow));
        check(stat(reload.c_str(),&after) == 0 && before.st_ino == after.st_ino);
        check(records.find(volume,static_cast<std::uint32_t>(minor),
            "/.synosnap_data/"+std::to_string(1030+minor)).has_value());
    }
}
void released_capture_completion() {
    char pattern[] = "/tmp/opensabba-completion-XXXXXX";
    const char* created = mkdtemp(pattern);
    if (!created) throw Error("cannot create completion fixture");
    const std::filesystem::path parent(created);
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::error_code ignored; std::filesystem::remove_all(path,ignored); }
    } cleanup{parent};
    auto journal = ready();
    journal.schema = 5;
    const auto directory = parent/("capture-"+journal.id);
    std::filesystem::create_directory(directory);
    check(chmod(directory.c_str(),0700) == 0);
    // Prior-boot metadata and nonexistent sources deliberately cannot be
    // rediscovered or uploaded. Replaying their durable release must still work
    // without source files, snapshots, a driver, or a mounted boot filesystem.
    const Value mount{Value::Object{
        {"device",Value{(parent/"absent-source").string()}},
        {"device_number",Value{std::string("254:254")}},{"mount_id",n(123)},
        {"mount_path",Value{std::string("/absent-mount")}},
        {"filesystem",Value{std::string("ext4")}},
        {"mount_options",Value{std::string("rw")}},{"super_options",Value{std::string("rw")}},
        {"offset",n(0)},{"length",n(512)}}};
    auto boot = mount;
    set(boot,"filesystem",Value{std::string("vfat")});
    set(boot,"mount_path",Value{std::string("/boot")});
    set(journal.plan,"boot",boot);
    set(journal.plan,"root",mount);
    set(journal.plan,"disk",Value{(parent/"absent-disk").string()});
    set(journal.plan,"cow_directory",Value{(parent/"absent-cow-directory").string()});
    set(journal.plan,"selected_extra",Value{Value::Array{mount}});
    set(journal.reservation,"directory",Value{directory.string()});
    struct stat raw_directory_stat{};
    check(stat(directory.c_str(),&raw_directory_stat) == 0);
    set(journal.reservation,"raw_storage_ready",n(1));
    set(journal.reservation,"raw_directory",Value{directory.string()});
    set(journal.reservation,"raw_directory_inode",n(raw_directory_stat.st_ino));
    set(journal.reservation,"raw_cache_policy",Value{Value::Object{{"cached_enabled",n(0)}}});
    set(journal.reservation,"minor",n(252));
    set(journal.reservation,"cow_path",Value{(parent/"absent-cow").string()});
    set(journal.reservation,"snapshot_attempted",n(1));
    set(journal.reservation,"snapshot_released",n(0));
    set(journal.reservation,"extras",Value{Value::Array{Value{Value::Object{
        {"mount_path",Value{std::string("/absent-mount")}},
        {"minor",n(253)},{"attempted",n(1)},{"released",n(0)},
        {"snapshot",journal.snapshot}}}}});
    const auto write = [&](const char* name, const CaptureJournal& value) {
        const auto bytes = encode(capture_journal_value(value));
        const auto path = directory/name;
        std::ofstream output(path,std::ios::binary|std::ios::trunc);
        output.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());
        output.close();
        check(chmod(path.c_str(),0600) == 0);
    };
    auto released = journal;
    set(released.reservation,"snapshot_released",n(1));
    auto& released_extras = std::get<Value::Array>(
        std::get<Value::Object>(released.reservation.data).at("extras").data);
    set(released_extras.front(),"released",n(1));
    write("capture.pstream",journal);
    write("release.pstream",released);
    struct stat before{}, after{};
    check(stat((directory/"release.pstream").c_str(),&before) == 0);
    finish_machine_capture(directory);
    finish_machine_capture(directory);
    check(capture_journal_value(inspect_machine_capture(directory,true,&journal)) ==
          capture_journal_value(journal));
    check(stat((directory/"release.pstream").c_str(),&after) == 0 &&
          before.st_ino == after.st_ino);
    rejects([&] { ReadyMachineCapture source(directory); });
    rejects([&] { (void)resume_machine_capture(directory,journal,{}); });
    const auto refuse = [&](const CaptureJournal& state) {
        write("release.pstream",state);
        rejects([&] { finish_machine_capture(directory); });
        rejects([&] { (void)inspect_machine_capture(directory,true,&journal); });
    };
    // Neither missing evidence nor partial completion authorizes retirement.
    std::filesystem::remove(directory/"release.pstream");
    rejects([&] { finish_machine_capture(directory); });
    refuse(journal);
    auto partial = released;
    set(partial.reservation,"snapshot_released",n(0));
    refuse(partial);
    partial = released;
    set(std::get<Value::Array>(
        std::get<Value::Object>(partial.reservation.data).at("extras").data).front(),"released",n(0));
    refuse(partial);
    // Complete flags do not replace exact capture/ownership evidence.
    auto foreign = released;
    foreign.id = std::string(32,'f');
    refuse(foreign);
    foreign = released;
    set(foreign.snapshot,"uuid",Value{std::string(32,'e')});
    refuse(foreign);
    foreign = released;
    set(foreign.reservation,"snapshot_released",n(2));
    refuse(foreign);
    foreign = released;
    set(foreign.reservation,"extras",Value{Value::Array{}});
    refuse(foreign);
    foreign = released;
    auto& foreign_extras = std::get<Value::Array>(
        std::get<Value::Object>(foreign.reservation.data).at("extras").data);
    foreign_extras.push_back(foreign_extras.front());
    refuse(foreign);
    auto invalid = journal;
    set(invalid.reservation,"snapshot_released",n(2));
    write("capture.pstream",invalid);
    std::filesystem::remove(directory/"release.pstream");
    rejects([&] { finish_machine_capture(directory); });
    rejects([&] { (void)inspect_machine_capture(directory,true,&invalid); });
    invalid = released;
    set(invalid.reservation,"snapshot_attempted",n(0));
    write("capture.pstream",invalid);
    rejects([&] { finish_machine_capture(directory); });
    rejects([&] { (void)inspect_machine_capture(directory,true,&invalid); });
    // A release overlay can only advance an already recorded release.
    set(journal.reservation,"snapshot_released",n(1));
    write("capture.pstream",journal);
    set(released.reservation,"snapshot_released",n(0));
    refuse(released);
}
void tracking_cleanup_after_renumber() {
    char pattern[] = "/tmp/opensabba-retention-reboot-XXXXXX";
    const auto made = mkdtemp(pattern);
    if (!made) throw Error("cannot create tracking retention fixture");
    const std::filesystem::path parent(made);
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::error_code ignored; std::filesystem::remove_all(path,ignored); }
    } cleanup{parent};
    auto journal = ready();
    journal.schema = 5;
    const auto directory = parent/("capture-"+journal.id);
    std::filesystem::create_directory(directory);
    check(chmod(directory.c_str(),0700) == 0);
    const auto image = directory/"raw.cache", cow = parent/"old-cow";
    { std::ofstream out(image); out << "cache"; }
    // A nonempty directory makes remove(3) fail. the official agent ignores that failure
    // after committing history deletion, without blocking the next resource.
    std::filesystem::create_directory(cow);
    { std::ofstream out(cow/"entry"); out << "unlink failure fixture"; }
    const Value volume{Value::Object{{"device",Value{std::string("/dev/testvg/root")}}}};
    set(journal.plan,"root",volume);
    for (const auto* key : {"selected_extra","additional_disks"}) set(journal.plan,key,Value{Value::Array{}});
    set(journal.reservation,"directory",Value{directory.string()});
    struct stat raw_directory_stat{};
    check(stat(directory.c_str(),&raw_directory_stat) == 0);
    set(journal.reservation,"raw_storage_ready",n(1));
    set(journal.reservation,"raw_directory",Value{directory.string()});
    set(journal.reservation,"raw_directory_inode",n(raw_directory_stat.st_ino));
    set(journal.reservation,"raw_cache_policy",Value{Value::Object{{"cached_enabled",n(0)}}});
    set(journal.reservation,"minor",n(6));
    set(journal.reservation,"extras",Value{Value::Array{}});
    set(journal.reservation,"snapshot_released",n(1));
    set(journal.reservation,"tracking_filesystem_uuid",Value{std::string("same-filesystem-after-reboot")});
    set(journal.reservation,"cow_path",Value{cow.string()});
    set(journal.reservation,"cow_relative",Value{std::string("/.synosnap_data/old")});
    const Value stale{Value::Object{{"device",n(2064)},{"inode",n(1)}}};
    set(journal.reservation,"cow",stale);
    set(journal.reservation,"output",stale);
    auto old = journal.reservation;
    set(old,"device",Value{std::string("/dev/testvg/root")});
    auto base = old;
    set(base,"cow_relative",Value{std::string("/.synosnap_data/base")});
    MachineTrackingDatabase history;
    history.add(old); history.add(base);
    MachineTrackingDatabaseStore store(parent/"tracking-history.pstream");
    store.save(history);
    const auto bytes = encode(capture_journal_value(journal));
    { std::ofstream out(directory/"capture.pstream",std::ios::binary);
      out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size()); }
    check(chmod((directory/"capture.pstream").c_str(),0600) == 0);
    // Cache integrity is private bookkeeping, checked after official agent resource
    // deletion. Its failure must never strand the eligible history rows.
    check(chmod(image.c_str(),0644) == 0);
    rejects([&] { prune_machine_capture(journal); });
    check(store.load().minors() == std::vector<std::uint32_t>{6});
    check(MachineTrackingHistory(directory).retired(old));
    check(std::filesystem::exists(cow/"entry"));
    check(chmod(image.c_str(),0600) == 0);
    prune_machine_capture(journal);
    check(!std::filesystem::exists(image));
    check(store.load().minors() == std::vector<std::uint32_t>{6});
    prune_machine_capture(journal);
}
void pruned_artifact() {
    char pattern[] = "/tmp/opensabba-retention-XXXXXX";
    const char* created = mkdtemp(pattern);
    if (!created) throw Error("cannot create retention fixture");
    const std::filesystem::path parent(created);
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::error_code ignored; std::filesystem::remove_all(path,ignored); }
    } cleanup{parent};
    auto journal = ready();
    journal.schema = 5;
    set(journal.reservation,"snapshot_released",n(0));
    set(journal.reservation,"extras",Value{Value::Array{}});
    const auto directory = parent/("capture-"+journal.id),
               image = directory/"raw.cache";
    std::filesystem::create_directory(directory);
    check(chmod(directory.c_str(),0700) == 0);
    { std::ofstream out(image); out << "owned image"; }
    check(chmod(image.c_str(),0400) == 0);
    struct stat st{};
    check(stat(image.c_str(),&st) == 0);
    set(journal.reservation,"directory",Value{directory.string()});
    struct stat raw_directory_stat{};
    check(stat(directory.c_str(),&raw_directory_stat) == 0);
    set(journal.reservation,"raw_storage_ready",n(1));
    set(journal.reservation,"raw_directory",Value{directory.string()});
    set(journal.reservation,"raw_directory_inode",n(raw_directory_stat.st_ino));
    set(journal.reservation,"raw_cache_policy",Value{Value::Object{{"cached_enabled",n(0)}}});
    set(journal.reservation,"output",Value{Value::Object{
        {"device",n(st.st_dev)},{"inode",n(st.st_ino)}}});
    set(journal.reservation,"cow",Value{Value::Object{
        {"device",n(st.st_dev)},{"inode",n(1)}}}); // Already released by synosnap.
    const auto save = [&] {
        const auto bytes = encode(capture_journal_value(journal));
        const auto path = directory/"capture.pstream";
        std::ofstream out(path,std::ios::binary|std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size()); out.close();
        check(chmod(path.c_str(),0600) == 0);
        {
            auto released = journal;
            set(released.reservation,"snapshot_released",n(1));
            const auto state = encode(capture_journal_value(released));
            const auto release = directory/"release.pstream";
            std::ofstream output(release,std::ios::binary|std::ios::trunc);
            output.write(reinterpret_cast<const char*>(state.data()),state.size()); output.close();
            check(chmod(release.c_str(),0600) == 0);
        }
    };
    save();
    // the official agent cleanup unlinks the reserved pathname without reopening payload
    // identity as a prerequisite. A stale saved kernel device (reboot disk
    // renumbering) and a replaced private cache do not strand COW history.
    auto stale = std::get<Value::Object>(journal.reservation.data).at("output");
    set(stale,"device",n(st.st_dev+1));
    set(journal.reservation,"output",stale);
    save();
    std::filesystem::rename(image,directory/"original.img");
    { std::ofstream out(image); out << "replacement"; }
    check(chmod(image.c_str(),0400) == 0);
    prune_machine_capture(journal);
    check(std::filesystem::exists(directory/"original.img"));
    check(!std::filesystem::exists(image) && std::filesystem::exists(directory/"capture.pstream"));
    prune_machine_capture(journal); // Deleted marker makes replay idempotent.
    // Simulate death after unlink but before the final tombstone.
    Value marker{Value::Object{{"format",n(1)},{"capture_id",Value{journal.id}},
        {"state",Value{std::string("delete-pending")}}}};
    { const auto bytes = encode(marker); std::ofstream out(directory/"retention.pstream",std::ios::binary|std::ios::trunc);
      out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size()); }
    prune_machine_capture(journal);
    // Manual deletion before the first retention pass: the capture journal
    // remains, while the primary, additional-disk and LV images are absent.
    std::filesystem::remove(directory/"retention.pstream");
    const auto identity = Value{Value::Object{{"device",n(st.st_dev)},{"inode",n(st.st_ino)}}};
    set(journal.reservation,"disks",Value{Value::Array{
        Value{Value::Object{{"output",identity}}}}});
    save();
    prune_machine_capture(journal);
    const auto marker_path = directory/"retention.pstream";
    std::ifstream input(marker_path,std::ios::binary);
    const Bytes marker_bytes{std::istreambuf_iterator<char>(input),std::istreambuf_iterator<char>()};
    const auto deleted = decode(marker_bytes);
    check(std::get<Value::Object>(deleted.data).at("state") == Value{std::string("deleted")});
    struct stat before{}, after{};
    check(stat(marker_path.c_str(),&before) == 0);
    prune_machine_capture(journal);
    check(stat(marker_path.c_str(),&after) == 0 && before.st_ino == after.st_ino);
}


#endif
}
int main() {
    try {
        const auto first_cow = machine_tracking_cow_name(1700000000);
        const auto second_cow = machine_tracking_cow_name(1700000000);
        check(first_cow != second_cow && first_cow.starts_with("1700000000_") &&
            first_cow.size() == 47 && first_cow[25] == '4' &&
            std::string_view("89ab").find(first_cow[30]) != std::string_view::npos);
        std::size_t reads = 0;
        bool valid = true;
        ImageSource original(512,[&](auto,auto count,auto) { ++reads; return Bytes(count,0); },
            [&] { if (!valid) throw Error("snapshot disappeared"); });
        auto journal = ready();
        verify_machine_artifact(journal,original);
        for (auto phase : {CapturePhase::prepared,CapturePhase::seal_intent,
                           CapturePhase::recovery_required,CapturePhase::aborted}) {
            auto changed = journal; changed.phase = phase;
            rejects([&] { verify_machine_artifact(changed,original); });
        }
        auto changed = journal;
        changed.failure = "unconfirmed cleanup";
        rejects([&] { verify_machine_artifact(changed,original); });
        check(reads == 0);
        changed = journal; set(changed.reservation,"snapshot_time",n(0));
        rejects([&] { verify_machine_artifact(changed,original); });
        for (auto key : {"length","sector_size"}) {
            changed = journal; set(changed.artifact,key,n(4096));
            rejects([&] { verify_machine_artifact(changed,original); });
        }
        ImageSource immutable(Bytes(512,0));
        rejects([&] { verify_machine_artifact(journal,immutable); });
        valid = false;
        rejects([&] { verify_machine_artifact(journal,original); });
        valid = true;
        bool cancelled = false;
        try { verify_machine_artifact(journal,original,[] { return true; }); }
        catch (const Cancelled&) { cancelled = true; }
        check(cancelled);
        verify_machine_artifact(journal,original,[] { return false; });
        automatic_capture_policy();
        complete_interval_cbt();
        persistent_tracking_ranges();
        resized_tracking_volume();
        fresh_interval_coordinates();
        reject_earlier_schema();
        snapshot_rotation();
#ifdef __linux__
        base_rotation_keeps_absent_origins();
#endif
#ifdef __linux__
        released_capture_completion();
        pruned_artifact();
        tracking_cleanup_after_renumber();
#endif
        std::cout << "Machine artifact integrity tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
