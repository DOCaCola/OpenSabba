#include "opensabba/machine.hpp"
#include "opensabba/capture.hpp"
#include <algorithm>
#include <iostream>
#include <source_location>

using namespace opensabba;
using namespace opensabba::pstream;
namespace {
constexpr std::uint64_t mib = 1024*1024;
void check(bool okay, std::source_location at = std::source_location::current()) {
    if (!okay) throw Error("raw cache test failed at line "+std::to_string(at.line()));
}
template<class F> void rejects(F operation) {
    bool rejected = false;
    try { operation(); } catch (const Error&) { rejected = true; }
    check(rejected);
}
Value plan() {
    ImageLayout table{ImageLayout::Scheme::mbr,512,26*mib,"disk",
        {{1,2*mib,8*mib,0,0x82},{2,12*mib,8*mib,0,0x83}}};
    return Value{Value::Object{{"layout",layout_value(table)},
        {"layout_policy",Value{std::string("linux-layout-v1")}},
        {"volume_policy",Value{std::string("linux-bare-metal-v1")}},
        {"swap_page_size",Value{std::uint64_t{4096}}},
        {"selected_extra",Value{Value::Array{Value{Value::Object{
            {"offset",Value{12*mib}},{"length",Value{8*mib}}}}}}},
        {"excluded",Value{Value::Array{Value{Value::Object{
            {"partition",Value{std::uint64_t{1}}},{"offset",Value{2*mib}},
            {"length",Value{8*mib}},{"filesystem",Value{std::string("swap")}},
            {"mount_path",Value{std::string{}}}}}}}}}};
}
void fallback() {
    auto disk = plan(), durable = disk;
    const auto candidates = machine_cached_regions(disk);
    unsigned copies = 0, saves = 0;
    machine_cache_raw_regions(disk,[&](const auto& region) {
        ++copies;
        if (region.offset == 0 || region.label == "swap_partition_body")
            throw MachineRawCacheCopyError("injected read or partial write failure");
    },[] {},[&] {
        ++saves;
        validate_machine_raw_cache_failures(disk);
        durable = decode(encode(disk));
    });
    check(copies == candidates.size() && saves == 2 && durable == disk);
    check(machine_layout_regions(durable).front().type == 2);
    const auto& volume = std::get<Value::Array>(
        std::get<Value::Object>(durable.data).at("excluded").data).front();
    const auto swap = machine_partition_regions(durable,volume);
    check(swap[0].type == 3 && swap[1].type == 5);
    check(machine_cached_regions(durable).size()+2 == candidates.size());
    const auto unused = machine_unused_extents(durable);
    check(unused.size() == 1 && unused[0].offset == 2*mib+4096 &&
        unused[0].length == 8*mib-4096);
    const auto schedule = machine_additional_static_regions(durable);
    check(std::any_of(schedule.begin(),schedule.end(),[&](const auto& region) {
        return region.offset == unused[0].offset && region.length == unused[0].length && !region.read_source;
    }));
    // An incremental must replace an older cached swap body with changed-free
    // information; every retained raw fallback still has no CBT context.
    DeltaPlan delta{26*mib,0,{{0,26*mib,false}}};
    delta.filesystem_allocation = true;
    machine_force_raw_changes(delta,durable);
    for (const auto& range : {ChangedExtent{0,mib},unused.front()})
        check(std::any_of(delta.ranges.begin(),delta.ranges.end(),[&](const auto& entry) {
            return entry.changed && entry.offset <= range.offset &&
                entry.offset+entry.length >= range.offset+range.length;
        }));
    const auto reread = machine_reread_ranges(durable,26*mib);
    check(std::none_of(reread.begin(),reread.end(),[&](const auto& range) {
        return range.offset < 10*mib && range.offset+range.length > 2*mib+4096;
    }));
    // Header failure retains the first page as live raw data.
    auto header_failure = plan();
    machine_cache_raw_regions(header_failure,[](const auto& region) {
        if (region.label == "swap_partition_header") throw MachineRawCacheCopyError("read");
    },[] {},[] {});
    check(machine_partition_regions(header_failure,volume)[0].type == 2 &&
        machine_partition_regions(header_failure,volume)[1].type == 3);
    auto bad = durable;
    auto& failures = std::get<Value::Array>(
        std::get<Value::Object>(bad.data).at("raw_cache_failures").data);
    failures.push_back(failures.front());
    rejects([&] { validate_machine_raw_cache_failures(bad); });
    failures.pop_back();
    std::get<Value::Object>(failures.front().data)["length"] = Value{mib+512};
    rejects([&] { validate_machine_raw_cache_failures(bad); });
}
void fatal_errors() {
    for (unsigned failure = 0; failure != 6; ++failure) {
        auto disk = plan(), durable = disk;
        unsigned verifications = 0, saves = 0;
        rejects([&] {
            machine_cache_raw_regions(disk,[&](const auto&) {
                if (failure == 0) throw CaptureStopRequested();
                if (failure == 1) throw CaptureUncertain("foreign source");
                if (failure == 2) throw Error("ownership failure");
                throw MachineRawCacheCopyError("copy I/O");
            },[&] {
                ++verifications;
                if (failure == 3 && verifications == 2) throw CaptureStopRequested();
                if (failure == 4 && verifications == 2) throw CaptureUncertain("lost boot lease");
            },[&] {
                ++saves;
                if (failure == 5) throw CapturePersistenceError("journal fsync");
                durable = disk;
            });
        });
        check(durable == plan() && saves == (failure == 5 ? 1U : 0U));
    }
}
}
int main() {
    try { fallback(); fatal_errors(); std::cout << "raw cache fallback passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
