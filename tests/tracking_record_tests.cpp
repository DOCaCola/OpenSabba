#include "opensabba/tracking_record.hpp"
#include <iostream>
#include <source_location>
#include <utility>
#include <vector>

using namespace opensabba;
using namespace opensabba::pstream;
namespace {
void check(bool ok, std::source_location at = std::source_location::current()) {
    if (!ok) throw Error("tracking invariant failed at "+std::to_string(at.line()));
}
template<class F> void rejects(F operation) {
    bool rejected = false;
    try { operation(); } catch (const std::exception&) { rejected = true; }
    check(rejected);
}
Value& field(Value& value, const char* key) { return std::get<Value::Object>(value.data).at(key); }
const Value& field(const Value& value, const char* key) { return std::get<Value::Object>(value.data).at(key); }
void set(Value& value, const char* key, Value next) {
    std::get<Value::Object>(value.data)[key] = std::move(next);
}
Value integer(std::uint64_t value) { return Value{value}; }
Value string(std::string value) { return Value{std::move(value)}; }
constexpr auto old_path = "/.synosnap_data/1700000000_11111111-1111-4111-8111-111111111111";
constexpr auto new_path = "/.synosnap_data/1700001000_22222222-2222-4222-8222-222222222222";
Value volume() {
    return Value{Value::Object{{"filesystem_uuid",string("6445f0de-2bf8-41ce-8627-486bda099468")},
        {"device",string("/dev/dm-0")},{"mount_path",string("/")}}};
}
Value snapshot(std::string path = old_path) {
    return Value{Value::Object{{"minor",integer(0)},{"uuid",string("401a2bf9a42e4597ba7278fb03ebc337")},
        {"sequence",integer(7)},{"origin_path",string("/dev/dm-0")},{"cow_path",string(std::move(path))},
        {"snapshot_mode",integer(0)},{"active",integer(1)},{"unverified",integer(0)},
        {"cancelled",integer(0)},{"error_code",string("0")}}};
}
Value reservation(bool old = false) {
    const auto path = old ? old_path : new_path;
    return Value{Value::Object{{"minor",integer(0)},{"cow_relative",string(path)},
        {"cow_path",string(path)},{"tracking_filesystem_uuid",field(volume(),"filesystem_uuid")},
        {"cow",Value{Value::Object{{"inode",integer(old ? 101 : 102)},{"device",integer(253)}}}}}};
}
Value unverified() {
    auto result = snapshot();
    set(result,"uuid",string(std::string(32,'0')));
    set(result,"sequence",integer(0));
    set(result,"active",integer(0));
    set(result,"unverified",integer(1));
    set(result,"error_code",string("-22"));
    return result;
}
Value reserved_reload() {
    auto result = unverified();
    set(result,"snapshot_mode",integer(1));
    return result;
}
Value reset_reservation(bool missing = false) {
    auto result = reservation();
    auto prior = reservation(true);
    set(prior,"snapshot",unverified());
    set(prior,"durable_owner",machine_tracking_owner(volume(),reservation(true),snapshot()));
    if (missing) set(prior,"cow_missing",integer(1));
    set(result,"prior",prior);
    return result;
}
// Models committed kernel mutations and the single durable reload file.
// Crashes can occur before/after every driver/retirement operation. Boot uses
// only the committed reload file, never an independent journal or.tmp file.
struct Control final : MachineTrackingControl {
    std::optional<Value> slot = unverified();
    std::string record = machine_tracking_record(
        machine_tracking_owner(volume(),reservation(true),snapshot()),"/usr/bin/opensabba",false);
    std::string captured_record;
    int releases = 0, creates = 0, renewals = 0, retirements = 0;
    int point = 0, fail = -1;
    bool release_stuck = false;
    bool prior_cow_replaced = false;
    bool prior_cow_missing = false;
    int compressions = 0;
    int cow_verifications = 0;
    void boundary() { if (++point == fail) throw Error("process death"); }
    std::optional<Value> information(std::uint32_t) override {
        boundary();
        auto result = slot;
        boundary();
        return result;
    }
    void verify_prior_cow(const Value&) override {
        boundary();
        if (prior_cow_replaced) throw Error("prior COW inode changed");
        ++cow_verifications;
        boundary();
    }
    Value close_prior(const Value&, const Value&, const Value&) override {
        ++compressions;
        if (prior_cow_missing) throw SnapshotPreviousCowError("previous COW missing",2);
        return Value{Bytes{0}};
    }
    void release(const Value& expected) override {
        boundary();
        if (slot) {
            check(field(*slot,"cow_path") == field(expected,"cow_path"));
            ++releases;
            if (!release_stuck) slot.reset();
        }
        boundary();
    }
    void retire_record(const Value&, const Value&) override {
        boundary();
        record.clear();
        ++retirements;
        boundary();
    }
    void create(std::uint32_t, const std::string&, const std::string& cow, std::uint64_t) override {
        boundary();
        // Production fresh setup queries/destroys its history-selected minor
        // before setup; kernel occupancy alone does not reserve this minor.
        // Snapshot boundary precedes publication of its own reload record.
        captured_record = record;
        slot = snapshot(cow);
        set(*slot,"uuid",string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        set(*slot,"sequence",integer(1));
        set(*slot,"snapshot_mode",integer(1));
        ++creates;
        boundary();
    }
    void renew(const Value& expected, const std::string& cow, std::uint64_t) override {
        boundary();
        captured_record = record;
        slot = expected;
        set(*slot,"cow_path",string(cow));
        set(*slot,"sequence",integer(std::get<std::uint64_t>(field(expected,"sequence").data)+1));
        set(*slot,"snapshot_mode",integer(1));
        ++renewals;
        boundary();
    }
    void publish(const Value& reserved) {
        check(slot.has_value());
        record = machine_tracking_record(machine_tracking_owner(volume(),reserved,*slot),"/usr/bin/opensabba",true);
    }
    void reboot() {
        const auto owner = machine_tracking_record_owner(record);
        slot = owner ? std::optional<Value>{unverified()} : std::nullopt;
        if (slot) {
            set(*slot,"minor",field(*owner,"minor"));
            set(*slot,"cow_path",field(*owner,"cow_relative"));
        }
    }
};
void record_tests() {
    const auto owner = machine_tracking_owner(volume(),reservation(true),snapshot());
    for (const bool active : {false,true}) {
        const auto record = machine_tracking_record(owner,"/usr/bin/sabba's snapshot reload-test",active);
        check(machine_tracking_record_owner(record) == owner);
        auto tampered = record;
        tampered.replace(tampered.rfind(old_path),std::string(old_path).size(),new_path);
        rejects([&] { machine_tracking_record_owner(tampered); });
        rejects([&] { machine_tracking_record_owner(record.substr(0,40)); });
    }
    check(!machine_tracking_record_owner("#!/bin/sh\nexec /usr/bin/opensabba snapshot reload-incremental\n"));
    for (const auto key : {"minor","cow_relative","filesystem_uuid"}) {
        auto wrong = owner;
        set(wrong,key,key == std::string("minor") ? integer(1) : string("foreign"));
        rejects([&] { require_machine_tracking_owner(wrong,volume(),snapshot()); });
    }
    auto foreign = snapshot();
    set(foreign,"uuid",string("ffffffffffffffffffffffffffffffff"));
    for (const auto error : {"0","-28"}) {
        set(foreign,"error_code",string(error));
        rejects([&] { require_machine_tracking_owner(owner,volume(),foreign); });
    }
    require_machine_tracking_owner(owner,volume(),unverified());
    check(machine_tracking_owner_reservation(owner,reservation(true)));
    auto replaced = reservation(true);
    set(field(replaced,"cow"),"inode",integer(999));
    check(!machine_tracking_owner_reservation(owner,replaced));
    set(replaced,"tracking_filesystem_uuid",string("foreign-filesystem"));
    check(!machine_tracking_owner_reservation(owner,replaced));
    check(!machine_tracking_owner_reservation(owner,reservation()));
    const Value inode{Value::Object{{"inode",integer(101)},{"filesystem_uuid",field(volume(),"filesystem_uuid")}}};
    const auto recovered = machine_tracking_recovery_prior(owner,volume(),unverified(),inode);
    check(field(recovered,"durable_owner") == owner);
    check(!std::get<Value::Object>(recovered.data).contains("capture_id"));
    check(field(machine_tracking_recovery_prior(owner,volume(),snapshot(),inode),"snapshot") == snapshot());
    check(std::get<Value::Object>(machine_tracking_recovery_prior(owner,volume(),snapshot(),{}).data).contains("cow_missing"));
    auto wrong_inode = inode;
    set(wrong_inode,"inode",integer(333));
    rejects([&] { machine_tracking_recovery_prior(owner,volume(),unverified(),wrong_inode); });
    set(wrong_inode,"inode",integer(101));
    set(wrong_inode,"filesystem_uuid",string("foreign"));
    rejects([&] { machine_tracking_recovery_prior(owner,volume(),unverified(),wrong_inode); });
    for (const bool failed : {false,true}) {
        auto other = snapshot();
        if (failed) set(other,"error_code",string("-28"));
        set(other,"uuid",string("ffffffffffffffffffffffffffffffff"));
        rejects([&] { machine_tracking_recovery_prior(owner,volume(),other,inode); });
        other = failed ? unverified() : snapshot();
        set(other,"cow_path",string(new_path));
        rejects([&] { machine_tracking_recovery_prior(owner,volume(),other,inode); });
        other = failed ? unverified() : snapshot();
        set(other,"origin_path",string("/dev/foreign"));
        rejects([&] { machine_tracking_recovery_prior(owner,volume(),other,inode); });
    }
    auto renumbered = volume();
    set(renumbered,"device",string("/dev/dm-7"));
    auto remapped = unverified();
    set(remapped,"origin_path",string("/dev/dm-7"));
    rejects([&] { machine_tracking_recovery_prior(owner,renumbered,remapped,inode); });
}
void reservation_owner_tests() {
    const auto owner = machine_tracking_reservation_owner(volume(),reservation(true));
    check(field(owner,"phase") == string("reserved"));
    check(!std::get<Value::Object>(owner.data).contains("snapshot"));
    rejects([&] { machine_tracking_record(owner,"/usr/bin/opensabba",true); });
    // Reservation evidence survives only in independent capture journals;
    // it cannot become an executable boot command before successful setup.
    const auto record = machine_tracking_record(
        machine_tracking_owner(volume(),reservation(true),snapshot()),"/usr/bin/opensabba",true);
    rejects([&] { machine_tracking_record(owner,"/usr/bin/opensabba",false); });
    auto invented = owner;
    set(invented,"snapshot",field(machine_tracking_owner(volume(),reservation(true),snapshot()),"snapshot"));
    rejects([&] { machine_tracking_record(invented,"/usr/bin/opensabba",true); });
    auto wrong_phase = owner;
    set(wrong_phase,"phase",string("initialized"));
    rejects([&] { machine_tracking_record(wrong_phase,"/usr/bin/opensabba",true); });
    auto wrong_command = record;
    wrong_command.replace(wrong_command.rfind(" 0\n"),3," 1\n");
    rejects([&] { machine_tracking_record_owner(wrong_command); });
    const auto failed = reserved_reload();
    require_machine_tracking_owner(owner,volume(),failed);
    rejects([&] { require_machine_tracking_owner(owner,volume(),unverified()); });
    auto pending_mount = failed;
    set(pending_mount,"error_code",string("0"));
    rejects([&] { require_machine_tracking_owner(owner,volume(),pending_mount); });
    auto active_failed = failed;
    set(active_failed,"active",integer(1));
    rejects([&] { require_machine_tracking_owner(owner,volume(),active_failed); });
    auto verified_failed = failed;
    set(verified_failed,"unverified",integer(0));
    rejects([&] { require_machine_tracking_owner(owner,volume(),verified_failed); });
    auto healthy = snapshot();
    set(healthy,"snapshot_mode",integer(1));
    rejects([&] { require_machine_tracking_owner(owner,volume(),healthy); });
    set(healthy,"error_code",string("-28"));
    rejects([&] { require_machine_tracking_owner(owner,volume(),healthy); });
    const Value cow{Value::Object{{"inode",integer(101)},
        {"filesystem_uuid",field(volume(),"filesystem_uuid")}}};
    auto prior = machine_tracking_recovery_prior(owner,volume(),failed,cow);
    auto reserved = reservation();
    set(reserved,"prior",prior);
    require_machine_tracking_owner(owner,volume(),failed);
    Control restored;
    restored.slot = failed;
    restored.record = record;
    const auto reset = transition_machine_tracking(reserved,volume(),0,restored);
    check(restored.releases == 1 && restored.creates == 1 && restored.renewals == 0);
    check(field(reset,"sequence") == integer(1));
    check(field(reserved,"tracking_recovery") == string("durable-owner-fresh-chain"));
    check(!std::get<Value::Object>(reserved.data).contains("changes"));
    check(!std::get<Value::Object>(reserved.data).contains("previous_capture_id"));
    for (const auto key : {"minor","origin_path","cow_path"}) {
        auto foreign = failed;
        set(foreign,key,std::string(key) == "minor" ? integer(1) : string("foreign"));
        rejects([&] { machine_tracking_recovery_prior(owner,volume(),foreign,cow); });
    }
    // Fresh setup has no pre-publication boot record. A crash after its
    // ioctl leaves only independent journal evidence; reboot cannot execute a
    // command for a reservation which has never entered successful history.
    Control fresh;
    fresh.slot.reset();
    fresh.record.clear();
    auto new_reservation = reservation();
    const auto new_owner = machine_tracking_reservation_owner(volume(),new_reservation);
    const auto current = transition_machine_tracking(new_reservation,volume(),0,fresh);
    check(fresh.creates == 1 && fresh.releases == 0 && fresh.renewals == 0);
    check(fresh.captured_record.empty() && fresh.record.empty());
    rejects([&] { require_machine_tracking_owner(new_owner,volume(),current); });
    fresh.reboot();
    check(!fresh.slot);
    // Every modeled interruption in reserved-owner reset preserves only the
    // exact reservation or its committed retirement, never old-hook authority.
    Control completed;
    completed.slot = failed;
    completed.record = record;
    auto completed_reservation = reservation();
    set(completed_reservation,"prior",prior);
    transition_machine_tracking(completed_reservation,volume(),0,completed);
    for (int fail = 1; fail <= completed.point; ++fail) {
        Control crash;
        crash.slot = failed;
        crash.record = record;
        crash.fail = fail;
        auto pending = reservation();
        set(pending,"prior",prior);
        rejects([&] { transition_machine_tracking(pending,volume(),0,crash); });
        const auto retained = machine_tracking_record_owner(crash.record);
        check(!retained || retained == machine_tracking_record_owner(record));
        check(!std::get<Value::Object>(pending.data).contains("previous_capture_id"));
        check(!std::get<Value::Object>(pending.data).contains("changes"));
    }
}
void transition_tests() {
    {
        Control absent;
        absent.slot.reset();
        auto saved = reset_reservation();
        transition_machine_tracking(saved,volume(),0,absent);
        check(absent.releases == 0 && absent.retirements == 1 && absent.creates == 1);
        check(absent.captured_record.empty());
    }
    for (const bool missing : {false,true}) {
        Control control;
        auto reserved = reset_reservation(missing);
        const auto result = transition_machine_tracking(reserved,volume(),0,control);
        check(field(result,"sequence") == integer(1));
        check(control.releases == 1 && control.creates == 1 && control.renewals == 0);
        check(control.captured_record.empty());
        check(field(reserved,"tracking_recovery") == string("durable-owner-fresh-chain"));
        const auto& properties = std::get<Value::Object>(reserved.data);
        check(!properties.contains("previous_capture_id") && !properties.contains("changes"));
        control.publish(reserved);
        check(machine_tracking_record_owner(control.record) ==
              machine_tracking_owner(volume(),reserved,result));
    }
    // Valid external history keeps its existing healthy renewal branch and
    // does not need durable-owner recovery.
    Control normal;
    normal.slot = snapshot();
    auto reserved = reservation();
    auto prior = reservation(true);
    set(prior,"snapshot",snapshot());
    set(prior,"owner_snapshot",snapshot());
    set(prior,"capture_id",string("retained-capture"));
    set(prior,"directory",string("/captures/retained-capture"));
    set(reserved,"prior",prior);
    const auto result = transition_machine_tracking(reserved,volume(),0,normal);
    check(normal.renewals == 1 && normal.releases == 0 && normal.creates == 0);
    check(field(result,"sequence") == integer(8));
    const auto captured_owner = machine_tracking_record_owner(normal.captured_record);
    check(captured_owner == machine_tracking_owner(volume(),reservation(true),snapshot()));
    // Publication changes the live file; the captured old record and old COW
    // inode still agree. A pending uncommitted replacement is not a boot record.
    const auto pending = machine_tracking_record(machine_tracking_owner(volume(),reserved,result),"/usr/bin/opensabba",true);
    check(normal.record == normal.captured_record);
    normal.publish(reserved);
    check(normal.record == pending && normal.captured_record != normal.record);
    check(field(field(*captured_owner,"cow"),"inode") == integer(101));
    // Known journal-owned bad state retains the ordinary fresh-chain branch.
    Control bad;
    auto owned = reservation();
    set(prior,"snapshot",unverified());
    set(owned,"prior",prior);
    transition_machine_tracking(owned,volume(),0,bad);
    check(bad.releases == 1 && bad.creates == 1 && bad.renewals == 0);
    // No history/owner takes official agent's fresh setup path regardless of the
    // history-selected minor's occupancy; it never invents CBT ancestry.
    for (const bool failed : {false,true}) {
        Control foreign;
        foreign.slot = failed ? unverified() : snapshot();
        foreign.record.clear();
        auto fresh = reservation();
        transition_machine_tracking(fresh,volume(),0,foreign);
        check(foreign.releases == 0 && foreign.creates == 1 && foreign.record.empty());
        check(!std::get<Value::Object>(fresh.data).contains("previous_capture_id"));
        check(!std::get<Value::Object>(fresh.data).contains("changes"));
        foreign.slot = failed ? unverified() : snapshot();
        foreign.creates = 0;
        // Independently saved exact prior evidence remains authoritative when
        // the boot command is missing or its basename has been overwritten.
        auto saved = reset_reservation();
        if (!failed) set(field(saved,"prior"),"snapshot",snapshot());
        transition_machine_tracking(saved,volume(),0,foreign);
        check(foreign.releases == (failed ? 1 : 0));
        check(foreign.creates == (failed ? 1 : 0));
        check(foreign.renewals == (failed ? 0 : 1));
    }
    Control changed;
    set(*changed.slot,"cow_path",string("/.synosnap_data/foreign"));
    auto wrong = reset_reservation();
    rejects([&] { transition_machine_tracking(wrong,volume(),0,changed); });
    check(changed.releases == 0);
    Control healthy;
    healthy.slot = snapshot();
    auto healthy_reset = reset_reservation();
    set(field(healthy_reset,"prior"),"snapshot",snapshot());
    transition_machine_tracking(healthy_reset,volume(),0,healthy);
    check(healthy.releases == 0 && healthy.renewals == 1 && healthy.creates == 0);
    check(healthy.cow_verifications == 1);
    check(field(healthy_reset,"tracking_recovery") == string("durable-owner-renewed-without-history"));
    check(!std::get<Value::Object>(healthy_reset.data).contains("previous_capture_id"));
    check(!std::get<Value::Object>(healthy_reset.data).contains("changes"));
    Control stuck;
    stuck.release_stuck = true;
    auto stuck_reserved = reset_reservation();
    rejects([&] { transition_machine_tracking(stuck_reserved,volume(),0,stuck); });
    check(stuck.creates == 0 && stuck.retirements == 0 && !stuck.record.empty());
}
Value history_row(std::string device, std::uint64_t minor, std::uint64_t sequence,
                  std::string capture) {
    auto prior = reservation(true);
    auto saved = snapshot();
    set(saved,"minor",integer(minor));
    set(saved,"sequence",integer(sequence));
    set(saved,"origin_path",string(device));
    set(prior,"minor",integer(minor));
    set(prior,"device",string(device));
    set(prior,"snapshot",saved);
    set(prior,"capture_id",string(capture));
    set(prior,"directory",string("/captures/"+capture));
    return prior;
}
void logical_origin_history_tests() {
    const auto lv = [](std::string name, std::string kernel) {
        auto result = volume();
        set(result,"logical_path",string("/dev/testvg/"+name));
        set(result,"lv_uuid",string(name+"-lv-uuid"));
        set(result,"device",string(kernel));
        return result;
    };
    auto root = lv("root","/dev/dm-3"), absent = lv("absent","/dev/dm-0");
    MachineTrackingDatabase history;
    history.add(history_row("/dev/testvg/root",0,7,"root"));
    history.add(history_row("/dev/testvg/absent",2,4,"absent"));
    history.add(history_row("/dev/testvg/scratch",3,11,"scratch"));
    const auto absent_before = *history.last(absent);
    Control root_driver;
    root_driver.slot = field(*history.last(root),"snapshot");
    set(*root_driver.slot,"origin_path",field(root,"device"));
    const auto prior = prepare_machine_tracking(history,root,root_driver);
    check(prior && field(*prior,"minor") == integer(0));
    auto reserved = reservation();
    set(reserved,"prior",*prior);
    const auto current = transition_machine_tracking(reserved,root,0,root_driver);
    check(root_driver.renewals == 1 && root_driver.releases == 0 &&
          field(current,"sequence") == integer(8) && field(current,"origin_path") == field(root,"device"));
    check(*history.last(absent) == absent_before); // No action for a detached origin.
    // Reattachment at another dm number still selects the exact saved bdev.
    set(absent,"device",string("/dev/dm-8"));
    Control absent_driver;
    absent_driver.slot = field(absent_before,"snapshot");
    set(*absent_driver.slot,"origin_path",field(absent,"device"));
    const auto returned = prepare_machine_tracking(history,absent,absent_driver);
    check(returned && field(*returned,"minor") == integer(2));
    check(absent_driver.renewals == 0 && absent_driver.releases == 0);
    // If no healthy reload exists, only this saved path's chain is retired.
    absent_driver.slot.reset();
    check(!prepare_machine_tracking(history,absent,absent_driver));
    check(!history.last(absent) && history.last(root) && history.minors() == std::vector<std::uint32_t>({0,3}));
    check(machine_tracking_free_minor(history.minors()) == 1);
    auto renamed = lv("renamed","/dev/dm-3");
    check(!history.last(renamed)); // No lookup by filesystem UUID or rdev alias.
    // Old non-official agent dm-N rows are not reinterpreted. In particular, the
    // currently frozen wrong scratch seq12 snapshot is not selected/reset.
    MachineTrackingDatabase old;
    old.add(history_row("/dev/dm-0",0,7,"old-root"));
    old.add(history_row("/dev/dm-3",3,11,"old-scratch"));
    Control scratch_driver;
    scratch_driver.slot = snapshot();
    set(*scratch_driver.slot,"minor",integer(3));
    set(*scratch_driver.slot,"sequence",integer(12));
    set(*scratch_driver.slot,"snapshot_mode",integer(1));
    const auto untouched = *scratch_driver.slot;
    check(!prepare_machine_tracking(old,root,scratch_driver));
    check(*scratch_driver.slot == untouched && scratch_driver.releases == 0 && scratch_driver.renewals == 0);
    check(old.minors() == std::vector<std::uint32_t>({0,3}));
}
void history_retention_tests() {
    auto first = history_row("/dev/testvg/root",6,5,"v185");
    auto second = history_row("/dev/testvg/root",6,6,"v186");
    auto base = history_row("/dev/testvg/root",6,7,"base");
    auto sibling = history_row("/dev/testvg/sibling",7,5,"sibling");
    set(first,"cow_relative",string("/.synosnap_data/first"));
    set(second,"cow_relative",string("/.synosnap_data/second"));
    set(base,"cow_relative",string("/.synosnap_data/base"));
    set(sibling,"cow_relative",string("/.synosnap_data/sibling"));
    MachineTrackingDatabase history;
    for (const auto& row : {first,sibling,second,base}) history.add(row);
    // v185/v186 are unmarked even if a non-official agent already lost their
    // catalog rows. Requesting the later snapshot cannot infer their deletion.
    check(history.delete_snapshot(base).empty());
    history = MachineTrackingDatabase(decode(encode(history.value())));
    check(history.minors().size() == 4);
    check(history.delete_snapshot(second).empty());
    // After the last earlier live row is marked, the newest marked candidate
    // removes its complete bdev prefix. Other bdevs stay independent.
    const auto removed = history.delete_snapshot(first);
    check(removed.size() == 3);
    check(field(removed.front(),"capture_id") == string("v185"));
    check(field(removed.back(),"capture_id") == string("base"));
    check(history.minors() == std::vector<std::uint32_t>{7});
    check(history.delete_snapshot(first).empty());
    check(history.delete_snapshot(sibling).size() == 1 && history.minors().empty());
}
void lost_module_history_tests() {
    MachineTrackingDatabase history;
    history.add(history_row("/dev/dm-0",0,6,"older"));
    history.add(history_row("/dev/sibling",1,3,"sibling"));
    history.add(history_row("/dev/dm-0",0,7,"base"));
    check(field(*history.last(volume()),"capture_id") == string("base"));
    check(machine_tracking_free_minor(history.minors()) == 2);
    // Module unload/load removes every slot but no saved row. Resolution is
    // by saved bdev/row ID, independent of the driver and reload file.
    Control absent;
    absent.slot.reset();
    const auto prior = prepare_machine_tracking(history,volume(),absent);
    check(!prior && absent.retirements == 1 && absent.releases == 0);
    check(!history.last(volume()));
    check(machine_tracking_free_minor(history.minors()) == 0);
    auto selected = reservation();
    const auto fresh = transition_machine_tracking(selected,volume(),0,absent);
    check(field(fresh,"sequence") == integer(1));
    check(field(fresh,"uuid") != field(snapshot(),"uuid"));
    check(!std::get<Value::Object>(selected.data).contains("changes"));
    check(!std::get<Value::Object>(selected.data).contains("previous_capture_id"));
    auto current_row = history_row("/dev/dm-0",0,1,"new-base");
    set(current_row,"snapshot",fresh);
    set(current_row,"cow_relative",field(selected,"cow_relative"));
    set(current_row,"cow_path",field(selected,"cow_path"));
    history.add(current_row);
    history = MachineTrackingDatabase(decode(encode(history.value())));
    check(field(*history.last(volume()),"history_id") == integer(4));
    check(machine_tracking_free_minor(history.minors()) == 2);
    // The following backup continues the fresh chain with CBT. Both prior
    // rows stayed retired; the unrelated origin retained its row/minor.
    set(*absent.slot,"snapshot_mode",integer(0));
    const auto tracked = prepare_machine_tracking(history,volume(),absent);
    check(tracked && absent.retirements == 1);
    auto next = reservation();
    set(next,"cow_relative",string("/.synosnap_data/third"));
    set(next,"cow_path",field(next,"cow_relative"));
    set(next,"prior",*tracked);
    const auto renewed = transition_machine_tracking(next,volume(),0,absent);
    check(field(renewed,"sequence") == integer(2));
    check(field(renewed,"uuid") == field(fresh,"uuid"));
    check(absent.renewals == 1 && absent.compressions == 1);
    check(field(next,"previous_capture_id") == string("new-base"));
    check(std::get<Value::Object>(next.data).contains("changes"));
    auto sibling = volume();
    set(sibling,"device",string("/dev/sibling"));
    check(field(*history.last(sibling),"capture_id") == string("sibling"));
    // A failed destroy leaves its rows allocated. the official agent still takes setup's
    // first free history minor and does not delete the surviving slot's rows.
    MachineTrackingDatabase busy_history;
    busy_history.add(history_row("/dev/dm-0",0,7,"busy"));
    const auto busy_saved = busy_history.value();
    Control busy;
    busy.release_stuck = true;
    check(!prepare_machine_tracking(busy_history,volume(),busy));
    check(busy.retirements == 0 && busy_history.value() == busy_saved);
    check(machine_tracking_free_minor(busy_history.minors()) == 1);
    // Empty history never imports an old journal or durable reload owner.
    MachineTrackingDatabase empty;
    Control occupied;
    occupied.slot = snapshot();
    check(!prepare_machine_tracking(empty,volume(),occupied));
    check(occupied.releases == 0 && occupied.retirements == 0);
}
void stale_history_tests() {
    for (const bool changed_uuid : {false,true}) {
        MachineTrackingDatabase history;
        auto prior = reservation(true);
        set(prior,"snapshot",snapshot());
        set(prior,"device",field(volume(),"device"));
        set(prior,"capture_id",string("base"));
        set(prior,"directory",string("/captures/base"));
        history.add(prior);
        Control control;
        control.slot = snapshot("/.synosnap_data/unpublished");
        set(*control.slot,"sequence",integer(9));
        if (changed_uuid) set(*control.slot,"uuid",string(std::string(32,'d')));
        const auto observed = *control.slot;
        const auto old_record = control.record;
        const auto saved_history = history.value();
        const auto selected = prepare_machine_tracking(history,volume(),control);
        check(selected && field(*selected,"snapshot") == field(prior,"snapshot"));
        check(control.releases == 0 && control.retirements == 0 && history.value() == saved_history);
        auto next = reservation();
        set(next,"prior",*selected);
        const auto current = transition_machine_tracking(next,volume(),0,control);
        check(control.renewals == 1 && control.compressions == 1 && control.creates == 0);
        check(field(current,"sequence") == integer(10) && field(current,"uuid") == field(observed,"uuid"));
        check(field(next,"previous_capture_id") == string("base"));
        check(control.record == old_record && history.value() == saved_history);
    }
}
void missing_previous_cow_tests() {
    Control missing;
    missing.slot = snapshot();
    missing.prior_cow_missing = true;
    auto next = reservation();
    auto prior = reservation(true);
    set(prior,"snapshot",snapshot());
    set(prior,"capture_id",string("base"));
    set(prior,"directory",string("/captures/base"));
    set(prior,"cow_missing",integer(1));
    MachineTrackingDatabase history;
    set(prior,"device",field(volume(),"device"));
    history.add(prior);
    history.add(history_row("/dev/sibling",1,3,"healthy-sibling"));
    const auto saved_history = history.value();
    set(next,"prior",*history.last(volume()));
    const auto old_record = missing.record;
    bool omitted = false;
    try { transition_machine_tracking(next,volume(),0,missing); }
    catch (const SnapshotPreviousCowError& error) { omitted = error.error == 2; }
    check(omitted && missing.renewals == 1 && missing.compressions == 1);
    check(missing.releases == 0 && missing.retirements == 0 && missing.creates == 0);
    check(missing.slot && field(*missing.slot,"sequence") == integer(8));
    check(field(*missing.slot,"snapshot_mode") == integer(1));
    check(missing.record == old_record && history.value() == saved_history);
    check(!std::get<Value::Object>(next.data).contains("changes"));
    check(!std::get<Value::Object>(next.data).contains("previous_capture_id"));
    // The failed origin has no new successful history. The next backup uses
    // the same old row, sees the leftover snapshot mode and recreates its chain.
    auto retry = reservation();
    set(retry,"cow_relative",string("/.synosnap_data/third"));
    set(retry,"cow_path",field(retry,"cow_relative"));
    const auto retry_prior = prepare_machine_tracking(history,volume(),missing);
    check(!retry_prior && !history.last(volume()));
    auto sibling = volume();
    set(sibling,"device",string("/dev/sibling"));
    check(field(*history.last(sibling),"capture_id") == string("healthy-sibling"));
    check(machine_tracking_free_minor(history.minors()) == 0);
    const auto recovered = transition_machine_tracking(retry,volume(),0,missing);
    check(missing.releases == 1 && missing.retirements == 1 && missing.creates == 1);
    check(missing.renewals == 1 && missing.compressions == 1);
    check(field(recovered,"sequence") == integer(1));
    check(field(recovered,"uuid") != field(snapshot(),"uuid"));
    check(!std::get<Value::Object>(retry.data).contains("changes"));
    check(!std::get<Value::Object>(retry.data).contains("previous_capture_id"));
}
void history_minor_tests() {
    check(machine_tracking_free_minor({}) == 0);
    const std::uint32_t occupied[]{0,2,0,4};
    check(machine_tracking_free_minor(occupied) == 1);
    const std::uint32_t orphaned[]{0,1,2};
    check(machine_tracking_free_minor(orphaned) == 3);
    std::vector<std::uint32_t> full;
    for (std::uint32_t minor = 0; minor < 255; ++minor) full.push_back(minor);
    check(machine_tracking_free_minor(full) == -1);
    check(static_cast<std::uint32_t>(machine_tracking_free_minor(full)) == machine_tracking_no_minor);
}
void crash_tests() {
    Control complete;
    auto reserved = reset_reservation();
    transition_machine_tracking(reserved,volume(),0,complete);
    const auto boundaries = complete.point;
    for (int fail = 1; fail <= boundaries; ++fail) {
        Control crash;
        crash.fail = fail;
        auto interrupted = reset_reservation();
        rejects([&] { transition_machine_tracking(interrupted,volume(),0,crash); });
        // Until a validated new slot has been published, the only durable
        // owner is the exact old generation, or its committed retirement.
        const auto record = machine_tracking_record_owner(crash.record);
        check(!record || *record == machine_tracking_owner(volume(),reservation(true),snapshot()));
        crash.fail = -1;
        if (!crash.slot || field(*crash.slot,"cow_path") == string(new_path)) {
            transition_machine_tracking(interrupted,volume(),0,crash);
            check(crash.slot && field(*crash.slot,"cow_path") == string(new_path));
            crash.publish(interrupted);
            check(machine_tracking_record_owner(crash.record) ==
                  machine_tracking_owner(volume(),interrupted,*crash.slot));
        }
        // Reboot cannot obtain an uncommitted new generation or CBT ancestry
        // from the independent store. Restored owner files can only reset the
        // exact old slot they describe.
        crash.reboot();
        check(!crash.slot || field(*crash.slot,"cow_path") ==
              field(*machine_tracking_record_owner(crash.record),"cow_relative"));
    }
    // History-authorized removal follows the saved basename even if another
    // generation has since replaced its command (Reload-record removal ).
    Control retired;
    retired.slot = snapshot(new_path);
    retired.publish(reservation());
    retired.retire_record(volume(),reservation(true));
    check(retired.record.empty());
    retired.retire_record(volume(),reservation());
    check(retired.record.empty());
}
void healthy_owner_without_history_tests() {
    const auto owner = machine_tracking_owner(volume(),reservation(true),snapshot());
    const Value cow{Value::Object{{"inode",integer(101)},
        {"filesystem_uuid",field(volume(),"filesystem_uuid")}}};
    const auto prior = machine_tracking_recovery_prior(owner,volume(),snapshot(),cow);
    const auto make_reserved = [&] {
        auto result = reservation();
        set(result,"prior",prior);
        return result;
    };
    Control complete;
    complete.slot = snapshot();
    auto reserved = make_reserved();
    const auto current = transition_machine_tracking(reserved,volume(),0,complete);
    check(complete.renewals == 1 && complete.releases == 0 && complete.creates == 0);
    check(complete.cow_verifications == 1);
    check(field(current,"uuid") == field(snapshot(),"uuid") && field(current,"sequence") == integer(8));
    check(field(reserved,"tracking_recovery") == string("durable-owner-renewed-without-history"));
    for (const auto key : {"changes","previous_capture_id","previous_directory"})
        check(!std::get<Value::Object>(reserved.data).contains(key));
    // Independent history is absent even though kernel generation renewal is
    // consecutive. A lost ioctl result must not renew twice or invent ancestry.
    for (int fail = 1; fail <= complete.point; ++fail) {
        Control crash;
        crash.slot = snapshot();
        crash.fail = fail;
        auto pending = make_reserved();
        rejects([&] { transition_machine_tracking(pending,volume(),0,crash); });
        crash.fail = -1;
        transition_machine_tracking(pending,volume(),0,crash);
        check(crash.renewals == 1 && crash.releases == 0 && crash.creates == 0);
        check(field(pending,"tracking_recovery") == string("durable-owner-renewed-without-history"));
        for (const auto key : {"changes","previous_capture_id","previous_directory"})
            check(!std::get<Value::Object>(pending.data).contains(key));
    }
    for (const auto changed_key : {"uuid","sequence","origin_path","cow_path","minor"}) {
        Control changed;
        changed.slot = snapshot();
        set(*changed.slot,changed_key,std::string(changed_key) == "sequence" ||
            std::string(changed_key) == "minor" ? integer(200) : string("foreign"));
        auto pending = make_reserved();
        rejects([&] { transition_machine_tracking(pending,volume(),0,changed); });
        check(changed.renewals == 0 && changed.releases == 0 && changed.creates == 0);
    }
    Control replaced;
    replaced.slot = snapshot();
    replaced.prior_cow_replaced = true;
    auto pending = make_reserved();
    rejects([&] { transition_machine_tracking(pending,volume(),0,replaced); });
    check(replaced.renewals == 0 && replaced.releases == 0 && replaced.creates == 0);
    Control lost_owner;
    lost_owner.slot = snapshot();
    lost_owner.record.clear();
    pending = make_reserved();
    transition_machine_tracking(pending,volume(),0,lost_owner);
    check(lost_owner.renewals == 1 && lost_owner.releases == 0 && lost_owner.creates == 0);
    check(field(pending,"tracking_recovery") == string("durable-owner-renewed-without-history"));
}
}
int main() {
    try {
        record_tests();
        reservation_owner_tests();
        transition_tests();
        lost_module_history_tests();
        logical_origin_history_tests();
        history_retention_tests();
        missing_previous_cow_tests();
        stale_history_tests();
        history_minor_tests();
        crash_tests();
        healthy_owner_without_history_tests();
        std::cout << "tracking owner, restore transition and crash tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
