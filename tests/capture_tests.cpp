#include "opensabba/capture.hpp"
#include "opensabba/backup_scripts.hpp"
#include "opensabba/image.hpp"
#include "opensabba/tracking_record.hpp"
#include <iostream>
#include <algorithm>
#include <source_location>

using namespace opensabba;
using namespace opensabba::pstream;
namespace {
void check(bool condition, std::source_location at = std::source_location::current()) { if (!condition) throw Error("capture test invariant failed at line "+std::to_string(at.line())); }
Value identity(std::string name) { return Value{Value::Object{{"identity", Value{std::move(name)}}}}; }
CaptureJournal prepared() {
    return {"00112233445566778899aabbccddeeff", "11223344-5566-7788-99aa-bbccddeeff00",
        CapturePhase::prepared, identity("disk-plan"), identity("reserved-cow-and-output"), {}, {}, {}};
}
struct Resources {
    bool snapshot = false, static_copy = false, root_copy = false, sealed = false;
    int extras = 0;
    bool extra_copy = false;
};
struct Checkpoint { CaptureJournal journal; Resources resources; };
struct Fake : CaptureOperations {
    Resources resources;
    CaptureJournal durable = prepared();
    int event = 0, fail = -1, recoveries = 0, snapshots = 0;
    int cancel_at = -1;
    bool persistent_save_failure = false, foreign_snapshot = false;
    bool cancel = false, stop = false, malformed_snapshot = false;
    int snapshot_recoveries = 0;
    int fail_extra = -1;
    std::uint64_t clock = 1000;
    int clock_samples = 0;
    std::uint64_t snapshot_time() override {
        check(durable.phase == CapturePhase::static_copied && resources.static_copy);
        ++clock_samples;
        return clock;
    }
    std::vector<Checkpoint> checkpoints;
    void point() {
        checkpoints.push_back({durable, resources});
        if (++event == fail) throw Error("injected operation failure");
        if (event == cancel_at) cancel = true;
    }
    void persist(const CaptureJournal& state) override {
        // Every crash/lost-write point below must see creation time and intent
        // in the same record. Sampling cannot follow a persisted ioctl intent.
        if (state.phase >= CapturePhase::snapshot_intent && state.phase <= CapturePhase::ready)
            check(std::get<std::uint64_t>(std::get<Value::Object>(state.reservation.data).at("snapshot_time").data) != 0);
        if (persistent_save_failure) throw Error("disk full");
        point();
        durable = capture_journal_from_value(decode(encode(capture_journal_value(state))));
        point(); // A committed write whose reply is lost.
    }
    void verify_inputs() override { point(); }
    Value snapshot_root() override {
        check(durable.phase == CapturePhase::snapshot_intent && resources.static_copy);
        check(std::get<std::uint64_t>(std::get<Value::Object>(durable.reservation.data).at("snapshot_time").data) == clock);
        point(); resources.snapshot = true; ++snapshots; point();
        return malformed_snapshot ? Value{std::string("bad reply")} : identity("owned-snapshot");
    }
    void snapshot_extra_volumes() override {
        check(durable.phase == CapturePhase::snapshot_intent && resources.snapshot);
        for (int index = 0; index < 3; ++index) {
            point();
            ++resources.extras;
            point();
            if (index == fail_extra) throw Error("extra snapshot creation failed");
        }
    }
    void cache_raw_regions() override {
        check(durable.phase == CapturePhase::static_copy_intent && !resources.snapshot);
        point(); resources.static_copy = true; ++clock; point();
    }
    void prepare_snapshot_root(const Value& snapshot) override {
        check(durable.phase == CapturePhase::root_copy_intent && resources.snapshot &&
              resources.extras == 3);
        check(snapshot == identity("owned-snapshot"));
        point(); resources.root_copy = true; point();
    }
    void prepare_extra_volumes() override {
        check(durable.phase == CapturePhase::extra_copy_intent && resources.snapshot &&
              resources.extras == 3 && resources.root_copy);
        point(); resources.extra_copy = true; point();
    }
    Value seal_raw_cache() override {
        check(durable.phase == CapturePhase::seal_intent && resources.snapshot);
        check(resources.static_copy && resources.root_copy && resources.extra_copy && resources.extras == 3);
        point(); resources.sealed = true; point();
        return identity("sealed-image");
    }
    bool cancelled() override { return cancel; }
    bool stopping() override { return stop && cancel; }
    void recover_snapshot(const CaptureJournal&) override {
        ++snapshot_recoveries;
        ++recoveries;
        if (foreign_snapshot) throw Error("foreign driver slot");
        resources.snapshot = false;
        resources.extras = 0;
    }
};
struct Partial : Fake {
    CaptureJournal& journal;
    bool omit_root;
    unsigned omitted_extras;
    std::uint64_t acquisition_error;
    Partial(CaptureJournal& state, bool root, unsigned extras, std::uint64_t error = 28)
        : journal(state), omit_root(root), omitted_extras(extras), acquisition_error(error) {}
    Value snapshot_root() override {
        const auto acquired = Fake::snapshot_root();
        auto& reservation = std::get<Value::Object>(journal.reservation.data);
        reservation["snapshot_attempted"] = Value{std::uint64_t{1}};
        reservation["snapshot_released"] = Value{std::uint64_t{0}};
        if (!omit_root) return acquired;
        return record_snapshot_acquisition_failure(journal,journal.reservation,true,
            SnapshotAcquisitionError("rejected root setup",static_cast<int>(acquisition_error)),
            [] {},[&](const CaptureJournal& state) { persist(state); });
    }
    void snapshot_extra_volumes() override {
        Fake::snapshot_extra_volumes();
        Value::Array extras;
        for (unsigned index = 0; index < 3; ++index)
            extras.push_back(Value{Value::Object{
                {"attempted",Value{std::uint64_t{1}}},
                {"released",Value{std::uint64_t{0}}},
                {"snapshot",identity("extra-snapshot")}}});
        std::get<Value::Object>(journal.reservation.data)["extras"] = Value{std::move(extras)};
        auto& reserved = std::get<Value::Array>(
            std::get<Value::Object>(journal.reservation.data).at("extras").data);
        for (unsigned index = 0; index < 3; ++index)
            if (omitted_extras & (1U << index))
                record_snapshot_acquisition_failure(journal,reserved[index],false,
                    SnapshotAcquisitionError("rejected extra setup",static_cast<int>(acquisition_error)),
                    [] {},[&](const CaptureJournal& state) { persist(state); });
        persist(journal);
    }
    void prepare_snapshot_root(const Value& snapshot) override {
        if (!capture_snapshot_omitted(snapshot)) { Fake::prepare_snapshot_root(snapshot); return; }
        check(omit_root);
        point(); resources.root_copy = true; point();
    }
};
void acquisition_failure_evidence() {
    for (const bool root : {false,true}) for (const bool compressed : {false,true}) {
        auto journal = prepared();
        journal.phase = CapturePhase::snapshot_intent;
        journal.reservation = Value{Value::Object{{"snapshot_attempted",Value{std::uint64_t{1}}},
            {"snapshot_released",Value{std::uint64_t{0}}}}};
        Value extra{Value::Object{{"attempted",Value{std::uint64_t{1}}},
            {"released",Value{std::uint64_t{0}}},{"snapshot",Value{}}}};
        int saved = 0, retired = 0;
        const auto record = [&](const SnapshotAcquisitionError& error) {
            return record_snapshot_acquisition_failure(journal,root ? journal.reservation : extra,root,error,
                [&] { check(saved == 1); ++retired; },
                [&](const CaptureJournal&) { ++saved; });
        };
        const auto result = compressed ? record(SnapshotPreviousCowError("old COW open failed",2)) :
            record(SnapshotAcquisitionError("setup/renew rejected",16));
        check(capture_snapshot_omitted(result) && saved == 1 && retired == (compressed ? 0 : 1));
        const auto& fields = std::get<Value::Object>((root ? journal.reservation : extra).data);
        check(fields.at(root ? "snapshot_released" : "released") == Value{std::uint64_t{1}});
        check(root ? journal.snapshot == result : fields.at("snapshot") == result);
    }
}
template<class F> void reject(F function, std::string_view needle) {
    try { function(); } catch (const Error& error) {
        check(std::string_view(error.what()).find(needle) != std::string_view::npos);
        return;
    }
    throw Error("expected capture rejection");
}
}
int main() {
    try {
        acquisition_failure_evidence();
        auto journal = prepared();
        auto old_format = capture_journal_value(journal);
        std::get<Value::Object>(old_format.data)["schema"] = Value{std::uint64_t{1}};
        reject([&] { (void)capture_journal_from_value(old_format); }, "unsupported");
        std::get<Value::Object>(old_format.data)["schema"] = Value{std::uint64_t{0}};
        reject([&] { (void)capture_journal_from_value(old_format); }, "unsupported");
        Fake success;
        run_machine_capture(journal, success);
        check(journal.phase == CapturePhase::ready && success.resources.sealed);
        check(success.resources.snapshot && success.resources.extras == 3);
        check(success.snapshots == 1);
        check(success.clock_samples == 1);
        {
            auto warned = prepared();
            Fake ops;
            unsigned analyses = 0;
            run_machine_capture(warned,ops,SnapshotBoundaryHooks{{},{},{},[&](const Value& plan) {
                check(plan == warned.plan && ops.durable.phase == CapturePhase::static_copied);
                ++analyses;
                return std::vector<std::string>{"/missing-b","/missing-a"};
            }});
            check(analyses == 1 && warned.logs.size() == 2);
            const auto& warning = std::get<Value::Object>(warned.logs.at(1).data);
            check(warning.at("log_type") == Value{std::uint64_t{7096}});
            check(warning.at("parameters") == Value{Value::Object{
                {"mount_path",Value{std::string("/missing-b, /missing-a")}}}});
            for (const auto& checkpoint : ops.checkpoints) {
                if (checkpoint.journal.phase < CapturePhase::snapshot_intent ||
                    checkpoint.journal.phase > CapturePhase::seal_intent) continue;
                check(checkpoint.journal.logs == warned.logs);
                if (checkpoint.journal.phase == CapturePhase::snapshot_intent) continue;
                auto interrupted = capture_journal_from_value(decode(encode(capture_journal_value(checkpoint.journal))));
                Fake resumed;
                resumed.resources = checkpoint.resources;
                resumed.durable = interrupted;
                resume_machine_capture(interrupted,resumed);
                check(interrupted.logs == warned.logs && resumed.snapshots == 0);
            }
            check(analyses == 1);
        }
        // the official agent proceeds with every successful origin, including when root
        // acquisition failed. Only a wholly failed snapshot set is fatal.
        for (const auto error : {2U,16U,28U})
        for (const bool root_omitted : {false,true}) {
            auto partial = prepared();
            Partial ops(partial,root_omitted,5,error);
            run_machine_capture(partial,ops);
            check(partial.phase == CapturePhase::ready && partial.failure.empty());
            check(capture_snapshot_omitted(partial.snapshot) == root_omitted);
            check(partial.logs.size() == 1); // 7001, without all-failed 7083.
            const auto saved = capture_journal_from_value(decode(encode(capture_journal_value(partial))));
            check(saved.snapshot == partial.snapshot && saved.reservation == partial.reservation);
            if (root_omitted) {
                auto invalid = saved;
                std::get<Value::Object>(invalid.reservation.data)["snapshot_released"] = Value{std::uint64_t{0}};
                reject([&] { (void)capture_journal_value(invalid); }, "confirmed acquisition retirement");
            }
            for (const auto& checkpoint : ops.checkpoints) {
                if (checkpoint.journal.phase < CapturePhase::snapshot_active ||
                    checkpoint.journal.phase > CapturePhase::seal_intent) continue;
                auto interrupted = checkpoint.journal;
                Partial resumed(interrupted,root_omitted,5,error);
                resumed.resources = checkpoint.resources;
                resumed.durable = interrupted;
                resume_machine_capture(interrupted,resumed);
                check(interrupted.phase == CapturePhase::ready && resumed.snapshots == 0 &&
                    interrupted.snapshot == saved.snapshot);
            }
        }
        for (const auto error : {2U,16U,28U}) {
            auto failed_set = prepared();
            Partial ops(failed_set,true,7,error);
            reject([&] { run_machine_capture(failed_set,ops); }, "no selected filesystem snapshot");
            check(failed_set.phase == CapturePhase::aborted && !ops.resources.snapshot &&
                !ops.resources.extras && !ops.resources.root_copy);
            check(failed_set.logs.size() == 1); // Nonempty failed origin set has no official agent 7083.
            struct OnlyFailed : Partial {
                using Partial::Partial;
                void snapshot_extra_volumes() override {
                    std::get<Value::Object>(journal.reservation.data)["extras"] = Value{Value::Array{}};
                    persist(journal);
                }
            };
            auto only = prepared();
            OnlyFailed single(only,true,0,error);
            reject([&] { run_machine_capture(only,single); }, "no selected filesystem snapshot");
            check(only.phase == CapturePhase::aborted && capture_failure_reportable(only) &&
                capture_snapshot_omitted(only.snapshot) && !single.resources.sealed);
        }
        reject([&] { (void)capture_snapshot_omitted(Value{Value::Object{
            {"acquisition_error",Value{std::uint64_t{0}}}}}); }, "invalid omitted");
        {
            Fake failed; failed.fail_extra = 0;
            auto aborted = prepared();
            bool definitive = false;
            try { run_machine_capture(aborted,failed); }
            catch (const CaptureFailed&) { definitive = true; }
            check(definitive && aborted.phase == CapturePhase::aborted &&
                aborted.failure_disposition == "failure" &&
                !failed.resources.snapshot && !failed.resources.extras);
            const auto restored = capture_journal_from_value(decode(encode(capture_journal_value(failed.durable))));
            check(restored.failure_disposition == "failure");
        }
        // CLI edit and termination share official agent service-abort. Once the set
        // exists, device metadata construction/sealing publishes it before post can abort.
        // Exercise every persisted/operation boundary, including root, extra
        // and seal, and prove reuse needs no scripts or second acquisition.
        for (int at = 1; at <= success.event; ++at) {
            Fake ops; ops.cancel_at = at; ops.stop = true;
            journal = prepared();
            int pre = 0, post = 0;
            bool abandoned = false;
            try { run_machine_capture(journal,ops,{[&] { ++pre; },[&] { ++post; }}); }
            catch (const CaptureInterrupted&) {}
            catch (const CaptureCancelled&) { abandoned = true; }
            if (abandoned) {
                check(journal.phase == CapturePhase::aborted && ops.snapshot_recoveries == 1);
                check(!ops.resources.snapshot && !ops.resources.extras);
                continue;
            }
            check(journal.phase == CapturePhase::ready && ops.resources.snapshot && ops.resources.extras == 3);
            check(pre == 1 && post == 1 && ops.snapshots == 1 && ops.snapshot_recoveries == 0);
            const auto retained = capture_journal_from_value(decode(encode(capture_journal_value(ops.durable))));
            check(retained.id == journal.id && retained.snapshot == journal.snapshot && retained.phase == CapturePhase::ready);
        }
        for (const auto& checkpoint : success.checkpoints) {
            if (checkpoint.journal.phase < CapturePhase::snapshot_active ||
                checkpoint.journal.phase > CapturePhase::seal_intent) continue;
            Fake ops;
            ops.resources = checkpoint.resources;
            ops.durable = checkpoint.journal;
            ops.cancel = ops.stop = true;
            auto saved = checkpoint.journal;
            resume_machine_capture(saved,ops);
            check(saved.phase == CapturePhase::ready && ops.snapshot_recoveries == 0 &&
                  ops.resources.snapshot && ops.resources.extras == 3 && ops.snapshots == 0);
        }
        {
            Fake ops;
            journal = prepared();
            int pre = 0, post = 0;
            bool interrupted = false;
            try { run_machine_capture(journal,ops,{[&] { ++pre; },[&] {
                ++post;
                check(journal.phase == CapturePhase::ready && ops.durable.phase == CapturePhase::ready);
                ops.cancel = ops.stop = true;
                throw CaptureStopRequested();
            }}); } catch (const CaptureInterrupted&) { interrupted = true; }
            check(interrupted && journal.phase == CapturePhase::ready && journal.failure.empty() &&
                  pre == 1 && post == 1 && ops.snapshots == 1 && ops.snapshot_recoveries == 0);
        }
        // Cancellation only becomes a nonfatal outcome after BOTH resources
        // and the durable journal confirm cleanup at every interruption point.
        for (int at = 1; at <= success.event; ++at) {
            Fake ops; ops.cancel_at = at;
            journal = prepared();
            bool cancelled_cleanly = false;
            try { run_machine_capture(journal,ops); }
            catch (const CaptureCancelled&) { cancelled_cleanly = true; }
            check((cancelled_cleanly ? !ops.resources.snapshot && !ops.resources.extras :
                ops.resources.snapshot && ops.resources.extras == 3));
            check(journal.phase == (cancelled_cleanly ? CapturePhase::aborted : CapturePhase::ready));
            check(ops.durable.phase == journal.phase);
            if (cancelled_cleanly) check(journal.failure_disposition == "interrupted");
        }
        for (int fault = 0; fault < 2; ++fault) {
            Fake ops; ops.cancel = true;
            ops.foreign_snapshot = fault == 0;
            ops.persistent_save_failure = fault == 1;
            journal = prepared();
            bool fatal = false;
            try { run_machine_capture(journal,ops); }
            catch (const CaptureCancelled&) { throw Error("failed cleanup was reported as harmless cancellation"); }
            catch (const Error&) { fatal = true; }
            check(fatal && journal.phase == CapturePhase::recovery_required);
            check(journal.failure_disposition == "uncertain");
        }
        // Failure before and after every durable write and every operation,
        // including mutation applied but returned identity/result lost.
        for (int failure = 1; failure <= success.event; ++failure) {
            Fake ops; ops.fail = failure;
            journal = prepared();
            int pre = 0, post = 0;
            reject([&] { run_machine_capture(journal, ops,{
                [&] { ++pre; }, [&] { ++post; }}); }, "injected");
            check(!ops.resources.snapshot && !ops.resources.extras);
            check(ops.durable.phase != CapturePhase::ready);
            check(ops.snapshots <= 1 && ops.recoveries >= 1);
            check(post == pre);
            check(journal.failure_disposition == "failure" || journal.failure_disposition == "uncertain");
        }
        // Process death bypasses all destructors/exception handlers. Restore
        // just the durable journal and observed resources at each boundary.
        for (const auto& checkpoint : success.checkpoints) {
            Fake restarted;
            restarted.durable = checkpoint.journal;
            restarted.resources = checkpoint.resources;
            auto saved = checkpoint.journal;
            recover_machine_capture(saved, restarted);
            check((saved.phase == CapturePhase::ready ?
                restarted.resources.snapshot && restarted.resources.extras == 3 :
                !restarted.resources.snapshot && !restarted.resources.extras));
            check(saved.phase == CapturePhase::ready || saved.phase == CapturePhase::aborted);
            check(restarted.snapshots == 0);
            const auto count = restarted.recoveries;
            recover_machine_capture(saved, restarted);
            check(restarted.recoveries == count);
        }
        // A completed snapshot set survives process death even if its local
        // image copy or individual snapshot releases were interrupted. Reuse
        // the original snapshot time and data; no new snapshot runs.
        for (const auto& checkpoint : success.checkpoints) {
            if (checkpoint.journal.phase < CapturePhase::snapshot_active ||
                checkpoint.journal.phase > CapturePhase::seal_intent) continue;
            Fake restarted;
            restarted.durable = checkpoint.journal;
            restarted.resources = checkpoint.resources;
            auto saved = checkpoint.journal;
            const auto snapshot_time = std::get<Value::Object>(saved.reservation.data).at("snapshot_time");
            resume_machine_capture(saved,restarted);
            check(saved.phase == CapturePhase::ready && restarted.resources.snapshot &&
                restarted.resources.extras == 3 && restarted.resources.sealed);
            check(restarted.snapshots == 0 && restarted.clock_samples == 0);
            check(std::get<Value::Object>(saved.reservation.data).at("snapshot_time") == snapshot_time);
        }
        Fake no_disk;
        no_disk.resources = {true, false, false, false};
        no_disk.persistent_save_failure = true;
        journal = prepared(); journal.phase = CapturePhase::snapshot_intent;
        reject([&] { recover_machine_capture(journal, no_disk); }, "disk full");
        check(no_disk.recoveries == 1 && !no_disk.resources.snapshot);
        check(journal.phase == CapturePhase::recovery_required);
        {
            Fake foreign; foreign.resources = {true, false, false, false};
            foreign.foreign_snapshot = true;
            journal = prepared(); journal.phase = CapturePhase::snapshot_intent;
            reject([&] { recover_machine_capture(journal, foreign); }, "foreign");
            check(foreign.recoveries == 1 && journal.phase == CapturePhase::recovery_required);
            check(foreign.resources.snapshot);
        }
        Fake cancelled; cancelled.cancel = true; journal = prepared();
        reject([&] { run_machine_capture(journal, cancelled); }, "cancelled");
        check(cancelled.snapshots == 0);
        Fake malformed; malformed.malformed_snapshot = true; journal = prepared();
        reject([&] { run_machine_capture(journal, malformed); }, "object");
        check(!malformed.resources.snapshot);
        // Application quiescing encloses the complete snapshot set. Scripts
        // execute around acquisition, before any snapshot data transfer.
        {
            Fake ops;
            int pre = 0, post = 0;
            bool measured = false;
            journal = prepared();
            run_machine_capture(journal,ops,{
                [&] { check(!ops.resources.snapshot); ++pre; ops.clock = 2000; },
                [&] {
                    check(ops.resources.snapshot && ops.resources.extras == 3);
                    check(ops.resources.root_copy && ops.resources.extra_copy && journal.phase == CapturePhase::ready); ++post;
                },
                [&](std::uint64_t elapsed) {
                    check(pre == 1 && post == 0 && !ops.resources.root_copy &&
                          !ops.resources.extra_copy && elapsed > 0);
                    measured = true;
                }});
            check(pre == 1 && post == 1);
            check(measured);
            check(std::get<std::uint64_t>(std::get<Value::Object>(journal.reservation.data).at("snapshot_time").data) == 2001);
        }
        {
            Fake ops;
            int post = 0;
            journal = prepared();
            reject([&] { run_machine_capture(journal,ops,{
                [] { throw Error("pre abort"); }, [&] { ++post; }}); }, "pre abort");
            check(post == 0 && ops.snapshots == 0);
        }
        for (int extra = 0; extra < 3; ++extra) {
            Fake ops; ops.fail_extra = extra;
            int post = 0;
            journal = prepared();
            reject([&] { run_machine_capture(journal,ops,{{},[&] {
                check(ops.resources.snapshot && ops.resources.extras == extra+1);
                ++post;
            }}); }, "extra snapshot creation failed");
            check(post == 1 && !ops.resources.snapshot && !ops.resources.extras &&
                  journal.phase == CapturePhase::aborted);
        }
        {
            Fake ops; ops.fail_extra = 1;
            int post = 0;
            journal = prepared();
            reject([&] { run_machine_capture(journal,ops,{{},[&] {
                ++post; throw Error("post failed");
            }}); }, "extra snapshot creation failed; post snapshot: post failed");
            check(post == 1 && !ops.resources.snapshot && !ops.resources.extras);
        }
        {
            Fake ops;
            int post = 0;
            journal = prepared();
            reject([&] { run_machine_capture(journal,ops,{{},[&] {
                ++post; throw Error("post failed");
            }}); }, "post failed");
            check(post == 1 && ops.resources.snapshot && ops.resources.extras == 3 &&
                  journal.phase == CapturePhase::ready && ops.resources.root_copy);
        }
        // Exercise completed script results through the real policy and
        // acquisition boundary. A mode-1 post failure retains the published
        // snapshot while propagating the terminal capture outcome.
        for (const bool fail_pre : {true,false}) for (const bool stop : {false,true}) {
            BackupScripts policy{{true,0,".sh",{}},{true,0,".sh",{}},stop};
            auto scripts = new_script_run(policy,2,27,"task-uuid");
            Fake ops;
            journal = prepared();
            int pre = 0, post = 0;
            const auto invoke = [&](bool before) {
                const auto kind = std::uint64_t{before ? 7045U : 7049U}+
                    (before == fail_pre ? (stop ? 2 : 1) : 0);
                auto& entry = std::get<Value::Object>(scripts.data)[before ? "pre" : "post"];
                entry = Value{Value::Object{{"phase",Value{std::string("complete")}},
                    {"log_type",Value{kind}},{"exit_code",Value{std::string(before == fail_pre ? "37" : "0")}},
                    {"cancelled",Value{std::uint64_t{0}}},{"output",Value{std::uint64_t{0}}},
                    {"log_time",Value{std::uint64_t{1}}},{"reported",Value{std::uint64_t{0}}},
                    {"output_uploaded",Value{std::uint64_t{0}}}}};
                try { run_backup_script_once(scripts,policy,before,"unused",[](const Value&) {}); }
                catch (const BackupScriptFailed& error) { throw CaptureFailed(error.what()); }
            };
            bool terminal = false;
            try { run_machine_capture(journal,ops,{
                [&] { ++pre; invoke(true); },[&] { ++post; invoke(false); }}); }
            catch (const CaptureFailed&) { terminal = true; }
            check(terminal == stop && backup_scripts_failed(scripts) == stop);
            check(pre == 1 && post == (fail_pre && stop ? 0 : 1));
            check(journal.phase == (fail_pre && stop ? CapturePhase::aborted : CapturePhase::ready));
            check(ops.snapshots == (fail_pre && stop ? 0 : 1));
            if (!fail_pre && stop) check(ops.resources.snapshot && ops.snapshot_recoveries == 0);
            scripts = decode(encode(scripts));
            check(backup_scripts_failed(scripts) == stop); // Survives handoff/restart.
        }
        journal = prepared(); journal.phase = CapturePhase::static_copy_intent;
        Fake repeat;
        reject([&] { run_machine_capture(journal, repeat); }, "already started");
        check(repeat.snapshots == 0);

        // Composite reads cross table/boot/root/tail boundaries; uncovered or
        // overlapping bytes cannot silently fall back to live disk reads.
        auto static_image = std::make_shared<ImageSource>(Bytes(4096, 0x11));
        auto root = std::make_shared<ImageSource>(Bytes(2048, 0x77));
        ImageSource composed(4096, {{0,1024,0,static_image}, {1024,2048,0,root}, {3072,1024,3072,static_image}});
        auto expected = Bytes(4096, 0x11);
        std::fill(expected.begin()+1024, expected.begin()+3072, 0x77);
        check(composed.read(0,4096) == expected);
        for (std::size_t start : {0U, 1000U, 1024U, 3000U, 3072U, 4096U}) {
            const auto count = expected.size()-start;
            check(composed.read(start,count) == Bytes(expected.begin()+start,expected.end()));
        }
        std::uint64_t next = 512;
        stream_image(composed, "machine", 1536, [&](const Value& block) {
            const auto& fields = std::get<Value::Object>(block.data);
            check(std::get<std::uint64_t>(fields.at("offset").data) == next);
            const auto& data = std::get<Bytes>(fields.at("buffer").data);
            check(std::equal(data.begin(),data.end(),expected.begin()+next));
            next += data.size();
        }, {}, 512);
        check(next == 4096);
        reject([&] { ImageSource bad(4096, {{512,3584,0,static_image}}); }, "gaps");
        reject([&] { ImageSource bad(4096, {{0,2048,0,root}, {1024,2048,0,root}}); }, "overlaps");
        reject([&] { ImageSource bad(4096, {{0,2048,0,root}}); }, "incomplete");
        reject([&] { ImageSource bad(4096, {{0,4096,0,root}}); }, "exceeds");
        reject([&] { composed.read(4095,2); }, "exceeds");
        std::cout << "Capture failure/crash recovery and composite image coverage passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
