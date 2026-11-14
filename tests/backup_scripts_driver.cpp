#include "opensabba/backup_scripts.hpp"
#include "opensabba/capture.hpp"
#include "opensabba/server_time.hpp"
#include "opensabba/task_policy.hpp"
#include "opensabba/service_backup.hpp"
#include "opensabba/historical_logs.hpp"
#include <csignal>
#include <fstream>
#include <iostream>
#include <thread>
#include <atomic>
using namespace opensabba;
using pstream::Value;
using pstream::Error;
namespace {
void check(bool value) { if (!value) throw Error("script wire invariant failed"); }
Value n(std::uint64_t value) { return Value{value}; }
Value load(const std::filesystem::path& path) {
    std::ifstream input(path,std::ios::binary);
    return pstream::decode(pstream::Bytes{std::istreambuf_iterator<char>(input),{}});
}
void write(const std::filesystem::path& path, const Value& value) {
    const auto bytes = pstream::encode(value);
    std::ofstream output(path,std::ios::binary);
    output.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));
    check(bool(output));
}
// Exercise the real capture controller and durable journal using an in-memory
// snapshot backend. The service's Linux backend records the same per-root logs.
struct RecordedCapture : CaptureOperations {
    CaptureJournal& journal;
    bool stop = false;
    std::filesystem::path path;
    RecordedCapture(CaptureJournal& state, std::filesystem::path file) : journal(state),path(std::move(file)) {}
    void persist(const CaptureJournal& state) override { write(path,capture_journal_value(state)); }
    void verify_inputs() override {}
    Value snapshot_root() override {
        const auto durable = capture_journal_from_value(load(path));
        check(durable.logs == journal.logs && durable.phase == CapturePhase::snapshot_intent);
        for (const auto type : {7002U,7003U}) {
            journal.logs.push_back(Value{Value::Object{{"log_type",n(type)},{"log_time",Value{server_time_now()}},
                {"parameters",Value{Value::Object{{"volume_name",Value{std::string("/")}}}}}}});
            persist(journal);
        }
        return Value{Value::Object{{"identity",n(1)}}};
    }
    void snapshot_extra_volumes() override {}
    void cache_raw_regions() override {}
    void prepare_snapshot_root(const Value&) override {}
    void prepare_extra_volumes() override {}
    Value seal_raw_cache() override { return Value{Value::Object{{"identity",n(2)}}}; }
    bool cancelled() override { return stop; }
    bool stopping() override { return stop; }
    void recover_snapshot(const CaptureJournal&) override {}
};
}
int main(int argc, char** argv) {
#ifdef SIGPIPE
    std::signal(SIGPIPE,SIG_IGN);
#endif
    try {
        check(argc == 5);
        Endpoint endpoint{"127.0.0.1",static_cast<std::uint16_t>(std::stoul(argv[1])),argv[2]};
        std::atomic_bool shutdown{false};
        endpoint.cancelled = [&] { return shutdown.load(); };
        const SavedAuth auth{"test-user","test-device","test-token","test-nas"};
        const opensabba::TaskView task_view{
            [&](const opensabba::Endpoint& connection) { return opensabba::tasks(connection,auth); },
            [&](const opensabba::Endpoint& connection) { return opensabba::running_tasks(connection,auth); }};
        const std::filesystem::path directory(argv[3]);
        const std::string mode(argv[4]);
        const auto public_tasks = tasks(endpoint,auth);
        const auto& display = std::get<Value::Object>(public_tasks.at(0).data);
        check(display.at("pre_script_enabled") == n(1) &&
              !display.contains("pre_script_content") && !display.contains("pre_script_extension"));
        const auto private_tasks = execution_tasks(endpoint,auth);
        const auto scripts = backup_scripts(private_tasks.at(0));
        auto journal = new_script_run(mode.starts_with("capture-no-scripts") ? BackupScripts{} : scripts,2,27,"task-uuid");
        Value durable;
        const auto save = [&](const Value& state) { durable = pstream::decode(pstream::encode(state)); };
        if (mode.starts_with("boundary-")) {
            const bool pre_failure = mode.find("-pre-") != std::string::npos;
            const bool abort = mode.ends_with("-abort");
            const auto script_file = directory/(mode+"-scripts.pstream");
            const auto capture_file = directory/(mode+"-capture.pstream");
            CaptureJournal capture{std::string(32,'c'),"11223344-5566-7788-99aa-bbccddeeff00",
                CapturePhase::prepared,Value{Value::Object{}},
                Value{Value::Object{{"snapshot_attempted",n(0)},{"snapshot_released",n(0)},
                    {"extras",Value{Value::Array{}}}}},{},{},{},5,{},{}};
            RecordedCapture backend(capture,capture_file);
            const auto persist = [&](const Value& state) { write(script_file,state); };
            int pre_calls = 0, post_calls = 0;
            const auto invoke = [&](bool pre) {
                (pre ? pre_calls : post_calls)++;
                const auto kind = (pre ? 7045U : 7049U)+
                    (pre == pre_failure ? (scripts.stop_on_failure ? 2 : 1) : 0);
                const bool cancelled = abort && !pre;
                std::get<Value::Object>(journal.data)[pre ? "pre" : "post"] = Value{Value::Object{
                    {"phase",Value{std::string("complete")}},{"log_type",n(cancelled ? 0 : kind)},
                    {"exit_code",Value{std::string(cancelled ? "-1" : pre == pre_failure ? "37" : "0")}},
                    {"cancelled",n(cancelled)},{"output",n(!cancelled)},
                    {"log_time",n(1700000000)},{"reported",n(0)},{"output_uploaded",n(0)}}};
                std::ofstream(directory/((pre ? "pre" : "post")+std::string("27.log")+
                    (cancelled ? ".tmp" : ""))) << "script output";
                persist(journal);
                if (cancelled) backend.stop = true;
                try { run_backup_script_once(journal,scripts,pre,directory,persist); }
                catch (const BackupScriptFailed& error) { throw CaptureFailed(error.what()); }
                catch (const Cancelled&) { throw CaptureStopRequested(); }
            };
            bool interrupted = false;
            auto outcome = QueuedCaptureOutcome::complete;
            try {
                outcome = run_queued_machine_capture(endpoint,task_view,2,27,[&](const auto&) {
                    run_machine_capture(capture,backend,{[&] { invoke(true); },[&] { invoke(false); }});
                });
            } catch (const Cancelled&) { interrupted = true; }
            check(interrupted == abort && pre_calls == 1 &&
                post_calls == (pre_failure && scripts.stop_on_failure ? 0 : 1));
            check(outcome == (scripts.stop_on_failure && !abort ?
                QueuedCaptureOutcome::failed : QueuedCaptureOutcome::complete));
            // Reload the exact durable handoff; neither script is invoked again.
            journal = load(script_file);
            capture = capture_journal_from_value(load(capture_file));
            if (backup_scripts_failed(journal)) {
                std::get<Value::Object>(journal.data)["capture_failure"] = capture_journal_value(capture);
                try { check(finish_failed_backup(endpoint,auth,journal,directory,persist)); }
                catch (const TransportError&) { check(mode.ends_with("-lost")); }
                journal = load(script_file);
                check(finish_failed_backup(endpoint,auth,journal,directory,persist));
            } else report_backup_scripts(endpoint,auth,journal,directory,9,112,persist,capture.logs);
            check(capture.phase == (pre_failure && scripts.stop_on_failure ?
                CapturePhase::aborted : CapturePhase::ready));
            return 0;
        }
        if (mode.starts_with("activity-")) {
            const bool capture = mode.starts_with("activity-capture-");
            auto& fields = std::get<Value::Object>(journal.data);
            fields["pre"] = Value{Value::Object{
                {"phase",Value{std::string("complete")}},{"log_type",n(7045)},
                {"exit_code",Value{std::string("0")}},{"cancelled",n(0)},
                {"output",n(0)},{"log_time",n(1700000000)},{"reported",n(0)},{"output_uploaded",n(0)}}};
            const Value log{Value::Object{{"log_type",n(7001)},{"log_time",n(1700000000)},
                {"parameters",Value{Value::Object{}}}}};
            const auto persist = [&](const Value& state) {
                save(state);
                write(directory/(mode+".pstream"),state);
            };
            persist(journal);
            const auto report = [&] {
                if (capture) report_capture_activity(endpoint,auth,journal,{&log,1},112,persist);
                else report_backup_scripts(endpoint,auth,journal,directory,9,112,persist);
            };
            try { report(); }
            catch (const TransportError&) { check(capture); }
            journal = pstream::decode(pstream::encode(durable));
            report();
            journal = pstream::decode(pstream::encode(durable));
            report();
            check(capture ? std::get<Value::Object>(journal.data).at("capture_logs_reported") == n(1) :
                std::get<Value::Object>(std::get<Value::Object>(journal.data).at("pre").data).at("reported") == n(1));
            return 0;
        }
        if (mode.starts_with("successful")) {
            const bool acquiring = mode.ends_with("-acquire");
            const bool scripted = mode.find("scripts") != std::string::npos;
            const bool missing = mode.find("missing") != std::string::npos;
            const auto name = mode.substr(0,mode.rfind('-'));
            const auto script_file = directory/(name+"-scripts.pstream");
            const auto capture_file = directory/(name+"-capture.pstream");
            auto run = new_script_run(scripted ? scripts : BackupScripts{},2,27,"task-uuid");
            const auto persist = [&](const Value& state) { write(script_file,state); };
            if (acquiring) {
                set_server_time(ServerTime{"",321,0});
                CaptureJournal capture{std::string(32,'b'),"11223344-5566-7788-99aa-bbccddeeff00",
                    CapturePhase::prepared,Value{Value::Object{{"root",Value{Value::Object{
                        {"mount_path",Value{std::string("/")}}}}}}},
                    Value{Value::Object{{"extras",Value{Value::Array{}}}}},{},{},{},5,{},{}};
                const auto script = [&](bool pre) {
                    if (!scripted) return;
                    std::get<Value::Object>(run.data)[pre ? "pre" : "post"] = Value{Value::Object{
                        {"phase",Value{std::string("complete")}},{"log_type",n(pre ? 7045 : 7049)},
                        {"exit_code",Value{std::string("0")}},{"cancelled",n(0)},{"output",n(0)},
                        {"log_time",Value{server_time_now()}},{"reported",n(0)},{"output_uploaded",n(0)}}};
                    persist(run);
                };
                const Value task{Value::Object{{"source_type",n(3)},
                    {"custom_volume",Value{missing ? Value::Array{Value{std::string("/")},
                        Value{std::string("/missing-b")},Value{std::string("/missing-a")}} :
                        Value::Array{Value{std::string("/")}}}}}};
                RecordedCapture backend(capture,capture_file);
                persist(run);
                run_machine_capture(capture,backend,SnapshotBoundaryHooks{
                    [&] {
                        historical_backup_start(directory,name,
                            name.find("start-event") != std::string::npos ? 3 :
                            name.find("start-cache") != std::string::npos ? 5 : 1,9);
                        script(true);
                    },[&] { script(false); },{},
                    [&](const Value& plan) { return machine_task_missing_mounts(task,plan); }});
                // Even an explicit publication attempt cannot send logs while
                // the local capture has no bound NAS result.
                report_backup_scripts(endpoint,auth,run,directory,0,0,persist,capture.logs);
                report_capture_activity(endpoint,auth,run,capture.logs,0,persist);
                return 0;
            }
            // A separate process loads the capture made before NAS preparation.
            // Change the time offset to prove publication retains capture time.
            set_server_time(ServerTime{"",-500,0});
            run = load(script_file);
            const auto capture = capture_journal_from_value(load(capture_file));
            auto& fields = std::get<Value::Object>(run.data);
            if (!fields.contains("result_id")) {
                const auto bound = prepare_full_backup(endpoint,auth,27,[&] { persist(run); });
                fields["result_id"] = n(bound.result_id);
                fields["version_id"] = n(bound.version_id);
                persist(run);
            }
            report_backup_scripts(endpoint,auth,run,directory,
                std::get<std::uint64_t>(fields.at("version_id").data),
                std::get<std::uint64_t>(fields.at("result_id").data),persist,capture.logs);
            return 0;
        }
        if (mode == "partial" || mode == "partial-missing") {
            Value::Array logs;
            for (const auto type : {7001U,7002U,7004U,7002U,7003U}) {
                Value::Object parameters;
                if (type != 7001) parameters["volume_name"] = Value{std::string(type == 7003 ? "/data" : "/")};
                if (type == 7004) parameters["error_code"] = Value{std::string("ffffffffffffffe4")};
                logs.push_back(Value{Value::Object{{"log_type",n(type)},{"log_time",n(1700000000)},
                    {"parameters",Value{parameters}}}});
                if (type == 7001 && mode == "partial-missing")
                    logs.push_back(Value{Value::Object{{"log_type",n(7096)},{"log_time",n(1700000000)},
                        {"parameters",Value{Value::Object{{"mount_path",Value{std::string("/missing-b, /missing-a")}}}}}}});
            }
            report_capture_activity(endpoint,auth,journal,logs,112,save);
            journal = pstream::decode(pstream::encode(durable));
            report_capture_activity(endpoint,auth,journal,logs,112,save);
            check(std::get<Value::Object>(journal.data).at("capture_logs_reported") == n(logs.size()));
            return 0;
        }
        if (mode.starts_with("capture")) {
            for (const bool pre : {true,false}) {
                if (mode.starts_with("capture-no-scripts")) continue;
                std::get<Value::Object>(journal.data)[pre ? "pre" : "post"] = Value{Value::Object{
                    {"phase",Value{std::string("complete")}},{"log_type",n(pre ? 7045 : 7049)},
                    {"exit_code",Value{std::string("0")}},{"cancelled",n(0)},{"output",n(1)},
                    {"log_time",n(1700000000)},{"reported",n(0)},{"output_uploaded",n(0)}}};
                std::ofstream output(directory/(pre ? "pre27.log" : "post27.log"),std::ios::binary);
                output << (pre ? "pre output" : "post output");
            }
            CaptureJournal capture{std::string(32,'a'),"11223344-5566-7788-99aa-bbccddeeff00",
                CapturePhase::aborted,Value{Value::Object{}},Value{Value::Object{
                    {"snapshot_attempted",n(1)},{"snapshot_released",n(1)},{"extras",Value{Value::Array{}}}}},
                {},{},"create snapshot: No space left on device (errno 28)",5,"failure",{}};
            for (const auto type : {7001U,7002U,7004U,7083U}) {
                Value::Object parameters;
                if (type == 7002 || type == 7004) parameters["volume_name"] = Value{std::string("/")};
                if (type == 7004) parameters["error_code"] = Value{std::string("ffffffffffffffe4")};
                capture.logs.push_back(Value{Value::Object{{"log_type",n(type)},{"log_time",n(1700000000)},
                    {"parameters",Value{parameters}}}});
                if (type == 7001 && mode.find("missing") != std::string::npos)
                    capture.logs.push_back(Value{Value::Object{{"log_type",n(7096)},{"log_time",n(1700000000)},
                        {"parameters",Value{Value::Object{{"mount_path",Value{std::string("/missing-b, /missing-a")}}}}}}});
            }
            if (mode == "capture-uncertain") capture.failure_disposition = "uncertain";
            if (mode == "capture-old") {
                capture.schema = 3;
                capture.phase = CapturePhase::snapshot_intent;
                capture.failure_disposition.clear();
            }
            if (mode == "capture-release") std::get<Value::Object>(capture.reservation.data)["snapshot_released"] = n(0);
            if (mode == "capture-cleanup") {
                capture.phase = CapturePhase::recovery_required;
                capture.failure_disposition = "uncertain";
                std::get<Value::Object>(capture.reservation.data)["snapshot_released"] = n(0);
            }
            if (mode == "capture-old") {
                bool refused = false;
                try { (void)capture_journal_value(capture); } catch (const Error&) { refused = true; }
                check(refused);
                return 0;
            }
            std::get<Value::Object>(journal.data)["capture_failure"] = capture_journal_value(capture);
            save(journal);
            if (mode == "capture-release") {
                bool refused = false;
                try { finish_failed_backup(endpoint,auth,journal,directory,save); }
                catch (const Error&) { refused = true; }
                check(refused);
                return 0;
            }
            if (mode != "capture-restart") {
                try {
                const auto outcome = run_queued_machine_capture(endpoint,task_view,2,27,
                    [&](const std::function<bool()>& cancelled) {
                        if (mode.starts_with("capture-cancel-")) {
                            // The peer holds this observer at the selected
                            // transport stage before allowing capture to finish.
                            const auto ready = directory/(mode+"-observer-ready");
                            const auto deadline = std::chrono::steady_clock::now()+std::chrono::seconds{5};
                            while (!std::filesystem::exists(ready) && std::chrono::steady_clock::now() < deadline)
                                std::this_thread::sleep_for(std::chrono::milliseconds{1});
                            check(std::filesystem::exists(ready));
                        }
                        if (mode == "capture-observer") {
                            while (!cancelled()) std::this_thread::sleep_for(std::chrono::milliseconds{5});
                        }
                        if (mode == "capture-shutdown") shutdown = true;
                        throw CaptureFailed(capture.failure);
                    });
                check(outcome == QueuedCaptureOutcome::failed);
                } catch (const Error&) {
                    if (mode == "capture-observer" || mode == "capture-shutdown") return 0;
                    throw;
                }
                check(mode != "capture-observer" && mode != "capture-shutdown");
            }
            // Restart from bytes written before NAS preparation, with completed
            // scripts and a released aborted capture, and never execute scripts.
            journal = pstream::decode(pstream::encode(durable));
            try { check(finish_failed_backup(endpoint,auth,journal,directory,save)); }
            catch (const TransportError&) { check(mode == "capture-finish-lost"); }
            journal = pstream::decode(pstream::encode(durable));
            check(finish_failed_backup(endpoint,auth,journal,directory,save));
            if (mode == "capture-finish-lost") check(finish_failed_backup(endpoint,auth,journal,directory,save));
            check(run_queued_machine_capture(endpoint,task_view,2,28,
                [](const std::function<bool()>&) {}) == QueuedCaptureOutcome::complete);
            return 0;
        }
        if (mode.starts_with("failed") || mode == "prepare-lost" || mode == "finish-lost") {
            try { run_backup_script_once(journal,scripts,true,directory,save); }
            catch (const Error&) {}
            check(backup_scripts_failed(journal));
            try { finish_failed_backup(endpoint,auth,journal,directory,save); }
            catch (const TransportError&) {
                check(mode == "prepare-lost" || mode == "finish-lost");
            }
            if (mode == "prepare-lost") {
                journal = pstream::decode(pstream::encode(durable));
                check(finish_failed_backup(endpoint,auth,journal,directory,save));
                check(finish_failed_backup(endpoint,auth,journal,directory,save));
                check(run_queued_machine_capture(endpoint,task_view,2,28,
                    [](const std::function<bool()>&) {}) == QueuedCaptureOutcome::complete);
            } else finish_failed_backup(endpoint,auth,journal,directory,save);
        } else {
            check(scripts.pre.content == pstream::Bytes({'e','x','i','t',' ','0','\n'}));
            std::get<Value::Object>(journal.data)["pre"] = Value{Value::Object{
                {"phase",Value{std::string("complete")}},{"log_type",n(7045)},
                {"exit_code",Value{std::string("0")}},{"cancelled",n(0)},
                {"output",n(1)},{"log_time",n(1700000000)},{"reported",n(0)},{"output_uploaded",n(0)}}};
            std::ofstream output(directory/"pre27.log",std::ios::binary);
            if (mode != "empty") output.write("hello\0stderr\n",13);
            output.close();
            report_backup_scripts(endpoint,auth,journal,directory,9,112,save);
            report_backup_scripts(endpoint,auth,journal,directory,9,112,save);
            check(std::get<Value::Object>(std::get<Value::Object>(durable.data).at("pre").data)
                .at("output_uploaded") == n(1));
        }
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
