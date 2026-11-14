#include "opensabba/service_backup.hpp"
#include "opensabba/job_recovery.hpp"
#include "opensabba/machine_capture.hpp"
#include "opensabba/display.hpp"
#include "opensabba/agent_config.hpp"
#include "opensabba/source_read.hpp"
#include <atomic>
#include <condition_variable>
#include <ctime>
#include <mutex>
#include <sstream>
#include <thread>

namespace opensabba {
namespace {
using pstream::Value;
using pstream::Error;
std::uint64_t number(const Value& value, const char* key) {
    const auto& fields = std::get<Value::Object>(value.data);
    const auto entry = fields.find(key);
    if (entry == fields.end() || !std::holds_alternative<std::uint64_t>(entry->second.data))
        throw Error(std::string("NAS backup control missing numeric field: ") + key);
    return std::get<std::uint64_t>(entry->second.data);
}
BackupOutcome requested_outcome(const Value& journal) {
    const auto& requested = std::get<std::string>(std::get<Value::Object>(journal.data).at("requested_outcome").data);
    return requested == "error" ? BackupOutcome::error : requested == "cancel" ?
        BackupOutcome::cancelled : requested == "partial" ? BackupOutcome::partial : BackupOutcome::complete;
}
void retire_event(Value& journal, const SaveBackupJob& save) {
    std::get<Value::Object>(journal.data)["resolution"] = Value{Value::Object{
        {"state",Value{std::string("retired")}},{"outcome",Value{std::string("unknown")}}}};
    save(journal);
}
void publish_source_activities(const Endpoint& endpoint, const SavedAuth& auth,
                               Value& journal, const SaveBackupJob& save) {
    auto& fields = std::get<Value::Object>(journal.data);
    if (!fields.contains("source_read_logs")) return;
    auto reported = number(journal,"source_read_logs_reported");
    const auto count = std::get<Value::Array>(fields.at("source_read_logs").data).size();
    while (reported < count) {
        auto& current = std::get<Value::Object>(journal.data);
        const auto& log = std::get<Value::Array>(current.at("source_read_logs").data)[reported];
        auto parameters = std::get<Value::Object>(log.data).at("parameters");
        auto& values = std::get<Value::Object>(parameters.data);
        for (auto key : {"running_task_id","task_id","result_id","task_uuid"}) values[key] = current.at(key);
        values["id"] = current.at("running_task_id");
        std::ostringstream json;
        print_json(json,parameters);
        report_script_activity(endpoint,auth,number(journal,"running_task_id"),
            number(log,"log_type"),number(log,"log_time"),json.str());
        current["source_read_logs_reported"] = Value{++reported};
        save(journal);
    }
}
void append_source_activity(Value& journal, std::uint64_t type, Value::Object parameters) {
    auto& fields = std::get<Value::Object>(journal.data);
    if (!fields.contains("source_read_logs")) {
        fields["source_read_logs"] = Value{Value::Array{}};
        fields["source_read_logs_reported"] = Value{std::uint64_t{0}};
    }
    std::get<Value::Array>(fields.at("source_read_logs").data).push_back(Value{Value::Object{
        {"log_type",Value{type}},{"log_time",Value{server_time_now()}},
        {"parameters",Value{std::move(parameters)}}}});
}
enum class Observation { running, cancelling, absent };
Observation observe(const Endpoint& endpoint, const TaskView& view,
                    std::uint64_t task, const BackupRun& run) {
    auto result = Observation::absent;
    bool found = false;
    for (const auto& job : view.running(endpoint)) {
        if (number(job, "id") != run.running_task_id) continue;
        if (found || number(job, "type") != 0 || number(job, "task_id") != task ||
            number(job, "version_id") != run.version_id || number(job, "result_id") != run.result_id)
            throw Error("NAS backup control identity differs from the prepared service job");
        found = true;
        const auto status = number(job,"status");
        result = status == 3 ? Observation::cancelling : status == 5 ? Observation::absent : Observation::running;
    }
    return result;
}
}

void recover_service_backup(const Endpoint& endpoint, const SavedAuth& auth, Value& journal,
                            const SaveBackupJob& save) {
    auto summary = backup_job_status(journal,auth);
    publish_source_activities(endpoint,auth,journal,save);
    if (number(summary,"terminal")) return;
    auto phase = std::get<std::string>(std::get<Value::Object>(summary.data).at("phase").data);
    const auto task = number(summary,"task_id"), id = number(summary,"running_task_id");
    auto& fields = std::get<Value::Object>(journal.data);
    if (fields.contains("disconnect_start_time") &&
        backup_disconnect_expired(number(journal,"disconnect_start_time"),disconnect_timeout(),std::time(nullptr))) {
        fail_service_backup(endpoint,auth,journal,save,{},BackupOutcome::cancelled);
        return;
    }
    const auto persist = [&](const char* next) { fields["phase"] = Value{std::string(next)}; save(journal); phase = next; };
    if (phase == "cancel-pending") {
        fail_service_backup(endpoint,auth,journal,save,{},BackupOutcome::cancelled);
        return;
    }
    if (phase == "prepare" || phase == "prepared" || phase == "metadata") {
        const auto event = backup_event_state(endpoint,auth,task,id);
        if (!event) { retire_event(journal,save); return; }
        if (event->worker_active) throw BackupRetry("previous NAS backup worker is still active");
        if (phase == "prepare") {
            auto run = event->run;
            if (!run.version_id || !run.result_id) {
                const auto base = fields.contains("incremental") ?
                    number(fields.at("incremental"),"base_version_id") : 0;
                run = base ? prepare_incremental_backup(endpoint,auth,task,id,base,[] {}) :
                    prepare_full_backup(endpoint,auth,id,[] {});
            }
            fields["version_id"] = Value{run.version_id};
            fields["result_id"] = Value{run.result_id};
            fields["data_format"] = Value{run.data_format};
            persist("prepared");
        } else if (event->run.version_id != number(journal,"version_id") ||
                   event->run.result_id != number(journal,"result_id") ||
                   event->run.data_format != number(journal,"data_format")) {
            throw Error("NAS preparation identity differs from the retained service backup");
        }
        const BackupRun run{id,number(journal,"version_id"),number(journal,"result_id"),number(journal,"data_format")};
        if (event->status == 3 || event->error_code) {
            fail_service_backup(endpoint,auth,journal,save,{},event->status == 3 ?
                BackupOutcome::cancelled : BackupOutcome::error);
            return;
        }
        auto metadata_endpoint = endpoint;
        metadata_endpoint.backup_app_aware = fields.contains("app_aware_bkp");
        upload_backup_spec(metadata_endpoint,auth,run,std::get<pstream::Bytes>(fields.at("snapshot_info").data),
            [&] { persist("metadata"); },!event->resume_info.empty());
        persist("metadata-accepted");
    }
    if (phase == "finish") {
        const auto result = backup_result(endpoint,auth,task,number(journal,"result_id"));
        if (result != "incomplete") {
            recover_backup_job(endpoint,auth,journal,false,[&](const Value& saved) { journal = saved; save(journal); });
            return;
        }
        const auto event = backup_event_state(endpoint,auth,task,id);
        if (!event) { retire_event(journal,save); return; }
        if (event->worker_active) throw BackupRetry("previous NAS backup worker is still active");
        const BackupRun run{id,number(journal,"version_id"),number(journal,"result_id"),number(journal,"data_format")};
        if (event->run.version_id != run.version_id || event->run.result_id != run.result_id ||
            event->run.data_format != run.data_format)
            throw Error("NAS completion identity differs from the retained service backup");
        const auto outcome = finish_backup(endpoint,auth,run,requested_outcome(journal),[] {},backup_completion_cbt(journal));
        persist(outcome == BackupOutcome::complete ? "complete" : outcome == BackupOutcome::partial ?
            "partial" : outcome == BackupOutcome::cancelled ? "cancel" : "error");
    }
}

void fail_service_backup(const Endpoint& endpoint, const SavedAuth& auth, Value& journal,
                         const SaveBackupJob& save, std::string_view missing_volume, BackupOutcome requested) {
    const auto summary = backup_job_status(journal,auth);
    if (number(summary,"terminal")) return;
    auto& fields = std::get<Value::Object>(journal.data);
    const auto task = number(summary,"task_id"), id = number(summary,"running_task_id");
    if (!fields.contains("result_id")) {
        const auto event = backup_event_state(endpoint,auth,task,id);
        if (!event) { retire_event(journal,save); return; }
        if (event->worker_active) throw BackupRetry("backup failure is awaiting the NAS worker");
        auto run = event->run;
        if (!run.version_id || !run.result_id) {
            const auto base = fields.contains("incremental") ? number(fields.at("incremental"),"base_version_id") : 0;
            run = base ? prepare_incremental_backup(endpoint,auth,task,id,base,[] {}) :
                prepare_full_backup(endpoint,auth,id,[] {});
        }
        fields["version_id"] = Value{run.version_id}; fields["result_id"] = Value{run.result_id};
        fields["data_format"] = Value{run.data_format}; fields["phase"] = Value{std::string("prepared")};
        save(journal);
    }
    publish_source_activities(endpoint,auth,journal,save);
    if (backup_result(endpoint,auth,task,number(journal,"result_id")) != "incomplete") {
        recover_backup_job(endpoint,auth,journal,false,[&](const Value& saved) { journal = saved; save(journal); });
        return;
    }
    if (!missing_volume.empty() && !fields.contains("missing_snapshot_reported")) {
        std::ostringstream parameters;
        print_json(parameters,Value{Value::Object{{"id",Value{id}},{"running_task_id",Value{id}},
            {"task_id",Value{task}},{"result_id",Value{number(journal,"result_id")}},
            {"volume_name",Value{std::string(missing_volume)}}}});
        report_script_activity(endpoint,auth,id,7021,server_time_now(),parameters.str());
        fields["missing_snapshot_reported"] = Value{std::uint64_t{1}}; save(journal);
    }
    fields.erase("resolution");
    fields["requested_outcome"] = Value{std::string(requested == BackupOutcome::cancelled ? "cancel" : "error")};
    fields["phase"] = Value{std::string("finish")}; save(journal);
    const BackupRun run{id,number(journal,"version_id"),number(journal,"result_id"),number(journal,"data_format")};
    const auto outcome = finish_backup(endpoint,auth,run,requested,[] {},backup_completion_cbt(journal));
    fields["phase"] = Value{std::string(outcome == BackupOutcome::error ? "error" :
        outcome == BackupOutcome::cancelled ? "cancel" : outcome == BackupOutcome::partial ? "partial" : "complete")};
    save(journal);
}

QueuedCaptureOutcome run_queued_machine_capture(const Endpoint& endpoint, const TaskView& view, std::uint64_t task,
    std::uint64_t run, const std::function<void(const std::function<bool()>&)>& operation) {
    auto queued = [&](const Endpoint& connection) {
        const auto jobs = view.running(connection);
        for (const auto& job : jobs)
            if (number(job,"id") == run && (number(job,"task_id") != task || number(job,"type") != 0))
                throw Error("queued capture job identity changed");
        return queued_machine_run(jobs,task) == run;
    };
    const auto present = [&](const Endpoint& connection) {
        return endpoint.prepared_backup ?
            observe(connection,view,task,endpoint.prepared_backup->run) == Observation::running : queued(connection);
    };
    if (!present(endpoint)) return QueuedCaptureOutcome::cancelled;
    std::atomic_bool finished{false}, interrupted{false};
    std::mutex mutex;
    std::condition_variable changed;
    std::exception_ptr observer_error, capture_error;
    auto control = endpoint;
    control.timeout = std::chrono::seconds{5};
    control.cancelled = [&] { return finished || (endpoint.cancelled && endpoint.cancelled()); };
    const std::function<bool()> cancelled = [&] {
        return interrupted || (endpoint.cancelled && endpoint.cancelled());
    };
    std::thread observer([&] {
        try {
            std::unique_lock lock(mutex);
            while (!finished) {
                lock.unlock();
                const bool active = present(control);
                lock.lock();
                if (!active) { interrupted = true; break; }
                changed.wait_for(lock,std::chrono::seconds{5},[&] { return finished.load(); });
            }
        } catch (...) {
            if (!finished) { observer_error = std::current_exception(); interrupted = true; }
        }
    });
    try { operation(cancelled); } catch (...) { capture_error = std::current_exception(); }
    {
        std::lock_guard lock(mutex);
        finished = true;
    }
    changed.notify_all();
    observer.join();
    // Capture errors include recovery diagnostics and must not be hidden by a
    // concurrent observation failure or cancellation.
    bool safely_cancelled = false;
    bool safely_failed = false;
    if (capture_error) {
        try { std::rethrow_exception(capture_error); }
        catch (const CaptureInterrupted&) { throw Cancelled(); }
        catch (const CaptureCancelled&) { safely_cancelled = true; }
        catch (const CaptureFailed&) { safely_failed = true; }
    }
    if (observer_error) std::rethrow_exception(observer_error);
    if (endpoint.cancelled && endpoint.cancelled()) throw Cancelled();
    if (interrupted) return QueuedCaptureOutcome::cancelled;
    if (safely_cancelled) throw Error("capture stopped without a confirmed queue cancellation");
    if (safely_failed) return QueuedCaptureOutcome::failed;
    return QueuedCaptureOutcome::complete;
}

void run_service_backup(const Endpoint& endpoint, const SavedAuth& auth, const TaskView& view, std::uint64_t task,
                        std::optional<Value> latest, const SaveBackupJob& save,
                        const std::function<void(const Endpoint&, const SaveBackupJob&)>& operation) {
    if (latest) {
        const auto summary = backup_job_status(*latest, auth);
        if (number(summary, "task_id") != task || number(summary, "terminal"))
            throw Error("service backup monitor requires its unresolved saved task");
    }
    auto persist = [&](const Value& record) {
        auto saved = record;
        auto& fields = std::get<Value::Object>(saved.data);
        if (!endpoint.backup_task_uuid.empty()) fields["task_uuid"] = Value{endpoint.backup_task_uuid};
        // The image job checkpoints its own record after the read worker has
        // appended activities. Keep both parts of the same service journal.
        if (latest && !fields.contains("source_read_logs")) {
            const auto& previous = std::get<Value::Object>(latest->data);
            if (previous.contains("source_read_logs")) {
                fields["source_read_logs"] = previous.at("source_read_logs");
                fields["source_read_logs_reported"] = previous.at("source_read_logs_reported");
            }
        }
        save(saved);
        latest = std::move(saved);
    };
    auto resolve = [&](bool cancel) {
        if (cancel) {
            fail_service_backup(endpoint,auth,*latest,persist,{},BackupOutcome::cancelled);
            return;
        }
        if (!cancel && backup_result(endpoint,auth,task,number(*latest,"result_id")) == "incomplete") {
            retire_event(*latest,persist);
            return;
        }
        recover_backup_job(endpoint, auth, *latest, cancel, persist);
        const auto summary = backup_job_status(*latest, auth);
        if (!number(summary,"terminal")) throw BackupRetry("NAS backup result is still incomplete");
    };
    // A persisted request survives process death before cancellation intent was
    // sent. recover_job never replays an uncertain check_complete request.
    if (latest && std::get<Value::Object>(latest->data).contains("nas_cancel_requested")) {
        resolve(true);
        return;
    }
    std::optional<BackupRun> watched;
    auto identity = [&](const Value& record) {
        const auto& fields = std::get<Value::Object>(record.data);
        if (!fields.contains("result_id")) return;
        watched = BackupRun{number(record, "running_task_id"), number(record, "version_id"),
                            number(record, "result_id"), number(record, "data_format")};
    };
    if (latest) identity(*latest);
    // Check a resumed job before fingerprinting or attempting its checkpoint.
    auto observed = watched ? observe(endpoint, view, task, *watched) : Observation::running;
    std::atomic_bool finished{false}, interrupt{observed != Observation::running};
    std::mutex mutex;
    std::condition_variable changed;
    std::exception_ptr observer_error;
    auto control_endpoint = endpoint;
    control_endpoint.cancelled = [&] {
        return finished.load() || (endpoint.cancelled && endpoint.cancelled());
    };
    auto transfer_endpoint = endpoint;
    transfer_endpoint.cancelled = [&] {
        return interrupt.load() || (endpoint.cancelled && endpoint.cancelled());
    };
    transfer_endpoint.source_read_activity = [&](std::uint64_t type, Value::Object parameters) {
        auto saved = *latest;
        append_source_activity(saved,type,std::move(parameters));
        persist(saved);
        publish_source_activities(endpoint,auth,*latest,persist);
    };
    std::thread observer([&] {
        try {
            std::unique_lock lock(mutex);
            changed.wait(lock, [&] { return finished.load() || watched.has_value(); });
            while (!finished && !interrupt) {
                const auto run = *watched;
                lock.unlock();
                const auto state = observe(control_endpoint, view, task, run);
                lock.lock();
                if (state != Observation::running) {
                    observed = state;
                    interrupt = true;
                    break;
                }
                changed.wait_for(lock, std::chrono::seconds{5}, [&] { return finished.load(); });
            }
        } catch (...) {
            if (!finished) {
                observer_error = std::current_exception();
                interrupt = true;
            }
        }
    });
    std::exception_ptr transfer_error;
    try {
        if (!interrupt) operation(transfer_endpoint, [&](const Value& record) {
            auto saved = record;
            std::get<Value::Object>(saved.data)["task_id"] = Value{task};
            persist(saved);
            {
                std::lock_guard lock(mutex);
                identity(saved);
            }
            changed.notify_all();
        });
    } catch (...) { transfer_error = std::current_exception(); }
    {
        std::lock_guard lock(mutex);
        finished = true;
    }
    changed.notify_all();
    observer.join(); // No observer ever accesses latest or the caller's store.
    if (latest && number(backup_job_status(*latest, auth), "terminal")) {
        if (transfer_error) std::rethrow_exception(transfer_error);
        return; // A received terminal reply wins a concurrent status observation.
    }
    if (endpoint.cancelled && endpoint.cancelled()) {
        if (transfer_error) std::rethrow_exception(transfer_error);
        throw Cancelled();
    }
    const auto record_disconnect = [&](const std::exception_ptr& error) {
        if (!error || !latest) return;
        try { std::rethrow_exception(error); }
        catch (const TransportError&) {
            auto saved = *latest;
            auto& fields = std::get<Value::Object>(saved.data);
            if (!fields.contains("disconnect_start_time")) {
                fields["disconnect_start_time"] = Value{static_cast<std::uint64_t>(std::time(nullptr))};
                persist(saved);
            }
        } catch (...) {}
    };
    record_disconnect(observer_error);
    record_disconnect(transfer_error);
    if (observer_error) std::rethrow_exception(observer_error);
    if (observed != Observation::running) {
        if (observed == Observation::cancelling) {
            auto saved = *latest;
            std::get<Value::Object>(saved.data)["nas_cancel_requested"] = Value{std::uint64_t{1}};
            persist(saved);
        }
        // Closing the transfer comes before cancellation. Missing queue entries
        // permit result reconciliation only, never a guessed cancellation.
        resolve(observed == Observation::cancelling);
        return;
    }
    if (transfer_error) {
        try { std::rethrow_exception(transfer_error); }
        catch (const TransportError&) { throw; }
        catch (const Cancelled&) { throw; }
        catch (const BackupRetry&) { throw; }
        catch (const BackupStateError&) { throw; }
        catch (const SourceReadError& error) {
            if (!latest) throw;
            auto saved = *latest;
            if (error.log_type() == 7020 && error.snapshot_error) {
                std::ostringstream hex;
                hex << std::hex << static_cast<std::uint64_t>(static_cast<std::int64_t>(error.snapshot_error));
                append_source_activity(saved,7084,{{"error_code",Value{hex.str()}}});
            }
            append_source_activity(saved,error.log_type(),error.parameters());
            auto& fields = std::get<Value::Object>(saved.data);
            fields["requested_outcome"] = Value{std::string("error")};
            fields["phase"] = Value{std::string("finish")};
            persist(saved);
            fail_service_backup(endpoint,auth,*latest,persist);
        }
        catch (const Error&) {
            if (!latest) throw;
            fail_service_backup(endpoint,auth,*latest,persist);
        }
    }
}
}
