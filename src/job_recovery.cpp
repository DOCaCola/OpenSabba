#include "opensabba/job_recovery.hpp"
#include "opensabba/backup_job.hpp"

namespace opensabba {
namespace {
using pstream::Value;
using pstream::Error;
const Value& field(const Value& value, const char* key) {
    const auto* map = std::get_if<Value::Object>(&value.data);
    if (!map || !map->contains(key)) throw Error(std::string("job recovery missing ") + key);
    return map->at(key);
}
std::string text(const Value& value, const char* key) {
    const auto* result = std::get_if<std::string>(&field(value, key).data);
    if (!result) throw Error("invalid job recovery text");
    return *result;
}
std::uint64_t number(const Value& value, const char* key) {
    const auto* result = std::get_if<std::uint64_t>(&field(value, key).data);
    if (!result) throw Error("invalid job recovery number");
    return *result;
}
bool terminal(std::string_view status) {
    return status == "complete" || status == "partial" || status == "error" || status == "cancel";
}
}
void apply_job_resolution(const Value& record, Value& summary) {
    const auto& fields = std::get<Value::Object>(record.data);
    if (!fields.contains("resolution")) return;
    const auto& resolution = fields.at("resolution");
    if (number(summary, "terminal") || !number(summary, "running_task_id"))
        throw Error("job resolution requires an unresolved known running task");
    const auto state = text(resolution, "state");
    const auto outcome = text(resolution, "outcome");
    const bool retired = state == "retired" && outcome == "unknown";
    if ((state == "cancel-pending" && outcome != "cancel") ||
        (state == "resolved" && !terminal(outcome)) ||
        (state != "resolved" && state != "cancel-pending" && !retired))
        throw Error("invalid job resolution state");
    auto& result = std::get<Value::Object>(summary.data);
    // Verification describes local file evidence, independent of NAS outcome.
    if (result.contains("verified") && state == "resolved" && outcome == "complete" &&
        !number(summary, "verified"))
        throw Error("restore cannot resolve as complete without verified image evidence");
    result["transfer_phase"] = field(summary, "phase");
    result["phase"] = Value{state == "resolved" ? outcome : state};
    result["terminal"] = Value{std::uint64_t{state == "resolved" || retired}};
}

void recover_job(const Endpoint& endpoint, const SavedAuth& auth, const Value& record,
                 bool cancel,const JobRecoveryPolicy& policy,const std::function<void(const Value&)>& save) {
    if (!save) throw Error("job recovery requires durable storage");
    const auto summary = policy.status(record);
    if (number(summary, "terminal")) throw Error("job already has a confirmed terminal outcome");
    const auto run = number(summary, "running_task_id");
    if (!run) throw Error("NAS creation outcome is unknown; no running task ID is available to reconcile or cancel");
    const auto task = number(summary, "task_id");
    auto saved = record;
    auto persist = [&] {
        // Validate before writing; a NAS outcome must never create a journal
        // that status cannot read (notably complete without local verification).
        (void)policy.status(saved);
        save(saved);
    };
    auto resolve = [&](std::string state, std::string outcome) {
        std::get<Value::Object>(saved.data)["resolution"] = Value{Value::Object{
            {"state", Value{std::move(state)}}, {"outcome", Value{std::move(outcome)}}}};
        persist();
    };
    const auto result_id = policy.result_id(saved);
    if (!std::get<Value::Object>(saved.data).contains("result_id")) {
        std::get<Value::Object>(saved.data)["result_id"] = Value{result_id};
        persist();
    }
    const auto outcome = policy.outcome(result_id);
    if (terminal(outcome)) { resolve("resolved", outcome); return; }
    if (!cancel) throw Error("NAS job result is still incomplete; journal remains unresolved");
    if (text(summary, "phase") == "cancel-pending")
        throw Error("previous cancellation outcome is unknown; cancellation was not replayed");
    bool found = false;
    for (const auto& job : running_tasks(endpoint, auth)) {
        if (number(job, "id") != run) continue;
        if (found || number(job, "task_id") != task ||
            number(job, "version_id") != number(summary, "version_id"))
            throw Error("NAS running task does not match the saved job");
        if (number(job, "result_id") != result_id || number(job, "type") != policy.task_type ||
            (policy.device_id && number(job,"device_id") != *policy.device_id))
            throw Error("NAS running task identity differs from the saved job");
        found = true;
    }
    if (!found) throw Error("saved job is no longer running; absence does not establish its outcome");
    auto intent = [&] { resolve("cancel-pending", "cancel"); };
    policy.cancel(saved,intent);
    resolve("resolved", "cancel");
}
void recover_backup_job(const Endpoint& endpoint,const SavedAuth& auth,const Value& record,
    bool cancel,const std::function<void(const Value&)>& save) {
    const JobRecoveryPolicy policy{0,{},
        [&](const Value& saved) { return backup_job_status(saved,auth); },
        [](const Value& saved) { return number(saved,"result_id"); },
        [&](std::uint64_t result) { return backup_result(endpoint,auth,number(record,"task_id"),result); },
        [&](const Value& saved,const std::function<void()>& intent) {
            const BackupRun run{number(saved,"running_task_id"),number(saved,"version_id"),
                number(saved,"result_id"),number(saved,"data_format")};
            if (finish_backup(endpoint,auth,run,BackupOutcome::cancelled,intent,
                backup_completion_cbt(saved)) != BackupOutcome::cancelled)
                throw Error("NAS did not confirm backup cancellation");
        }};
    recover_job(endpoint,auth,record,cancel,policy,save);
}

}
