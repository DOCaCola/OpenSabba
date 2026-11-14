#pragma once
#include "opensabba/client.hpp"

namespace opensabba {
// A completed mode-1 failure is terminal for this event, unlike transport or
// persistence uncertainty and service abort during script execution.
class BackupScriptFailed : public pstream::Error {
public: using Error::Error;
};
struct BackupScript {
    bool enabled = false;
    std::uint64_t error = 0;
    std::string extension;
    pstream::Bytes content;
};
struct BackupScripts {
    BackupScript pre, post;
    bool stop_on_failure = false;
    bool enabled() const { return pre.enabled || post.enabled; }
};
// Execution-only task data. Never include its contents in discovery/display.
pstream::Value::Object task_script_execution_policy(const pstream::Value&);
BackupScripts backup_scripts(const pstream::Value&);
struct ScriptResult {
    std::uint64_t log_type = 0;
    int exit_code = -1;
    bool cancelled = false;
    bool has_output = false;
};
ScriptResult execute_backup_script(const BackupScript&, bool pre, bool stop_on_failure,
    const std::filesystem::path& directory, std::uint64_t run,
    const std::function<bool()>& cancelled = {},
    std::chrono::milliseconds timeout = std::chrono::seconds{180});
using SaveScriptRun = std::function<void(const pstream::Value&)>;
// Intent survives process death. An uncertain invocation is never replayed.
pstream::Value new_script_run(const BackupScripts&, std::uint64_t task, std::uint64_t run,
                             std::string_view task_uuid);
void validate_script_run(const pstream::Value&, const BackupScripts&, std::uint64_t task,
                         std::uint64_t run, std::string_view task_uuid);
BackupScripts retained_backup_scripts(const pstream::Value&);
void run_backup_script_once(pstream::Value&, const BackupScripts&, bool pre,
    const std::filesystem::path& directory, const SaveScriptRun&,
    const std::function<bool()>& cancelled = {});
// Publish only after result binding; capture details belong between pre and post.
void report_backup_scripts(const Endpoint&, const SavedAuth&, pstream::Value&,
    const std::filesystem::path& directory, std::uint64_t version, std::uint64_t result,
    const SaveScriptRun&, std::span<const pstream::Value> capture_logs = {});
void report_capture_activity(const Endpoint&, const SavedAuth&, pstream::Value&,
    std::span<const pstream::Value> logs, std::uint64_t result, const SaveScriptRun&);
bool backup_scripts_failed(const pstream::Value&);
// Failed capture has no image journal. Recover NAS preparation by its exact
// event and retry incomplete completion against the same result. Returns true
// only after completion and all pending script/output/detail reports are saved.
bool finish_failed_backup(const Endpoint&, const SavedAuth&, pstream::Value&,
    const std::filesystem::path&, const SaveScriptRun&);
}
