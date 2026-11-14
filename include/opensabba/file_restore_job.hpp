#pragma once
#include "opensabba/backup_job.hpp"
#include <optional>

namespace opensabba {
// Validate and allowlist the official agent type-1 task schema. Boolean wire values are
// PStream integers, and missing transfer settings are errors.
pstream::Value file_restore_task(const pstream::Value& running);
struct FileRestoreRecordFlags { bool skip, compression; };
// Stream record flags are optional: official agent mutable lookups materialize null
// for false skip, and raw records need not contain compression.
FileRestoreRecordFlags file_restore_record_flags(const pstream::Value& file);
// the official agent's metadata decoder uses unsigned 32-bit fields, initialized to -1
// when absent and zero when explicitly null. ACL/xattrs are not applied.
pstream::Value file_restore_metadata(const pstream::Value& file);
pstream::Value file_restore_job_status(const pstream::Value&, const SavedAuth&);
inline constexpr pstream::Limits file_restore_limits{34 * 1024 * 1024, 100'000, 64};
// Extract only the destination ID for the saved UUID from list_device_task;
// source backup tasks may belong to another device.
std::uint64_t file_restore_device(const Endpoint&, const SavedAuth&);

void download_restore_files(const Endpoint&, const SavedAuth&, std::uint64_t run,
    const std::optional<pstream::Value>& resume,
    const std::function<void(const pstream::Value&)>& receive,
    const std::function<pstream::Value::Array(const pstream::Value&,
                                            const std::function<void()>&)>& precheck);
void acknowledge_restore_files(const Endpoint&, const SavedAuth&, std::uint64_t run,
                               const pstream::Value::Array& done);
std::string finish_file_restore(const Endpoint&, const SavedAuth&, std::uint64_t run,
                               std::string_view status, const std::function<void()>& before_send);
// One official agent NAS-pushed file restore. The context and callback are process-local;
// the service retains them across connection attempts, never across restart.
// Transport failure retains the partial file and queued IDs for that process.
std::string run_service_file_restore(const Endpoint&, const SavedAuth&, const TaskView&,
    const pstream::Value& running, std::optional<pstream::Value> context, const SaveBackupJob&);
}
