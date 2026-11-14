#pragma once
#include "opensabba/backup_job.hpp"

namespace opensabba {
// Observe a queued entry or the exact pre-handshaken capture run. The capture
// thread receives only a nonblocking cancellation predicate.
enum class QueuedCaptureOutcome { complete, cancelled, failed };
QueuedCaptureOutcome run_queued_machine_capture(const Endpoint&, const TaskView&, std::uint64_t task,
    std::uint64_t run, const std::function<void(const std::function<bool()>&)>&);
// Reconstruct preparation from the exact NAS event, retry metadata with the
// retained snapshot, and reconcile/retry a lost completion reply.
void recover_service_backup(const Endpoint&, const SavedAuth&, pstream::Value&,
                            const SaveBackupJob&);
void fail_service_backup(const Endpoint&, const SavedAuth&, pstream::Value&,
                         const SaveBackupJob&, std::string_view missing_volume = {},
                         BackupOutcome requested = BackupOutcome::error);
// The calling thread owns the store and performs every journal write. The
// observer reads the event-refreshed task view for the exact prepared identity.
void run_service_backup(const Endpoint&, const SavedAuth&, const TaskView&, std::uint64_t task_id,
                        std::optional<pstream::Value> saved, const SaveBackupJob&,
                        const std::function<void(const Endpoint&, const SaveBackupJob&)>& operation);
}
