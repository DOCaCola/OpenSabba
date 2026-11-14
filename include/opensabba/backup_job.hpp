#pragma once
#include "opensabba/client.hpp"
#include "opensabba/image.hpp"

namespace opensabba {
// Invalid local journal identity, schema or retained transfer policy. This is
// distinct from an operational failure of the backup described by the record:
// an untrusted record cannot authorize a NAS completion or further uploads.
class BackupStateError : public pstream::Error { public: using Error::Error; };
// Save must atomically persist and fsync the entire record or throw. The caller
// must hold its private job-store lock, reject unresolved earlier jobs, and bind
// loaded records to the current NAS/device/account before reconciliation.
using SaveBackupJob = std::function<void(const pstream::Value&)>;
BackupOutcome resume_image_job(const Endpoint&, const SavedAuth&, ImageSource&,
                                    const pstream::Value& saved, const SaveBackupJob&,
                                    std::span<const ChangedExtent> unused_ranges = {},
                                    std::span<const ChangedExtent> reread_ranges = {});
struct BackupImage {
    ImageSource* source;
    std::string name;
    // Explicit type-5 intervals and wholly free filesystem query ranges.
    std::vector<ChangedExtent> unused_ranges;
    // Raw intervals reread by every incremental without CBT context.
    std::vector<ChangedExtent> reread_ranges = {};
};
BackupOutcome run_full_images_job(const Endpoint&, const SavedAuth&, std::uint64_t running_task_id,
                                  std::span<const BackupImage>, std::span<const std::uint8_t> snapshot_json,
                                  const SaveBackupJob&, TransferCompression);
BackupOutcome resume_images_job(const Endpoint&, const SavedAuth&, std::span<const BackupImage>,
                                const pstream::Value& saved, const SaveBackupJob&);
struct IncrementalBackup {
    std::uint64_t base_version_id, base_result_id, base_running_task_id;
    std::string base_snapshot_id, base_image_sha256;
    DeltaPlan plan;
    std::vector<ChangedExtent> reread_ranges = {};
    // Machine-only origin correspondence and actual CBT context outcomes.
    std::optional<pstream::Value> machine_policy = {};
};
// Completion CBT describes successful filesystem contexts, independently of the NAS base.
bool backup_completion_cbt(const pstream::Value&);
BackupOutcome run_incremental_images_job(const Endpoint&, const SavedAuth&, std::uint64_t task_id,
                                         std::uint64_t running_task_id, std::span<const BackupImage>,
                                         std::span<const IncrementalBackup>,
                                         std::span<const std::uint8_t> snapshot_json,
                                         const SaveBackupJob&, TransferCompression);
BackupOutcome create_cached_images_job(const Endpoint&, const SavedAuth&, std::uint64_t task_id,
    std::span<const BackupImage>, std::span<const IncrementalBackup>,
    std::span<const std::uint8_t> snapshot_json, const SaveBackupJob&, TransferCompression,
    BackupOutcome requested = BackupOutcome::complete);
BackupOutcome run_incremental_image_job(const Endpoint&, const SavedAuth&, std::uint64_t task_id,
                                        std::uint64_t running_task_id, ImageSource&, std::string_view image_name,
                                        std::span<const std::uint8_t> snapshot_json,
                                        const IncrementalBackup&, const SaveBackupJob&, TransferCompression,
                                        std::span<const ChangedExtent> unused_ranges = {},
                                        std::span<const ChangedExtent> reread_ranges = {});
BackupOutcome create_incremental_image_job(const Endpoint&, const SavedAuth&, std::uint64_t task_id,
                                           ImageSource&, std::string_view image_name,
                                           std::span<const std::uint8_t> snapshot_json,
                                           const IncrementalBackup&, const SaveBackupJob&,
                                           TransferCompression);
BackupOutcome create_full_image_job(const Endpoint&, const SavedAuth&, std::uint64_t task_id,
                                    ImageSource&, std::string_view image_name,
                                    std::span<const std::uint8_t> snapshot_json,
                                    const SaveBackupJob&,
                                    TransferCompression compression = TransferCompression::none);

// Executes one full image against a NAS-created running task. snapshot_json
// must be produced by a validated snapshot provider for this image.
// Persists intent before each mutation and observations after every reply.
// A lost reply or failed save leaves an unresolved journal, never auto-retried.
// Keeps one ImageSource descriptor open throughout; path replacement cannot
// substitute a different file after metadata was sent.
BackupOutcome run_full_image_job(const Endpoint&, const SavedAuth&, std::uint64_t running_task_id,
                                 ImageSource&, std::string_view image_name,
                                 std::span<const std::uint8_t> snapshot_json,
                                 const SaveBackupJob&,
                                 BackupOutcome requested = BackupOutcome::complete,
                                 TransferCompression compression = TransferCompression::none,
                                 std::span<const ChangedExtent> unused_ranges = {});
// Checks schema and identity, returns a credential-free status summary. Does
// not resume a job or infer a NAS outcome from a local pending phase.
pstream::Value backup_job_status(const pstream::Value&, const SavedAuth&);
}
