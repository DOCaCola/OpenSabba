#pragma once
#include "opensabba/backup_job.hpp"

namespace opensabba {
struct BackupCachePolicy {
    bool enabled = false, paused = false;
    std::string volume_uuid, mount_path;
    std::uint64_t floor_unit = 0, floor_value = 0;
};
struct CaptureJournal;
// Only controller-confirmed acquisition omissions make a successful cache partial.
bool backup_cache_capture_partial(const CaptureJournal&);
// Local cache bases require a clean capture for the configured topology and
// independent storage. A durable retention marker makes a retired capture
// ineligible, even while its old NAS backup record remains in the job archive.
bool backup_cache_base_eligible(const CaptureJournal&, const pstream::Value& configured_target);
// Normalize official agent generate_event/cache_write input against the assigned task.
// The service persists the result before acknowledging local acceptance.
pstream::Value backup_cache_write_event(const pstream::Value& request,
    const pstream::Value& task_owner, const pstream::Value& policy_record,
    std::string event_id, std::uint64_t now);
BackupCachePolicy backup_cache_policy(const pstream::Value&);
pstream::Value translate_backup_cache_task(pstream::Value task, const pstream::Value::Array& mounted);
bool backup_cache_space_enough(const BackupCachePolicy&, std::uint64_t capacity,
                              std::uint64_t free);
// Resolve the filesystem UUID against current mounts; the display path is not
// authoritative. The returned directory belongs to the task UUID.
std::filesystem::path backup_cache_directory(const BackupCachePolicy&, std::string_view task_uuid,
                                            bool admission = true);
// Portable, explicitly little-endian record/data pairs. The manifest is
// published by the caller only after all pairs have closed and synced.
pstream::Value write_backup_cache_image(const std::filesystem::path& directory,
    std::string_view basename, const BackupImage&, const IncrementalBackup&,
    TransferCompression, const std::function<bool()>& cancelled = {});
void validate_backup_cache_image_policy(const pstream::Value& manifest, const BackupImage&,
    const IncrementalBackup&, TransferCompression);
class CachedBackupImage {
public:
    CachedBackupImage(const std::filesystem::path& directory, const pstream::Value& manifest);
    ~CachedBackupImage();
    ImageSource& source();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
// Deletes only exact manifest-owned file pairs after authoritative completion
// or terminal invalidation. No directory globbing or space-driven eviction.
void remove_backup_cache_image(const std::filesystem::path&, const pstream::Value&);
void remove_backup_cache_attempt(const std::filesystem::path&, std::string_view basename);
// Physical filesystem ranges occupied by immutable queued cache files on this
// origin. Other filesystems are ignored by identity, never by pathname.
std::vector<ChangedExtent> backup_cache_exclusions(std::string_view origin,
    std::uint64_t length, std::span<const std::filesystem::path> files);
}
