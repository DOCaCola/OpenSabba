#pragma once
#include "opensabba/backup_job.hpp"
#include <optional>
#include <string_view>

namespace opensabba {
// Restore an image selected from a successful private backup journal. With no
// selector, use its primary image. The caller holds the store lock and rejects
// unresolved earlier jobs.
// Destination must be new; failures preserve it and the last durable phase.
void restore_saved_image(const Endpoint&, const SavedAuth&, const pstream::Value& backup,
                         const std::filesystem::path& destination,
                         std::optional<std::string_view> image_name, const SaveBackupJob&);
pstream::Value restore_job_status(const pstream::Value&, const SavedAuth&);
// Resume only a journaled download on the same live NAS run. Checks file
// identity and the durable prefix hash before discarding uncommitted tail bytes.
void resume_saved_image(const Endpoint&, const SavedAuth&, const pstream::Value&, const SaveBackupJob&);
}
