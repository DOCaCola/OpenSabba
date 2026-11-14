#pragma once
#include "opensabba/capture.hpp"
#include "opensabba/delta_plan.hpp"
#include <filesystem>

namespace opensabba {
// One new random RFC 4122 version-4 UUID for every origin and renewal.
std::string machine_tracking_cow_name(std::uint64_t seconds);
// On-origin COW storage and mount-time reload records used by automatic capture.
// The returned reservation owns an empty private file and a selected minor.
pstream::Value reserve_machine_tracking(const pstream::Value& volume,
    const std::filesystem::path& captures, std::string_view capture_id,
    std::span<const std::uint32_t> reserved_minors);
// Caller journals the reservation before changing the driver. On success the
// callback persists the established generation before publishing its reload.
// A lost reply is reconciled against the reserved generation, never replayed.
pstream::Value acquire_machine_tracking(pstream::Value& reservation,
    const pstream::Value& volume, std::uint64_t allocated_mib,
    const std::function<void(const pstream::Value&)>& persist);
void finish_machine_tracking(const pstream::Value& reservation,
    const pstream::Value& volume, const pstream::Value& snapshot);
void discard_machine_tracking(const pstream::Value& reservation,
    const pstream::Value& volume, const pstream::Value& snapshot);
// Retires only the reservation's exact inode, never a live driver's COW.
void prune_machine_tracking(const pstream::Value& reservation);
// The setup/renew ioctl definitively failed. Its new COW was never adopted;
// unlink only that exact reserved inode without querying or changing a slot,
// previous history or a reload command.
void prune_failed_machine_tracking(const pstream::Value& reservation);
// Mark the requested history deleted; remove an eligible bdev prefix and
// unlink its COWs, then remove saved-bdev reload and destroy the minor only
// when no history for that bdev remains (official agent Snapshot deletion).
void prune_machine_tracking_history(const pstream::Value& reservation,
    const pstream::Value& volume, const std::filesystem::path& captures);
void verify_machine_tracking_cow(const pstream::Value& reservation);
// Uses persisted generation ranges; no image comparison or live-origin reads.
DeltaPlan machine_tracking_delta(const CaptureJournal& current,
    const CaptureJournal& base, std::size_t image_index,
    std::span<const std::string> current_images, std::span<const std::string> base_images,
    std::vector<ChangedExtent>* reread_ranges = nullptr, bool require_cbt = false,
    pstream::Value* interval_policy = nullptr);
std::vector<ChangedExtent> machine_tracking_unused(const CaptureJournal&, std::size_t image_index,
    bool incremental = false, std::span<const ChangedExtent> reread = {});
std::vector<ChangedExtent> machine_snapshot_omissions(const CaptureJournal&, std::size_t image_index);
}
