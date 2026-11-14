#pragma once
#include "opensabba/pstream.hpp"
#include "opensabba/snapshot_driver.hpp"
#include <optional>
#include <filesystem>
#include <string>
#include <string_view>
#include <span>
#include <vector>

namespace opensabba {
// the official agent preserves the discovery path as the history bdev and reload key.
// An LV uses /dev/VG/LV; its canonical dm-N path is only an I/O identity.
const std::string& machine_tracking_device(const pstream::Value& volume);

// Reload command and durable ownership are one atomic filesystem object. The
// record contains no capture-directory or CBT ancestry and cannot authorize
// incremental transfer without the independent capture journals.
pstream::Value machine_tracking_owner(const pstream::Value& volume,
    const pstream::Value& reservation, const pstream::Value& snapshot);
// Independent capture-journal reservation evidence for an incomplete setup.
// This is never a boot reload record and never authorizes a verified generation.
pstream::Value machine_tracking_reservation_owner(const pstream::Value& volume,
    const pstream::Value& reservation);
std::string machine_tracking_record(const pstream::Value& owner,
    std::string_view executable, bool active_snapshot);
std::optional<pstream::Value> machine_tracking_record_owner(std::string_view record);
// Checks UUID/path/minor/generation before a durable owner can reset a slot.
// A verified generation mismatch is always foreign, including failed slots.
void require_machine_tracking_owner(const pstream::Value& owner,
    const pstream::Value& volume, const pstream::Value& observed);
bool machine_tracking_owner_reservation(const pstream::Value& owner,
    const pstream::Value& reservation);
// Observed COW identity is inode + filesystem_uuid; a missing file is nullopt.
// This establishes exact slot authority, never capture/base/CBT ancestry.
pstream::Value machine_tracking_recovery_prior(const pstream::Value& owner,
    const pstream::Value& volume, const pstream::Value& observed,
    const std::optional<pstream::Value>& cow);
bool machine_tracking_healthy(const pstream::Value& observed);
// Free-minor selection: first integer 0..254 absent from history.
// Kernel occupancy is deliberately not an input; -1 means none is available.
std::int32_t machine_tracking_free_minor(std::span<const std::uint32_t> history);
inline constexpr std::uint32_t machine_tracking_no_minor = UINT32_MAX;

struct MachineTrackingOwnerRecord { pstream::Value owner; std::string name; };
// Linux filesystem store. Production binds this to /etc/synosnap/dla; file-only
// tests use a private temporary directory and the same read/publish/retire path.
class MachineTrackingRecords {
    std::filesystem::path directory_;
    void publish_owner(const pstream::Value& volume, const pstream::Value& owner,
                       std::string_view executable, bool active) const;
public:
    explicit MachineTrackingRecords(std::filesystem::path directory);
    // Lookup recovery metadata for an exact driver/journal COW and minor.
    // Several retained basenames may contain the same filesystem UUID.
    std::optional<MachineTrackingOwnerRecord> find(const pstream::Value& volume,
        std::uint32_t minor, std::string_view cow_relative) const;
    void publish(const pstream::Value& volume, const pstream::Value& reservation,
                 const pstream::Value& snapshot, std::string_view executable, bool active) const;
    // Call only after the history lifecycle authorizes removal. the official agent removes
    // the saved bdev basename even if a later writer replaced its contents.
    void retire(const pstream::Value& volume) const;
};

// Per-origin database deletion state, separate from immutable capture/CBT
// evidence. Retired generations no longer own a minor or authorize renewal.
class MachineTrackingHistory {
    std::filesystem::path directory_;
public:
    explicit MachineTrackingHistory(std::filesystem::path directory);
    bool retired(const pstream::Value& reservation) const;
    void retire(const pstream::Value& reservation) const;
};

// libsynosnap history has its own insertion order, independent of the agent's
// backup/version catalog. Only successfully inserted rows allocate minors.
class MachineTrackingDatabase {
    std::uint64_t next_id_ = 1;
    pstream::Value::Array rows_;
public:
    MachineTrackingDatabase() = default;
    explicit MachineTrackingDatabase(const pstream::Value& saved);
    pstream::Value value() const;
    std::optional<pstream::Value> last(const pstream::Value& volume) const;
    void add(pstream::Value prior);
    std::vector<std::uint32_t> minors() const;
    pstream::Value::Array remove_before(const pstream::Value& prior);
    pstream::Value::Array delete_snapshot(const pstream::Value& reservation);
};
class MachineTrackingDatabaseStore {
    std::filesystem::path path_;
public:
    explicit MachineTrackingDatabaseStore(std::filesystem::path path);
    MachineTrackingDatabase load() const;
    void save(const MachineTrackingDatabase& history) const;
};

// Renewal succeeded, but previous-generation index retention could not open the old
// COW. The new snapshot stays in the driver without a history/reload entry.
class SnapshotPreviousCowError : public SnapshotAcquisitionError {
public: using SnapshotAcquisitionError::SnapshotAcquisitionError;
};

// Driver transition boundary, shared by production and the fault/reboot model.
// Filesystem publication follows only after this returns a validated new slot.
class MachineTrackingControl {
public:
    virtual ~MachineTrackingControl() = default;
    virtual std::optional<pstream::Value> information(std::uint32_t minor) = 0;
    virtual void verify_prior_cow(const pstream::Value& reservation) = 0;
    virtual pstream::Value close_prior(const pstream::Value& prior,
        const pstream::Value& current, const pstream::Value& volume) = 0;
    virtual void release(const pstream::Value& observed) = 0;
    virtual void retire_record(const pstream::Value& volume, const pstream::Value& reservation) = 0;
    virtual void create(std::uint32_t minor, const std::string& origin,
                        const std::string& cow, std::uint64_t mib) = 0;
    virtual void renew(const pstream::Value& observed, const std::string& cow, std::uint64_t mib) = 0;
};
// Resolve the saved bdev row before minor allocation; bad-state cleanup frees
// its row and all predecessors even when the kernel has forgotten every slot.
std::optional<pstream::Value> prepare_machine_tracking(MachineTrackingDatabase& history,
    const pstream::Value& volume, MachineTrackingControl& control);
pstream::Value transition_machine_tracking(pstream::Value& reservation,
    const pstream::Value& volume, std::uint64_t mib, MachineTrackingControl& control);
}
