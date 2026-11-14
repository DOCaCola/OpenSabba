#pragma once
#include "opensabba/pstream.hpp"
#include "opensabba/bad_cluster.hpp"
#include <optional>
#include <memory>

namespace opensabba {
class SnapshotDriverError : public pstream::Error {
public:
    int error;
    SnapshotDriverError(std::string message, int code) : Error(std::move(message)), error(code) {}
};
// A setup/renew ioctl or previous-COW compression rejected this origin.
// Control access, ABI, identity queries and later health failures are never this type.
class SnapshotAcquisitionError : public SnapshotDriverError {
public: using SnapshotDriverError::SnapshotDriverError;
};
// Pins an explicitly selected ext2/ext3/ext4/XFS origin's canonical path, device number,
// byte length and filesystem UUID without creating a snapshot.
pstream::Value snapshot_origin_identity(const std::string& path);
// Read-only control inspection. Never loads a module, creates a snapshot,
// reserves a minor, opens an origin, or treats ioctl success as backup readiness.
// An absent control device is a reported state; permissions/ABI failures throw.
pstream::Value snapshot_driver_status(std::optional<std::uint32_t> minor = {});
// Missing slot is distinct from unavailable control/failed query.
std::optional<pstream::Value> snapshot_driver_information(std::uint32_t minor);
// Refuse retirement while any driver slot refers to this origin (including
// aliases and unverified reload slots). Never destroys a slot or COW file.
void snapshot_driver_require_untracked(const std::string& origin, std::uint64_t device);
// Runs deletion while holding the control lock after checking every driver slot.
// Also works when the separately managed module is unloaded.
void with_unused_snapshot_cow(const std::string& path, std::uint64_t device, std::uint64_t inode,
                              const std::function<void()>&);
// Caller must durably journal intent and own an exclusive private COW file.
// These do not load the module or manage mounted filesystems.
// Allocation 0 selects official agent's driver default (10% of this origin).
void snapshot_driver_create(std::uint32_t minor, const std::string& origin,
                            const std::string& cow, std::uint64_t allocated_mib);
// the official agent fresh setup: query the history-selected minor, try to unmount its
// /tmp/dev/synosnapN mount, ignore destroy failure, then attempt setup once.
void snapshot_driver_setup(std::uint32_t minor, const std::string& origin,
                           const std::string& cow, std::uint64_t allocated_mib);
// Bad-state cleanup: unmount /tmp/dev/synosnapN when present, attempt
// destruction even for a vanished slot, and report destroy failure to syslog.
// Caller queries absence before deleting saved history.
void snapshot_driver_bad_state(const pstream::Value& saved);
// Rechecks identity under an advisory control lock before mutation.
// Requires exclusive lifecycle management: the official agent does not honor it.
void snapshot_driver_release(const pstream::Value& expected);
// Caller journals intent and owns the next COW file before renewal.
void snapshot_driver_track(const pstream::Value& expected);
void snapshot_driver_renew(const pstream::Value& expected, const std::string& cow,
                           std::uint64_t allocated_mib);
// Boot hook only: register an unmounted origin for mount-time reactivation.
void snapshot_driver_reload(std::uint32_t minor, const std::string& origin,
                            const std::string& relative_cow, bool snapshot);
// Holds the control lock and a verified snapshot descriptor for its lifetime.
// Never opens the origin. Health and identity are checked around every read.
class SnapshotReader {
public:
    explicit SnapshotReader(const pstream::Value& identity, bool interval_source = false);
    ~SnapshotReader();
    SnapshotReader(const SnapshotReader&) = delete;
    SnapshotReader& operator=(const SnapshotReader&) = delete;
    std::uint64_t size() const;
    const BadClusterContext& bad_clusters() const;
    void verify() const;
    // Checks all driver slots while retaining this reader's control lock.
    void verify_cow_unused(const std::string& path, std::uint64_t device, std::uint64_t inode) const;
    pstream::Bytes read(std::uint64_t offset, std::size_t length,
                        std::uint64_t* read_nanoseconds = nullptr);
    // Used/allocation metadata keeps the buffered filesystem-parser descriptor.
    pstream::Bytes read_metadata(std::uint64_t offset, std::size_t length);
private:
    pstream::Bytes read_from(bool metadata, std::uint64_t, std::size_t, std::uint64_t*);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
