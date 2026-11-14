#pragma once
#include "opensabba/pstream.hpp"

namespace opensabba {
// Backend request versus controller-confirmed, durably recorded cleanup.
class CaptureStopRequested : public pstream::Error {
public: CaptureStopRequested() : Error("machine capture cancelled") {}
};
class CaptureInterrupted : public pstream::Error {
public: CaptureInterrupted() : Error("machine capture interrupted; snapshots retained") {}
};
class CaptureCancelled : public pstream::Error {
public: CaptureCancelled() : Error("machine capture cancelled; owned resources released") {}
};
class CaptureFailed : public pstream::Error {
public: using Error::Error;
};
class CapturePersistenceError : public pstream::Error {
public: using Error::Error;
};
class CaptureUncertain : public pstream::Error {
public: using Error::Error;
};
// Intent is persisted before an operation. A restarted process never resumes
// an intent by repeating its mutation; it reconciles/abandons the capture.
enum class CapturePhase {
    prepared, static_copy_intent, static_copied,
    snapshot_intent, snapshot_active,
    root_copy_intent, root_copied, extra_copy_intent, extra_copied,
    seal_intent, ready, recovery_required, aborted
};
// Pre runs before discovery/static-copy/snapshot work. After pre succeeds,
// post runs once after usable snapshot publication or a boundary failure.
// Neither callback runs on recovery.
struct SnapshotBoundaryHooks {
    std::function<void()> pre_snapshot;
    std::function<void()> post_snapshot;
    // Successful acquisition boundary; application scripts are outside it.
    std::function<void(std::uint64_t nanoseconds)> snapshot_elapsed;
    // Analyze custom selection at the snapshot boundary. The controller records
    // one durable 7096 before acquisition; recovery never repeats this callback.
    std::function<std::vector<std::string>(const pstream::Value&)> missing_custom_mounts;
};
struct CaptureJournal {
    std::string id, boot_id;
    CapturePhase phase = CapturePhase::prepared;
    pstream::Value plan, reservation, snapshot, artifact;
    std::string failure;
    // Current capture schema; older serialized artifacts are not supported.
    std::uint64_t schema = 5;
    // Describes the local attempt. NAS checkpoint state decides whether an
    // interrupted attempt is recaptured or reported as a missing snapshot.
    std::string failure_disposition;
    pstream::Value::Array logs;
};
pstream::Value capture_journal_value(const CaptureJournal&);
CaptureJournal capture_journal_from_value(const pstream::Value&);
bool capture_failure_reportable(const CaptureJournal&);
// Durable type-4 result, distinct from a missing/lost acquired snapshot.
bool capture_snapshot_omitted(const pstream::Value&);
class SnapshotAcquisitionError;
// A definitive failed acquisition owns no new driver slot. Durably record
// type-4/released state, then retire only its unused reservation. A successful
// renewal followed by previous-COW compression failure retains its new COW.
// Unknown control/query/identity outcomes must never use this path.
pstream::Value record_snapshot_acquisition_failure(CaptureJournal&,
    pstream::Value& reservation, bool root, const SnapshotAcquisitionError&,
    const std::function<void()>& retire_unused,
    const std::function<void(const CaptureJournal&)>& persist);

// The backend owns pinned descriptors and snapshot resource identities.
// Storage is reserved before this transaction; network work belongs outside it.
// Synosnap freezes/thaws mounted origins inside its snapshot ioctl.
class CaptureOperations {
public:
    virtual ~CaptureOperations() = default;
    virtual void persist(const CaptureJournal&) = 0; // atomic, durable
    virtual void verify_inputs() = 0;
    virtual std::uint64_t snapshot_time();
    virtual pstream::Value snapshot_root() = 0;
    // Establish every selected extra snapshot in a distinct journaled slot.
    // No snapshot reader/control lock may survive snapshot creation.
    virtual void snapshot_extra_volumes() = 0;
    // Small official agent type-3 intervals only; check cancellation and source identity.
    virtual void cache_raw_regions() = 0;
    virtual void prepare_snapshot_root(const pstream::Value&) = 0;
    // Reads the already established snapshots; never creates/releases one.
    virtual void prepare_extra_volumes() = 0;
    virtual pstream::Value seal_raw_cache() = 0; // fsync + validate + immutable identity
    virtual bool cancelled() = 0;
    // the official agent service-abort: connection editing and termination both join workers.
    // An established set is published/retained; abort before acquisition cleans up.
    virtual bool stopping() { return false; }

    // Reconciliation must consult actual resource identities and the reservation
    // even when an operation applied but its result was lost. These are
    // idempotent ONLY for proven owned resources. Foreign/unknown => throw.
    virtual void recover_snapshot(const CaptureJournal&) = 0;
};
// On failure, reconcile owned snapshots even when journal writes fail.
void run_machine_capture(CaptureJournal&, CaptureOperations&, const SnapshotBoundaryHooks& = {});
// Reuse an established snapshot set after process death. Scripts and snapshot
// creation are not repeated; incomplete allocation preparation is rebuilt.
void resume_machine_capture(CaptureJournal&, CaptureOperations&);
// Cleanup-only recovery never publishes a partial image. Service restart can
// select resume_machine_capture for an established set before calling this.
void recover_machine_capture(CaptureJournal&, CaptureOperations&);
}
