#pragma once
#include "opensabba/capture.hpp"
#include "opensabba/image.hpp"
#include "opensabba/client.hpp"
namespace opensabba {
// Capture a NAS-selected current inventory plan. The plan, not a boot/root
// discovery convention, identifies the snapshot origins and physical images.
CaptureJournal create_machine_capture_from_plan(pstream::Value plan,
    const pstream::Value& task,
    std::uint64_t cow_mib,
    const std::function<void(const CaptureJournal&)>& reserved,
    const std::function<bool()>& cancelled = {},
    const std::function<void(const pstream::Value&)>& validate_plan = {},
    const SnapshotBoundaryHooks& hooks = {}, bool persistent_tracking = true,
    const std::vector<std::filesystem::path>& cache_exclusions = {},
    const std::function<bool()>& stopping = {});
// Reservation callback must durably record ownership before capture mutates
// driver state. No signal handlers or network operations are installed.
CaptureJournal create_machine_capture(const std::string& disk, const std::string& directory,
    std::uint64_t cow_mib,
    const std::function<void(const CaptureJournal&)>& reserved,
    const std::function<bool()>& cancelled = {},
    const std::function<void(const pstream::Value&)>& validate_plan = {},
    const std::vector<std::string>& selected_mounts = {},
    bool bare_metal = false, const SnapshotBoundaryHooks& hooks = {},
    bool persistent_tracking = false,
    const std::vector<std::filesystem::path>& cache_exclusions = {},
    const std::function<bool()>& stopping = {});
CaptureJournal inspect_machine_capture(const std::filesystem::path&, bool recover = false,
                                      const CaptureJournal* expected = nullptr);
CaptureJournal resume_machine_capture(const std::filesystem::path&, const CaptureJournal&,
                                      const std::function<bool()>& cancelled,
                                      const std::function<bool()>& stopping = {});
// Stable configured topology, excluding boot IDs and transient mount IDs.
pstream::Value machine_capture_target(const pstream::Value& plan);
// Transfer identity excludes LV physical discovery/inventory metadata; live
// source validation and persisted CBT ancestry remain separate requirements.
pstream::Value machine_incremental_target(const pstream::Value& plan);
void verify_machine_reservation(const CaptureJournal& reserved, const CaptureJournal& current);
// Retire only this released service artifact's reserved image/COW files.
// Keeps journals and a durable deletion marker for restart reconciliation.
void prune_machine_capture(const CaptureJournal&);
// End reading after a terminal NAS outcome; idempotently renew tracking state.
void finish_machine_capture(const std::filesystem::path&);
std::optional<std::uint64_t> queued_machine_run(const pstream::Value::Array&, std::uint64_t task);
// Validates captured interval geometry and live source ownership without payload reads.
void verify_machine_artifact(const CaptureJournal&, ImageSource&,
                             const std::function<bool()>& cancelled = {});
// Holds the capture directory and shared snapshot-reader locks through transfer.
// Raw disk intervals and retained small caches remain pinned alongside snapshots.
class ReadyMachineCapture {
public:
    explicit ReadyMachineCapture(const std::filesystem::path&);
    ~ReadyMachineCapture();
    const CaptureJournal& journal() const;
    ImageSource& source();
    std::size_t disk_count() const;
    ImageSource& source(std::size_t disk_index);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
// Typed unpublished-allocation cleanup; validates the reserved identities.
void discard_machine_reservation(const std::filesystem::path&);
}
