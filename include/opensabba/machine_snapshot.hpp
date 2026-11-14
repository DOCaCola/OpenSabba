#pragma once
#include "opensabba/capture.hpp"
#include <span>
#include <optional>
namespace opensabba {
// the official agent snapshot DB identity is an autoincrement key, independent of NAS
// versions, capture UUIDs, origin generations and wall-clock adjustments.
struct MachineSnapshot {
    std::uint64_t id{}, task_id{}, running_task_id{}, version_id{}, base_snapshot_id{};
    std::string task_uuid;
    std::optional<CaptureJournal> capture;
    std::vector<CaptureJournal> superseded;
};
class MachineSnapshotCatalog {
public:
    MachineSnapshotCatalog() = default;
    explicit MachineSnapshotCatalog(const pstream::Value&);
    pstream::Value value() const;
    bool empty() const { return snapshots_.empty(); }
    std::uint64_t reserve(std::uint64_t task, std::string uuid, std::uint64_t run, std::uint64_t base = 0, std::uint64_t version = 0);
    void attach(std::uint64_t id, const CaptureJournal&);
    void version(std::string_view capture, std::uint64_t version);
    const MachineSnapshot* capture(std::string_view id) const;
    const MachineSnapshot* snapshot(std::uint64_t id) const;
    const MachineSnapshot* event(std::string_view task_uuid, std::uint64_t run) const;
    std::vector<MachineSnapshot> older(std::string_view task_uuid, std::uint64_t base_id) const;
    const MachineSnapshot* base(std::string_view task_uuid, std::uint64_t version) const;
    std::vector<MachineSnapshot> rotation(std::string_view task_uuid, std::uint64_t version) const;
    std::vector<MachineSnapshot> removed_tasks(std::span<const std::string> task_uuids) const;
    void erase(std::uint64_t id);
    // Resource rotation and row deletion precede the durable placeholder used
    // by preparation; later capture/report failures cannot undo either step.
    std::uint64_t prepare(std::uint64_t task, std::string uuid, std::uint64_t run, std::uint64_t base_id,
        const std::function<void(const MachineSnapshot&)>& cleanup,
        const std::function<void(const MachineSnapshotCatalog&)>& save, std::uint64_t version = 0);
private:
    std::uint64_t next_id_ = 1;
    std::vector<MachineSnapshot> snapshots_;
};
}
