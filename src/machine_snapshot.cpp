#include "opensabba/machine_snapshot.hpp"
#include <algorithm>
#include <set>
namespace opensabba {
using pstream::Value;
using pstream::Error;
namespace {
const Value& field(const Value& v, const char* key) { return std::get<Value::Object>(v.data).at(key); }
std::uint64_t number(const Value& v, const char* key) { return std::get<std::uint64_t>(field(v,key).data); }
const std::string& text(const Value& v, const char* key) { return std::get<std::string>(field(v,key).data); }
}
MachineSnapshotCatalog::MachineSnapshotCatalog(const Value& saved) {
    if (number(saved,"format") != 1 || !(next_id_ = number(saved,"next_id")))
        throw Error("invalid machine snapshot catalog");
    std::set<std::uint64_t> ids;
    std::set<std::string> captures;
    for (const auto& row : std::get<Value::Array>(field(saved,"snapshots").data)) {
        MachineSnapshot snapshot{number(row,"id"),number(row,"task_id"),number(row,"running_task_id"),
            number(row,"version_id"),number(row,"base_snapshot_id"),text(row,"task_uuid"),{}, {}};
        if (!snapshot.id || snapshot.id >= next_id_ || !snapshot.task_id || snapshot.task_uuid.empty() ||
            !ids.insert(snapshot.id).second) throw Error("invalid machine snapshot catalog row");
        if (std::get<Value::Object>(row.data).contains("capture")) {
            snapshot.capture = capture_journal_from_value(field(row,"capture"));
            if (!captures.insert(snapshot.capture->id).second) throw Error("duplicate catalog capture");
        }
        for (const auto& capture : std::get<Value::Array>(field(row,"superseded").data)) {
            auto previous = capture_journal_from_value(capture);
            if (!captures.insert(previous.id).second) throw Error("duplicate catalog capture");
            snapshot.superseded.push_back(std::move(previous));
        }
        snapshots_.push_back(std::move(snapshot));
    }
}
Value MachineSnapshotCatalog::value() const {
    Value::Array rows;
    for (const auto& snapshot : snapshots_) {
        Value::Object row{{"id",Value{snapshot.id}},{"task_id",Value{snapshot.task_id}},
            {"task_uuid",Value{snapshot.task_uuid}},{"running_task_id",Value{snapshot.running_task_id}},
            {"version_id",Value{snapshot.version_id}},{"base_snapshot_id",Value{snapshot.base_snapshot_id}}};
        if (snapshot.capture) row.emplace("capture",capture_journal_value(*snapshot.capture));
        Value::Array superseded;
        for (const auto& previous : snapshot.superseded) superseded.push_back(capture_journal_value(previous));
        row.emplace("superseded",Value{std::move(superseded)});
        rows.push_back(Value{std::move(row)});
    }
    return Value{Value::Object{{"format",Value{std::uint64_t{1}}},{"next_id",Value{next_id_}},
        {"snapshots",Value{std::move(rows)}}}};
}
std::uint64_t MachineSnapshotCatalog::reserve(std::uint64_t task, std::string uuid, std::uint64_t run, std::uint64_t base, std::uint64_t version) {
    if (!task || uuid.empty() || next_id_ == UINT64_MAX) throw Error("invalid snapshot catalog reservation");
    const auto id = next_id_++;
    snapshots_.push_back({id,task,run,version,base,std::move(uuid),{}, {}});
    return id;
}
void MachineSnapshotCatalog::attach(std::uint64_t id, const CaptureJournal& capture) {
    for (auto& snapshot : snapshots_) if (snapshot.id == id) {
        if (snapshot.capture && snapshot.capture->id != capture.id)
            snapshot.superseded.push_back(std::move(*snapshot.capture));
        snapshot.capture = capture;
        return;
    }
    throw Error("snapshot catalog reservation is missing");
}
void MachineSnapshotCatalog::version(std::string_view capture, std::uint64_t version) {
    for (auto& snapshot : snapshots_) if (snapshot.capture && snapshot.capture->id == capture) {
        if (snapshot.version_id && snapshot.version_id != version) throw Error("snapshot catalog version changed");
        snapshot.version_id = version;
        return;
    }
    throw Error("snapshot catalog capture is missing");
}
const MachineSnapshot* MachineSnapshotCatalog::base(std::string_view uuid, std::uint64_t version) const {
    if (!version) return nullptr;
    for (const auto& snapshot : snapshots_)
        if (snapshot.task_uuid == uuid && snapshot.version_id == version) return &snapshot;
    return nullptr;
}
const MachineSnapshot* MachineSnapshotCatalog::capture(std::string_view id) const {
    for (const auto& snapshot : snapshots_)
        if (snapshot.capture && snapshot.capture->id == id) return &snapshot;
    return nullptr;
}
const MachineSnapshot* MachineSnapshotCatalog::snapshot(std::uint64_t id) const {
    for (const auto& snapshot : snapshots_) if (snapshot.id == id) return &snapshot;
    return nullptr;
}
const MachineSnapshot* MachineSnapshotCatalog::event(std::string_view uuid, std::uint64_t run) const {
    if (run) for (auto it = snapshots_.rbegin(); it != snapshots_.rend(); ++it)
        if (it->task_uuid == uuid && it->running_task_id == run) return &*it;
    return nullptr;
}
std::vector<MachineSnapshot> MachineSnapshotCatalog::older(std::string_view uuid, std::uint64_t base_id) const {
    std::vector<MachineSnapshot> result;
    if (base_id) for (const auto& snapshot : snapshots_)
        if (snapshot.task_uuid == uuid && snapshot.id < base_id) result.push_back(snapshot);
    return result;
}
std::vector<MachineSnapshot> MachineSnapshotCatalog::rotation(std::string_view uuid, std::uint64_t version) const {
    const auto* selected = base(uuid,version);
    return older(uuid,selected ? selected->id : 0);
}
std::vector<MachineSnapshot> MachineSnapshotCatalog::removed_tasks(std::span<const std::string> uuids) const {
    std::vector<MachineSnapshot> result;
    for (const auto& snapshot : snapshots_)
        if (std::find(uuids.begin(),uuids.end(),snapshot.task_uuid) == uuids.end()) result.push_back(snapshot);
    return result;
}
void MachineSnapshotCatalog::erase(std::uint64_t id) {
    std::erase_if(snapshots_,[&](const MachineSnapshot& snapshot) { return snapshot.id == id; });
}
std::uint64_t MachineSnapshotCatalog::prepare(std::uint64_t task, std::string uuid, std::uint64_t run,
    std::uint64_t base_id, const std::function<void(const MachineSnapshot&)>& cleanup,
    const std::function<void(const MachineSnapshotCatalog&)>& save, std::uint64_t version) {
    if (const auto* reserved = event(uuid,run)) return reserved->id;
    const auto obsolete = older(uuid,base_id);
    for (const auto& snapshot : obsolete) cleanup(snapshot);
    // Snapshot rotation retains the agent DB rows. Each later
    // rotation retries resource deletion, including prior local failures.
    const auto id = reserve(task,std::move(uuid),run,base_id,version);
    save(*this);
    return id;
}

}
