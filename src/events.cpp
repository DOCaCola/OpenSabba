#include "opensabba/events.hpp"
#include "opensabba/volume_nodes.hpp"
#include <algorithm>

namespace opensabba {
using pstream::Value;
using pstream::Error;
namespace {
const Value& field(const Value& value, const char* key) {
    const auto* map = std::get_if<Value::Object>(&value.data);
    if (!map || !map->contains(key)) throw Error(std::string("event data missing ") + key);
    return map->at(key);
}
std::string text(const Value& value, const char* key) {
    const auto* result = std::get_if<std::string>(&field(value, key).data);
    if (!result || result->empty()) throw Error(std::string("invalid event text: ") + key);
    return *result;
}
std::uint64_t number(const Value& value, const char* key) {
    const auto* result = std::get_if<std::uint64_t>(&field(value, key).data);
    if (!result) throw Error(std::string("invalid event integer: ") + key);
    return *result;
}
const Value::Array& array(const Value& value, const char* key) {
    const auto* result = std::get_if<Value::Array>(&field(value, key).data);
    if (!result) throw Error(std::string("invalid event array: ") + key);
    return *result;
}
std::uint64_t validate(const Value& value) {
    const auto id = number(value, "id");
    if (!id) throw Error("event ID must be nonzero");
    text(value, "action");
    return id;
}
bool list_nodes(const Value& event) {
    const auto* object = std::get_if<Value::Object>(&event.data);
    if (!object || !object->contains("webapi_task") ||
        text(event,"action") != "act_client") return false;
    const auto* task = std::get_if<Value::Object>(&object->at("webapi_task").data);
    if (!task || !task->contains("subaction") || !task->contains("node_path") ||
        !task->contains("dir_only")) return false;
    const auto* subaction = std::get_if<std::string>(&task->at("subaction").data);
    const auto* path = std::get_if<std::string>(&task->at("node_path").data);
    const auto* directories = std::get_if<std::uint64_t>(&task->at("dir_only").data);
    return subaction && *subaction == "list_nodes" && path &&
           path->find('\0') == std::string::npos &&
           directories && *directories <= 1;
}
void validate_node_result(std::uint64_t id, const Value& result) {
    validate_client_node_result(result);
    if (number(result,"event_id") != id)
        throw Error("saved node-list result belongs to another event");
}
}
EventInbox::EventInbox(const SavedAuth& auth)
    : ds_id_(auth.ds_id), device_uuid_(auth.device_uuid), username_(auth.username) {}
void EventInbox::register_running_result(RunningResult result) {
    std::lock_guard lock(running_history_->mutex);
    auto& running_results_ = running_history_->entries;
    const auto found = std::find_if(running_results_.begin(),running_results_.end(),
        [&](const auto& entry) { return entry.run == result.run; });
    if (found == running_results_.end()) running_results_.push_back(std::move(result));
    else *found = std::move(result);
}
std::optional<EventInbox::RunningResult> EventInbox::running_result(
        std::uint64_t task, std::uint64_t version) const {
    if (!task || !version) return {};
    std::lock_guard lock(running_history_->mutex);
    auto& running_results_ = running_history_->entries;
    const auto found = std::find_if(running_results_.begin(),running_results_.end(),
        [&](const auto& entry) { return entry.task == task && entry.version == version; });
    return found == running_results_.end() ? std::optional<RunningResult>{} : *found;
}
void EventInbox::retire_running_result(std::uint64_t task, std::uint64_t version) {
    if (!task || !version) return;
    std::lock_guard lock(running_history_->mutex);
    auto& running_results_ = running_history_->entries;
    const auto found = std::find_if(running_results_.begin(),running_results_.end(),
        [&](const auto& entry) { return entry.task == task && entry.version == version; });
    if (found != running_results_.end()) running_results_.erase(found);
}
EventInbox::EventInbox(const SavedAuth& auth, const Value& saved) : EventInbox(auth) {
    const auto format = number(saved, "format");
    if (format != 1 && format != 2 && format != 3) throw Error("unsupported event inbox format");
    if (text(saved, "ds_id") != ds_id_ || text(saved, "device_uuid") != device_uuid_ ||
        text(saved, "username") != username_)
        throw Error("event inbox belongs to a different NAS, device, or user; preserve it before starting this session");
    tasks_ = array(saved, "task_snapshot");
    if (format >= 2) jobs_ = array(saved, "running_task_snapshot");
    if (format == 3) {
        bandwidth_ = field(saved,"bandwidth_snapshot");
        if (!std::holds_alternative<std::monostate>(bandwidth_.data)) {
            const auto* snapshot = std::get_if<Value::Object>(&bandwidth_.data);
            if (!snapshot || snapshot->size() > 1 ||
                (!snapshot->empty() && !snapshot->contains("backup_bandwidth")))
                throw Error("invalid saved bandwidth snapshot");
            if (!snapshot->empty()) (void)number(bandwidth_,"backup_bandwidth");
        }
    }
    for (const auto& record : array(saved, "receipts")) {
        const auto& payload = field(record, "payload");
        const auto id = validate(payload);
        const auto state = text(record, "state");
        if (state != "pending" && state != "ack_pending") throw Error("invalid event receipt state");
        const auto has_result = std::get<Value::Object>(record.data).contains("node_result");
        std::optional<Value> node_result;
        std::optional<Value> task_result;
        if (std::get<Value::Object>(record.data).contains("task_result")) {
            if (text(payload,"action") != "get_running_task_result")
                throw Error("task result belongs to another event");
            task_result = field(record,"task_result");
            if (!std::holds_alternative<Value::Object>(task_result->data))
                throw Error("invalid saved task result");
        }
        if (has_result) {
            if (!list_nodes(payload)) throw Error("node-list result belongs to another event");
            node_result = field(record,"node_result");
            validate_node_result(id,*node_result);
        }
        if (state == "ack_pending" && text(payload, "action") != "change_task" &&
            text(payload, "action") != "update_agent" &&
            !(format >= 2 && text(payload, "action") == "update_running_task") &&
            !(format == 3 && text(payload,"action") == "update_backup_bandwidth" &&
                std::holds_alternative<Value::Object>(bandwidth_.data)) &&
            !(list_nodes(payload) && node_result))
            if (!(text(payload,"action") == "get_running_task_result" && task_result))
                throw Error("unsupported event marked completed");
        const auto result_id = task_result ? number(record,"task_result_id") : 0;
        if (!receipts_.emplace(id, Receipt{payload, state == "ack_pending",node_result,task_result,result_id}).second)
            throw Error("duplicate event ID in inbox");
    }
    pstream::encode(serialize(), event_limits);
}
void EventInbox::merge(const Value::Array& events) {
    auto next = *this;
    for (const auto& event : events) {
        const auto id = validate(event);
        const auto found = next.receipts_.find(id);
        if (found != next.receipts_.end()) {
            if (found->second.payload != event) throw Error("server changed the payload of a retained event");
        } else next.receipts_.emplace(id, Receipt{event,false,{},{}});
    }
    pstream::encode(next.serialize(), event_limits);
    // Only receipts change here. Keep the history handle itself stable while
    // the transfer owner publishes registrations through that shared list.
    receipts_ = std::move(next.receipts_);
}
bool EventInbox::needs_task_refresh() const {
    for (const auto& [id, receipt] : receipts_)
        if (!receipt.ready && text(receipt.payload, "action") == "change_task") return true;
    return false;
}
void EventInbox::observe_tasks(Value::Array tasks) {
    tasks_ = std::move(tasks);
}
void EventInbox::finish_task_refresh(Value::Array tasks) {
    observe_tasks(std::move(tasks));
    for (auto& [id, receipt] : receipts_)
        if (text(receipt.payload, "action") == "change_task") receipt.ready = true;
}
bool EventInbox::needs_running_refresh() const {
    for (const auto& [id, receipt] : receipts_)
        if (!receipt.ready && text(receipt.payload, "action") == "update_running_task") return true;
    return false;
}
void EventInbox::finish_running_refresh(Value::Array jobs) {
    jobs_ = std::move(jobs);
    for (auto& [id, receipt] : receipts_)
        if (text(receipt.payload, "action") == "update_running_task") receipt.ready = true;
}
bool EventInbox::needs_bandwidth_refresh() const {
    for (const auto& [id, receipt] : receipts_)
        if (!receipt.ready && text(receipt.payload,"action") == "update_backup_bandwidth") return true;
    return false;
}
void EventInbox::finish_bandwidth_refresh(std::optional<std::uint64_t> rate) {
    Value::Object snapshot;
    if (rate) snapshot.emplace("backup_bandwidth",Value{*rate});
    bandwidth_ = Value{std::move(snapshot)};
    for (auto& [id, receipt] : receipts_)
        if (text(receipt.payload,"action") == "update_backup_bandwidth") receipt.ready = true;
}
bool EventInbox::needs_agent_update_finish() const {
    for (const auto& [id, receipt] : receipts_)
        if (!receipt.ready && text(receipt.payload, "action") == "update_agent") return true;
    return false;
}
std::vector<std::uint64_t> EventInbox::ignore_agent_update_requests() {
    std::vector<std::uint64_t> ids;
    for (auto& [id, receipt] : receipts_) {
        if (!receipt.ready && text(receipt.payload, "action") == "update_agent") {
            ids.push_back(id);
            receipt.ready = true;
        }
    }
    return ids;
}
Value::Array EventInbox::task_result_requests() const {
    Value::Array result;
    for (const auto& [id,receipt] : receipts_)
        if (!receipt.ready && text(receipt.payload,"action") == "get_running_task_result")
            result.push_back(receipt.payload);
    return result;
}
std::optional<Value> EventInbox::task_result(std::uint64_t id) const {
    return receipts_.at(id).task_result;
}
std::uint64_t EventInbox::task_result_id(std::uint64_t id) const {
    return receipts_.at(id).task_result_id;
}
void EventInbox::prepare_task_result(std::uint64_t id, std::uint64_t result_id, Value result) {
    const auto found = receipts_.find(id);
    if (found == receipts_.end() || found->second.ready ||
        found->second.task_result || text(found->second.payload,"action") != "get_running_task_result")
        throw Error("task-result event is not pending");
    found->second.task_result = std::move(result);
    found->second.task_result_id = result_id;
}
void EventInbox::finish_task_result(std::uint64_t id, Value result) {
    const auto found = receipts_.find(id);
    if (found == receipts_.end() || found->second.ready ||
        text(found->second.payload,"action") != "get_running_task_result")
        throw Error("task-result event is not pending");
    if (found->second.task_result && *found->second.task_result != result)
        throw Error("task-result reply differs from its saved response");
    const auto& reply = std::get<Value::Object>(result.data);
    if (reply.contains("running_task_result")) {
        const auto& activity = reply.at("running_task_result");
        const auto action = text(activity,"job_action");
        const auto status = action == "unknown" ? std::string{} : text(activity,"status");
        if (action == "backup" &&
            (status == "complete" || status == "partial_success" || status == "failure")) {
            bool updated = false;
            for (auto& task : tasks_)
                if (number(task,"id") == number(activity,"task_id")) {
                    std::get<Value::Object>(task.data)["last_backup_success_time"] = field(activity,"time_start");
                    updated = true;
                }
            // the official agent updates the persisted task row, then its manager entry.
            // Failure to find the in-memory task returns handler failure.
            if (!updated) throw Error("result timestamp has no assigned task");
        }
    }
    found->second.task_result = std::move(result);
    found->second.ready = true;
}
Value::Array EventInbox::node_requests() const {
    Value::Array result;
    for (const auto& [id, receipt] : receipts_)
        if (!receipt.ready && !receipt.node_result && list_nodes(receipt.payload))
            result.push_back(receipt.payload);
    return result;
}
void EventInbox::prepare_node_result(std::uint64_t id, Value result) {
    const auto found = receipts_.find(id);
    if (found == receipts_.end() || found->second.ready ||
        found->second.node_result || !list_nodes(found->second.payload))
        throw Error("node-list event is not pending");
    validate_node_result(id,result);
    found->second.node_result = std::move(result);
}
Value::Array EventInbox::node_results() const {
    Value::Array result;
    for (const auto& [id, receipt] : receipts_)
        if (!receipt.ready && receipt.node_result)
            result.push_back(*receipt.node_result);
    return result;
}
void EventInbox::node_result_sent(std::uint64_t id) {
    const auto found = receipts_.find(id);
    if (found == receipts_.end() || found->second.ready || !found->second.node_result)
        throw Error("node-list result is not pending");
    found->second.ready = true;
}
Value::Array EventInbox::held_ids() const {
    Value::Array result;
    for (const auto& [id, receipt] : receipts_) result.push_back(Value{id});
    return result;
}
Value::Array EventInbox::ready_ids() const {
    Value::Array result;
    for (const auto& [id, receipt] : receipts_)
        if (receipt.ready) result.push_back(Value{id});
    return result;
}
void EventInbox::acknowledged(const Value::Array& ids) {
    for (const auto& id : ids) {
        auto found = receipts_.find(std::get<std::uint64_t>(id.data));
        if (found == receipts_.end() || !found->second.ready)
            throw Error("cannot retire an unfinished event");
    }
    for (const auto& id : ids) receipts_.erase(std::get<std::uint64_t>(id.data));
}
Value EventInbox::serialize() const {
    Value::Array records;
    for (const auto& [id, receipt] : receipts_) {
        Value::Object record{
            {"payload", receipt.payload},
            {"state", Value{std::string(receipt.ready ? "ack_pending" : "pending")}}};
        if (receipt.node_result) record.emplace("node_result",*receipt.node_result);
        if (receipt.task_result) {
            record.emplace("task_result",*receipt.task_result);
            record.emplace("task_result_id",Value{receipt.task_result_id});
        }
        records.push_back(Value{std::move(record)});
    }
    return Value{Value::Object{{"format", Value{std::uint64_t{3}}},
        {"ds_id", Value{ds_id_}}, {"device_uuid", Value{device_uuid_}}, {"username", Value{username_}},
        {"receipts", Value{std::move(records)}}, {"task_snapshot", Value{tasks_}},
        {"running_task_snapshot", Value{jobs_}}, {"bandwidth_snapshot",bandwidth_}}};
}
Value EventInbox::summary() const {
    Value::Array records;
    for (const auto& [id, receipt] : receipts_)
        records.push_back(Value{Value::Object{{"id", Value{id}},
            {"action", Value{text(receipt.payload, "action")}},
            {"state", Value{std::string(receipt.ready ? "ack_pending" :
                (text(receipt.payload, "action") == "change_task" || list_nodes(receipt.payload) ||
                 text(receipt.payload, "action") == "update_backup_bandwidth" ||
                 text(receipt.payload, "action") == "update_agent" ||
                 text(receipt.payload, "action") == "get_running_task_result") ? "pending" : "unsupported")}}}});
    return Value{Value::Object{{"events", Value{std::move(records)}}}};
}
}
