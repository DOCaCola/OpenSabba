#pragma once
#include "opensabba/client.hpp"
#include <map>
#include <optional>
#include <mutex>

namespace opensabba {
inline constexpr pstream::Limits event_limits{4 * 1024 * 1024, 100'000, 64};

// A receipt is pending until a supported handler has persisted its result.
// ack_pending receipts survive lost done_event replies and can be retried.
class EventInbox {
public:
    explicit EventInbox(const SavedAuth&);
    EventInbox(const SavedAuth&, const pstream::Value& saved);
    void merge(const pstream::Value::Array&);
    void observe_tasks(pstream::Value::Array tasks);
    bool needs_task_refresh() const;
    const pstream::Value::Array& task_snapshot() const { return tasks_; }
    void finish_task_refresh(pstream::Value::Array tasks);
    bool needs_running_refresh() const;
    void finish_running_refresh(pstream::Value::Array jobs);
    bool needs_bandwidth_refresh() const;
    void finish_bandwidth_refresh(std::optional<std::uint64_t>);
    pstream::Value::Array task_result_requests() const;
    std::optional<pstream::Value> task_result(std::uint64_t id) const;
    std::uint64_t task_result_id(std::uint64_t id) const;
    void prepare_task_result(std::uint64_t id, std::uint64_t result_id, pstream::Value result);
    void finish_task_result(std::uint64_t id, pstream::Value result);
    struct RunningResult {
        std::uint64_t run, task, version, result;
    };
    void register_running_result(RunningResult);
    std::optional<RunningResult> running_result(std::uint64_t task, std::uint64_t version) const;
    void retire_running_result(std::uint64_t task, std::uint64_t version);
    pstream::Value::Array node_requests() const;
    void prepare_node_result(std::uint64_t id, pstream::Value result);
    pstream::Value::Array node_results() const;
    void node_result_sent(std::uint64_t id);
    pstream::Value::Array held_ids() const;
    pstream::Value::Array ready_ids() const;
    void acknowledged(const pstream::Value::Array&);
    pstream::Value serialize() const;
    pstream::Value summary() const;
private:
    struct Receipt {
        pstream::Value payload;
        bool ready = false;
        std::optional<pstream::Value> node_result;
        std::optional<pstream::Value> task_result;
        std::uint64_t task_result_id = 0;
    };
    std::string ds_id_, device_uuid_, username_;
    std::map<std::uint64_t, Receipt> receipts_;
    pstream::Value::Array tasks_;
    pstream::Value::Array jobs_;
    // Null: never refreshed. Object: last successful response (possibly empty,
    // which means unchanged). No authentication data is retained.
    pstream::Value bandwidth_;
    // the official agent history belongs to this process, not to archived job journals.
    struct RunningHistory {
        std::mutex mutex;
        std::vector<RunningResult> entries;
    };
    // Handler entry publishes history synchronously, even while a control
    // request is in flight. Only this subobject is shared with the transfer.
    std::shared_ptr<RunningHistory> running_history_ = std::make_shared<RunningHistory>();
};
}
