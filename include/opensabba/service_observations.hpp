#pragma once
#include "opensabba/events.hpp"

namespace opensabba {
// The control worker owns refreshes; the local backup worker reads immutable copies.
class ServiceObservations {
public:
    struct Snapshot {
        pstream::Value::Array tasks, running;
        // Private script bodies are never serialized into the public inbox.
        pstream::Value::Array execution_tasks;
    };
    using TasksChanged = std::function<void(pstream::Value::Array&)>;
    void initialize(const Endpoint&, const SavedAuth&, EventInbox&, const TasksChanged&);
    void refresh_tasks(const Endpoint&, const SavedAuth&, EventInbox&, const TasksChanged&);
    void refresh_running(const Endpoint&, const SavedAuth&, EventInbox&, const TasksChanged&);
    Snapshot snapshot() const;
    void observe_tasks(pstream::Value::Array);
    void register_backup(EventInbox::RunningResult);
private:
    mutable std::mutex mutex_;
    Snapshot snapshot_;
};
// Long polling waits independently of local handler retries. The callback
// returns the greatest received server event ID after durably accepting a pull.
void run_service_events(const Endpoint&, const SavedAuth&, const std::function<bool()>& handlers_pending,
    const std::function<std::uint64_t(bool pull)>& handle);

}
