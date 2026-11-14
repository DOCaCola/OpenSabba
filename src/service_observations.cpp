#include "opensabba/service_observations.hpp"
#include <atomic>
#include <future>
#include <thread>

namespace opensabba {
namespace {
std::map<std::uint64_t,std::uint64_t> running_statuses(const pstream::Value::Array& jobs) {
    std::map<std::uint64_t,std::uint64_t> result;
    for (const auto& job : jobs) {
        const auto& fields = std::get<pstream::Value::Object>(job.data);
        result.emplace(std::get<std::uint64_t>(fields.at("id").data),
                       std::get<std::uint64_t>(fields.at("status").data));
    }
    return result;
}
}
void ServiceObservations::initialize(const Endpoint& endpoint,const SavedAuth& auth,
    EventInbox& inbox,const TasksChanged& changed) {
    // Assigned-task and running-task handlers queued by connection initialization.
    refresh_tasks(endpoint,auth,inbox,changed);
    refresh_running(endpoint,auth,inbox,changed);
}
void ServiceObservations::refresh_tasks(const Endpoint& endpoint,const SavedAuth& auth,
    EventInbox& inbox,const TasksChanged& changed) {
    auto execution = execution_tasks(endpoint,auth);
    auto assigned = execution;
    for (auto& task : assigned) {
        auto& fields = std::get<pstream::Value::Object>(task.data);
        for (const auto* key : {"pre_script_extension","pre_script_error","pre_script_content",
                                "post_script_extension","post_script_error","post_script_content"})
            fields.erase(key);
    }
    changed(assigned);
    for (std::size_t index = 0; index < assigned.size(); ++index) {
        auto& fields = std::get<pstream::Value::Object>(execution[index].data);
        for (const auto& [key,value] : std::get<pstream::Value::Object>(assigned[index].data)) fields[key] = value;
    }
    inbox.finish_task_refresh(assigned);
    std::lock_guard lock(mutex_);
    snapshot_.tasks = std::move(assigned);
    snapshot_.execution_tasks = std::move(execution);
}
void ServiceObservations::refresh_running(const Endpoint& endpoint,const SavedAuth& auth,
    EventInbox& inbox,const TasksChanged& changed) {
    auto running = running_tasks(endpoint,auth);
    // Compare running IDs and statuses, then run the
    // assigned-task handler before publishing changed server queue entries.
    const auto before = snapshot();
    if (running_statuses(before.running) != running_statuses(running))
        refresh_tasks(endpoint,auth,inbox,changed);
    inbox.finish_running_refresh(running);
    std::lock_guard lock(mutex_);
    snapshot_.running = std::move(running);
}
void ServiceObservations::observe_tasks(pstream::Value::Array tasks) {
    std::lock_guard lock(mutex_);
    snapshot_.tasks = std::move(tasks);
}
void ServiceObservations::register_backup(EventInbox::RunningResult run) {
    std::lock_guard lock(mutex_);
    for (auto& job : snapshot_.running) {
        auto& fields = std::get<pstream::Value::Object>(job.data);
        if (std::get<std::uint64_t>(fields.at("id").data) != run.run) continue;
        if (std::get<std::uint64_t>(fields.at("type").data) == 0) {
            if (!std::get<std::uint64_t>(fields.at("status").data))
                fields["status"] = pstream::Value{std::uint64_t{1}};
            fields["version_id"] = pstream::Value{run.version};
            fields["result_id"] = pstream::Value{run.result};
        }
        return;
    }
    // The job handshake updates its local event from the known reply via
    // running-ID update, before any running-task notification.
    snapshot_.running.emplace_back(pstream::Value::Object{
        {"id",pstream::Value{run.run}},{"task_id",pstream::Value{run.task}},
        {"type",pstream::Value{std::uint64_t{0}}},{"status",pstream::Value{std::uint64_t{1}}},
        {"version_id",pstream::Value{run.version}},{"result_id",pstream::Value{run.result}},
        {"detail_status",pstream::Value{std::uint64_t{0}}}});
}
ServiceObservations::Snapshot ServiceObservations::snapshot() const {
    std::lock_guard lock(mutex_);
    return snapshot_;
}
void run_service_events(const Endpoint& endpoint,const SavedAuth& auth,
    const std::function<bool()>& handlers_pending,const std::function<std::uint64_t(bool)>& handle) {
    std::future<bool> poll;
    std::atomic_bool finished{false};
    auto polling = endpoint;
    polling.cancelled = [&] { return finished.load() || endpoint.cancelled(); };
    std::exception_ptr error;
    try {
        std::uint64_t cursor = 0;
        auto retry_at = std::chrono::steady_clock::now();
        while (!endpoint.cancelled()) {
            bool pull = false;
            if (poll.valid() && poll.wait_for(std::chrono::seconds{0}) == std::future_status::ready)
                pull = poll.get();
            const auto now = std::chrono::steady_clock::now();
            const bool pending = handlers_pending();
            if (pull || (pending && now >= retry_at)) {
                cursor = std::max(cursor,handle(pull));
                retry_at = std::chrono::steady_clock::now()+std::chrono::seconds{1};
            }
            if (!poll.valid()) poll = std::async(std::launch::async,[&,cursor] {
                return events_pending(polling,auth,cursor);
            });
            poll.wait_for(std::chrono::milliseconds{100});
        }
    } catch (const Cancelled&) {
        if (!endpoint.cancelled()) error = std::current_exception();
    } catch (...) { error = std::current_exception(); }
    finished = true;
    if (poll.valid()) {
        try { (void)poll.get(); }
        catch (const Cancelled&) {}
        catch (...) { if (!error) error = std::current_exception(); }
    }
    if (error) std::rethrow_exception(error);
}

}
