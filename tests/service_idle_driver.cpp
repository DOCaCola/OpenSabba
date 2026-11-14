#include "opensabba/service_observations.hpp"
#include "opensabba/service_backup.hpp"
#include <atomic>
#include <future>
#include <iostream>
#include <set>
#include <thread>
using namespace opensabba;
using pstream::Value;
int main(int argc,char** argv) {
    try {
        if (argc != 4) throw pstream::Error("idle fixture requires port, CA, duration");
        Endpoint endpoint{"127.0.0.1",static_cast<std::uint16_t>(std::stoul(argv[1])),argv[2]};
        std::atomic_bool stopped{false};
        endpoint.cancelled = [&] { return stopped.load(); };
        SavedAuth auth{"test-user","test-device","registration-test-token","registration-test-nas"};
        // A successful local handshake owns a run before a NAS notification.
        // Capture must consume that queue entry without another list request.
        ServiceObservations local;
        local.register_backup({42,7,9,112});
        const TaskView local_view{
            [&](const Endpoint&) { return local.snapshot().execution_tasks; },
            [&](const Endpoint&) { return local.snapshot().running; }};
        auto capture = endpoint;
        capture.prepared_backup = PreparedBackup{{42,9,112,1},0};
        unsigned captures = 0;
        if (run_queued_machine_capture(capture,local_view,7,42,[&](const auto&) { ++captures; }) !=
                QueuedCaptureOutcome::complete || captures != 1)
            throw pstream::Error("known local handshake waited for NAS notification");
        const auto registered = reconnect(endpoint,auth,DeviceMetadata{"fixture","Linux","fixture",3600});
        auth.token = registered.token;
        endpoint.service_status->result(running_task_result(endpoint,auth));
        EventInbox inbox{auth};
        ServiceObservations observations;
        observations.initialize(endpoint,auth,inbox,[](const auto&) {});
        heartbeat(endpoint,auth);
        auto controls = std::async(std::launch::async,[&] {
            run_service_events(endpoint,auth,[] { return false; },[&](bool pull) {
                if (!pull) throw pstream::Error("idle handler ran without an event");
                const auto incoming = pull_events(endpoint,auth,inbox.held_ids());
                inbox.merge(incoming);
                if (inbox.needs_task_refresh()) observations.refresh_tasks(endpoint,auth,inbox,[](const auto&) {});
                if (inbox.needs_running_refresh()) observations.refresh_running(endpoint,auth,inbox,[](const auto&) {});
                const auto done = inbox.ready_ids();
                if (!done.empty()) { done_events(endpoint,auth,done); inbox.acknowledged(done); }
                std::uint64_t cursor = 0;
                for (const auto& event : incoming)
                    cursor = std::max(cursor,std::get<std::uint64_t>(std::get<Value::Object>(event.data).at("id").data));
                return cursor;
            });
        });
        struct StopOnExit {
            std::atomic_bool& stopped;
            ~StopOnExit() { stopped = true; }
        } stop_on_exit{stopped};
        auto next_beat = std::chrono::steady_clock::now()+std::chrono::seconds{5+std::rand()%3};
        const auto until = std::chrono::steady_clock::now()+std::chrono::seconds{std::stoul(argv[3])};
        std::set<std::uint64_t> dispatched;
        while (std::chrono::steady_clock::now() < until) {
            // The same local observation consumed by the service dispatcher.
            for (const auto& run : observations.snapshot().running)
                dispatched.insert(std::get<std::uint64_t>(std::get<Value::Object>(run.data).at("id").data));
            if (std::chrono::steady_clock::now() >= next_beat) {
                heartbeat(endpoint,auth);
                next_beat = std::chrono::steady_clock::now()+std::chrono::seconds{5+std::rand()%3};
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
        }
        stopped = true;
        controls.get();
        const auto snapshot = observations.snapshot();
        if (!snapshot.tasks.empty()) {
            if (std::get<Value::Object>(snapshot.tasks.front().data).contains("pre_script_content") ||
                !std::get<Value::Object>(snapshot.execution_tasks.front().data).contains("pre_script_content"))
                throw pstream::Error("script body crossed the public snapshot boundary");
        }
        std::cout << "tasks=" << snapshot.tasks.size() << " runs=" << snapshot.running.size()
                  << " dispatches=" << dispatched.size() << '\n';
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
