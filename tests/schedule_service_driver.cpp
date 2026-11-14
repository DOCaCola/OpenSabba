#include "opensabba/task_schedule.hpp"
#include "opensabba/events.hpp"
#include <iostream>
using namespace opensabba;
using pstream::Value;
using pstream::Error;
int main(int argc,char** argv) {
    try {
        if (argc != 4) throw Error("schedule fixture requires port, certificate and base");
        Endpoint endpoint{"127.0.0.1",static_cast<std::uint16_t>(std::stoul(argv[1])),argv[2]};
        const SavedAuth auth{"test-user","test-device","test-token","test-nas"};
        // No cache settings: this is an ordinary online scheduled task.
        const Value task{Value::Object{{"id",Value{std::uint64_t{2}}},
            {"sched_content",Value{std::string(R"({"schedule_setting_type":1,"run_hour":10,"run_min":30,"run_weekday":[0],"repeat_hour":0,"enable_backup_window":false})")}}}};
        std::uint64_t now = 1'704'585'600 + 10*3600+29*60;
        TaskScheduler scheduler{[&] { return now; }};
        scheduler.update({task},0);
        if (!scheduler.poll().empty()) throw Error("scheduled task ran early");
        now += 60;
        auto due = scheduler.poll();
        if (due.size() != 1) throw Error("scheduled task was not queued");
        unsigned sends = 0;
        const auto run = trigger_scheduled_backup(endpoint,auth,2,std::stoull(argv[3]),[&] { ++sends; });
        EventInbox inbox{auth};
        inbox.register_running_result({run.running_task_id,2,run.version_id,run.result_id});
        const auto registered = inbox.running_result(2,run.version_id);
        if (sends != 1 || !registered || registered->run != 27 || run.result_id != 112 ||
            !scheduler.poll().empty()) throw Error("scheduled run identity or deduplication changed");
        std::cout << "Scheduled backup registered.\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
