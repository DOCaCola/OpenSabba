#include "opensabba/service_status.hpp"
#include "opensabba/server_time.hpp"
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <source_location>
using opensabba::pstream::Value;
using opensabba::ServiceStatus;
const Value& field(const Value& value, const char* key) { return std::get<Value::Object>(value.data).at(key); }
void check(bool ok, std::source_location location = std::source_location::current()) {
    if (!ok) throw std::runtime_error("service status invariant failed at line "+std::to_string(location.line()));
}
Value activity(const char* action, const char* status) {
    Value record{Value::Object{{"job_action",Value{std::string(action)}},
                              {"status",Value{std::string(status)}}}};
    return Value{Value::Object{{"running_task_result",std::move(record)}}};
}
Value restore(std::uint64_t bytes) {
    Value task{Value::Object{{"total_size",Value{std::uint64_t{4096}}}}};
    Value run{Value::Object{{"file_restore_task",std::move(task)}}};
    return Value{Value::Object{{"phase",Value{std::string("download")}},
        {"running_task_id",Value{std::uint64_t{42}}},{"current_size",Value{bytes}},
        {"running",std::move(run)}}};
}
int main() {
    try {
#ifdef _WIN32
        _putenv_s("TZ","UTC"); _tzset();
#else
        setenv("TZ","UTC",1); tzset();
#endif
        // Missing NAS time is distinct from a refreshed UTC offset. Do not
        // display a fabricated UTC next time after logout or a failed refresh.
        ServiceStatus calendar;
        const Value scheduled{Value::Object{{"sched_content",Value{std::string(
            R"({"schedule_setting_type":1,"run_hour":3,"run_min":0,"run_weekday":[0,1,2,3,4,5,6],"repeat_hour":0,"enable_backup_window":false})")}}}};
        calendar.tasks({scheduled},opensabba::server_time_offset({"",0,3600}),1704585600);
        check(field(field(calendar.snapshot(),"content"),"next_backup_time") == Value{std::uint64_t{0}});
        calendar.tasks({scheduled},opensabba::server_time_offset({"0",0,0}),1704585600);
        check(field(field(calendar.snapshot(),"content"),"next_backup_time") == Value{std::uint64_t{1704596400}});
        calendar.tasks({scheduled},opensabba::server_time_offset({"",0,3600}),1704585600);
        check(field(field(calendar.snapshot(),"content"),"next_backup_time") == Value{std::uint64_t{0}});
        calendar.tasks({scheduled},opensabba::server_time_offset({"3600",0,3600}),1704585600);
        check(field(field(calendar.snapshot(),"content"),"next_backup_time") == Value{std::uint64_t{1704592800}});
        ServiceStatus state;
        check(field(state.snapshot(),"status") == Value{std::uint64_t{0x1000}});
        state.connected();
        state.file_restore(restore(1024),100);
        check(field(state.snapshot(),"status") == Value{std::uint64_t{0x4000}});
        state.result(activity("restore","incomplete"),100);
        state.result(activity("unknown",""),100);
        check(field(state.snapshot(),"status") == Value{std::uint64_t{0x4000}});
        state.result(activity("restore","complete"),100);
        check(field(state.snapshot(),"status") == Value{std::uint64_t{0x2000}});
        check(!std::get<Value::Object>(field(state.snapshot(),"content").data).contains("transfer"));
        state.file_restore(restore(2048),100); // the official agent's one-update-per-second guard.
        check(field(state.snapshot(),"status") == Value{std::uint64_t{0x2000}});
        state.file_restore(restore(3072),101);
        check(field(state.snapshot(),"status") == Value{std::uint64_t{0x4000}});
        check(field(field(field(state.snapshot(),"content"),"transfer"),"speed") == Value{std::uint64_t{2048}});
        auto result = activity("restore","complete");
        std::get<Value::Object>(result.data)["backup_result"] = Value{Value::Object{
            {"last_success_time",Value{std::uint64_t{7200}}},{"last_backup_status",Value{std::string("failure")}}}};
        opensabba::set_server_time({"3600",3600,0});
        state.result(result,102);
        auto snapshot = state.snapshot();
        check(field(field(field(snapshot,"content"),"last_backup_result"),"last_success_time") == Value{std::uint64_t{3600}});
        std::get<Value::Object>(snapshot.data)["connection"] = Value{Value::Object{
            {"address",Value{std::string("nas")}},{"username",Value{std::string("user")}}}};
        std::ostringstream visible;
        opensabba::print_service_status(visible,snapshot);
        check(visible.str().starts_with("Server address: nas             \t\t Username: user\n"));
        check(visible.str().find("Last backup time: 1970-01-01 01:00 \t\t Next backup time:  - \n"
            "Service Status: Idle - Failed\n\nRecovery portal:  - \n\n") != std::string::npos);
        check(field(field(field(ServiceStatus{}.snapshot(),"content"),"last_backup_result"),"last_success_time") == Value{std::uint64_t{0}});
        opensabba::set_server_time({"0",0,0});
        std::get<Value::Object>(snapshot.data)["status"] = Value{std::uint64_t{0x3000}};
        std::get<Value::Object>(std::get<Value::Object>(snapshot.data).at("content").data)["transfer"] =
            Value{Value::Object{{"progress",Value{std::uint64_t{1024000}}},
                {"total",Value{std::uint64_t{4096}}},{"speed",Value{std::uint64_t{1000}}}}};
        visible.str("");
        opensabba::print_service_status(visible,snapshot);
        check(visible.str().find("Service Status: Backing up... - 0.98 MB / 4.00 KB (0.98 KB/s)\n") != std::string::npos);
        std::get<Value::Object>(snapshot.data)["url"] = Value{std::string{}};
        visible.str("");
        opensabba::print_service_status(visible,snapshot);
        check(visible.str().find("Recovery portal: \n\n") != std::string::npos);
        ServiceStatus backup_state;
        backup_state.connected();
        backup_state.backup(Value{Value::Object{{"phase",Value{std::string("upload")}},
            {"running_task_id",Value{std::uint64_t{27}}}}});
        backup_state.backup_transfer(0,8192,100);
        backup_state.backup_transfer(4096,8192,100); // Same-second publication is ignored.
        backup_state.backup_transfer(4096,8192,101);
        auto active = backup_state.snapshot();
        check(field(field(field(active,"content"),"transfer"),"progress") == Value{std::uint64_t{4096}});
        check(field(field(field(active,"content"),"transfer"),"total") == Value{std::uint64_t{8192}});
        check(field(field(field(active,"content"),"transfer"),"speed") == Value{std::uint64_t{4096}});
        // A paced first record can remain in flight for several seconds. The
        // manager drops its preparation update if the initial zero used the
        // same second; status reads do not publish it later on a timer.
        ServiceStatus paced;
        paced.connected();
        paced.backup(Value{Value::Object{{"phase",Value{std::string("upload")}},
            {"running_task_id",Value{std::uint64_t{28}}}}});
        constexpr std::uint64_t mib = 1024*1024;
        paced.backup_transfer(0,4*mib,100);
        paced.backup_transfer(mib,4*mib,100);
        auto waiting = paced.snapshot();
        check(field(field(field(waiting,"content"),"transfer"),"progress") == Value{std::uint64_t{0}});
        check(field(field(field(waiting,"content"),"transfer"),"speed") == Value{std::uint64_t{0}});
        check(paced.snapshot() == waiting);
        // The next prepared buffer advances the shared aggregate before that
        // record has been sent and independently of durable job saves.
        paced.backup_transfer(2*mib,4*mib,108);
        waiting = paced.snapshot();
        check(field(field(field(waiting,"content"),"transfer"),"progress") == Value{std::uint64_t{2*mib}});
        check(field(field(field(waiting,"content"),"transfer"),"total") == Value{std::uint64_t{4*mib}});
        check(field(field(field(waiting,"content"),"transfer"),"speed") == Value{std::uint64_t{mib/4}});
        state.disconnected();
        auto failed = state.snapshot();
        std::get<Value::Object>(failed.data)["connection"] = field(snapshot,"connection");
        visible.str("");
        opensabba::print_service_status(visible,failed);
        check(visible.str().find("Service Status: Error\xc2\xa0 - Internet error. Please check your Internet connection.") != std::string::npos);
        check(visible.str().ends_with("Retrieved service status successfully\n"));
        std::cout << "Service status sources, active result ordering and visible output passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
