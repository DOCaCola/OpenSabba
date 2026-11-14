#include "opensabba/task_schedule.hpp"
#include <iostream>

using namespace opensabba;
using pstream::Error;
using pstream::Value;
namespace {
void check(bool condition) {
    if (!condition) throw Error("task schedule invariant failed");
}
Value task(std::string content) {
    return Value{Value::Object{{"sched_content", Value{std::move(content)}}}};
}
std::string schedule(std::string days = "[0,1,2,3,4,5,6]", int repeat = 0,
                     std::string window = "false", std::string extra = "") {
    return R"({"schedule_setting_type":1,"run_hour":10,"run_min":30,"run_weekday":)" +
        days + R"(,"repeat_hour":)" + std::to_string(repeat) +
        R"(,"enable_backup_window":)" + window + extra + "}";
}
template<class F> void rejects(F action) {
    try { action(); }
    catch (const Error&) { return; }
    throw Error("invalid schedule was accepted");
}
}
int main() {
    try {
        // 2024-01-07 00:00 UTC is Sunday.
        constexpr std::uint64_t sunday = 1'704'585'600;
        constexpr std::uint64_t at = 10 * 3600 + 30 * 60;
        const auto daily = task(schedule());
        check(next_task_schedule(daily, sunday) == sunday + at);
        check(next_task_schedule(daily, sunday + at - 1) == sunday + at);
        check(next_task_schedule(daily, sunday + at) == sunday + 86400 + at);
        check(next_task_schedule(task(schedule("[1]")), sunday) == sunday + 86400 + at);
        check(next_task_schedule(task(schedule("[0]")), sunday + at) == sunday + 7 * 86400 + at);
        check(!next_task_schedule(task(schedule("[]")), sunday));
        check(!next_task_schedule(task(""), sunday));
        check(!next_task_schedule(task("{}"), sunday));
        check(!next_task_schedule(task(R"({"run_hour":3})"), sunday));
        check(!next_task_schedule(Value{Value::Object{}}, sunday));
        check(!next_task_schedule(task(R"({"schedule_setting_type":4})"), sunday));
        check(!next_task_schedule(task(R"({"schedule_setting_type":2})"), sunday));
        check(next_task_schedule(task(schedule("[0]", 1)), sunday + at) == sunday + at + 3600);
        check(next_task_schedule(task(schedule("[0]", 9)), sunday + at) == sunday + at + 3600);
        check(next_task_schedule(task(schedule("[0]", 1)), sunday + 23 * 3600 + 31 * 60) ==
              sunday + 7 * 86400 + at);
        std::string window(168, '0');
        window[11] = '1';
        check(next_task_schedule(task(schedule("[0]", 1, "true",
            R"(,"backup_window":")" + window + '"')), sunday) == sunday + at + 3600);
        check(!next_task_schedule(task(schedule("[0]", 0, "true",
            R"(,"backup_window":")" + window + '"')), sunday));
        check(!next_task_schedule(task(schedule("[1]", 1, "true",
            R"(,"backup_window":")" + window + '"')), sunday));
        // NAS time is independent of the operating system's timezone.
        check(next_task_schedule(daily, sunday, 3600) == sunday + at - 3600);
        check(next_task_schedule(daily, sunday, -3600) == sunday + at + 3600);
        check(next_task_schedule(daily, sunday, 3661) == sunday + at - 3661);
        check(next_task_schedule(task(schedule("[0]")), sunday - 1800, 3600) ==
              sunday + at - 3600);
        // Epoch boundary and dates beyond signed 32-bit time_t.
        check(next_task_schedule(daily, 0) == at);
        check(next_task_schedule(daily, 0, -3600) == at + 3600);
        constexpr std::uint64_t year2100 = 4'102'444'800;
        check(next_task_schedule(daily, year2100) == year2100 + at);
        // Full JSON parsing: escaped keys, nested unrelated strings, numbers,
        // booleans and Unicode cannot accidentally become policy fields.
        check(next_task_schedule(task(
            R"({"schedule\u005fsetting_type":1,"run_hour":10,"run_min":30,)"
            R"("run_weekday":[0],"repeat_hour":0,"enable_backup_window":false,)"
            R"("other":{"run_hour":22,"unicode":"\ud83d\ude00","values":[null,true,-2,1.5e+2]},)"
            R"("text":"\"run_hour\":23"})"), sunday) == sunday + at);
        for (const auto* bad : {
            "{", "[]", "null",
            R"({"schedule_setting_type":01})",
            R"({"schedule_setting_type":1,})",
            R"({"schedule_setting_type":1} false)",
            R"({"schedule_setting_type":"1"})",
            R"({"schedule_setting_type":-1})",
            R"({"schedule_setting_type":1,"x":"\ud800"})",
            R"({"schedule_setting_type":1,"x":1.})"
        }) rejects([&] { (void)next_task_schedule(task(bad), sunday); });
        for (const auto& bad : {
            schedule("[7]"), schedule("[-1]"), schedule("null"),
            schedule("[0]", 0, "true"),
            schedule("[0]", 0, "true", R"(,"backup_window":"1")"),
            schedule("[0]", 0, "\"false\"")
        }) rejects([&] { (void)next_task_schedule(task(bad), sunday); });
        auto invalid_window = window;
        invalid_window[11] = 'x';
        rejects([&] { (void)next_task_schedule(task(schedule("[0]", 1, "true",
            R"(,"backup_window":")" + invalid_window + '"')), sunday); });
        rejects([&] { (void)next_task_schedule(daily, UINT64_MAX); });
        rejects([&] { (void)next_task_schedule(daily, sunday, INT64_MAX); });
        // The daemon checks every 60 seconds, including when its backup worker
        // is occupied. A long delay queues one event and advances past now.
        std::uint64_t now = sunday + at - 30;
        TaskScheduler scheduler{[&] { return now; }};
        auto assigned_daily = daily;
        auto assigned_hourly = task(schedule("[0]",1));
        std::get<Value::Object>(assigned_daily.data)["id"] = Value{std::uint64_t{2}};
        std::get<Value::Object>(assigned_hourly.data)["id"] = Value{std::uint64_t{7}};
        scheduler.update({assigned_daily,assigned_hourly},0);
        check(scheduler.poll().empty());
        now += 29;
        check(scheduler.poll().empty());
        ++now; // Timeout checks align to Unix-minute boundaries.
        auto due = scheduler.poll();
        check(due.size() == 2 && due[0].due == sunday+at && due[1].due == sunday+at &&
            std::get<Value::Object>(due[0].task.data).at("id") !=
            std::get<Value::Object>(due[1].task.data).at("id"));
        check(scheduler.poll().empty());
        now += 3*3600;
        due = scheduler.poll();
        check(due.size() == 1 && due[0].due == sunday+at+3600);
        now += 60;
        check(scheduler.poll().empty()); // missed hourly slots do not flood queue
        scheduler.update({},0); // task removal resets the complete assigned set
        now += 86400;
        check(scheduler.poll().empty());
        scheduler.update({daily},0);
        now = sunday+2*86400+at+30;
        check(scheduler.poll().size() == 1);
        // Refreshing tasks recalculates every schedule, even with an unchanged schedule.
        scheduler.update({daily},0);
        now += 60;
        check(scheduler.poll().empty());
        // A spring timezone jump over the next scheduled local time queues it
        // once; a backward jump or an unrelated large move does not catch up.
        now = sunday+at-1800;
        TaskScheduler spring{[&] { return now; }};
        spring.update({daily},0);
        check(spring.timezone(3600,3600).size() == 1);
        check(spring.poll().empty());
        check(spring.timezone(0,-3600).empty());
        check(spring.timezone(14400,14400).empty());
        // The persisted next time survives an offline process restart. The
        // successful get_task update later resets it to the next future slot.
        auto persisted = scheduler.state();
        now = sunday+4*86400+at;
        TaskScheduler recovered{[&] { return now; }};
        recovered.restore(pstream::decode(pstream::encode(persisted)));
        check(recovered.poll().size() == 1);
        recovered.update({daily},0);
        check(recovered.poll().empty());
        // A new service with no saved task has no historical catch-up.
        TaskScheduler restarted{[&] { return now; }};
        restarted.update({daily},0);
        check(restarted.poll().empty());
        std::cout << "task schedule tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
