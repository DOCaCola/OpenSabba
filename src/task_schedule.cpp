#include "opensabba/task_schedule.hpp"
#include <array>
#include <charconv>
#include <string_view>
#include <ctime>
#include "json.hpp"

namespace opensabba {
namespace {
using pstream::Error;
using pstream::Value;
using json_detail::Json;
using json_detail::Parser;
const Json& member(const Json& json, const char* key) {
    const auto found = json.members.find(key);
    if (found == json.members.end()) throw Error(std::string("missing schedule field: ") + key);
    return found->second;
}
std::int64_t integer(const Json& json) {
    std::int64_t result = 0;
    const auto parsed = std::from_chars(json.scalar.data(), json.scalar.data() + json.scalar.size(), result);
    if (json.kind != Json::number || parsed.ec != std::errc{} ||
        parsed.ptr != json.scalar.data() + json.scalar.size())
        throw Error("invalid integer schedule field");
    return result;
}
bool boolean(const Json& json) {
    if (json.kind == Json::boolean) return json.scalar == "true";
    if (json.kind == Json::number) return integer(json) != 0;
    throw Error("invalid boolean schedule field");
}
std::int64_t add(std::int64_t a, std::int64_t b) {
    if ((b > 0 && a > INT64_MAX - b) || (b < 0 && a < INT64_MIN - b))
        throw Error("schedule time is out of range");
    return a + b;
}
std::int64_t floor_div(std::int64_t value, std::int64_t divisor) {
    return value / divisor - (value % divisor < 0 ? 1 : 0);
}
struct Schedule {
    std::int64_t hour, minute;
    bool repeat;
    std::array<bool,7> weekdays;
    std::string window;
};
std::optional<Schedule> decode_schedule(const Value& task) {
    const auto* fields = std::get_if<Value::Object>(&task.data);
    if (!fields) throw Error("invalid task schedule object");
    const auto found = fields->find("sched_content");
    if (found == fields->end()) return std::nullopt;
    const auto* content = std::get_if<std::string>(&found->second.data);
    if (!content) throw Error("invalid sched_content string");
    if (content->empty()) return std::nullopt;
    const auto policy = Parser(*content).parse();
    // Missing schedule type decodes as zero.
    if (!policy.members.contains("schedule_setting_type")) return std::nullopt;
    const auto type = integer(member(policy, "schedule_setting_type"));
    if (type < 0) throw Error("invalid schedule setting type");
    if ((type & 1) == 0) return std::nullopt;
    const auto hour = integer(member(policy, "run_hour"));
    const auto minute = integer(member(policy, "run_min"));
    const auto repeat = boolean(member(policy, "repeat_hour"));
    if (hour < 0 || hour > 23 || minute < 0 || minute > 59)
        throw Error("invalid schedule hour or minute");
    const auto& days = member(policy, "run_weekday");
    if (days.kind != Json::array) throw Error("invalid schedule weekday array");
    std::array<bool, 7> weekdays{};
    for (const auto& day : days.elements) {
        const auto index = integer(day);
        if (index < 0 || index > 6) throw Error("invalid schedule weekday");
        weekdays[static_cast<std::size_t>(index)] = true;
    }
    std::string window(168, '1');
    if (boolean(member(policy, "enable_backup_window"))) {
        const auto& bitmap = member(policy, "backup_window");
        if (bitmap.kind != Json::string || bitmap.scalar.size() != 168 ||
            bitmap.scalar.find_first_not_of("01") != std::string::npos)
            throw Error("invalid schedule backup window");
        window = bitmap.scalar;
    }
    return Schedule{hour,minute,repeat,weekdays,std::move(window)};
}
std::int64_t schedule_local(std::uint64_t instant,std::int64_t offset) {
    if (instant > INT64_MAX || offset == INT64_MIN) throw Error("schedule time is out of range");
    const auto minutes = floor_div(offset,60);
    if (minutes < INT64_MIN/60) throw Error("schedule offset is out of range");
    return add(static_cast<std::int64_t>(instant),minutes*60);
}
bool window_allows(const Value& task,std::uint64_t now,std::int64_t offset) {
    const auto policy = decode_schedule(task);
    if (!policy) return false;
    const auto local = schedule_local(now,offset);
    const auto day = floor_div(local,86400);
    const auto weekday = static_cast<std::size_t>((day%7+11)%7);
    const auto hour = static_cast<std::size_t>((local-day*86400)/3600);
    return policy->window[weekday*24+hour] != '0';
}
}

std::optional<std::uint64_t> next_task_schedule(const Value& task, std::uint64_t after,
                                                std::int64_t server_offset_seconds) {
    const auto policy = decode_schedule(task);
    if (!policy) return std::nullopt;
    const auto& [hour,minute,repeat,weekdays,window] = *policy;
    const auto local = schedule_local(after,server_offset_seconds);
    const auto epoch = static_cast<std::int64_t>(after);
    auto day = floor_div(local, 86400);
    // A policy repeats weekly. Eight calendar dates include the later part of
    // the current day and the same weekday in the following week.
    for (unsigned date = 0; date < 8; ++date, ++day) {
        const auto weekday = static_cast<std::size_t>((day % 7 + 11) % 7);
        if (!weekdays[weekday]) continue;
        for (auto at_hour = hour; at_hour < 24; at_hour += repeat ? 1 : 24) {
            if (window[weekday * 24 + static_cast<std::size_t>(at_hour)] == '0') continue;
            if (day > INT64_MAX / 86400 || day < INT64_MIN / 86400)
                throw Error("schedule time is out of range");
            auto candidate = add(day * 86400, at_hour * 3600 + minute * 60);
            candidate = add(candidate, -server_offset_seconds);
            if (candidate > epoch) return static_cast<std::uint64_t>(candidate);
        }
    }
    return std::nullopt;
}
}

namespace opensabba {
TaskScheduler::TaskScheduler(Now now) : now_(now ? std::move(now) : Now{[] {
    return static_cast<std::uint64_t>(std::time(nullptr));
}}) {}
void TaskScheduler::update(const pstream::Value::Array& tasks, std::int64_t offset) {
    const auto now = now_();
    std::vector<Entry> updated;
    for (const auto& task : tasks) updated.push_back({task,next_task_schedule(task,now,offset)});
    entries_ = std::move(updated);
    offset_ = offset;
}
std::vector<ScheduledTask> TaskScheduler::poll() {
    const auto now = now_();
    if (now > INT64_MAX) throw Error("schedule time is out of range");
    if (!cadence_.check(static_cast<std::int64_t>(now))) return {};
    std::vector<ScheduledTask> due;
    for (auto& entry : entries_) {
        if (!entry.next || now < *entry.next) continue;
        due.push_back({entry.task,*entry.next});
        // Event queuing advances before task-event deduplication. A delayed
        // scheduler produces one event, never one event per elapsed interval.
        entry.next = next_task_schedule(entry.task,now,offset_);
    }
    return due;
}
}

namespace opensabba {
BackupRun trigger_scheduled_backup(const Endpoint& connected, const SavedAuth& auth,
    std::uint64_t task, std::uint64_t base_version, const std::function<void()>& before_send) {
    auto endpoint = connected;
    endpoint.backup_trigger_type = scheduled_trigger_type;
    return base_version ? create_incremental_backup(endpoint,auth,task,base_version,before_send) :
        create_full_backup(endpoint,auth,task,before_send);
}
}

namespace opensabba {
pstream::Value TaskScheduler::state() const {
    pstream::Value::Array entries;
    for (const auto& entry : entries_) entries.push_back(pstream::Value{pstream::Value::Object{
        {"task",entry.task},{"next",pstream::Value{entry.next.value_or(0)}}}});
    return pstream::Value{pstream::Value::Object{{"offset",pstream::Value{std::to_string(offset_)}},
        {"entries",pstream::Value{std::move(entries)}}}};
}
void TaskScheduler::restore(const pstream::Value& saved) {
    const auto& object = std::get<pstream::Value::Object>(saved.data);
    const auto& encoded = std::get<std::string>(object.at("offset").data);
    std::int64_t offset;
    const auto parsed = std::from_chars(encoded.data(),encoded.data()+encoded.size(),offset);
    if (parsed.ec != std::errc{} || parsed.ptr != encoded.data()+encoded.size())
        throw pstream::Error("invalid saved schedule offset");
    std::vector<Entry> restored;
    for (const auto& item : std::get<pstream::Value::Array>(object.at("entries").data)) {
        const auto& fields = std::get<pstream::Value::Object>(item.data);
        const auto next = std::get<std::uint64_t>(fields.at("next").data);
        restored.push_back({fields.at("task"),next ? std::optional{next} : std::nullopt});
    }
    entries_ = std::move(restored);
    offset_ = offset;
    cadence_ = TimeoutChecker{60};
}
}

namespace opensabba {
std::vector<ScheduledTask> TaskScheduler::timezone(std::int64_t offset,std::int64_t delta) {
    const auto now = now_();
    std::vector<ScheduledTask> due;
    for (auto& entry : entries_) {
        const auto next = next_task_schedule(entry.task,now,offset);
        // Schedule advancement catches an instant skipped by a forward
        // timezone change up to three hours, if the current window permits it.
        if (delta > 0 && delta <= 10800 && entry.next && next && *entry.next < *next &&
            *entry.next <= static_cast<std::uint64_t>(add(static_cast<std::int64_t>(now),delta)) &&
            window_allows(entry.task,now,offset)) due.push_back({entry.task,*entry.next});
        entry.next = next;
    }
    offset_ = offset;
    return due;
}
}
