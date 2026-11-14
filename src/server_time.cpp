#include "opensabba/server_time.hpp"
#include <atomic>
#include <bit>
#include <ctime>
#include <cerrno>
#include <cstdlib>

namespace opensabba {
using pstream::Value;
using pstream::Error;
namespace {
std::atomic<std::int64_t> difference{0};
const Value& field(const Value& value, const char* key) {
    return std::get<Value::Object>(value.data).at(key);
}
// Control-value string conversion accepts numeric control values as decimal text. PStream
// carries signed integers in its uint64 bit pattern, as elsewhere in the client.
std::string decimal(const Value& value) {
    if (const auto* text = std::get_if<std::string>(&value.data)) return *text;
    if (const auto* number = std::get_if<std::uint64_t>(&value.data))
        return std::to_string(std::bit_cast<std::int64_t>(*number));
    throw Error("server time field must be decimal text or an integer");
}
std::int64_t integer(const Value& value, const char* name) {
    try { return std::stoll(decimal(value)); }
    catch (const std::invalid_argument&) { throw Error(std::string("invalid server time field: ") + name); }
    catch (const std::out_of_range&) { throw Error(std::string("server time field out of range: ") + name); }
}
}
bool TimeoutChecker::check(std::int64_t now) {
    if (!period_ || now < 0) return true;
    if (last_ > now || last_ + period_ <= now) {
        last_ = now - now % period_;
        return true;
    }
    return false;
}
ServerTime server_time_reply(const Value& reply, std::int64_t before, std::int64_t after) {
    ServerTime result;
    result.timezone = integer(field(reply,"timezone"),"timezone");
    result.difference = integer(field(reply,"epoch"),"epoch") - before/2 - after/2;
    if (result.difference >= -300 && result.difference <= 300) result.difference = 0;
    result.offset = std::to_string(result.difference + result.timezone);
    return result;
}
Value server_time_value(const ServerTime& time) {
    return Value{Value::Object{
        {"server_timeoffset",Value{time.offset}},
        {"server_timediff",Value{std::to_string(time.difference)}},
        {"server_timezone",Value{std::to_string(time.timezone)}}}};
}
ServerTime server_time_from_value(const Value& value) {
    return {decimal(field(value,"server_timeoffset")),integer(field(value,"server_timediff"),"server_timediff"),
            integer(field(value,"server_timezone"),"server_timezone")};
}
std::optional<std::int64_t> server_time_offset(const ServerTime& time) {
    // backup-window-utility.cpp treats stoll's invalid_argument
    // as "not yet ready", but propagates out_of_range. Preserve its decimal
    // prefix/whitespace handling without replacing an unset offset with UTC.
    char* end;
    errno = 0;
    const auto offset = std::strtoll(time.offset.c_str(), &end, 10);
    if (end == time.offset.c_str()) return std::nullopt;
    if (errno == ERANGE) throw Error("server time field out of range: server_timeoffset");
    return offset;
}
void set_server_time(const ServerTime& time) { difference = time.difference; }
std::int64_t to_server_time(std::int64_t time) { return time + difference.load(); }
std::int64_t to_client_time(std::int64_t time) { return time - difference.load(); }
std::uint64_t server_time_now() {
    const auto now = std::time(nullptr);
    if (now <= 0) throw Error("cannot determine snapshot/log time");
    return static_cast<std::uint64_t>(to_server_time(now));
}
void client_display_times(Value& value) {
    if (auto* fields = std::get_if<Value::Object>(&value.data)) {
        for (auto& [key,entry] : *fields) {
            // Task discovery's last_backup_success_time is the NAS equivalent
            // of Local service status's last_success_time. Other task and
            // restore-catalog times have no corresponding official agent conversion.
            if (key == "last_backup_success_time") {
                auto& time = std::get<std::uint64_t>(entry.data);
                if (time) time = static_cast<std::uint64_t>(to_client_time(static_cast<std::int64_t>(time)));
            } else client_display_times(entry);
        }
    } else if (auto* entries = std::get_if<Value::Array>(&value.data))
        for (auto& entry : *entries) client_display_times(entry);
}
}
