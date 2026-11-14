#include "opensabba/server_time.hpp"
#include <iostream>

using namespace opensabba;
using namespace opensabba::pstream;
void check(bool condition) { if (!condition) throw Error("server time invariant failed"); }
Value reply(std::string epoch, Value timezone = Value{std::string("3600")}) {
    return Value{Value::Object{{"epoch",Value{std::move(epoch)}},{"timezone",std::move(timezone)}}};
}
int main() {
    try {
        TimeoutChecker timer(180);
        check(!timer.check(0) && !timer.check(179));
        check(timer.check(180) && !timer.check(180));
        check(timer.check(1001));
        check(!timer.check(1079));
        check(timer.check(1080)); // aligned, rather than 180 s after first check
        check(!timer.check(1080));
        check(timer.check(900)); // backwards clock
        check(!timer.check(901));
        check(timer.check(1261)); // skipped periods
        TimeoutChecker always(0);
        check(always.check(0) && always.check(1) && always.check(1));
        check(timer.check(-1)); // official agent failed-clock behavior
        check(!timer.check(1262)); // failed time did not advance the boundary
        for (const auto delta : {-301,-300,-299,0,299,300,301}) {
            const auto result = server_time_reply(reply(std::to_string(1000+delta)),1000,1000);
            const auto expected = delta >= -300 && delta <= 300 ? 0 : delta;
            check(result.difference == expected);
            check(result.offset == std::to_string(3600+expected));
        }
        // Integer halves deliberately differ from the ordinary rounded midpoint.
        check(server_time_reply(reply("1301"),1001,1001).difference == 301);
        auto numeric = reply("2000",Value{static_cast<std::uint64_t>(std::int64_t{-3600})});
        std::get<Value::Object>(numeric.data)["epoch"] = Value{std::uint64_t{2000}};
        const auto result = server_time_reply(decode(encode(numeric)),1000,1000);
        check(result.timezone == -3600 && result.difference == 1000 && result.offset == "-2600");
        check(server_time_from_value(decode(encode(server_time_value(result)))) == result);
        check(server_time_offset(result) == -2600);
        // the official agent's schedule offset parser accepts stoll decimal prefixes and
        // postpones scheduling on invalid_argument, including logout's sentinel.
        for (const auto* unset : {"", " ", "not-ready"})
            check(!server_time_offset(ServerTime{unset}));
        check(server_time_offset(ServerTime{"0"}) == 0);
        check(server_time_offset(ServerTime{" +3600 trailing"}) == 3600);
        for (const auto* overflow : {"9223372036854775808", "-9223372036854775809"}) {
            bool failed = false;
            try { (void)server_time_offset(ServerTime{overflow}); }
            catch (const Error& error) {
                failed = std::string(error.what()) == "server time field out of range: server_timeoffset";
            }
            check(failed);
        }
        bool bad_epoch = false;
        try { (void)server_time_reply(reply("not-an-epoch"),1000,1000); }
        catch (const Error& error) { bad_epoch = std::string(error.what()) == "invalid server time field: epoch"; }
        check(bad_epoch);
        set_server_time(result);
        check(to_server_time(1000) == 2000 && to_client_time(2000) == 1000);
        Value display{Value::Object{{"start_time",Value{std::uint64_t{2000}}},
            {"last_backup_success_time",Value{std::uint64_t{2000}}},
            {"task_list",Value{Value::Array{Value{Value::Object{
                {"last_backup_success_time",Value{std::uint64_t{0}}}}}}}},
            {"local_time",Value{std::uint64_t{2000}}}}};
        client_display_times(display);
        check(std::get<std::uint64_t>(std::get<Value::Object>(display.data).at("start_time").data) == 2000);
        check(std::get<std::uint64_t>(std::get<Value::Object>(display.data).at("last_backup_success_time").data) == 1000);
        const auto& task = std::get<Value::Array>(std::get<Value::Object>(display.data).at("task_list").data).front();
        check(std::get<std::uint64_t>(std::get<Value::Object>(task.data).at("last_backup_success_time").data) == 0);
        check(std::get<std::uint64_t>(std::get<Value::Object>(display.data).at("local_time").data) == 2000);
        // Explicit logout keeps the timezone, clears the combined offset and
        // removes the epoch correction. The private store exercises this
        // round-trip in the Linux registration fixture.
        auto reset = result;
        reset.offset.clear();
        reset.difference = 0;
        check(server_time_from_value(decode(encode(server_time_value(reset)))) == reset);
        check(!server_time_offset(server_time_from_value(decode(encode(server_time_value(reset))))));
        set_server_time(reset);
        check(to_server_time(1000) == 1000 && to_client_time(1000) == 1000);
        std::cout << "server time tests passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
