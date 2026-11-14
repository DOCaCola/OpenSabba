#include "opensabba/diagnostics.hpp"
#include "opensabba/display.hpp"
#include <iostream>
#include <sstream>
#include <set>

using namespace opensabba;
using namespace opensabba::pstream;
void check(bool value) { if (!value) throw Error("diagnostic report invariant failed"); }
int main() {
    try {
        std::set<std::string> reads;
        auto report = diagnostic_report([&](const char* name) -> std::optional<Value> {
            check(reads.emplace(name).second);
            if (std::string_view(name) == "session.pstream")
                return Value{Value::Object{{"token",Value{std::string("SECRET_TOKEN")}},
                    {"username",Value{std::string("SECRET_USER")}}, {"format",Value{std::uint64_t{2}}},
                    {"password",Value{std::string("SECRET_PASSWORD")}}}};
            if (std::string_view(name) == "backup-job.pstream")
                return Value{Value::Object{{"phase",Value{std::string("upload")}},
                    {"image_size",Value{std::uint64_t{4096}}},
                    {"source_capture",Value{Value::Object{
                        {"phase",Value{std::string("SECRET_PHASE")}},
                        {"token",Value{std::string("SECRET_NESTED")}}}}},
                    {"offset",Value{std::string("SECRET_WRONG_TYPE")}}}};
            if (std::string_view(name) == "events.pstream")
                return Value{Value::Object{{"receipts",Value{Value::Array{
                    Value{std::string("SECRET_PAYLOAD")}}}}}};
            if (std::string_view(name) == "service-machine-event.pstream") throw Error("SECRET_ERROR");
            if (std::string_view(name) == "identity.pstream") return Value{std::string("SECRET_BAD_MAP")};
            return {};
        });
        std::ostringstream json;
        print_json(json,report);
        const auto encoded = json.str();
        check(reads.size() == 8 && encoded.find("SECRET") == std::string::npos);
        for (const auto removed : {"restore-job.pstream","snapshot-job.pstream","service-origin.pstream",
                                   "service-machine.pstream","service-boot-recovery.pstream","service-reboot-policy.pstream"})
            check(!reads.contains(removed));
        const auto& records = std::get<Value::Object>(
            std::get<Value::Object>(report.data).at("journals").data);
        auto record = [&](const char* name) -> const Value::Object& {
            return std::get<Value::Object>(records.at(name).data);
        };
        check(record("service-machine-event.pstream").at("status") == Value{std::string("unreadable")});
        check(record("identity.pstream").at("status") == Value{std::string("unreadable")});
        check(record("service-source.pstream").at("status") == Value{std::string("missing")});
        const auto& backup = std::get<Value::Object>(record("backup-job.pstream").at("summary").data);
        check(backup.at("image_size") == Value{std::uint64_t{4096}});
        check(backup.at("phase") == Value{std::string("upload")} && !backup.contains("offset"));
        std::cout << "Diagnostic projection tests passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
