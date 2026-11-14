#include "opensabba/log_export.hpp"
#include "opensabba/pstream.hpp"
#include "opensabba/historical_logs.hpp"
#include "../src/diagnostic_zip.hpp"
#include <fstream>
#include <iostream>
#include <regex>

int main(int argc, char** argv) {
    try {
        using opensabba::redact_diagnostic_text;
        auto check = [](bool pass) {
            if (!pass) throw opensabba::pstream::Error("log export invariant failed");
        };
        check(redact_diagnostic_text("safe PRIVATE_TOKEN end",{"PRIVATE_TOKEN"}) == "safe [redacted] end");
        check(redact_diagnostic_text("password=\"two words\"",{}).find("two words") == std::string::npos);
        check(redact_diagnostic_text("Authorization: Bearer abc",{}).find("abc") == std::string::npos);
        check(redact_diagnostic_text("https://user:pass@host/",{}).find("pass") == std::string::npos);
        check(redact_diagnostic_text("command --proxy-password abc",{}).find("abc") == std::string::npos);
        check(redact_diagnostic_text("safe\nTOKEN: abc\nsafe\n",{}) ==
            "safe\n[credential-bearing line redacted]\nsafe\n");
        check(redact_diagnostic_text("line one\nline two",{}) == "line one\nline two");
        check(std::regex_match(opensabba::default_log_archive().filename().string(),
            std::regex("abb_debuglog_[0-9]{8}_[0-9]{6}\\.zip")));
        using opensabba::pstream::Value;
        for (const auto trigger : {0U,1U,2U,3U,4U}) {
            const auto activity = opensabba::backup_start_activity("Fixture \"task\"\n",trigger,9,1234);
            check(activity.has_value());
            const auto& fields = std::get<Value::Object>(activity->data);
            check(fields.size() == 3 && fields.at("log_type") ==
                Value{std::uint64_t{trigger == 3 ? 1115U : 1101U}});
            check(fields.at("log_time") == Value{std::uint64_t{1234}});
            check(fields.at("parameters") == Value{Value::Object{
                {"task_name",Value{std::string("Fixture \"task\"\n")}},
                {"trigger_type",Value{std::uint64_t{trigger}}},{"trigger_event",Value{std::uint64_t{9}}}}});
        }
        check(!opensabba::backup_start_activity("Cache capture",5,0,1234));
        if (argc == 2) {
            std::ofstream output(argv[1],std::ios::binary);
            opensabba::detail::DiagnosticZip zip([&](std::string_view data) {
                output.write(data.data(),static_cast<std::streamsize>(data.size()));
                if (!output) throw opensabba::pstream::Error("fixture archive write failed");
            });
            zip.text("empty","");
            zip.text("diagnostics.json","{\"format\":1}\n");
            zip.text("agent_log/log.txt",std::string(150000,'x')+"\n");
            zip.finish();
            output.close();
            check(static_cast<bool>(output));
        }
        std::cout << "Log export redaction tests passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
