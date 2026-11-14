#include "opensabba/log_export.hpp"
#include "opensabba/historical_logs.hpp"
#include "opensabba/pstream.hpp"
#include <iostream>
#include <cstdarg>
#include <cstdio>
#include <syslog.h>
#include <unistd.h>

namespace {
std::vector<std::string> system_messages;
}
extern "C" void syslog(int priority, const char* format, ...) {
    if (priority != LOG_INFO) return;
    va_list arguments;
    va_start(arguments,format);
    char message[1024];
    vsnprintf(message,sizeof(message),format,arguments);
    va_end(arguments);
    system_messages.emplace_back(message);
}
int main(int argc, char** argv) {
    try {
        if (argc != 4) throw opensabba::pstream::Error("expected root output log-directory");
        opensabba::DiagnosticCollection options;
        options.system_root = argv[1];
        options.log_directory = argv[3];
        options.journal_summary = "{\"format\":1}\n";
        options.secrets = {"PRIVATE_TOKEN","PRIVATE_USER"};
        options.run = [](const opensabba::DiagnosticCommand& command, int fd) {
            if (command.name == "modinfo") return 127;
            const auto text = "command="+command.name+"\nPRIVATE_TOKEN\npassword=another secret\nsafe\n";
            if (write(fd,text.data(),text.size()) != static_cast<ssize_t>(text.size()))
                throw opensabba::pstream::Error("fixture output failed");
            return 0;
        };
        opensabba::export_diagnostic_archive(argv[2],options);
        using opensabba::pstream::Value;
        opensabba::historical_journal_event(std::filesystem::path(argv[3]).parent_path(),
            "backup-job.pstream",Value{Value::Object{{"phase",Value{std::string("upload")}},
                {"offset",Value{std::uint64_t{512}}},{"token",Value{std::string("PRIVATE_TOKEN")}},
                {"script_content",Value{std::string("PRIVATE_SCRIPT")}}}});
        const auto state = std::filesystem::path(argv[3]).parent_path();
        opensabba::historical_backup_start(state,"Fixture \"task\"\n",1,0);
        opensabba::historical_backup_start(state,"Fixture \"task\"\n",3,9);
        opensabba::historical_backup_start(state,"Fixture \"task\"\n",5,0);
        // Same-event recapture enters a new boundary and logs another start.
        opensabba::historical_backup_start(state,"Fixture \"task\"\n",1,0);
        if (system_messages != std::vector<std::string>{
            "The backup task Fixture \"task\"\n has started.",
            "Backup task Fixture \"task\"\n has been triggered by event unknown type of event.",
            "The backup task Fixture \"task\"\n has started."})
            throw opensabba::pstream::Error("start activity syslog differed from official");
        opensabba::historical_backup_start(state/"missing","Unavailable local database",1,0);
        if (system_messages.back() != "The backup task Unavailable local database has started.")
            throw opensabba::pstream::Error("local log failure suppressed syslog");
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
