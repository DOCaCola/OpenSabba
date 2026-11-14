#include "opensabba/historical_logs.hpp"
#include "opensabba/diagnostics.hpp"
#include "opensabba/display.hpp"
#include "opensabba/server_time.hpp"
#include <algorithm>
#include <array>
#include <cstdlib>
#include <ctime>
#include <exception>
#include <iostream>
#include <mutex>
#include <sstream>
#ifdef __linux__
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#endif

namespace opensabba {
namespace {
#ifdef __linux__
using pstream::Error;
constexpr std::size_t rotate_bytes = 1024*1024;
std::mutex log_mutex;
struct File {
    int fd;
    explicit File(int value) : fd(value) {
        if (fd < 0) throw Error("cannot open historical log storage");
    }
    ~File() { close(fd); }
};
void private_file(int fd, bool directory) {
    struct stat info{};
    if (fstat(fd,&info) || info.st_uid != getuid() || (info.st_mode & 0077) ||
        (directory ? !S_ISDIR(info.st_mode) : !S_ISREG(info.st_mode) || info.st_nlink != 1))
        throw Error("historical log storage must be private and owned by this user");
}
void append(const std::filesystem::path& storage, const std::string& content) {
    std::lock_guard guard(log_mutex);
    File base(open(storage.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    private_file(base.fd,true);
    if (mkdirat(base.fd,"log",0700) && errno != EEXIST)
        throw Error("cannot create historical log directory");
    File directory(openat(base.fd,"log",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    private_file(directory.fd,true);
    // A separate inode coordinates all CLI/service writers through rotation.
    File lock(openat(directory.fd,".lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600));
    private_file(lock.fd,false);
    if (flock(lock.fd,LOCK_EX)) throw Error("cannot lock historical logs");
    File output(openat(directory.fd,"log.txt",O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600));
    private_file(output.fd,false);
    const auto now = std::time(nullptr);
    std::tm calendar{};
    if (!localtime_r(&now,&calendar)) throw Error("cannot timestamp historical log");
    std::array<char,32> date{};
    std::strftime(date.data(),date.size(),"%Y-%m-%d %H:%M:%S",&calendar);
    const auto line = std::string(date.data())+" pid="+std::to_string(getpid())+" "+content+"\n";
    std::size_t offset = 0;
    while (offset < line.size()) {
        auto count = write(output.fd,line.data()+offset,line.size()-offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw Error("cannot write historical log");
        offset += static_cast<std::size_t>(count);
    }
    struct stat info{};
    if (fstat(output.fd,&info)) throw Error("cannot inspect historical log");
    if (info.st_size > static_cast<off_t>(rotate_bytes)) {
        // the official agent passes 50 to Log rotation, shifts _0.._48 up, removes
        // _49, then renames the current file to _0: 49 retained rotations.
        for (int index = 48; index >= 0; --index) {
            const auto from = "log.txt_"+std::to_string(index);
            const auto to = "log.txt_"+std::to_string(index+1);
            if (renameat(directory.fd,from.c_str(),directory.fd,to.c_str()) && errno != ENOENT)
                throw Error("cannot rotate historical log");
        }
        if (unlinkat(directory.fd,"log.txt_49",0) && errno != ENOENT)
            throw Error("cannot expire historical log");
        if (renameat(directory.fd,"log.txt",directory.fd,"log.txt_0"))
            throw Error("cannot retain historical log");
        File fresh(openat(directory.fd,"log.txt",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
        if (fsync(directory.fd)) throw Error("cannot persist historical log rotation");
    }
}
std::filesystem::path existing_storage() {
    const char* config = std::getenv("XDG_CONFIG_HOME");
    std::filesystem::path base;
    if (config && *config) base = config;
    else {
        const char* home = std::getenv("HOME");
        if (!home || !*home) throw Error("HOME is not set");
        base = std::filesystem::path(home)/".config";
    }
    if (!base.is_absolute()) throw Error("configuration path must be absolute");
    return base/"opensabba";
}
#endif
}
std::optional<pstream::Value> backup_start_activity(std::string_view task_name,
    std::uint64_t trigger_type, std::uint64_t trigger_event, std::uint64_t log_time) {
    if (trigger_type == 5) return {};
    using pstream::Value;
    return Value{Value::Object{{"log_type",Value{std::uint64_t{trigger_type == 3 ? 1115U : 1101U}}},
        {"log_time",Value{log_time}},{"parameters",Value{Value::Object{
            {"task_name",Value{std::string(task_name)}},{"trigger_type",Value{trigger_type}},
            {"trigger_event",Value{trigger_event}}}}}}};
}
void historical_backup_start(const std::filesystem::path& storage, std::string_view task_name,
    std::uint64_t trigger_type, std::uint64_t trigger_event) {
    const auto activity = backup_start_activity(task_name,trigger_type,trigger_event,server_time_now());
    if (!activity) return;
#ifdef __linux__
    std::ostringstream content;
    content << "[INFO] activity=";
    print_json(content,*activity);
    // the official agent ignores local activity insertion's error result and still writes syslog.
    // A local activity-storage failure must not fail the snapshot itself.
    try { append(storage,content.str()); }
    catch (const pstream::Error& error) {
        std::cerr << "opensabba: start activity logging failed: " << error.what() << '\n';
    }
    const std::string task(task_name);
    if (trigger_type == 3) {
        const char* event = trigger_event == 1 ? "screen locked" :
            trigger_event == 2 ? "signing out" : trigger_event == 3 ? "startup" : "unknown type of event";
        syslog(LOG_INFO,"Backup task %s has been triggered by event %s.",task.c_str(),event);
    } else syslog(LOG_INFO,"The backup task %s has started.",task.c_str());
#else
    (void)storage;
#endif
}
void historical_service_event(const std::filesystem::path& storage, HistoricalEvent event) {
#ifdef __linux__
    const char* text;
    switch (event) {
    case HistoricalEvent::connection_attempt: text = "[INFO] service=connection-attempt"; break;
    case HistoricalEvent::connected: text = "[INFO] service=connected"; break;
    case HistoricalEvent::connection_interrupted: text = "[WARNING] service=connection-interrupted"; break;
    case HistoricalEvent::reload: text = "[INFO] service=reload"; break;
    case HistoricalEvent::stopped: text = "[INFO] service=stopped"; break;
    }
    append(storage,text);
#else
    (void)storage; (void)event;
#endif
}
void historical_journal_event(const std::filesystem::path& storage,
                              std::string_view journal, const pstream::Value& value) {
#ifdef __linux__
    constexpr std::array names{"session.pstream","identity.pstream","backup-job.pstream",
        "events.pstream","service-source.pstream","service-machine-pending.pstream",
        "service-machine-event.pstream","service-machine-recapture.pstream"};
    if (std::find(names.begin(),names.end(),journal) == names.end()) return;
    const auto summary = diagnostic_summary(value);
    std::ostringstream event;
    event << "[INFO] journal=" << journal;
    for (const auto& [key,field] : std::get<pstream::Value::Object>(summary.data)) {
        if (const auto* number = std::get_if<std::uint64_t>(&field.data))
            event << ' ' << key << '=' << *number;
        else if (const auto* text = std::get_if<std::string>(&field.data))
            event << ' ' << key << '=' << *text;
    }
    append(storage,event.str());
#else
    (void)storage; (void)journal; (void)value;
#endif
}
HistoricalLogRun::HistoricalLogRun(std::string_view command) : exceptions_(std::uncaught_exceptions()) {
#ifdef __linux__
    // Only fixed command identifiers are retained; never copy untrusted argv.
    constexpr std::array commands{"login","connect","--connect","-c","logout","--logout","-l",
        "status","--status","-s","reconnect","reload","--reload","-r","heartbeat","tasks",
        "service","events","backup","restore","snapshot","machine","registration","probe"};
    if (std::find(commands.begin(),commands.end(),command) == commands.end()) return;
    storage_ = existing_storage();
    // Read-only commands must not manufacture session storage. Store writes
    // provide history once login/service initializes it.
    if (!std::filesystem::exists(storage_)) { storage_.clear(); return; }
    command_ = command;
    append(storage_,"[INFO] command="+command_+" state=started");
#else
    (void)command;
#endif
}
HistoricalLogRun::~HistoricalLogRun() {
#ifdef __linux__
    if (storage_.empty()) return;
    try {
        const bool error = std::uncaught_exceptions() > exceptions_;
        append(storage_,std::string(error ? "[ERROR]" : "[INFO]")+" command="+command_+
            " state="+(error ? "failed" : "stopped"));
    } catch (const std::exception& error) {
        // A destructor cannot throw while handling a command failure.
        std::cerr << "opensabba: historical logging failed: " << error.what() << '\n';
    }
#endif
}
}
