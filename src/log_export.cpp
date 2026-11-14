#include "opensabba/log_export.hpp"
#include "opensabba/pstream.hpp"
#include "diagnostic_zip.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <regex>
#include <sstream>
#include <thread>
#ifdef __linux__
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace opensabba {
using pstream::Error;
namespace fs = std::filesystem;
namespace {
#ifdef __linux__
struct File {
    int fd;
    explicit File(int descriptor) : fd(descriptor) {
        if (fd < 0) throw Error("cannot open diagnostic file");
    }
    ~File() { close(fd); }
};
struct Temporary {
    FILE* stream = std::tmpfile();
    Temporary() { if (!stream) throw Error("cannot create private diagnostic temporary file"); }
    ~Temporary() { fclose(stream); }
    int fd() const { return fileno(stream); }
};
void write_all(int fd, std::string_view value) {
    std::size_t at = 0;
    while (at < value.size()) {
        const auto count = write(fd,value.data()+at,value.size()-at);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw Error("cannot write diagnostic archive");
        at += static_cast<std::size_t>(count);
    }
}
// ZIP64 with stored entries: no external archiver or host-specific library.
// Sizes and CRC are finalized using descriptors, so inputs stream to disk.
class Zip : public detail::DiagnosticZip {
public:
    explicit Zip(int fd) : detail::DiagnosticZip([fd](std::string_view value) { write_all(fd,value); }) {}
    void add(const std::string& name, int input) {
        if (lseek(input,0,SEEK_SET) < 0) throw Error("cannot rewind diagnostic input");
        detail::DiagnosticZip::add(name,[input](char* buffer, std::size_t size) -> std::size_t {
            ssize_t count;
            do { count = read(input,buffer,size); } while (count < 0 && errno == EINTR);
            if (count < 0) throw Error("cannot read diagnostic input");
            return static_cast<std::size_t>(count);
        });
    }
};
int run_command(const DiagnosticCommand& command, int output) {
    std::vector<char*> arguments;
    for (const auto& argument : command.arguments) arguments.push_back(const_cast<char*>(argument.c_str()));
    arguments.push_back(nullptr);
    const auto child = fork();
    if (child < 0) throw Error("cannot start diagnostic command");
    if (!child) {
        setpgid(0,0);
        const int null = open("/dev/null",O_RDWR);
        if (null < 0 || dup2(null,STDIN_FILENO) < 0 || dup2(output,STDOUT_FILENO) < 0 ||
            dup2(null,STDERR_FILENO) < 0) _exit(126);
        execvp(arguments.front(),arguments.data());
        _exit(127);
    }
    setpgid(child,child);
    const auto deadline = std::chrono::steady_clock::now()+std::chrono::seconds(30);
    int status{};
    for (;;) {
        const auto done = waitpid(child,&status,WNOHANG);
        if (done == child) return WIFEXITED(status) ? WEXITSTATUS(status) : 128+WTERMSIG(status);
        if (done < 0 && errno != EINTR) throw Error("cannot wait for diagnostic command");
        if (std::chrono::steady_clock::now() >= deadline) {
            kill(-child,SIGKILL);
            while (waitpid(child,&status,0) < 0 && errno == EINTR) {}
            return 124;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}
class Collector {
    const DiagnosticCollection& options_;
    Zip zip_;
    std::ostringstream manifest_;
    fs::path physical(const fs::path& path) const { return options_.system_root/path.relative_path(); }
    void result(const std::string& name, const char* status) {
        manifest_ << name << ": " << status << '\n';
    }
    bool sanitize(int input, int output) {
        if (lseek(input,0,SEEK_SET) < 0) throw Error("cannot rewind diagnostic text");
        std::array<char,65536> buffer{};
        std::string line;
        bool oversized = false;
        for (;;) {
            const auto count = read(input,buffer.data(),buffer.size());
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) throw Error("cannot read diagnostic text");
            if (!count) break;
            for (ssize_t i = 0; i < count; ++i) {
                const auto ch = buffer[static_cast<std::size_t>(i)];
                if (!ch) return false;
                if (ch == '\n') {
                    write_all(output,oversized ? "[oversized line omitted]\n" :
                        redact_diagnostic_text(std::move(line),options_.secrets)+"\n");
                    line.clear(); oversized = false;
                } else if (!oversized) {
                    line += ch;
                    if (line.size() > 65536) { oversized = true; line.clear(); }
                }
            }
        }
        if (oversized) write_all(output,"[oversized line omitted]\n");
        else if (!line.empty()) write_all(output,redact_diagnostic_text(std::move(line),options_.secrets));
        return true;
    }
    void file(const fs::path& path, const std::string& entry, bool metadata_only = false) {
        auto extension = path.extension().string();
        std::transform(extension.begin(),extension.end(),extension.begin(),
            [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        if (extension == ".sh" || extension == ".py" || extension == ".pl" ||
            extension == ".ps1" || extension == ".bat" || extension == ".cmd") {
            result(entry,"script file omitted");
            return;
        }
        // Opening each component prevents a symlinked directory from escaping
        // the selected root, including while files are replaced during export.
        File root(open(options_.system_root.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        int parent = dup(root.fd);
        if (parent < 0) throw Error("cannot open diagnostic root");
        File directory(parent);
        auto relative = path.relative_path();
        for (const auto& component : relative.parent_path()) {
            const int next = openat(directory.fd,component.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            if (next < 0) { result(entry,"unavailable or unsafe parent"); return; }
            close(directory.fd); directory.fd = next;
        }
        const int descriptor = openat(directory.fd,relative.filename().c_str(),O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
        if (descriptor < 0) { result(entry,"missing, unreadable or symlink"); return; }
        File input(descriptor);
        struct stat info{};
        if (fstat(input.fd,&info)) throw Error("cannot inspect diagnostic input");
        if (!S_ISREG(info.st_mode)) { result(entry,"non-regular file omitted"); return; }
        if (metadata_only) {
            manifest_ << entry << ": binary crash data omitted; size=" << info.st_size << '\n';
            return;
        }
        Temporary scrubbed;
        if (!sanitize(input.fd,scrubbed.fd())) { result(entry,"binary data omitted"); return; }
        zip_.add(entry,scrubbed.fd());
        result(entry,"included (text redacted)");
    }
    void tree(const fs::path& path, const std::string& prefix, bool metadata_only = false) {
        std::error_code error;
        const auto status = fs::symlink_status(physical(path),error);
        if (error || status.type() == fs::file_type::not_found) { result(prefix,"missing"); return; }
        if (status.type() != fs::file_type::directory) { result(prefix,"unsafe directory omitted"); return; }
        fs::recursive_directory_iterator item(physical(path),fs::directory_options::skip_permission_denied,error), end;
        while (item != end) {
            const auto relative = item->path().lexically_relative(physical(path));
            const auto entry = prefix+"/"+relative.generic_string();
            const auto type = item->symlink_status(error).type();
            if (error) throw Error("cannot inspect diagnostic directory entry");
            if (type == fs::file_type::regular) file(path/relative,entry,metadata_only);
            else if (type != fs::file_type::directory) result(entry,"symlink or special file omitted");
            item.increment(error);
            if (error) throw Error("cannot enumerate diagnostic directory");
        }
    }
public:
    Collector(const DiagnosticCollection& options, int fd) : options_(options),zip_(fd) {
        manifest_ << "OpenSabba diagnostic archive\n"
            "Credentials and credential-shaped lines are redacted. Saved state is allowlisted JSON.\n"
            "Process command arguments, binary dumps and script files are excluded.\n"
            "Missing commands/files do not prevent other diagnostics; command timeout is 30 seconds.\n"
            "Journals and logs are individually sampled, not one transaction.\n";
    }
    void collect() {
        zip_.text("diagnostics.json",options_.journal_summary);
        for (const auto* name : {"/sys/devices/virtual/dmi/id/product_uuid","/etc/machine-id",
                                "/etc/os-release","/etc/fstab","/etc/centos-release"})
            file(name,fs::path(name).relative_path().generic_string());
        tree("/etc/Synology","etc/Synology");
        tree("/var/lib/systemd/coredump","var/lib/systemd/coredump",true);
        tree("/var/crash","var/crash",true);
        bool system_log = false;
        for (const auto* name : {"syslog","messages","dmesg","kern.log"}) {
            const auto path = fs::path("/var/log")/name;
            std::error_code error;
            if ((std::string_view(name) == "syslog" || std::string_view(name) == "messages") &&
                fs::is_regular_file(fs::symlink_status(physical(path),error))) system_log = true;
            file(path,"var/log/"+std::string(name));
        }
        std::vector<DiagnosticCommand> commands{
            {"fdisk",{"fdisk","-l"}},{"blkid",{"blkid"}},{"lsblk",{"lsblk"}},
            {"uname",{"uname","-a"}},{"dkms",{"dkms","status"}},{"modinfo",{"modinfo","synosnap"}},
            {"df",{"df","-Th"}},{"free",{"free","-h"}},
            {"ps",{"ps","-eo","user,pid,pcpu,pmem,vsz,rss,tty,stat,start,time,comm"}},
            {"ss",{"ss","-pe"}},{"ip",{"ip","addr"}},{"mount",{"mount"}},
            {"synosnap-info",{"cat","/proc/synosnap-info"}},
            {"slabinfo",{"cat","/proc/slabinfo"}},{"partitions",{"cat","/proc/partitions"}},
            {"dmesg",{"dmesg","-T"}}};
        if (!system_log) commands.push_back({"journalctl",{"journalctl","--since","30 days ago","--no-pager"}});
        for (const auto& command : commands) {
            Temporary output;
            const auto code = options_.run ? options_.run(command,output.fd()) : run_command(command,output.fd());
            if (code) { manifest_ << command.name << ": command exit=" << code << '\n'; continue; }
            Temporary scrubbed;
            if (!sanitize(output.fd(),scrubbed.fd())) { result(command.name,"binary command output omitted"); continue; }
            zip_.add(command.name,scrubbed.fd());
            result(command.name,"included (text redacted)");
        }
        zip_.text("abb-cli-s",options_.journal_summary);
        zip_.text("abb-cli-v","OpenSabba "+std::string(OPENSABBA_VERSION)+"\n");
        if (!options_.log_directory.empty()) {
            // Logs live outside system_root in tests and may use another XDG
            // root in production. Restrict export to our own fixed log names.
            std::error_code error;
            const auto state = fs::symlink_status(options_.log_directory,error);
            if (!error && state.type() == fs::file_type::directory) {
                File directory(open(options_.log_directory.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
                for (int index = -1; index < 49; ++index) {
                    const auto name = index < 0 ? std::string("log.txt") : "log.txt_"+std::to_string(index);
                    const int descriptor = openat(directory.fd,name.c_str(),O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
                    if (descriptor < 0 && errno == ENOENT) continue;
                    if (descriptor < 0) { result("agent_log/"+name,"unreadable or symlink"); continue; }
                    File input(descriptor);
                    struct stat info{};
                    if (fstat(input.fd,&info) || !S_ISREG(info.st_mode) || info.st_nlink != 1 ||
                        info.st_uid != getuid() || (info.st_mode & 0077)) {
                        result("agent_log/"+name,"unsafe log omitted"); continue;
                    }
                    Temporary scrubbed;
                    if (sanitize(input.fd,scrubbed.fd())) zip_.add("agent_log/"+name,scrubbed.fd());
                    else result("agent_log/"+name,"binary log omitted");
                }
            } else result("agent_log","missing or unsafe directory");
        }
        zip_.text("collection.txt",redact_diagnostic_text(manifest_.str(),options_.secrets));
        zip_.finish();
    }
};
#endif
}
fs::path default_log_archive() {
    const auto now = std::time(nullptr);
    std::tm calendar{};
#ifdef _WIN32
    if (localtime_s(&calendar,&now)) throw Error("cannot determine diagnostic archive time");
#else
    if (!localtime_r(&now,&calendar)) throw Error("cannot determine diagnostic archive time");
#endif
    std::array<char,64> name{};
    if (!std::strftime(name.data(),name.size(),"abb_debuglog_%Y%m%d_%H%M%S.zip",&calendar))
        throw Error("cannot format diagnostic archive name");
    return fs::path(".")/name.data();
}
std::string redact_diagnostic_text(std::string text, const std::vector<std::string>& secrets) {
    for (const auto& secret : secrets) {
        if (secret.empty()) continue;
        std::size_t at = 0;
        while ((at = text.find(secret,at)) != text.npos) {
            text.replace(at,secret.size(),"[redacted]");
            at += 10;
        }
    }
    // Drop an entire credential-shaped line, including URLs and quoted values.
    // This deliberately favors privacy over keeping surrounding prose.
    static const std::regex credential(
        R"((password|passwd|passphrase|token|secret|authorization|cookie|private.key|script.content|proxy.username|username)\s*["']?\s*[:=]|--(password|proxy-password|token)\b|://[^/\s]*@)",
        std::regex::icase);
    std::istringstream input(text);
    std::string result, line;
    bool first = true;
    while (std::getline(input,line)) {
        if (!first) result += '\n';
        first = false;
        result += std::regex_search(line,credential) ? "[credential-bearing line redacted]" : line;
    }
    if (!text.empty() && text.back() == '\n') result += '\n';
    return result;
}
void export_diagnostic_archive(const std::filesystem::path& output, const DiagnosticCollection& options) {
#ifdef __linux__
    File file(open(output.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
    try {
        Collector(options,file.fd).collect();
        if (fsync(file.fd)) throw Error("cannot persist diagnostic archive");
    } catch (...) {
        unlink(output.c_str());
        throw;
    }
#else
    (void)output; (void)options;
    throw Error("diagnostic archive collection requires Linux");
#endif
}
}
