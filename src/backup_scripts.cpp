#include "opensabba/backup_scripts.hpp"
#include "opensabba/capture.hpp"
#include "opensabba/display.hpp"
#include <openssl/sha.h>
#include <algorithm>
#include <fstream>
#include <thread>
#include <ctime>
#include <climits>
#include <charconv>
#include <sstream>
#ifdef __linux__
#include <cerrno>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace opensabba {
using pstream::Value;
using pstream::Error;
namespace {
const Value::Object& object(const Value& value) { return std::get<Value::Object>(value.data); }
std::uint64_t number(const Value& value, const char* key) {
    return std::get<std::uint64_t>(object(value).at(key).data);
}
std::string text(const Value& value, const char* key) {
    return std::get<std::string>(object(value).at(key).data);
}
const char* side(bool pre) { return pre ? "pre" : "post"; }
void check_component(std::string_view value, bool empty) {
    if ((!empty && value.empty()) || value.size() > 128 ||
        value.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") != value.npos ||
        value == "." || value == "..")
        throw Error("invalid NAS script filename component");
}
Value definition(const BackupScript& script) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(script.content.data(),script.content.size(),hash);
    std::string digest;
    constexpr char hex[] = "0123456789abcdef";
    for (auto ch : hash) { digest += hex[ch >> 4]; digest += hex[ch & 15]; }
    return Value{Value::Object{{"enabled",Value{std::uint64_t{script.enabled}}},
        {"error",Value{script.error}},{"extension",Value{script.extension}},{"sha256",Value{digest}}}};
}
Value policy_identity(const BackupScripts& policy) {
    return Value{Value::Object{{"pre",definition(policy.pre)},{"post",definition(policy.post)},
        {"stop_on_failure",Value{std::uint64_t{policy.stop_on_failure}}}}};
}
void validate_result(const Value& result) {
    if (std::holds_alternative<std::monostate>(result.data)) return;
    const auto phase = text(result,"phase");
    if (phase == "intent") return;
    if (phase != "complete") throw Error("invalid backup script result phase");
    const auto exit = text(result,"exit_code");
    int code{};
    const auto [end,error] = std::from_chars(exit.data(),exit.data()+exit.size(),code);
    if (error != std::errc{} || end != exit.data()+exit.size() || code < -1 || code > 255)
        throw Error("invalid backup script exit code");
    for (auto key : {"cancelled","output","reported","output_uploaded"})
        if (number(result,key) > 1) throw Error("invalid backup script result flag");
    (void)number(result,"log_time");
    if (!number(result,"cancelled") && !number(result,"log_type"))
        throw Error("backup script result has no log type");
}
std::filesystem::path output_path(const std::filesystem::path& directory, bool pre, std::uint64_t run) {
    return directory/(std::string(side(pre))+std::to_string(run)+".log");
}
#ifdef __linux__
struct File {
    int fd;
    explicit File(int descriptor) : fd(descriptor) {
        if (fd < 0) throw Error("cannot access backup script storage");
    }
    ~File() { close(fd); }
};
void write_script(int dir, const std::string& name, const pstream::Bytes& content) {
    const auto temporary = name+".tmp";
    File file(openat(dir,temporary.c_str(),O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600));
    std::size_t at = 0;
    while (at < content.size()) {
        const auto count = write(file.fd,content.data()+at,content.size()-at);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw Error("cannot write backup script");
        at += static_cast<std::size_t>(count);
    }
    if (fsync(file.fd) || renameat(dir,temporary.c_str(),dir,name.c_str()) || fsync(dir))
        throw Error("cannot persist backup script");
}
void terminate_group(pid_t child) {
    // the official agent sends SIGTERM and makes five nonblocking waits before SIGKILL.
    kill(-child,SIGTERM);
    int status{};
    for (int attempt = 0; attempt < 5; ++attempt) {
        const auto observed = waitpid(child,&status,WNOHANG);
        if (observed == child || (observed < 0 && errno != EINTR)) return;
    }
    kill(-child,SIGKILL);
    while (waitpid(child,&status,0) < 0 && errno == EINTR) {}
}
#endif
}

Value::Object task_script_execution_policy(const Value& task) {
    const auto& source = object(task);
    const auto settings = source.find("pre_post_script_setting");
    if (settings == source.end()) return {};
    const auto& fields = object(settings->second);
    Value::Object result;
    for (auto prefix : {"pre","post"}) {
        const auto enabled = std::string(prefix)+"_script_enabled";
        if (!std::get<std::uint64_t>(fields.at(enabled).data)) continue;
        for (auto suffix : {"extension","error"}) {
            const auto key = std::string(prefix)+"_script_"+suffix;
            const auto found = fields.find(key);
            if (found == fields.end()) throw Error("NAS script policy is missing "+key);
            result.emplace(key,found->second);
        }
        const auto key = std::string(prefix)+"_script_content";
        if (!std::get<std::uint64_t>(fields.at(std::string(prefix)+"_script_error").data)) {
            const auto found = source.find(key);
            if (found == source.end() || !std::holds_alternative<pstream::Bytes>(found->second.data))
                throw Error("NAS script content must be a binary buffer");
            result.emplace(key,found->second);
        }
    }
    return result;
}
BackupScripts backup_scripts(const Value& task) {
    const auto& fields = object(task);
    BackupScripts policy;
    const auto mode = fields.find("script_exec_mode");
    policy.stop_on_failure = mode != fields.end() && std::get<std::uint64_t>(mode->second.data) == 1;
    for (bool pre : {true,false}) {
        auto& script = pre ? policy.pre : policy.post;
        const auto prefix = std::string(side(pre))+"_script_";
        const auto enabled = fields.find(prefix+"enabled");
        script.enabled = enabled != fields.end() && std::get<std::uint64_t>(enabled->second.data) != 0;
        if (!script.enabled) continue;
        const auto extension = fields.find(prefix+"extension"), error = fields.find(prefix+"error");
        if (extension == fields.end() || error == fields.end())
            throw Error("enabled NAS scripts require execution task discovery");
        script.extension = std::get<std::string>(extension->second.data);
        check_component(script.extension,true);
        script.error = std::get<std::uint64_t>(error->second.data);
        if (script.error) continue;
        const auto content = fields.find(prefix+"content");
        if (content == fields.end() || !std::holds_alternative<pstream::Bytes>(content->second.data))
            throw Error("NAS script content must be a binary buffer");
        script.content = std::get<pstream::Bytes>(content->second.data);
        if (script.content.size() > 32768) { script.error = 7055; script.content.clear(); }
    }
    return policy;
}
ScriptResult execute_backup_script(const BackupScript& script, bool pre, bool stop_on_failure,
    const std::filesystem::path& directory, std::uint64_t run,
    const std::function<bool()>& cancelled, std::chrono::milliseconds timeout) {
    ScriptResult result;
    if (!script.enabled) return result;
    if (script.error) { result.log_type = script.error; return result; }
    const auto base = std::uint64_t{pre ? 7045U : 7049U};
    result.log_type = base+(stop_on_failure ? 2 : 1);
#ifdef __linux__
    check_component(script.extension,true);
    if (script.content.size() > 32768) { result.log_type = 7055; return result; }
    std::error_code directory_error;
    std::filesystem::create_directories(directory,directory_error);
    if (directory_error) { result.log_type = 7053; return result; }
    const auto directory_fd = open(directory.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (directory_fd < 0) { result.log_type = 7053; return result; }
    File dir(directory_fd);
    const auto filename = std::string(side(pre))+script.extension;
    try { write_script(dir.fd,filename,script.content); }
    catch (const Error&) { result.log_type = 7053; return result; }
    const auto log = output_path(directory,pre,run);
    const auto temporary = log.string()+".tmp";
    const auto output_fd = open(temporary.c_str(),O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0644);
    if (output_fd < 0) { result.log_type = 7053; return result; }
    File output(output_fd);
    if (fchmod(output.fd,0644)) { result.log_type = 7053; return result; }
    const auto script_path = std::filesystem::absolute(directory/filename).string();
    int lifeline[2];
    if (socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,lifeline))
        throw Error("cannot create script parent-liveness channel");
    File parent_life(lifeline[0]), child_life(lifeline[1]);
    int gate[2];
    if (socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,gate))
        throw Error("cannot create script launch channel");
    File parent_gate(gate[0]), child_gate(gate[1]);
    const auto child = fork();
    if (child < 0) return result;
    if (!child) {
        close(parent_life.fd);
        close(child_life.fd);
        close(parent_gate.fd);
        setpgid(0,0);
        char start{};
        ssize_t count;
        do { count = recv(child_gate.fd,&start,1,0); } while (count < 0 && errno == EINTR);
        if (count != 1 || start != 'g') _exit(127);
        umask(0);
        if (fchdir(dir.fd) || dup2(output.fd,STDOUT_FILENO) < 0 || dup2(output.fd,STDERR_FILENO) < 0)
            _exit(127);
        if (syscall(SYS_close_range,3U,UINT_MAX,0U)) _exit(127);
        execl("/bin/sh","sh",script_path.c_str(),static_cast<char*>(nullptr));
        _exit(127);
    }
    setpgid(child,child);
    // The sibling watcher is outside the shell's child/job table. A script
    // using wait must not wait for the watcher that observes its own completion.
    const auto watcher = fork();
    if (watcher < 0) { terminate_group(child); return result; }
    if (!watcher) {
        close(parent_life.fd);
        if (setpgid(0,child)) _exit(127);
        syscall(SYS_close_range,0U,static_cast<unsigned>(child_life.fd-1),0U);
        syscall(SYS_close_range,static_cast<unsigned>(child_life.fd+1),UINT_MAX,0U);
        char complete{};
        ssize_t count;
        do { count = recv(child_life.fd,&complete,1,0); } while (count < 0 && errno == EINTR);
        if (count != 1 || complete != 'q') kill(-child,SIGKILL);
        _exit(0);
    }
    close(child_life.fd); child_life.fd = -1;
    close(child_gate.fd); child_gate.fd = -1;
    const char start = 'g';
    (void)send(parent_gate.fd,&start,1,MSG_NOSIGNAL);
    close(parent_gate.fd); parent_gate.fd = -1;
    const auto deadline = std::chrono::steady_clock::now()+timeout;
    int status{};
    for (;;) {
        const auto observed = waitpid(child,&status,WNOHANG);
        if (observed == child) {
            if (WIFEXITED(status)) result.exit_code = WEXITSTATUS(status);
            if (result.exit_code == 0) result.log_type = base;
            break;
        }
        if (observed < 0 && errno != EINTR) { terminate_group(child); break; }
        if (cancelled && cancelled()) {
            terminate_group(child);
            result.cancelled = true; result.log_type = 0;
            break;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            terminate_group(child);
            result.log_type = base+3;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    const char complete = 'q';
    (void)send(parent_life.fd,&complete,1,MSG_NOSIGNAL);
    int watcher_status{};
    while (waitpid(watcher,&watcher_status,0) < 0 && errno == EINTR) {}
    // The official agent wrapper observes service abort after execution, before output
    // publication and result reporting, even when the shell already exited.
    if (cancelled && cancelled()) {
        result.cancelled = true;
        result.log_type = 0;
    }
    if (result.cancelled) return result;
    if (fsync(output.fd) || rename(temporary.c_str(),log.c_str()) || fsync(dir.fd))
        throw Error("cannot persist script output");
    result.has_output = true;
    return result;
#else
    (void)directory; (void)run; (void)cancelled; (void)timeout;
    throw Error("backup script execution requires Linux");
#endif
}

Value new_script_run(const BackupScripts& scripts, std::uint64_t task, std::uint64_t run,
                     std::string_view task_uuid) {
    check_component(task_uuid,false);
    if (!task || !run) throw Error("backup scripts require task and run identities");
    Value::Object retained{{"script_exec_mode",Value{std::uint64_t{scripts.stop_on_failure}}}};
    for (bool pre : {true,false}) {
        const auto& script = pre ? scripts.pre : scripts.post;
        const auto prefix = std::string(side(pre))+"_script_";
        retained[prefix+"enabled"] = Value{std::uint64_t{script.enabled}};
        retained[prefix+"error"] = Value{script.error};
        retained[prefix+"extension"] = Value{script.extension};
        retained[prefix+"content"] = Value{script.content};
    }
    return Value{Value::Object{{"schema",Value{std::uint64_t{1}}},{"task_id",Value{task}},
        {"running_task_id",Value{run}},{"task_uuid",Value{std::string(task_uuid)}},
        {"policy",policy_identity(scripts)},{"scripts",Value{std::move(retained)}},
        {"pre",Value{}},{"post",Value{}}}};
}
BackupScripts retained_backup_scripts(const Value& journal) {
    check_component(text(journal,"task_uuid"),false);
    if (number(journal,"schema") != 1 || !number(journal,"task_id") || !number(journal,"running_task_id"))
        throw Error("invalid backup script run identity");
    validate_result(object(journal).at("pre"));
    validate_result(object(journal).at("post"));
    auto result = backup_scripts(object(journal).at("scripts"));
    if (policy_identity(result) != object(journal).at("policy"))
        throw Error("retained script settings differ from their recorded policy");
    return result;
}
void validate_script_run(const Value& journal, const BackupScripts& scripts, std::uint64_t task,
                         std::uint64_t run, std::string_view task_uuid) {
    if (number(journal,"schema") != 1 || number(journal,"task_id") != task ||
        number(journal,"running_task_id") != run || text(journal,"task_uuid") != task_uuid ||
        object(journal).at("policy") != policy_identity(scripts))
        throw Error("script journal differs from the queued task or script policy");
}
void run_backup_script_once(Value& journal, const BackupScripts& scripts, bool pre,
    const std::filesystem::path& directory, const SaveScriptRun& save,
    const std::function<bool()>& cancelled) {
    const auto& script = pre ? scripts.pre : scripts.post;
    if (!script.enabled) return;
    auto& entry = std::get<Value::Object>(journal.data).at(side(pre));
    if (!std::holds_alternative<std::monostate>(entry.data)) {
        validate_result(entry);
        if (text(entry,"phase") != "complete")
            throw Error("backup script execution is uncertain; retained intent must be reconciled");
    } else {
        entry = Value{Value::Object{{"phase",Value{std::string("intent")}}}};
        save(journal);
        const auto result = execute_backup_script(script,pre,scripts.stop_on_failure,directory,
            number(journal,"running_task_id"),cancelled);
        entry = Value{Value::Object{{"phase",Value{std::string("complete")}},
            {"log_type",Value{result.log_type}},{"exit_code",Value{std::to_string(result.exit_code)}},
            {"cancelled",Value{std::uint64_t{result.cancelled}}},
            {"output",Value{std::uint64_t{result.has_output}}},
            {"log_time",Value{server_time_now()}},
            {"reported",Value{std::uint64_t{0}}},{"output_uploaded",Value{std::uint64_t{0}}}}};
        save(journal);
    }
    if (number(entry,"cancelled")) throw Cancelled();
    const auto success = std::uint64_t{pre ? 7045U : 7049U};
    if (scripts.stop_on_failure && number(entry,"log_type") != success)
        throw BackupScriptFailed(std::string(side(pre))+" backup script failed");
}

void report_backup_scripts(const Endpoint& endpoint, const SavedAuth& auth, Value& journal,
    const std::filesystem::path& directory, std::uint64_t version, std::uint64_t result,
    const SaveScriptRun& save, std::span<const Value> capture_logs) {
    if (!result) return;
    (void)retained_backup_scripts(journal);
    for (bool pre : {true,false}) {
        if (!pre) report_capture_activity(endpoint,auth,journal,capture_logs,result,save);
        auto& entry = std::get<Value::Object>(journal.data).at(side(pre));
        if (std::holds_alternative<std::monostate>(entry.data) || text(entry,"phase") != "complete" ||
            number(entry,"cancelled")) continue;
        if (!number(entry,"reported")) {
            const auto run = number(journal,"running_task_id"), task = number(journal,"task_id");
            const auto parameters = "{\"id\":"+std::to_string(run)+",\"running_task_id\":"+
                std::to_string(run)+",\"task_id\":"+std::to_string(task)+",\"task_uuid\":\""+
                text(journal,"task_uuid")+"\",\"result_id\":"+std::to_string(result)+
                ",\"version_id\":"+std::to_string(version)+",\"exit_code\":"+text(entry,"exit_code")+"}";
            try { report_script_activity(endpoint,auth,run,number(entry,"log_type"),number(entry,"log_time"),parameters); }
            catch (const TransportError& error) {
                std::get<Value::Object>(entry.data)["report_error"] = Value{std::string(error.what())};
                save(journal); return; // Retain reporting work for the next service pass.
            }
            catch (const ServerError& error) {
                std::get<Value::Object>(entry.data)["report_error"] = Value{std::string(error.what())};
                save(journal); return;
            }
            std::get<Value::Object>(entry.data)["reported"] = Value{std::uint64_t{1}};
            save(journal);
        }
        if (number(entry,"output") && !number(entry,"output_uploaded")) {
            try {
                std::ifstream input(output_path(directory,pre,number(journal,"running_task_id")),std::ios::binary);
                if (!input) throw Error("cannot read retained script output");
                pstream::Bytes output{std::istreambuf_iterator<char>(input),std::istreambuf_iterator<char>()};
                if (input.bad()) throw Error("cannot read retained script output");
                upload_script_output(endpoint,auth,number(journal,"task_id"),version,pre,output);
            } catch (const Cancelled&) { throw; }
            catch (const TransportError& error) {
                std::get<Value::Object>(entry.data)["report_error"] = Value{std::string(error.what())};
                save(journal); return;
            } catch (const Error& error) {
                std::get<Value::Object>(entry.data)["report_error"] = Value{std::string(error.what())};
                save(journal);
                try { report_script_upload_error(endpoint,auth,server_time_now()); }
                catch (const Cancelled&) { throw; }
                catch (const Error& activity_error) {
                    std::get<Value::Object>(entry.data)["report_error"] = Value{std::string(activity_error.what())};
                    save(journal);
                }
                return;
            }
            std::get<Value::Object>(entry.data)["output_uploaded"] = Value{std::uint64_t{1}};
            save(journal);
        }
    }
}
bool backup_scripts_failed(const Value& journal) {
    const auto policy = retained_backup_scripts(journal);
    if (!policy.stop_on_failure) return false;
    for (bool pre : {true,false}) {
        const auto& entry = object(journal).at(side(pre));
        if (!std::holds_alternative<std::monostate>(entry.data) &&
            text(entry,"phase") == "complete" && !number(entry,"cancelled") &&
            number(entry,"log_type") != (pre ? 7045U : 7049U)) return true;
    }
    return false;
}
void report_capture_activity(const Endpoint& endpoint, const SavedAuth& auth, Value& journal,
    std::span<const Value> logs, std::uint64_t result, const SaveScriptRun& save) {
    if (!result) return; // A queued run has no NAS result to own these logs yet.
    auto& fields = std::get<Value::Object>(journal.data);
    auto reported = fields.contains("capture_logs_reported") ? number(journal,"capture_logs_reported") : 0;
    if (reported > logs.size()) throw Error("invalid capture log checkpoint");
    while (reported < logs.size()) {
        const auto& log = logs[reported];
        auto parameters = object(log).at("parameters");
        auto& values = std::get<Value::Object>(parameters.data);
        for (auto key : {"running_task_id","task_id","task_uuid"})
            values[key] = fields.at(key);
        values["result_id"] = Value{result};
        values["id"] = fields.at("running_task_id");
        std::ostringstream json;
        print_json(json,parameters);
        report_script_activity(endpoint,auth,number(journal,"running_task_id"),
            number(log,"log_type"),number(log,"log_time"),json.str());
        fields["capture_logs_reported"] = Value{++reported};
        save(journal);
    }
}

bool finish_failed_backup(const Endpoint& endpoint, const SavedAuth& auth, Value& journal,
    const std::filesystem::path& directory, const SaveScriptRun& save) {
    (void)retained_backup_scripts(journal);
    auto& fields = std::get<Value::Object>(journal.data);
    const bool capture_failed = fields.contains("capture_failure");
    const bool script_failed = backup_scripts_failed(journal);
    const bool published_script_failure = capture_failed && script_failed &&
        capture_journal_from_value(fields.at("capture_failure")).phase == CapturePhase::ready;
    if ((capture_failed && !published_script_failure &&
            !capture_failure_reportable(capture_journal_from_value(fields.at("capture_failure")))) ||
        (!capture_failed && !script_failed))
        throw Error("backup run has no definitive preparation failure");
    auto phase = fields.contains("nas_phase") ? text(journal,"nas_phase") : std::string{};
    auto persist = [&](const char* state) {
        fields["nas_phase"] = Value{std::string(state)}; save(journal); phase = state;
    };
    if (phase == "terminal" && text(journal,"nas_outcome") == "unknown") return true;
    if (phase == "prepare-intent") {
        const auto event = backup_event_state(endpoint,auth,number(journal,"task_id"),
            number(journal,"running_task_id"));
        if (!event) {
            fields["nas_outcome"] = Value{std::string("unknown")};
            fields["version_id"] = Value{std::uint64_t{0}};
            fields["result_id"] = Value{std::uint64_t{0}};
            fields["data_format"] = Value{std::uint64_t{0}};
            persist("terminal");
            return true; // Event retirement does not invent a NAS result.
        }
        if (event->worker_active) throw BackupRetry("failed backup preparation is awaiting the NAS worker");
        if (event->run.version_id && event->run.result_id) {
            fields["version_id"] = Value{event->run.version_id};
            fields["result_id"] = Value{event->run.result_id};
            fields["data_format"] = Value{event->run.data_format};
            persist("prepared");
        } else phase.clear(); // The exact event is still unprepared.
    }
    if (phase.empty()) {
        const auto run = prepare_full_backup(endpoint,auth,number(journal,"running_task_id"),
            [&] { persist("prepare-intent"); });
        fields["version_id"] = Value{run.version_id};
        fields["result_id"] = Value{run.result_id};
        fields["data_format"] = Value{run.data_format};
        persist("prepared");
    }
    const auto capture_logs = capture_failed ?
        capture_journal_from_value(fields.at("capture_failure")).logs : Value::Array{};
    report_backup_scripts(endpoint,auth,journal,directory,number(journal,"version_id"),
        number(journal,"result_id"),save,capture_logs);
    if (fields.contains("snapshot_missing")) {
        auto& missing = fields.at("snapshot_missing");
        if (!number(missing,"reported")) {
            std::ostringstream parameters;
            print_json(parameters,Value{Value::Object{{"id",fields.at("running_task_id")},
                {"running_task_id",fields.at("running_task_id")},{"task_id",fields.at("task_id")},
                {"task_uuid",fields.at("task_uuid")},{"result_id",fields.at("result_id")},
                {"volume_name",object(missing).at("volume_name")}}});
            report_script_activity(endpoint,auth,number(journal,"running_task_id"),7021,
                number(missing,"log_time"),parameters.str());
            std::get<Value::Object>(missing.data)["reported"] = Value{std::uint64_t{1}};
            save(journal);
        }
    }
    bool reports_complete = true;
    for (auto side : {"pre","post"}) {
        const auto& entry = fields.at(side);
        if (!std::holds_alternative<std::monostate>(entry.data) && text(entry,"phase") == "complete" &&
            !number(entry,"cancelled") &&
            (!number(entry,"reported") || (number(entry,"output") && !number(entry,"output_uploaded"))))
            reports_complete = false;
    }
    if (phase == "terminal") return reports_complete;
    if (phase == "finish-intent") {
        const auto outcome = backup_result(endpoint,auth,number(journal,"task_id"),number(journal,"result_id"));
        if (outcome != "incomplete") {
            fields["nas_outcome"] = Value{outcome};
            persist("terminal");
            return reports_complete;
        }
        // the official agent re-enters check_complete for the same event after disconnect.
        // A terminal NAS result above suppresses a duplicate completion.
        phase = "prepared";
    }
    if (phase != "prepared") throw Error("invalid failed backup phase");
    const BackupRun run{number(journal,"running_task_id"),number(journal,"version_id"),
        number(journal,"result_id"),number(journal,"data_format")};
    const auto outcome = finish_backup(endpoint,auth,run,BackupOutcome::error,
        [&] { persist("finish-intent"); });
    fields["nas_outcome"] = Value{std::string(outcome == BackupOutcome::error ? "error" :
        outcome == BackupOutcome::cancelled ? "cancel" : outcome == BackupOutcome::partial ? "partial" : "complete")};
    persist("terminal");
    return reports_complete;
}
}
