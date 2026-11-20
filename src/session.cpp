#include "opensabba/session.hpp"
#include "session_runtime.hpp"
#include "opensabba/registration.hpp"
#include "opensabba/service_process.hpp"
#include "opensabba/display.hpp"
#include "opensabba/events.hpp"
#include "opensabba/service_observations.hpp"
#include "opensabba/backup_job.hpp"
#include "opensabba/service_backup.hpp"
#include "opensabba/file_restore_job.hpp"
#include "opensabba/job_recovery.hpp"
#include "opensabba/snapshot.hpp"
#include "opensabba/machine_capture.hpp"
#include "opensabba/machine_snapshot.hpp"
#include "opensabba/service_machine_capture.hpp"
#include "opensabba/machine_tracking.hpp"
#include "opensabba/machine.hpp"
#include "opensabba/task_policy.hpp"
#include "opensabba/backup_scripts.hpp"
#include "opensabba/volume_nodes.hpp"
#include "opensabba/diagnostics.hpp"
#include "opensabba/log_export.hpp"
#include "opensabba/historical_logs.hpp"
#include "opensabba/certificate_trust.hpp"
#include "opensabba/cli.hpp"
#include "opensabba/agent_config.hpp"
#include "opensabba/backup_cache.hpp"
#include "opensabba/task_schedule.hpp"
#include "opensabba/device_info.hpp"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <charconv>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <utility>
#include <atomic>
#include <csignal>
#include <future>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>
#include "opensabba/snapshot_driver.hpp"
#include "opensabba/cow_index.hpp"
#include "opensabba/delta_plan.hpp"

#ifndef _WIN32
#include <cerrno>
#include <fcntl.h>
#include <dirent.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace opensabba {
using pstream::Error;
using pstream::Value;
using namespace session_detail;
#ifdef _WIN32
void load_saved_server_time() {}
int session_command(int, char**,const SessionInvocation&) {
    throw Error("saved-session commands currently require Linux; run this command on the Pi");
}
Endpoint saved_endpoint() {
    throw Error("saved-session commands currently require Linux");
}
int export_logs_command(const std::filesystem::path&, bool) {
    throw Error("diagnostic archive collection requires Linux");
}
#else
namespace {
} // namespace
void refresh_server_time(Store& store, const Endpoint& endpoint, const SavedAuth& auth) {
    try {
        const auto updated = get_server_time(endpoint,auth);
        const auto previous = store.read("server-time.pstream");
        if (!previous || server_time_from_value(*previous) != updated)
            store.write("server-time.pstream",server_time_value(updated));
        set_server_time(updated);
    } catch (const Cancelled&) { throw; }
    catch (const ServerError& error) {
        std::cerr << "get timezone failed (" << error.code.value_or(0)
                  << ": '" << error.server_message << "')\n";
    }
    catch (const std::exception& error) {
        std::cerr << "Server time refresh failed: " << error.what() << '\n';
    }
}

namespace {
int export_log_archive(const std::filesystem::path& destination, bool quiet) {
    std::optional<Store> store;
    if (std::filesystem::symlink_status(storage_path(false)).type() != std::filesystem::file_type::not_found)
        store.emplace(false,false);
    auto report = diagnostic_report([&](const char* name) -> std::optional<Value> {
        return store ? store->read(name,backup_limits) : std::optional<Value>{};
    });
    auto& object = std::get<Value::Object>(report.data);
    object.emplace("client_version",Value{std::string(OPENSABBA_VERSION)});
    object.emplace("generated_at_unix",Value{static_cast<std::uint64_t>(std::time(nullptr))});
    struct utsname system{};
    if (uname(&system) != 0) throw Error("cannot read kernel version for diagnostics");
    object.emplace("kernel_release",Value{std::string(system.release)});
    object.emplace("architecture",Value{std::string(system.machine)});
    std::ostringstream json;
    print_json(json,report);
    json << '\n';
    DiagnosticCollection collection;
    collection.journal_summary = json.str();
    collection.log_directory = storage_path(false)/"log";
    // Saved credentials and identities can appear in unrelated system logs.
    // Collect all string/buffer leaves from these private objects for scrubbing,
    // without exporting the objects themselves or their exception messages.
    std::function<void(const Value&)> secrets = [&](const Value& value) {
        if (const auto* text = std::get_if<std::string>(&value.data)) {
            if (!text->empty()) collection.secrets.push_back(*text);
        } else if (const auto* bytes = std::get_if<pstream::Bytes>(&value.data)) {
            if (!bytes->empty()) collection.secrets.emplace_back(bytes->begin(),bytes->end());
        } else if (const auto* entries = std::get_if<Value::Object>(&value.data)) {
            for (const auto& [key,entry] : *entries) { (void)key; secrets(entry); }
        } else if (const auto* entries = std::get_if<Value::Array>(&value.data)) {
            for (const auto& entry : *entries) secrets(entry);
        }
    };
    if (store) for (const auto* name : {"session.pstream","identity.pstream"}) {
        try { if (auto value = store->read(name,backup_limits)) secrets(*value); }
        catch (const Error&) { throw Error("cannot safely redact credentials from unreadable saved identity"); }
    }
    const auto output = destination.empty() ? default_log_archive() : destination;
    export_diagnostic_archive(output,collection);
    if (!quiet) std::cout << "Diagnostic logs exported to " << output.string() << '\n';
    return 0;
}

std::string script_run_name(std::uint64_t run) {
    return "backup-scripts-"+std::to_string(run)+".pstream";
}
void record_backup_start(const Value& event) {
    const Value empty{Value::Object{}};
    const auto& task = fields(event).contains("backup_task") ? field(event,"backup_task") : empty;
    // Task decoding uses zero/empty values for absent event members.
    const auto trigger = [&](const char* key) {
        return fields(task).contains(key) ? number(task,key) : std::uint64_t{0};
    };
    historical_backup_start(storage_path(false),
        fields(task).contains("task_name") ? text(task,"task_name",true) : std::string{},
        trigger("trigger_type"),trigger("trigger_event"));
}
std::filesystem::path script_directory(const Value& journal) {
    return storage_path(false)/"script"/text(journal,"task_uuid");
}
void validate_script_owner(const Value& journal, const Value& identity) {
    for (auto key : {"ds_id","device_uuid","username"})
        if (field(journal,key) != field(identity,key))
            throw Error("backup script journal belongs to another NAS, device or account");
}
void publish_script_reports(Store& store, const Endpoint& endpoint, const SavedAuth& auth,
                            const Value& backup) {
    if (!fields(backup).contains("script_run_id") || !fields(backup).contains("result_id")) return;
    const auto filename = script_run_name(number(backup,"script_run_id"));
    auto journal = store.read(filename.c_str());
    if (!journal) throw Error("backup script journal is missing");
    validate_script_owner(*journal,backup);
    (void)retained_backup_scripts(*journal);
    if (number(*journal,"running_task_id") != number(backup,"running_task_id") ||
        number(*journal,"task_id") != number(backup,"task_id") ||
        field(*journal,"policy") != field(backup,"script_policy") ||
        text(*journal,"capture_id") != text(field(backup,"source_capture"),"id"))
        throw Error("backup script policy differs from its prepared journal");
    const auto capture = capture_journal_from_value(field(backup,"source_capture"));
    report_backup_scripts(endpoint,auth,*journal,script_directory(*journal),
        number(backup,"version_id"),number(backup,"result_id"),
        [&](const Value& saved) { store.write(filename.c_str(),saved); },capture.logs);
    for (auto side : {"pre","post"}) {
        const auto& entry = field(*journal,side);
        if (!std::holds_alternative<std::monostate>(entry.data) &&
            fields(entry).contains("report_error") &&
            (!number(entry,"reported") || (number(entry,"output") && !number(entry,"output_uploaded"))))
            std::cerr << "Script reporting retained for retry: " << text(entry,"report_error") << '\n';
    }
}
void configure_certificate_trust(Endpoint&, bool interactive = false, bool quiet = false);
} // namespace
Endpoint endpoint_from(const Value& session) {
    if (number(session, "format") != 2)
        throw Error("saved session lacks registration metadata; run --connect --address HOST --username USER again");
    Endpoint endpoint;
    endpoint.host = text(session, "host");
    const auto port = number(session, "port");
    if (port == 0 || port > 65535) throw Error("invalid saved port");
    endpoint.port = static_cast<std::uint16_t>(port);
    endpoint.ca_file = text(session, "ca_file", true);
    if (fields(session).contains("proxy_host")) {
        endpoint.proxy_host = text(session, "proxy_host");
        const auto proxy_port = number(session, "proxy_port");
        if (!proxy_port || proxy_port > 65535) throw Error("invalid saved proxy port");
        endpoint.proxy_port = static_cast<std::uint16_t>(proxy_port);
    }
    if (fields(session).contains("proxy_username")) {
        ProxyCredentials proxy{text(session,"proxy_username"), text(session,"proxy_password",true)};
        proxy.scheme = fields(session).contains("proxy_auth") ? text(session,"proxy_auth") : "basic";
        if (proxy.scheme != "basic" && proxy.scheme != "ntlm")
            throw Error("invalid saved proxy authentication scheme");
        if (proxy.scheme == "ntlm") {
            proxy.domain = text(session,"proxy_domain",true);
            proxy.workstation = text(session,"proxy_workstation",true);
            const auto version = number(session,"proxy_ntlm_version");
            if (version != 1 && version != 2)
                throw Error("invalid saved NTLM version");
            proxy.ntlm_version = static_cast<unsigned>(version);
        }
        endpoint.proxy_credentials = std::move(proxy);
    }
    configure_certificate_trust(endpoint);
    return endpoint;
}

namespace {
// Read from the controlling terminal, never stdin or argv. Disabling ISIG
// makes Ctrl-C an ordinary byte so RAII restores echo before cancellation.
std::string terminal_secret(const char* prompt, bool allow_empty) {
    File terminal(open("/dev/tty", O_RDWR | O_CLOEXEC));
    termios previous{};
    if (tcgetattr(terminal.fd, &previous) != 0) throw Error("an interactive terminal is required");
    termios hidden = previous;
    hidden.c_lflag &= static_cast<tcflag_t>(~(ECHO | ICANON | ISIG));
    hidden.c_cc[VMIN] = 1;
    hidden.c_cc[VTIME] = 0;
    if (tcsetattr(terminal.fd, TCSAFLUSH, &hidden) != 0)
        throw Error("cannot disable terminal echo");
    struct Restore {
        int fd;
        termios previous;
        ~Restore() { tcsetattr(fd, TCSAFLUSH, &previous); }
    } restore{terminal.fd, previous};
    std::cerr << prompt << std::flush;
    std::string result;
    for (;;) {
        char ch;
        auto count = ::read(terminal.fd, &ch, 1);
        if (count < 0 && errno == EINTR) continue;
        if (count != 1 || ch == 3 || ch == 4) {
            OPENSSL_cleanse(result.data(), result.size());
            std::cerr << '\n';
            throw Error("login cancelled");
        }
        if (ch == '\n' || ch == '\r') break;
        if (ch == 127 || ch == '\b') {
            if (!result.empty()) { result.back() = '\0'; result.pop_back(); }
        } else {
            if (result.size() >= 4096) {
                OPENSSL_cleanse(result.data(), result.size());
                throw Error("credential exceeds size limit");
            }
            result += ch;
        }
    }
    std::cerr << '\n';
    if (!allow_empty && result.empty()) throw Error("password cannot be empty");
    return result;
}

std::string secret(const char* prompt, bool allow_empty) {
    try {
        return terminal_secret(prompt, allow_empty);
    } catch (const Error& error) {
        throw CliError(7, error.what());
    }
}

bool terminal_confirmation(const char* question) {
    for (;;) {
        auto answer = secret(question,true);
        std::transform(answer.begin(),answer.end(),answer.begin(),[](unsigned char ch) {
            return ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch-'A'+'a') : static_cast<char>(ch);
        });
        if (answer.empty() || answer == "y" || answer == "yes") return true;
        if (answer == "n" || answer == "no") return false;
    }
}

void configure_certificate_trust(Endpoint& endpoint, bool interactive, bool quiet) {
    const auto key = endpoint.host + ":" + std::to_string(endpoint.port);
    std::function<bool(const ServerCertificate&, bool)> prompt;
    if (interactive) {
        prompt = [](const ServerCertificate& certificate, bool changed) {
            std::cerr << "Subject: " << safe_display(certificate.subject)
                      << "\nIssuer: " << safe_display(certificate.issuer)
                      << "\nSHA-256: " << certificate.sha256
                      << "\nVerification: " << safe_display(certificate.verification_error) << '\n';
            const char* question = changed
                ? "The SSL certificate has been changed. This may mean that the server's certificate has been changed, or someone may be trying to intercept your connection. Proceed anyway? (y/n, default y): "
                : "The SSL certificate of the Synology NAS is not trusted. This may mean that it is a self-signed certificate, or someone may be trying to intercept your connection.Proceed anyway? (y/n, default y): ";
            return terminal_confirmation(question);
        };
    }
    auto verifier = certificate_verifier(
        [key]() -> std::optional<std::string> {
            Store store(false);
            auto certificates = store.read("certificates.pstream");
            if (!certificates || !fields(*certificates).contains(key)) return {};
            return text(field(*certificates, key.c_str()), "sha256",true);
        },
        [key](const std::string& fingerprint) {
            Store store(false);
            auto certificates = store.read("certificates.pstream");
            if (!certificates) certificates = Value{Value::Object{}};
            std::get<Value::Object>(certificates->data)[key] =
                Value{Value::Object{{"sha256", Value{fingerprint}}}};
            store.write("certificates.pstream", *certificates);
        }, std::move(prompt), quiet);
    endpoint.trust_certificate = [key, verifier = std::move(verifier)](const ServerCertificate& certificate) {
        if (verifier(certificate)) return true;
        Store store(false);
        const auto certificates = store.read("certificates.pstream");
        throw CertificateError(certificates && fields(*certificates).contains(key));
    };
}

unsigned option_number(const char* value, unsigned maximum) {
    std::string_view input(value);
    unsigned result{};
    auto [end, error] = std::from_chars(input.data(), input.data() + input.size(), result);
    if (error != std::errc{} || end != input.data() + input.size() || result == 0 || result > maximum)
        throw Error("invalid numeric option");
    return result;
}

} // namespace
DeviceMetadata device_metadata() {
    utsname system{};
    if (uname(&system) != 0) throw Error("cannot query device information");
    // Matches the official agent Linux helper: interpret UTC broken-down time as local
    // time with tm_isdst=0, then subtract. Wire assignment sign-extends int32.
    const auto now = std::time(nullptr);
    std::tm utc{};
    if (!gmtime_r(&now, &utc)) throw Error("cannot determine timezone");
    const auto interpreted = std::mktime(&utc);
    const auto offset = static_cast<std::int64_t>(now) - static_cast<std::int64_t>(interpreted);
    if (offset < -86400 || offset > 86400) throw Error("unsupported timezone offset");
    return {system.nodename, linux_os_name("/etc", system.machine, system.release),
            system.release, static_cast<std::int32_t>(offset)};
}

namespace {
void complete_connection(Store& store, Value& session, const Endpoint& endpoint, bool quiet,
                         const Value& display) {
    if (!quiet) {
        show_connection_template(std::cout,display);
        if (!confirm_connection_template(std::cin,std::cout)) {
            // CLI cancel_auth -> daemon unlinks the temporary
            // connection and clears local connection/token even on NAS failure.
            try { unlink_connection(endpoint,auth_from(session)); }
            catch (const Error&) {} // the official agent logs NAS unlink errors in the daemon.
            store.logout();
            std::cout << "Cancel login\n"; // String ID51, CLI.
            return;
        }
    }
    const auto& task = field(session,"task_template");
    const Registration selection{number(session,"backup_type"),
        std::holds_alternative<std::monostate>(task.data) ? 0 : number(task,"id"),"backup"};
    if (!quiet) std::cout << "Confirming authentication...\n"; // ID54.
    confirm_registration(endpoint,auth_from(session),device_metadata(),selection,[&] {
        set(session,"registration_state",Value{std::string("uncertain")});
        set(session,"connect_type",Value{std::string("backup")});
        store.write("session.pstream",session);
    });
    set(session,"registration_state",Value{std::string("confirmed")});
    store.write("session.pstream",session);
    if (!quiet) std::cout << "Successfully connected\n"; // ID56.
}
struct ControlAddress {
    sockaddr_un address{};
    socklen_t length;
    explicit ControlAddress(const Store& store) {
        const auto name = store.control_name();
        address.sun_family = AF_UNIX;
        if (name.size()+1 > sizeof(address.sun_path)) throw Error("service control address is too long");
        std::memcpy(address.sun_path+1,name.data(),name.size());
        length = static_cast<socklen_t>(offsetof(sockaddr_un,sun_path)+1+name.size());
    }
};
bool control_peer(int fd) {
    ucred peer{};
    socklen_t length = sizeof(peer);
    return getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&length) == 0 && peer.uid == getuid();
}
constexpr auto connection_keys = {"host", "port", "ca_file", "username", "proxy_host",
    "proxy_port", "proxy_username", "proxy_password", "proxy_auth", "proxy_domain",
    "proxy_workstation", "proxy_ntlm_version"};
Value connection_settings(const Value& session) {
    Value::Object settings;
    for (const auto key : connection_keys)
        if (fields(session).contains(key)) settings.emplace(key,field(session,key));
    return Value{std::move(settings)};
}
void edit_connection(Store& store, Value& session, const Value& settings) {
    if (text(settings,"username") != text(session,"username"))
        throw CliError(11,"Usernames of config and connection are different");
    auto updated = session;
    auto& object = std::get<Value::Object>(updated.data);
    for (const auto key : connection_keys) object.erase(key);
    for (const auto& [key,value] : fields(settings)) {
        if (std::find(connection_keys.begin(),connection_keys.end(),key) == connection_keys.end())
            throw Error("invalid connection setting");
        object.emplace(key,value);
    }
    const auto endpoint = endpoint_from(updated);
    if (text(probe(endpoint),"ds_id") != text(session,"ds_id"))
        throw Error("server identity (ds_id) differs from the saved session; connection not edited");
    store.write("session.pstream",updated);
    session = std::move(updated);
}
std::string cache_task_name(std::uint64_t task) {
    return "service-cache-task-"+std::to_string(task)+".pstream";
}
std::string cache_event_name(std::uint64_t task) {
    return "service-cache-event-task-"+std::to_string(task)+".pstream";
}
void validate_machine_task_owner(const Value&,const SavedAuth&);
class ServiceControl {
    File socket_;
    struct Edit {
        Value settings;
        std::promise<std::string> result;
    };
    std::mutex mutex_;
    std::mutex authentication_mutex_;
    std::shared_ptr<Edit> edit_;
    struct GeneratedEvent {
        Value request;
        std::promise<std::string> result;
    };
    std::shared_ptr<GeneratedEvent> generated_;
    std::atomic_bool generated_pending_{false};
    std::string authorization_;
    std::optional<SavedAuth> authorized_identity_;
    std::shared_ptr<ServiceStatus> status_;
    Value status_connection_;
    std::jthread listener_;
public:
    void publish_connection(const Value& session) {
        std::lock_guard lock(mutex_);
        status_connection_ = session;
    }
    bool event_pending() const { return generated_pending_.load(); }
    void apply_generated_event(Store& store, const SavedAuth& auth) {
        std::shared_ptr<GeneratedEvent> generated;
        {
            std::lock_guard lock(mutex_);
            generated = std::exchange(generated_,{});
            generated_pending_ = false;
        }
        if (!generated) return;
        try {
            const auto task = number(generated->request,"task_id");
            const auto policy = store.read(cache_task_name(task).c_str(),backup_limits);
            if (!policy) throw Error("no assigned backup cache policy");
            const auto& owner = field(*policy,"task_owner");
            validate_machine_task_owner(owner,auth);
            const auto normalized = backup_cache_write_event(generated->request,owner,*policy,
                random_hex(16),static_cast<std::uint64_t>(std::time(nullptr)));
            auto event = store.read(cache_event_name(task).c_str(),backup_limits);
            if (event) {
                if (backup_cache_write_event(*event,owner,*policy,text(*event,"event_id"),
                    number(*event,"due")) != *event)
                    throw Error("queued local cache event differs from its assigned policy");
            } else {
                event = normalized;
                store.write(cache_event_name(task).c_str(),*event,backup_limits);
            }
            generated->result.set_value("accepted:"+text(*event,"event_id"));
        } catch (const std::exception& error) {
            generated->result.set_value("error:"+std::string(error.what()));
        }
    }
    template<class Operation> auto authenticate(Operation operation) {
        std::lock_guard lock(authentication_mutex_);
        return operation();
    }
    void apply_edit(Store& store, Value& session) {
        std::shared_ptr<Edit> edit;
        {
            std::lock_guard lock(mutex_);
            edit = std::exchange(edit_,{});
        }
        if (!edit) return;
        try {
            authenticate([&] { edit_connection(store,session,edit->settings); });
            publish_connection(session);
            edit->result.set_value("edited");
        } catch (const std::exception& error) {
            edit->result.set_value("error:" + std::string(error.what()));
        }
    }
    explicit ServiceControl(Store& store, Value& session, std::shared_ptr<ServiceStatus> status) :
        socket_(socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0)), status_(std::move(status)),
        status_connection_(session) {
        const ControlAddress address(store);
        if (bind(socket_.fd,reinterpret_cast<const sockaddr*>(&address.address),address.length) ||
            listen(socket_.fd,4)) throw Error("cannot start service control socket");
        listener_ = std::jthread([this,&session](std::stop_token stop) {
            while (!stop.stop_requested()) {
                pollfd incoming{socket_.fd,POLLIN,0};
                if (poll(&incoming,1,100) <= 0) continue;
                const int fd = accept4(socket_.fd,nullptr,nullptr,SOCK_CLOEXEC|SOCK_NONBLOCK);
                if (fd < 0) continue;
                File peer(fd);
                if (!control_peer(peer.fd)) continue;
                pollfd request{peer.fd,POLLIN,0};
                if (poll(&request,1,1000) <= 0) continue;
                char bytes[65536];
                struct Wipe {
                    char* bytes;
                    ~Wipe() { OPENSSL_cleanse(bytes,65536); }
                } wipe{bytes};
                const auto count = recv(peer.fd,bytes,sizeof(bytes),0);
                if ((count == 10 && std::string_view(bytes,10) == "get_status") ||
                    (count == 22 && std::string_view(bytes,22) == "get_status_skip_portal")) {
                    auto response = status_->snapshot();
                    const auto connection = [&] {
                        // Connection-state lookup copies under its own short
                        // lock. Token authentication may be waiting on the NAS.
                        std::lock_guard lock(mutex_);
                        set(response,"connection",Value{Value::Object{
                            {"address",field(status_connection_,"host")},
                            {"username",field(status_connection_,"username")}}});
                        return std::pair{endpoint_from(status_connection_),auth_from(status_connection_)};
                    }();
                    if (count == 10 && (number(response,"status")&0xf000) != 0x1000) {
                        auto endpoint = connection.first;
                        // Portal-link lookup uses request handling(...,10).
                        endpoint.timeout = std::chrono::seconds{10};
                        endpoint.cancelled = [&] { return stop.stop_requested() || service_stop; };
                        try {
                            if (const auto url = portal_link(endpoint,connection.second))
                                set(response,"url",Value{*url});
                        }
                        catch (const std::exception&) {
                            set(response,"error",Value{Value::Object{{"code",Value{std::uint64_t{53248}}}}});
                        }
                    }
                    const auto encoded = pstream::encode(response);
                    (void)send(peer.fd,encoded.data(),encoded.size(),MSG_NOSIGNAL);
                    continue;
                }
                if (count > 5 && std::string_view(bytes,5) == "auth:") {
                    std::string response;
                    try {
                        auto request = pstream::decode(pstream::Bytes(bytes+5,bytes+count),{65531,4096,16});
                        (void)fields(request);
                        struct WipeCredentials {
                            Value& request;
                            ~WipeCredentials() {
                                for (auto& [key,value] : std::get<Value::Object>(request.data))
                                    if ((key == "password" || key == "otp") && std::holds_alternative<std::string>(value.data)) {
                                        auto& secret = std::get<std::string>(value.data);
                                        OPENSSL_cleanse(secret.data(),secret.size());
                                    }
                            }
                        } wipe_credentials{request};
                        authenticate([&] {
                            authorization_.clear();
                            authorized_identity_.reset();
                            LoginCredentials admin;
                            admin.username = text(request,"username");
                            admin.password = text(request,"password");
                            admin.otp = text(request,"otp",true);
                            struct WipeAdmin {
                                LoginCredentials& admin;
                                ~WipeAdmin() {
                                    OPENSSL_cleanse(admin.password.data(),admin.password.size());
                                    OPENSSL_cleanse(admin.otp.data(),admin.otp.size());
                                }
                            } wipe_admin{admin};
                            auto endpoint = endpoint_from(session);
                            endpoint.cancelled = [&] { return stop.stop_requested() || service_stop; };
                            const auto auth = auth_from(session);
                            authorize_logout(endpoint,auth,admin);
                            authorization_ = random_hex(16);
                            authorized_identity_ = auth;
                            response = "authorized:" + authorization_;
                        });
                    } catch (const ServerError& error) {
                        response = error.code ? "server-error:" + std::to_string(*error.code) :
                            "error:" + std::string(error.what());
                    } catch (const std::exception& error) {
                        response = "error:" + std::string(error.what());
                    }
                    (void)send(peer.fd,response.data(),response.size(),MSG_NOSIGNAL);
                    continue;
                } else if (count > 5 && std::string_view(bytes,5) == "stop:") {
                    const auto supplied = std::string_view(bytes+5,static_cast<std::size_t>(count)-5);
                    const bool authorized = authenticate([&] {
                        const auto auth = auth_from(session);
                        const bool matches = !authorization_.empty() && supplied == authorization_ &&
                            authorized_identity_->username == auth.username &&
                            authorized_identity_->device_uuid == auth.device_uuid &&
                            authorized_identity_->ds_id == auth.ds_id;
                        authorization_.clear();
                        authorized_identity_.reset();
                        return matches;
                    });
                    if (!authorized) continue;
                    service_stop = true;
                }
                else if (count > 15 && std::string_view(bytes,15) == "generate_event:") {
                    try {
                        auto generated = std::make_shared<GeneratedEvent>();
                        generated->request = pstream::decode(pstream::Bytes(bytes+15,bytes+count),{65521,4096,16});
                        auto result = generated->result.get_future();
                        {
                            std::lock_guard lock(mutex_);
                            generated_ = generated;
                            generated_pending_ = true;
                        }
                        // Accepted means durable local queue publication. Do
                        // not cancel a current snapshot/transfer to accept it.
                        while (!stop.stop_requested() &&
                               result.wait_for(std::chrono::milliseconds{100}) != std::future_status::ready) {}
                        if (!stop.stop_requested()) {
                            const auto response = result.get();
                            (void)send(peer.fd,response.data(),response.size(),MSG_NOSIGNAL);
                        }
                    } catch (const std::exception&) {
                        constexpr std::string_view error = "error:invalid generated event";
                        (void)send(peer.fd,error.data(),error.size(),MSG_NOSIGNAL);
                    }
                    continue;
                }
                else if (count > 5 && std::string_view(bytes,5) == "edit:") {
                    try {
                        auto edit = std::make_shared<Edit>();
                        edit->settings = pstream::decode(pstream::Bytes(bytes+5,bytes+count),{65531,4096,16});
                        auto result = edit->result.get_future();
                        {
                            std::lock_guard lock(mutex_);
                            edit_ = edit;
                        }
                        service_reload = true;
                        while (!stop.stop_requested() &&
                               result.wait_for(std::chrono::milliseconds{100}) != std::future_status::ready) {}
                        if (!stop.stop_requested()) {
                            const auto response = result.get();
                            (void)send(peer.fd,response.data(),response.size(),MSG_NOSIGNAL);
                        }
                    } catch (const std::exception&) {
                        (void)send(peer.fd,"error:invalid connection edit",29,MSG_NOSIGNAL);
                    }
                    continue;
                }
                else continue;
                (void)send(peer.fd,"accepted",8,MSG_NOSIGNAL);
            }
        });
    }
};
void request_service_control(const Store& store, std::string_view command) {
    const ControlAddress address(store);
    File connection(socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0));
    if (connect(connection.fd,reinterpret_cast<const sockaddr*>(&address.address),address.length))
        throw Error("no reachable OpenSabba service for this session; start service run first");
    if (!control_peer(connection.fd)) throw Error("service control peer has a different owner");
    if (send(connection.fd,command.data(),command.size(),MSG_NOSIGNAL) != static_cast<ssize_t>(command.size()))
        throw Error("cannot send service control request");
    pollfd reply{connection.fd,POLLIN,0};
    if (poll(&reply,1,2000) <= 0) throw Error("service control acknowledgment timed out");
    char bytes[32];
    const auto count = recv(connection.fd,bytes,sizeof(bytes),0);
    if (count != 8 || std::string_view(bytes,8) != "accepted")
        throw Error("service did not acknowledge control request");
}
Value request_service_status(const Store& store, bool skip_portal) {
    const ControlAddress address(store);
    File connection(socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0));
    if (connect(connection.fd,reinterpret_cast<const sockaddr*>(&address.address),address.length))
        throw CliError(2,"Cannot access synology-backupd");
    if (!control_peer(connection.fd)) throw Error("service control peer has a different owner");
    const std::string_view request = skip_portal ? "get_status_skip_portal" : "get_status";
    if (send(connection.fd,request.data(),request.size(),MSG_NOSIGNAL) != static_cast<ssize_t>(request.size()))
        throw CliError(2,"Cannot access synology-backupd");
    pollfd reply{connection.fd,POLLIN,0};
    if (poll(&reply,1,15000) <= 0) throw CliError(2,"Cannot access synology-backupd");
    pstream::Bytes response(event_limits.max_bytes);
    const auto count = recv(connection.fd,response.data(),response.size(),0);
    if (count <= 0) throw CliError(2,"Cannot access synology-backupd");
    response.resize(static_cast<std::size_t>(count));
    return pstream::decode(response,event_limits);
}
std::string request_service_authorization(const Store& store, const LoginCredentials& admin) {
    const ControlAddress address(store);
    File connection(socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0));
    if (connect(connection.fd,reinterpret_cast<const sockaddr*>(&address.address),address.length))
        throw CliError(2,"Cannot access OpenSabba service");
    if (!control_peer(connection.fd)) throw Error("service control peer has a different owner");
    Value credentials{Value::Object{
        {"username",Value{admin.username}}, {"password",Value{admin.password}}, {"otp",Value{admin.otp}}}};
    auto request = pstream::encode(credentials);
    for (const auto key : {"password","otp"}) {
        auto& secret = std::get<std::string>(std::get<Value::Object>(credentials.data).at(key).data);
        OPENSSL_cleanse(secret.data(),secret.size());
    }
    request.insert(request.begin(),{'a','u','t','h',':'});
    struct Wipe {
        pstream::Bytes& bytes;
        ~Wipe() { OPENSSL_cleanse(bytes.data(),bytes.size()); }
    } wipe{request};
    if (send(connection.fd,request.data(),request.size(),MSG_NOSIGNAL) != static_cast<ssize_t>(request.size()))
        throw Error("cannot send service authorization request");
    char bytes[65536];
    const auto count = recv(connection.fd,bytes,sizeof(bytes),0);
    if (count <= 0) throw CliError(3,"service did not acknowledge administrator authorization");
    const std::string response(bytes,static_cast<std::size_t>(count));
    if (response.starts_with("authorized:")) return response.substr(11);
    if (response.starts_with("server-error:")) {
        const auto number = response.substr(13);
        std::uint64_t code;
        const auto [end,error] = std::from_chars(number.data(),number.data()+number.size(),code);
        if (error == std::errc{} && end == number.data()+number.size())
            throw ServerError("administrator authorization rejected (error " + number + ")",code);
    }
    throw CliError(3,response.starts_with("error:") ? response.substr(6) :
        "service rejected administrator authorization");
}
int edit_connection_command(int argc, char** argv,const SessionInvocation& invocation) {
    Store store(false);
    auto session = store.read("session.pstream");
    if (!session) throw CliError(5,"No connection found");
    auto settings = connection_settings(*session);
    auto& object = std::get<Value::Object>(settings.data);
    bool quiet = false, proxy_changed = false, proxy_user_changed = false;
    for (int index = 2; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--quiet") { quiet = true; continue; }
        if (++index == argc) throw Error("missing option value");
        const std::string value(argv[index]);
        if (option == "--address") object["host"] = Value{value};
        else if (option == "--username") object["username"] = Value{value};
        else if (option == "--proxy-address") {
            object["proxy_host"] = Value{value};
            proxy_changed = true;
        } else if (option == "--proxy-port") object["proxy_port"] = Value{option_number(value.c_str(),65535)};
        else if (option == "--proxy-username") {
            object["proxy_username"] = Value{value};
            proxy_user_changed = true;
        }
        else if (option == "--proxy-password") object["proxy_password"] = Value{value};
        else throw Error("connected reload edits address and proxy settings; password authentication requires --connect");
    }
    if (text(settings,"username") != text(*session,"username"))
        throw CliError(11,"Usernames of config and connection are different");
    if (text(settings,"host",true).empty()) {
        if (quiet) throw CliError(1,"quiet connection edit requires a server address");
        object["host"] = Value{secret("Enter server address:",false)};
    }
    if (proxy_changed && text(settings,"proxy_host",true).empty()) {
        for (auto iterator = object.begin(); iterator != object.end();) {
            if (iterator->first.starts_with("proxy_")) iterator = object.erase(iterator);
            else ++iterator;
        }
    }
    if (proxy_user_changed && text(settings,"proxy_username",true).empty()) {
        for (const auto key : {"proxy_username","proxy_password","proxy_auth","proxy_domain",
                               "proxy_workstation","proxy_ntlm_version"}) object.erase(key);
    }
    // Trust review belongs to the interactive CLI. The service repeats the
    // identity check with the approved pin immediately before committing.
    auto candidate = *session;
    auto& candidate_fields = std::get<Value::Object>(candidate.data);
    for (const auto key : connection_keys) candidate_fields.erase(key);
    for (const auto& [key,value] : object) candidate_fields.emplace(key,value);
    auto endpoint = endpoint_from(candidate);
    if (invocation.prepare_endpoint) {
        invocation.prepare_endpoint(endpoint);
        object["port"] = Value{std::uint64_t{endpoint.port}};
        object["ca_file"] = Value{endpoint.ca_file};
        if (endpoint.proxy_credentials) {
            object["proxy_auth"] = Value{endpoint.proxy_credentials->scheme};
            object["proxy_username"] = Value{endpoint.proxy_credentials->username};
            object["proxy_domain"] = Value{endpoint.proxy_credentials->domain};
            object["proxy_workstation"] = Value{endpoint.proxy_credentials->workstation};
            object["proxy_ntlm_version"] = Value{std::uint64_t{endpoint.proxy_credentials->ntlm_version}};
        }
    }
    configure_certificate_trust(endpoint,!quiet,quiet);
    if (text(probe(endpoint),"ds_id") != text(*session,"ds_id"))
        throw CliError(4,"server identity (ds_id) differs from the saved session; connection not edited");
    if (store.try_lock()) {
        // A token may have rotated between reading the settings and taking the
        // writer lock. Merge only settings into the latest session.
        session = store.read("session.pstream");
        if (!session) throw CliError(5,"No connection found");
        edit_connection(store,*session,settings);
    } else {
        const ControlAddress address(store);
        File connection(socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0));
        if (connect(connection.fd,reinterpret_cast<const sockaddr*>(&address.address),address.length))
            throw CliError(2,"Cannot access OpenSabba service");
        if (!control_peer(connection.fd)) throw Error("service control peer has a different owner");
        const auto encoded = pstream::encode(settings,{65531,4096,16});
        std::string request("edit:");
        request.append(reinterpret_cast<const char*>(encoded.data()),encoded.size());
        if (send(connection.fd,request.data(),request.size(),MSG_NOSIGNAL) != static_cast<ssize_t>(request.size()))
            throw CliError(4,"cannot send connection edit");
        char response[65536];
        const auto count = recv(connection.fd,response,sizeof(response),0);
        const std::string_view reply(response,count > 0 ? static_cast<std::size_t>(count) : 0);
        if (reply != "edited")
            throw CliError(4,reply.starts_with("error:") ? std::string(reply.substr(6)) : "service did not finish connection edit");
    }
    std::cout << "Successfully reconnected; connection settings saved.\n";
    return 0;
}

Value prepared_backup_value(const PreparedBackup& prepared) {
    return Value{Value::Object{{"running_task_id",Value{prepared.run.running_task_id}},
        {"version_id",Value{prepared.run.version_id}},{"result_id",Value{prepared.run.result_id}},
        {"data_format",Value{prepared.run.data_format}},{"base_version_id",Value{prepared.base_version_id}}}};
}
PreparedBackup prepared_backup_from_value(const Value& value) {
    return {{number(value,"running_task_id"),number(value,"version_id"),number(value,"result_id"),
        number(value,"data_format")},number(value,"base_version_id")};
}
MachineSnapshotCatalog machine_snapshots(Store& store) {
    const auto saved = store.read("machine-snapshots.pstream",backup_limits);
    return saved ? MachineSnapshotCatalog{*saved} : MachineSnapshotCatalog{};
}
void save_machine_snapshots(Store& store, const MachineSnapshotCatalog& catalog) {
    store.write("machine-snapshots.pstream",catalog.value(),backup_limits);
}
void cleanup_machine_snapshot_resource(const MachineSnapshot& snapshot) {
    // A same-event recapture keeps the DB ID. Retire all
    // physical attempts belonging to it, as libsynosnap Snapshot deletion does.
    const auto remove = [&](const CaptureJournal& reserved) {
        try {
            auto capture = inspect_machine_capture(text(reserved.reservation,"directory"));
            if (reserved.phase == CapturePhase::prepared) verify_machine_reservation(reserved,capture);
            else if (capture_journal_value(reserved) != capture_journal_value(capture))
                throw Error("snapshot catalog capture ownership changed");
            if (capture.phase == CapturePhase::ready) finish_machine_capture(text(capture.reservation,"directory"));
            else if (capture.phase != CapturePhase::aborted)
                capture = inspect_machine_capture(text(capture.reservation,"directory"),true,&capture);
            prune_machine_capture(capture);
        } catch (const std::exception& error) {
            std::cerr << "Snapshot resource cleanup failed: " << error.what() << std::endl;
        }
    };
    for (const auto& capture : snapshot.superseded) remove(capture);
    if (snapshot.capture) remove(*snapshot.capture);
}
void remember_machine_version(Store& store, const Value& job) {
    if (!fields(job).contains("source_capture") || !fields(job).contains("version_id")) return;
    auto catalog = machine_snapshots(store);
    const auto capture = text(field(job,"source_capture"),"id");
    const auto* snapshot = catalog.capture(capture);
    if (!snapshot || snapshot->version_id == number(job,"version_id")) return;
    catalog.version(capture,number(job,"version_id"));
    save_machine_snapshots(store,catalog);
}

Value retained_base(Store& store,const SavedAuth& auth,const Value& record) try {
    const auto& info = field(record,"incremental");
    const auto archive = "backup-job-"+std::to_string(number(info,"base_running_task_id"))+"-"+
        std::to_string(number(info,"base_result_id"))+".pstream";
    const auto base = store.read(archive.c_str(),backup_limits);
    if (!base || text(backup_job_status(*base,auth),"phase") != "complete" ||
        number(*base,"version_id") != number(info,"base_version_id") ||
        number(*base,"result_id") != number(info,"base_result_id") ||
        number(*base,"running_task_id") != number(info,"base_running_task_id") ||
        number(*base,"task_id") != number(record,"task_id") || number(*base,"data_format") != 1 ||
        text(field(*base,"source_capture"),"id") != text(info,"base_snapshot_id"))
        throw Error("incremental resume base does not match the archived completed backup");
    return *base;
} catch (const Error& error) { throw BackupStateError(error.what()); }

#include "service_schedule.inc"

void refresh_machine_cache_tasks(Store&,Value::Array&,const Endpoint&,const SavedAuth&);

std::uint64_t process_events(Store& store, EventInbox& inbox, const Endpoint& endpoint, const SavedAuth& auth,
                    ServiceSchedules& schedules, ServiceObservations& observations, bool pull) {
    const auto save = [&] { store.write("events.pstream", inbox.serialize(), event_limits); };
    const auto report_done = [&] {
        const auto ids = inbox.ready_ids();
        if (ids.empty()) return;
        done_events(endpoint, auth, ids);
        inbox.acknowledged(ids);
        save();
        std::cout << "Refresh events completed: " << ids.size() << ".\n" << std::flush;
    };
    // Recover a lost acknowledgment reply before accepting more work.
    report_done();
    const auto incoming = pull ? pull_events(endpoint, auth, inbox.held_ids()) : Value::Array{};
    inbox.merge(incoming);
    save(); // Receipt is durable before any handler or done_event.
    if (inbox.needs_agent_update_finish()) {
        // The official agent closes the device's NAS update attempt even when it skips installation.
        finish_agent_update(endpoint, auth);
        const auto ids = inbox.ignore_agent_update_requests();
        save();
        for (const auto id : ids)
            std::cout << "Ignored NAS agent update request " << id
                      << " because OpenSabba does not self-update.\n" << std::flush;
        report_done();
    }
    const ServiceObservations::TasksChanged changed = [&](Value::Array& assigned) {
        refresh_machine_cache_tasks(store,assigned,endpoint,auth);
        schedules.update(assigned,auth,true);
        const auto time_state = store.read("server-time.pstream");
        endpoint.service_status->tasks(assigned,
            time_state ? server_time_offset(server_time_from_value(*time_state)) : std::nullopt);
    };
    if (inbox.needs_task_refresh()) {
        observations.refresh_tasks(endpoint,auth,inbox,changed);
        save(); // Task snapshot and ack_pending transition commit together.
        report_done();
    }
    if (inbox.needs_running_refresh()) {
        observations.refresh_running(endpoint,auth,inbox,changed);
        save(); // Receipt acknowledges a durable refresh, not backup completion.
        report_done();
    }
    if (inbox.needs_bandwidth_refresh()) {
        const auto rate = backup_bandwidth(endpoint,auth);
        inbox.finish_bandwidth_refresh(rate);
        save(); // Persist the result before publishing policy or acknowledging.
        endpoint.backup_bandwidth_policy->update(rate);
        report_done();
    }
    for (const auto& event : inbox.task_result_requests()) {
        const auto event_id = number(event,"id");
        const auto saved_result = inbox.task_result(event_id);
        std::uint64_t task = 0, version = 0, result_id = 0;
        Value result;
        try {
            task = number(event,"task_id");
            version = number(event,"version_id");
            const auto selected = inbox.running_result(task,version);
            result_id = saved_result ? inbox.task_result_id(event_id) : selected ? selected->result : 0;
            result = saved_result ? *saved_result : running_task_result(endpoint,auth,result_id);
            endpoint.service_status->result(result);
            auto checked = inbox;
            checked.finish_task_result(event_id,result);
        } catch (const Cancelled&) { throw; }
        catch (const std::exception& error) {
            std::cerr << "Task-result event " << event_id << " deferred: " << error.what() << "; retrying.\n";
            continue;
        }
        if (!saved_result) {
            inbox.prepare_task_result(event_id,result_id,result);
            save(); // Freeze the response before committing its receipt.
        }
        // the official agent updates observations, not the executing worker's state. In
        // particular a terminal NAS result cannot retire a partial local file.
        inbox.retire_running_result(task,version);
        inbox.finish_task_result(event_id,result);
        observations.observe_tasks(inbox.task_snapshot());
        save(); // Task timestamps and receipt commit before done_event.
        report_done();
    }
    for (const auto& event : inbox.node_requests()) {
        const auto id = number(event,"id");
        const auto& task = field(event,"webapi_task");
        if (number(task,"event_id") != id)
            throw Error("node-list event identity differs from its task");
        const auto& path = std::get<std::string>(field(task,"node_path").data);
        DirectoryNodes listing;
        if (path.empty()) listing.nodes = mounted_volume_nodes();
        else listing = directory_nodes(path,number(task,"dir_only") != 0);
        Value result{Value::Object{
            {"event_id",Value{id}},{"error_code",Value{listing.error_code}}}};
        if (!listing.nodes.empty())
            std::get<Value::Object>(result.data).emplace("node_list",Value{std::move(listing.nodes)});
        inbox.prepare_node_result(id,std::move(result));
        save(); // A transport retry must replay the same listing or failure.
    }
    for (const auto& result : inbox.node_results()) {
        report_client_nodes(endpoint,auth,result);
        inbox.node_result_sent(number(result,"event_id"));
        save(); // The NAS has the result before done_event may retire its request.
        report_done();
    }
    if (!incoming.empty()) {
        std::cout << "Events received: " << incoming.size()
                  << "; retained pending events: " << inbox.held_ids().size() << ".\n" << std::flush;
    }
    std::uint64_t cursor = 0;
    for (const auto& event : incoming) cursor = std::max(cursor,number(event,"id"));
    return cursor;
}

using RegisterRunningResult = std::function<void(EventInbox::RunningResult)>;

// The service control worker owns receipts for the whole connection lifetime.
// The backup worker receives snapshot copies and publishes only running history.
template<class Operation>
void with_service_events(Store& store, EventInbox& inbox, const Endpoint& endpoint,
    const SavedAuth& auth, std::atomic_bool& cycle_stop, ServiceSchedules& schedules, Operation operation) {
    ServiceObservations observations;
    const ServiceObservations::TasksChanged changed = [&](Value::Array& assigned) {
        refresh_machine_cache_tasks(store,assigned,endpoint,auth);
        schedules.update(assigned,auth,true);
        const auto time_state = store.read("server-time.pstream");
        endpoint.service_status->tasks(assigned,
            time_state ? server_time_offset(server_time_from_value(*time_state)) : std::nullopt);
    };
    bool initial_result_pending = true;
    const auto retry_result = [&] {
        if (!initial_result_pending) return;
        try {
            endpoint.service_status->result(running_task_result(endpoint,auth));
            initial_result_pending = false;
        } catch (const Cancelled&) { throw; }
        catch (const TransportError&) { throw; }
        catch (const std::exception& error) {
            std::cerr << "Initial task-result lookup failed: " << error.what() << "; retrying." << std::endl;
        }
    };
    retry_result();
    observations.initialize(endpoint,auth,inbox,changed);
    store.write("events.pstream",inbox.serialize(),event_limits);
    auto controls = std::async(std::launch::async,[&] {
        try {
            run_service_events(endpoint,auth,[&] {
                return inbox.needs_task_refresh() || inbox.needs_running_refresh() ||
                    inbox.needs_bandwidth_refresh() || inbox.needs_agent_update_finish() ||
                    !inbox.ready_ids().empty() ||
                    !inbox.task_result_requests().empty() || !inbox.node_requests().empty() ||
                    !inbox.node_results().empty();
            },[&](bool pull) {
                return process_events(store,inbox,endpoint,auth,schedules,observations,pull);
            });
        } catch (...) { cycle_stop = true; throw; }
    });
    std::set<std::uint64_t> published_runs;
    const RegisterRunningResult remember = [&](EventInbox::RunningResult result) {
        if (result.run && result.version && result.result && published_runs.insert(result.run).second) {
            observations.register_backup(result);
            inbox.register_running_result(std::move(result));
        }
    };
    std::exception_ptr work_error, control_error;
    try { operation(observations,remember,retry_result); }
    catch (...) { work_error = std::current_exception(); }
    cycle_stop = true;
    try { controls.get(); }
    catch (...) { control_error = std::current_exception(); }
    if (control_error) std::rethrow_exception(control_error);
    if (work_error) std::rethrow_exception(work_error);
}

std::string current_boot_id() {
    // Kernel-provided identity, never configurable: changing configuration must
    // not make a pre-reboot change map eligible for a new incremental backup.
    std::ifstream input("/proc/sys/kernel/random/boot_id");
    std::string id;
    if (!std::getline(input, id) || id.size() != 36 ||
        id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' ||
        id.find_first_not_of("0123456789abcdef-") != id.npos)
        throw Error("cannot read Linux boot identity");
    return id;
}

const Value& service_source_id(const Value& source) {
    return field(source,"capture_id");
}
std::unique_ptr<ReadyMachineCapture> open_service_machine(const Value& binding) {
    auto capture = std::make_unique<ReadyMachineCapture>(text(binding, "capture_directory"));
    if (capture_journal_value(capture->journal()) != field(binding, "capture"))
        throw Error("bound machine capture journal changed");
    return capture;
}

} // namespace
void validate_service_source(const Value& source,const SavedAuth& auth) {
    if (number(source,"format") != 3 || !number(source,"task_id") || text(source,"task_uuid").empty() ||
        text(source,"ds_id") != auth.ds_id || text(source,"device_uuid") != auth.device_uuid ||
        text(source,"username") != auth.username)
        throw Error("service source belongs to a different NAS, device, account or task, or has an invalid format");
    validate_image_options(text(source,"image_name"),1024*1024);
    const auto& id = text(source,"capture_id");
    if (id.size() != 32 || id.find_first_not_of("0123456789abcdef") != id.npos)
        throw Error("invalid service source identity");
    number(source,"claimed_run"); number(source,"queued_run"); number(source,"base_version_id");
    const auto capture = capture_journal_from_value(field(source,"capture"));
    if (capture.phase != CapturePhase::ready || capture.id != id ||
        text(capture.reservation,"directory") != text(source,"capture_directory"))
        throw Error("invalid completed machine capture binding");
}

namespace {
std::string service_run_archive(std::uint64_t run) {
    return "service-run-" + std::to_string(run) + ".pstream";
}

std::string machine_physical_image_name(const Value&, const Value&, std::string);
std::vector<ChangedExtent> machine_unused_ranges(const MetadataDisk&);
CaptureJournal validate_machine_incremental_base(const Value& base, const SavedAuth& auth, bool local_cache) try {
    const bool cached_base = local_cache && fields(base).contains("cache_state");
    if ((!cached_base && text(backup_job_status(base,auth),"phase") != "complete") ||
        (cached_base && text(base,"cache_state") != "cached") || number(base,"data_format") != 1)
        throw Error("machine incremental base must be a completed image backup");
    const auto original = capture_journal_from_value(field(base,"source_capture"));
    // The backup's saved capture is checked against its separate immutable
    // journal, without opening retired snapshots or comparing to a new target.
    (void)inspect_machine_capture(text(original.reservation,"directory"),false,&original);
    if (original.phase != CapturePhase::ready || !original.failure.empty() ||
        (local_cache && backup_cache_capture_partial(original)))
        throw Error("machine incremental base has no completed capture");
    const Value::Array empty;
    const auto plans = machine_image_plans(original.plan);
    const auto physical_count = machine_physical_image_count(original.plan);
    const auto& artifacts = fields(original.artifact).contains("additional_images") ?
        std::get<Value::Array>(field(original.artifact,"additional_images").data) : empty;
    const auto& images = fields(base).contains("images") ?
        std::get<Value::Array>(field(base,"images").data) : empty;
    if (artifacts.size()+1 != plans.size() || (plans.size() > 1 && images.size() != plans.size()) ||
        (plans.size() == 1 && !images.empty() && (!cached_base || images.size() != 1)))
        throw Error("machine incremental base artifact count changed");
    const bool unused_policy = plans.size() == 1 ?
        number(base,"schema") == 8 || number(base,"schema") == 9 :
        number(base,"schema") == 6 || number(base,"schema") == 7;
    std::set<std::string> names;
    for (std::size_t index = 0; index < plans.size(); ++index) {
        const auto& artifact = index ? artifacts[index-1] : original.artifact;
        const auto& entry = images.empty() ? base : images[index];
        const auto name = text(images.empty() ? base : images[index],images.empty() ? "image_name" : "name");
        validate_image_options(name,1024*1024);
        if (!names.insert(name).second || (!index && name != text(base,"image_name")))
            throw Error("machine incremental base image inventory changed");
        const auto length = index < physical_count ? number(field(*plans[index],"layout"),"length") :
            number(*plans[index],"length");
        if (number(artifact,"length") != length ||
            number(entry,images.empty() ? "image_size" : "size") != length ||
            text(entry,images.empty() ? "image_sha256" : "sha256",true) != text(artifact,"sha256",true) ||
            (index >= physical_count && name != text(*plans[index],"image_name")))
            throw Error("retained machine base differs from its completed backup");
        // Validate the base against its own immutable capture before deciding
        // whether a new source can inherit from it. A new full attempt must
        // never conceal damaged saved identities or unused-interval evidence.
        std::vector<ChangedExtent> reread;
        if (fields(base).contains("incremental")) {
            const auto& policy = images.empty() ? field(base,"incremental") : entry;
            if (fields(policy).contains("reread_ranges"))
                for (const auto& range : std::get<Value::Array>(field(policy,"reread_ranges").data))
                    reread.push_back({number(range,"offset"),number(range,"length")});
        }
        auto unused = machine_tracking_unused(original,index,fields(base).contains("incremental"),reread);
        if (index < physical_count) {
            const auto excluded = machine_unused_extents(*plans[index]);
            unused.insert(unused.end(),excluded.begin(),excluded.end());
        }
        unused = union_unused_ranges(length,std::move(unused));
        if (unused_policy) {
            Value::Array expected;
            for (const auto& range : unused)
                expected.push_back(Value{Value::Object{{"offset",Value{range.offset}},{"length",Value{range.length}}}});
            if (field(entry,"unused_ranges") != Value{std::move(expected)})
                throw Error("machine incremental base unused intervals changed");
        }
    }
    return original;
} catch (const Error& error) {
    throw BackupStateError(error.what());
}
std::vector<ChangedExtent> disk_reread_ranges(const MetadataDisk&, const IncrementalBackup*);
std::vector<IncrementalBackup> plan_machine_incremental(const Value& base,
    ReadyMachineCapture& capture, const std::string& configured_name, const Endpoint& endpoint,
    const SavedAuth& auth, const Value* resumed, bool local_cache) {
    const auto original = validate_machine_incremental_base(base,auth,local_cache);
    const bool cached_base = local_cache && fields(base).contains("cache_state");
    if (!fields(capture.journal().reservation).contains("cow_path"))
        throw Error("machine incremental backup requires persistent change tracking");
    verify_machine_images(capture,endpoint.cancelled);
    const auto current = machine_metadata_disks(capture,configured_name);
    const Value::Array empty;
    const auto& base_entries = fields(base).contains("images") ?
        std::get<Value::Array>(field(base,"images").data) : empty;
    std::vector<std::string> current_names, base_names;
    std::vector<const Value*> prior;
    for (const auto& disk : current) current_names.push_back(disk.image_name);
    if (base_entries.empty()) {
        base_names.push_back(text(base,"image_name")); prior.push_back(&base);
    } else for (const auto& entry : base_entries) {
        base_names.push_back(text(entry,"name")); prior.push_back(&entry);
    }
    // Cache writing requires the configured clean target and every filesystem
    // context. Ordinary online transfer instead decides for each current origin.
    if (local_cache && (machine_incremental_target(original.plan) !=
        machine_incremental_target(capture.journal().plan) || base_names != current_names))
        throw Error("cache capture image target differs from its retained base (7035)");
    const auto& resume_entries = resumed && fields(*resumed).contains("images") ?
        std::get<Value::Array>(field(*resumed,"images").data) : empty;
    if (resumed && ((current.size() > 1 && resume_entries.size() != current.size()) ||
        (current.size() == 1 && !resume_entries.empty())))
        throw BackupStateError("machine incremental resume image inventory changed");
    std::vector<IncrementalBackup> plans;
    plans.reserve(current.size());
    for (std::size_t index = 0; index < current.size(); ++index) {
        const auto found = std::find(base_names.begin(),base_names.end(),current_names[index]);
        const auto old_index = static_cast<std::size_t>(found-base_names.begin());
        const auto expected_sha = found == base_names.end() ? std::string{} :
            text(*prior[old_index],base_entries.empty() ? "image_sha256" : "sha256",true);
        std::vector<ChangedExtent> reread;
        Value policy;
        auto plan = machine_tracking_delta(capture.journal(),original,index,current_names,base_names,
            &reread,local_cache,&policy);
        // All new machine plans use independent used/changed/context flags.
        // Legacy saved plans remain immutable and cannot be silently converted.
        plan.filesystem_allocation = true;
        set(policy,"base_schema",field(base,"schema"));
        const bool unused_policy = prior.size() == 1 ? number(base,"schema") == 8 || number(base,"schema") == 9 :
            number(base,"schema") == 6 || number(base,"schema") == 7;
        if (!unused_policy && !machine_unused_ranges(current[index]).empty()) {
            if (local_cache) throw Error("cache base predates unused image interval policy (7035)");
            // This explicit local wire-policy conversion affects this image only.
            plan = DeltaPlan{plan.image_size,plan.image_size,{{0,plan.image_size,true}},true};
            reread = {{0,plan.image_size}};
            bool cbt = true;
            auto& origins = std::get<Value::Array>(std::get<Value::Object>(policy.data).at("origins").data);
            for (auto& origin : origins) {
                set(origin,"is_cbt",Value{std::uint64_t{0}});
                cbt &= number(origin,"omitted") != 0;
            }
            set(policy,"is_cbt",Value{std::uint64_t{cbt}});
        }
        if (current[index].machine_plan) machine_force_raw_changes(plan,*current[index].machine_plan);
        plans.push_back({cached_base ? 0 : number(base,"version_id"),cached_base ? 0 : number(base,"result_id"),
            cached_base ? 0 : number(base,"running_task_id"),original.id,expected_sha,
            std::move(plan),std::move(reread),std::move(policy)});
        if (resumed) {
            const auto& saved_policy = current.size() == 1 ? field(*resumed,"incremental") : resume_entries[index];
            const auto& name = current_names[index];
            if (!fields(saved_policy).contains("machine_policy") ||
                field(saved_policy,"machine_policy") != *plans.back().machine_policy ||
                !fields(saved_policy).contains("filesystem_allocation") || number(saved_policy,"filesystem_allocation") != 1 ||
                delta_plan_value(plans.back().plan) != field(saved_policy,"ranges") ||
                text(saved_policy,current.size() == 1 ? "base_image_sha256" : "base_sha256",true) != expected_sha ||
                (current.size() > 1 && (text(saved_policy,"name") != name ||
                    number(saved_policy,"size") != current[index].source->size())))
                throw BackupStateError("machine incremental resume differs from the retained image plans");
            Value::Array expected;
            for (const auto& range : disk_reread_ranges(current[index],&plans.back()))
                expected.push_back(Value{Value::Object{{"offset",Value{range.offset}},{"length",Value{range.length}}}});
            if (field(saved_policy,"reread_ranges") != Value{std::move(expected)})
                throw BackupStateError("machine incremental resume reread policy changed");
        }
    }
    if (!local_cache && (!resumed || text(backup_job_status(*resumed,auth),"phase") == "planned")) {
        if (backup_result(endpoint,auth,number(base,"task_id"),number(base,"result_id")) != "complete")
            throw Error("NAS does not confirm the machine incremental base");
        if (backup_base_version(endpoint,auth,number(base,"task_id")) != number(base,"version_id"))
            throw Error("NAS-selected base differs from the retained machine image; configure a full backup");
    }
    return plans;
}
std::vector<IncrementalBackup> machine_incremental(const Value& base, ReadyMachineCapture& capture,
    const std::string& configured_name, const Endpoint& endpoint, const SavedAuth& auth,
    const Value* resumed = nullptr, bool local_cache = false) {
    return plan_machine_incremental(base,capture,configured_name,endpoint,auth,resumed,local_cache);
}
std::string machine_physical_image_name(const Value& disk_plan, const Value& machine_plan,
                                        std::string proposed) {
    if (!fields(disk_plan).contains("layout"))
        return text(field(disk_plan,"root"),"image_name");
    if (fields(machine_plan).contains("selection"))
        proposed = machine_disk_image_name(text(disk_plan,"disk"));
    const auto& disk_fields = fields(disk_plan);
    if (!disk_fields.contains("excluded")) return proposed;
    for (const auto& excluded :
         std::get<Value::Array>(field(disk_plan,"excluded").data)) {
        if (!fields(excluded).contains("pv_uuid")) continue;
        const auto& disk = text(disk_plan,"disk");
        if (!disk.starts_with("/dev/")) throw Error("LVM source disk is not a direct device");
        const auto basename = disk.substr(5);
        const bool supported = basename.starts_with("sd") || basename.starts_with("hd") ||
            basename.starts_with("vd") || basename.starts_with("xvd") ||
            basename.starts_with("nvme");
        if (!supported || basename.size() < 3 ||
            !std::all_of(basename.begin(),basename.end(),[](char c) {
                return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
            })) throw Error("LVM source disk name is unsupported by the recovery media");
        const auto partition = number(excluded,"partition");
        const auto expected = disk + (basename.back() >= '0' && basename.back() <= '9' ? "p" : "") +
            std::to_string(partition);
        if (!partition || text(excluded,"device") != expected)
            throw Error("LVM physical volume path differs from its captured disk partition");
        bool found = false;
        const auto& groups = std::get<Value::Array>(
            field(field(machine_plan,"lvm"),"volume_groups").data);
        for (const auto& group : groups)
            for (const auto& pv :
                 std::get<Value::Array>(field(group,"physical_volumes").data))
                if (text(pv,"uuid") == text(excluded,"pv_uuid")) {
                    if (found || text(pv,"name") != expected)
                        throw Error("LVM physical volume identity differs from its captured disk");
                    found = true;
                }
        if (!found) throw Error("captured LVM physical volume is absent from its volume group");
        proposed = basename+".img";
    }
    return proposed;
}
} // namespace
std::vector<MetadataDisk> machine_metadata_disks(ReadyMachineCapture& capture,
                                                  const std::string& base_name, bool incremental,
                                                  std::span<const IncrementalBackup> deltas) {
    std::vector<MetadataDisk> result;
    result.reserve(capture.disk_count());
    const auto& journal = capture.journal();
    const Value::Array empty;
    const auto& artifacts = fields(journal.artifact).contains("additional_images") ?
        std::get<Value::Array>(field(journal.artifact,"additional_images").data) : empty;
    const auto plans = machine_image_plans(journal.plan);
    if (plans.size() != capture.disk_count() || artifacts.size()+1 != plans.size())
        throw Error("machine disk images differ from their capture plan");
    for (std::size_t index = 0; index < plans.size(); ++index) {
        const auto& plan = *plans[index];
        const auto& artifact = index ? artifacts[index-1] : journal.artifact;
        const auto name = fields(plan).contains("lv_uuid") ? text(plan,"image_name") :
            machine_physical_image_name(plan,journal.plan,index ?
                base_name+"-disk-"+std::to_string(index) : base_name);
        validate_image_options(name,1024*1024);
        result.push_back({&capture.source(index),static_cast<std::uint32_t>(number(artifact,"sector_size")),
            name,&plan,nullptr});
    }
    result.front().machine_inventory = &journal.plan;
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index].additional_unused = machine_tracking_unused(journal,index,incremental,
            deltas.empty() ? std::span<const ChangedExtent>{} : deltas[index].reread_ranges);
        result[index].omitted_snapshots = machine_snapshot_omissions(journal,index);
    }
    return result;
}
namespace {
std::vector<ChangedExtent> machine_unused_ranges(const MetadataDisk& disk) {
    auto ranges = disk.additional_unused;
    if (disk.machine_plan && fields(*disk.machine_plan).contains("excluded")) {
        const auto partition_ranges = machine_unused_extents(*disk.machine_plan);
        ranges.insert(ranges.end(),partition_ranges.begin(),partition_ranges.end());
    }
    ranges = union_unused_ranges(disk.source->size(),std::move(ranges));
    validate_unused_ranges(ranges,disk.source->size());
    return ranges;
}
std::vector<ChangedExtent> disk_reread_ranges(const MetadataDisk& disk, const IncrementalBackup* delta = nullptr) {
    auto ranges = disk.machine_plan ? machine_reread_ranges(*disk.machine_plan,disk.source->size()) :
        std::vector<ChangedExtent>{};
    if (delta) ranges.insert(ranges.end(),delta->reread_ranges.begin(),delta->reread_ranges.end());
    return union_changed_extents(disk.source->size(),std::move(ranges));
}
} // namespace
void verify_machine_images(ReadyMachineCapture& capture,
                           const std::function<bool()>& cancelled) {
    const auto& journal = capture.journal();
    const Value::Array empty;
    const auto& artifacts = fields(journal.artifact).contains("additional_images") ?
        std::get<Value::Array>(field(journal.artifact,"additional_images").data) : empty;
    const auto plans = machine_image_plans(journal.plan);
    if (plans.size() != capture.disk_count() || artifacts.size()+1 != plans.size())
        throw Error("machine disk images differ from their capture plan");
    for (std::size_t index = 0; index < plans.size(); ++index) {
        auto piece = journal;
        piece.plan = *plans[index];
        piece.artifact = index ? artifacts[index-1] : journal.artifact;
        verify_machine_artifact(piece,capture.source(index),cancelled);
    }
}

namespace {
void dispatch_source(Store& store,Value& binding,const Endpoint& endpoint,const SavedAuth& auth,
                     const RegisterRunningResult& register_result, const TaskView& task_view) {
    validate_service_source(binding,auth);
    const auto remember_result = [&](const Value& saved) {
        endpoint.service_status->backup(saved);
        if (!fields(saved).contains("result_id") || !fields(saved).contains("version_id")) return;
        register_result({number(saved,"running_task_id"),number(saved,"task_id"),
            number(saved,"version_id"),number(saved,"result_id")});
    };
    auto record = store.read("backup-job.pstream",backup_limits);
    auto claimed = number(binding,"claimed_run");
    bool restart_planned = false;
    if (!claimed && record && fields(*record).contains("service_source") &&
        field(*record,"service_source") == service_source_id(binding)) {
        if (text(backup_job_status(*record,auth),"phase") != "planned")
            throw Error("service source claim is missing for a prepared backup");
        claimed = number(*record,"running_task_id");
        set(binding,"claimed_run",Value{claimed});
        store.write("service-source.pstream",binding);
    }
    if (claimed) {
        if (!record || number(*record,"running_task_id") != claimed ||
            number(*record,"task_id") != number(binding,"task_id") ||
            !fields(*record).contains("service_source") || field(*record,"service_source") != service_source_id(binding))
            throw Error("claimed service job has no matching backup journal");
        recover_service_backup(endpoint,auth,*record,
            [&](const Value& saved) { store.write("backup-job.pstream",saved,backup_limits); });
        remember_machine_version(store,*record);
        const auto summary = backup_job_status(*record,auth);
        publish_script_reports(store,endpoint,auth,*record);
        if (number(summary,"terminal")) return;
        const auto phase = text(summary,"phase");
        if (fields(*record).contains("nas_cancel_requested")) {
            run_service_backup(endpoint,auth,task_view,number(binding,"task_id"),*record,
                [&](const Value& saved) { store.write("backup-job.pstream",saved,backup_limits); remember_result(saved); },
                [](const Endpoint&,const SaveBackupJob&) {});
            return;
        }
        if (phase == "planned") restart_planned = true;
        else {
            if ((phase == "finish" || phase == "uploaded") &&
                backup_result(endpoint,auth,number(binding,"task_id"),number(*record,"result_id")) != "incomplete") {
                recover_backup_job(endpoint,auth,*record,false,
                    [&](const Value& saved) { store.write("backup-job.pstream",saved,backup_limits); });
                return;
            }
            std::unique_ptr<ReadyMachineCapture> capture;
            try { capture = open_service_machine(binding); }
            catch (const Error&) {
                fail_service_backup(endpoint,auth,*record,
                    [&](const Value& saved) { store.write("backup-job.pstream",saved,backup_limits); },
                    text(field(field(field(binding,"capture"),"plan"),"root"),"device"));
                return;
            }
            if (field(*record,"source_capture") != field(binding,"capture"))
                throw Error("service backup does not identify its bound machine capture");
            const auto name = machine_physical_image_name(capture->journal().plan,
                capture->journal().plan,text(binding,"image_name"));
            if (text(*record,"image_name") != name)
                throw Error("service backup image identity differs from its bound machine capture");
            auto transfer_endpoint = endpoint;
            for (const auto& task : task_view.tasks(endpoint))
                if (number(task,"id") == number(binding,"task_id") && field(task,"task_uuid") == field(binding,"task_uuid")) {
                    transfer_endpoint.backup_task_uuid = text(task,"task_uuid");
                    transfer_endpoint.backup_encryption = task_transfer_encrypted(task);
                }
            run_service_backup(transfer_endpoint,auth,task_view,number(binding,"task_id"),*record,
                [&](const Value& saved) {
                    store.write("backup-job.pstream",saved,backup_limits);
                    remember_result(saved);
                    print_backup_progress(saved);
                },[&](const Endpoint& transfer,const SaveBackupJob& save) {
                    std::optional<std::vector<IncrementalBackup>> deltas;
                    if (fields(*record).contains("incremental"))
                        deltas = machine_incremental(retained_base(store,auth,*record),*capture,
                            text(binding,"image_name"),transfer,auth,&*record);
                    else verify_machine_images(*capture,transfer.cancelled);
                    const auto disks = machine_metadata_disks(*capture,text(binding,"image_name"),deltas.has_value(),
                        deltas ? *deltas : std::vector<IncrementalBackup>{});
                    std::vector<BackupImage> images;
                    for (std::size_t index = 0; index < disks.size(); ++index)
                        images.push_back({disks[index].source,disks[index].image_name,machine_unused_ranges(disks[index]),
                            deltas ? disk_reread_ranges(disks[index],&deltas->at(index)) : std::vector<ChangedExtent>{}});
                    if (images.size() > 1) resume_images_job(transfer,auth,images,*record,save);
                    else resume_image_job(transfer,auth,*images.front().source,*record,save,
                        images.front().unused_ranges,images.front().reread_ranges);
                });
            std::cout << "Service backup resumed; bound source consumed." << std::endl;
            return;
        }
    }
    const auto task_id = number(binding,"task_id");
    std::optional<Value> queued;
    for (const auto& job : task_view.running(endpoint)) {
        if (number(job,"task_id") != task_id || number(job,"type") != 0) continue;
        if (queued) throw Error("multiple NAS backup jobs match the bound service task");
        queued = job;
    }
    if (!queued || number(*queued,"status") != (fields(binding).contains("preparation") ? 1U : 0U)) return;
    const auto run = number(*queued,"id");
    if (!run) throw Error("NAS queued backup has an invalid running task ID");
    if (number(binding,"queued_run") != run) return;
    if (const auto prior = store.read(service_run_archive(run).c_str())) {
        validate_service_source(*prior,auth);
        if (number(*prior,"claimed_run") != run) throw Error("invalid service run archive");
        return;
    }
    if (restart_planned && run != claimed) throw Error("planned service job no longer matches the NAS queue");
    if (record && !restart_planned) {
        const auto summary = backup_job_status(*record,auth);
        if (!number(summary,"terminal") || number(summary,"running_task_id") == run)
            throw Error("previous backup is unresolved or already identifies this NAS job");
    }
    bool assigned = false;
    auto compression = TransferCompression::none;
    auto transfer_endpoint = endpoint;
    if (fields(binding).contains("preparation"))
        transfer_endpoint.prepared_backup = prepared_backup_from_value(field(binding,"preparation"));
    auto scripts = store.read(script_run_name(run).c_str());
    for (const auto& task : task_view.tasks(endpoint)) {
        if (number(task,"id") != task_id || field(task,"task_uuid") != field(binding,"task_uuid")) continue;
        assigned = true;
        // A retained snapshot keeps its acquisition and script boundary. Task
        // refresh changes transfer settings, not the captured selection.
        if (!scripts) {
            const auto capture = capture_journal_from_value(field(binding,"capture"));
            if (!capture.logs.empty()) {
                scripts = new_script_run({},task_id,run,text(task,"task_uuid"));
                for (const auto key : {"ds_id","device_uuid","username"}) set(*scripts,key,field(binding,key));
                set(*scripts,"capture_id",Value{capture.id});
                store.write(script_run_name(run).c_str(),*scripts);
            }
        }
        if (scripts) {
            validate_script_owner(*scripts,binding);
            validate_script_run(*scripts,retained_backup_scripts(*scripts),task_id,run,text(task,"task_uuid"));
            if (text(*scripts,"capture_id") != text(binding,"capture_id"))
                throw Error("backup scripts belong to a different machine capture");
        }
        compression = validate_machine_transfer_policy(task);
        transfer_endpoint.backup_app_aware = task_app_aware(task);
        transfer_endpoint.backup_encryption = task_transfer_encrypted(task);
        transfer_endpoint.backup_task_uuid = text(task,"task_uuid");
    }
    if (!assigned) throw Error("bound service task is no longer assigned to this device");
    if (record && text(backup_job_status(*record,auth),"phase") == "cancel") {
        const auto outcome = backup_result(endpoint,auth,task_id,number(*record,"result_id"));
        if (outcome == "incomplete") return;
        if (outcome != "cancel") throw Error("NAS result differs from the saved cancelled service backup");
    }
    auto capture = open_service_machine(binding);
    const auto name = text(binding,"image_name");
    const auto wire_name = machine_physical_image_name(capture->journal().plan,capture->journal().plan,name);
    std::optional<std::vector<IncrementalBackup>> deltas;
    if (restart_planned && field(*record,"source_capture") != field(binding,"capture"))
        throw Error("planned backup does not identify its bound machine capture");
    if (restart_planned && text(*record,"image_name") != wire_name)
        throw Error("planned backup image identity differs from its bound machine capture");
    if (restart_planned && fields(*record).contains("incremental"))
        deltas = machine_incremental(retained_base(store,auth,*record),*capture,name,endpoint,auth,&*record);
    else if (!restart_planned) {
        std::optional<Value> base;
        const auto catalog = machine_snapshots(store);
        const auto* selected = catalog.base(text(binding,"task_uuid"),number(binding,"base_version_id"));
        if (selected && selected->capture) {
            for (const auto& filename : store.names()) {
                if (!filename.starts_with("backup-job") || !filename.ends_with(".pstream")) continue;
                const auto candidate = *store.read(filename.c_str(),backup_limits);
                if (number(candidate,"task_id") != task_id || number(candidate,"version_id") != selected->version_id ||
                    !fields(candidate).contains("source_capture") ||
                    text(field(candidate,"source_capture"),"id") != selected->capture->id) continue;
                (void)backup_job_status(candidate,auth);
                base = candidate;
                break;
            }
            if (!base) throw Error("catalog base has no matching machine backup journal");
        }
        if (base) deltas = plan_machine_incremental(*base,*capture,name,endpoint,auth,nullptr,false);
        else std::cout << "No completed machine base is retained for this task; starting a full backup." << std::endl;
    }
    if (!deltas) verify_machine_images(*capture,endpoint.cancelled);
    auto disks = machine_metadata_disks(*capture,name,deltas.has_value(),deltas ? *deltas : std::vector<IncrementalBackup>{});
    if (deltas)
        for (std::size_t index = 0; index < disks.size(); ++index) disks[index].delta = &(*deltas)[index].plan;
    const auto metadata = fixed_machine_metadata(disks,number(capture->journal().reservation,"snapshot_time"));
    if (record && !restart_planned) {
        const auto archive = "backup-job-"+std::to_string(number(*record,"running_task_id"))+
            (fields(*record).contains("result_id") ? "-"+std::to_string(number(*record,"result_id")) :
                std::string("-retired"))+".pstream";
        store.write(archive.c_str(),*record,backup_limits);
    }
    const auto save = [&](const Value& update) {
        auto saved = update;
        set(saved,"task_id",Value{task_id});
        set(saved,"source_capture",field(binding,"capture"));
        set(saved,"service_source",service_source_id(binding));
        if (scripts) {
            set(saved,"script_run_id",Value{run});
            set(saved,"script_policy",field(*scripts,"policy"));
        }
        store.write("backup-job.pstream",saved,backup_limits);
        remember_machine_version(store,saved);
        remember_result(saved);
        publish_script_reports(store,endpoint,auth,saved);
        // The planned journal and source claim are durable before preparation.
        if (!number(binding,"claimed_run")) {
            set(binding,"claimed_run",Value{run});
            store.write("service-source.pstream",binding);
        }
        print_backup_progress(saved);
    };
    run_service_backup(transfer_endpoint,auth,task_view,task_id,{},save,
        [&](const Endpoint& transfer,const SaveBackupJob& persist) {
            std::vector<BackupImage> images;
            for (std::size_t index = 0; index < disks.size(); ++index)
                images.push_back({disks[index].source,disks[index].image_name,machine_unused_ranges(disks[index]),
                    deltas ? disk_reread_ranges(disks[index],&deltas->at(index)) : std::vector<ChangedExtent>{}});
            if (images.size() > 1) {
                if (deltas) run_incremental_images_job(transfer,auth,task_id,run,images,*deltas,metadata,persist,compression);
                else run_full_images_job(transfer,auth,run,images,metadata,persist,compression);
            } else if (deltas)
                run_incremental_image_job(transfer,auth,task_id,run,*images.front().source,images.front().name,
                    metadata,deltas->front(),persist,compression,images.front().unused_ranges,images.front().reread_ranges);
            else run_full_image_job(transfer,auth,run,*images.front().source,images.front().name,metadata,persist,
                BackupOutcome::complete,compression,images.front().unused_ranges);
        });
    std::cout << "Service backup finished; bound source consumed." << std::endl;
}

Value machine_task_identity(const SavedAuth& auth,const Value& task) {
    return Value{Value::Object{{"format",Value{std::uint64_t{2}}},{"ds_id",Value{auth.ds_id}},
        {"device_uuid",Value{auth.device_uuid}},{"username",Value{auth.username}},
        {"task_id",field(task,"id")},{"task_uuid",field(task,"task_uuid")}}};
}
void validate_machine_task_owner(const Value& identity, const SavedAuth& auth) {
    if (number(identity,"format") != 2 || text(identity,"ds_id") != auth.ds_id ||
        text(identity,"device_uuid") != auth.device_uuid || text(identity,"username") != auth.username ||
        !number(identity,"task_id") || text(identity,"task_uuid").empty())
        throw Error("invalid NAS machine task identity or account");
}
std::filesystem::path machine_working_directory() {
    const auto path = storage_path(false)/"captures";
    if (mkdir(path.c_str(),0700) && errno != EEXIST) throw Error("cannot create private capture working area");
    File directory(open(path.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    check_private(directory.fd,true);
    return path;
}
void check_machine_capture_directory(const Value& plan) {
    const std::filesystem::path directory(text(plan,"cow_directory"));
    const auto parent = machine_working_directory();
    if (directory == parent) return;
    const auto name = directory.filename().string();
    if (directory.parent_path() != parent || !name.starts_with("capture-") ||
        name.size() != 40 || name.substr(8).find_first_not_of("0123456789abcdef") != std::string::npos)
        throw Error("machine capture directory differs from its private working area");
}
void preflight_service_machine() {
    // Topology and NAS selection belong to each fresh job.
    const auto control_status = text(snapshot_driver_status(),"status");
    if (control_status != "control-available" && control_status != "no-free-minor")
        throw BackupRetry("automatic machine capture is awaiting a free synosnap slot");
}
Value machine_binding(const Value& owner, const CaptureJournal& capture, std::uint64_t run,
                      const Value& pending) {
    auto binding = Value{Value::Object{{"format",Value{std::uint64_t{3}}},
        {"ds_id",field(owner,"ds_id")},{"device_uuid",field(owner,"device_uuid")},
        {"username",field(owner,"username")},{"task_id",field(owner,"task_id")},
        {"image_name",Value{fields(capture.plan).contains("layout") ? machine_disk_image_name(text(capture.plan,"disk")) :
            text(field(capture.plan,"root"),"image_name")}},{"capture_id",Value{capture.id}},
        {"capture_directory",field(capture.reservation,"directory")},
        {"capture",capture_journal_value(capture)},{"queued_run",Value{run}},
        {"task_uuid",field(pending,"task_uuid")},{"base_version_id",field(pending,"base_version_id")},
        {"claimed_run",Value{std::uint64_t{0}}}}};
    set(binding,"preparation",field(pending,"preparation"));
    return binding;
}
bool reusable_capture_snapshot(const CaptureJournal& capture) {
    if (capture.phase < CapturePhase::snapshot_active || capture.phase > CapturePhase::ready)
        return false;
    if (capture.boot_id != current_boot_id() && !fields(capture.reservation).contains("cow_path")) return false;
    const auto present = [&](const Value& reserved, const Value& saved) {
        if (capture_snapshot_omitted(saved)) return true; // Journal validation proved retirement.
        const auto current = snapshot_driver_information(static_cast<std::uint32_t>(number(reserved,"minor")));
        if (!current || !number(*current,"active") || number(*current,"unverified") ||
            number(*current,"cancelled") || text(*current,"error_code") != "0") return false;
        for (const auto key : {"uuid","sequence","cow_path"})
            if (field(*current,key) != field(saved,key)) return false;
        return number(*current,"snapshot_mode") != 0;
    };
    if (!present(capture.reservation,capture.snapshot)) return false;
    for (const auto& extra : std::get<Value::Array>(field(capture.reservation,"extras").data))
        if (!present(extra,field(extra,"snapshot"))) return false;
    return true;
}
// Pending ownership precedes host mutations. Remove it only after committing a
// ready binding or an abort archive. Never replay an interrupted acquisition.
std::optional<CaptureJournal> recover_pending_machine(Store& store, const Value& owner, std::optional<Value>& binding,
                             bool publish = true) {
    const auto pending = store.read("service-machine-pending.pstream");
    if (!pending) return {};
    if (field(*pending,"task_owner") != owner || field(*pending,"task_uuid") != field(owner,"task_uuid"))
        throw Error("pending capture belongs to another NAS task");
    if (const auto skipped = store.read(("service-machine-skipped-"+std::to_string(number(*pending,"run"))+".pstream").c_str())) {
        if (field(*skipped,"task_owner") != owner || field(*skipped,"run") != field(*pending,"run"))
            throw Error("cancelled capture retirement belongs to another job");
        publish = false;
    }
    const auto& reserved = field(*pending,"capture");
    const auto directory = text(field(reserved,"reservation"),"directory");
    auto capture = inspect_machine_capture(directory);
    verify_machine_reservation(capture_journal_from_value(reserved),capture);
    if (fields(*pending).contains("local_snapshot_id")) {
        auto catalog = machine_snapshots(store);
        catalog.attach(number(*pending,"local_snapshot_id"),capture_journal_from_value(reserved));
        save_machine_snapshots(store,catalog);
    }
    const auto scripts = store.read(script_run_name(number(*pending,"run")).c_str());
    const bool script_failed = scripts && backup_scripts_failed(*scripts);
    if (script_failed) {
        validate_script_owner(*scripts,owner);
        if (number(*scripts,"running_task_id") != number(*pending,"run") ||
            number(*scripts,"task_id") != number(owner,"task_id") ||
            field(*scripts,"task_uuid") != field(*pending,"task_uuid") ||
            text(*scripts,"capture_id") != capture.id)
            throw Error("failed backup scripts belong to another capture or NAS run");
        // capture metadata publication precedes post. Its durable mode-1 result stops
        // this event even after death between script completion and handoff.
        // Keep the snapshot history, but never bind it as an upload source.
        if (publish && capture.phase == CapturePhase::ready) return capture;
    }
    if (publish && !script_failed && capture.phase != CapturePhase::ready && reusable_capture_snapshot(capture)) return capture;
    if (capture.phase != CapturePhase::ready && capture.phase != CapturePhase::aborted) {
        try { capture = inspect_machine_capture(directory,true,&capture); }
        catch (const Error& error) {
            std::cerr << "Capture cleanup deferred: " << error.what() << '\n';
            capture = inspect_machine_capture(directory);
        }
    }
    // After process death the official agent event handler consults NAS resume state;
    // it does not replay an isolated post script or require operator resolution.
    // Keep pending ownership until that online decision is durable.
    if (publish && (capture.phase == CapturePhase::aborted || capture.phase == CapturePhase::recovery_required))
        return capture;
    if (capture.phase == CapturePhase::ready && publish) {
        if (fields(*pending).contains("local_snapshot_id")) {
            auto catalog = machine_snapshots(store);
            catalog.attach(number(*pending,"local_snapshot_id"),capture);
            save_machine_snapshots(store,catalog); // the official agent updates the reserved row after acquisition succeeds.
        }
        if (binding && text(*binding,"capture_id") == capture.id) {
            if (field(*binding,"capture") != capture_journal_value(capture) ||
                number(*binding,"queued_run") != number(*pending,"run"))
                throw Error("pending machine capture differs from its saved binding");
        } else {
            if (binding) throw Error("pending machine capture conflicts with the existing service source");
            binding = machine_binding(owner,capture,number(*pending,"run"),*pending);
            store.write("service-source.pstream",*binding);
        }
    } else {
        if (capture.phase == CapturePhase::ready) finish_machine_capture(directory);
        store.write(((capture.phase == CapturePhase::ready ? "machine-unused-" : "machine-aborted-")+
            capture.id+".pstream").c_str(),capture_journal_value(capture));
        if (capture.phase == CapturePhase::recovery_required)
            store.write(("service-machine-cleanup-"+capture.id+".pstream").c_str(),*pending);
    }
    store.remove("service-machine-pending.pstream");
    if (fields(*pending).contains("preparation")) store.remove("service-machine-event.pstream");
    return {};
}

void recover_machine_cleanup(Store& store, const std::string& name, const Value& cleanup) {
    const auto directory = text(field(field(cleanup,"capture"),"reservation"),"directory");
    const auto current = inspect_machine_capture(directory);
    verify_machine_reservation(capture_journal_from_value(field(cleanup,"capture")),current);
    const auto capture = inspect_machine_capture(directory,true,&current);
    if (capture.phase != CapturePhase::aborted && capture.phase != CapturePhase::ready)
        throw Error("owned machine capture retirement is incomplete; saved token retained");
    store.remove(name.c_str());
}

bool finish_failed_machine(Store& store, const Value& owner, const CaptureJournal& capture,
                           const Endpoint& endpoint, const SavedAuth& auth, bool snapshot_missing = false) {
    const auto pending = store.read("service-machine-pending.pstream");
    const auto run = number(*pending,"run");
    const auto filename = script_run_name(run);
    auto journal = store.read(filename.c_str());
    if (!journal) {
        journal = new_script_run({},number(owner,"task_id"),run,text(*pending,"task_uuid"));
        for (auto key : {"ds_id","device_uuid","username"}) set(*journal,key,field(owner,key));
        set(*journal,"capture_id",Value{capture.id});
    }
    validate_script_owner(*journal,owner);
    if (!fields(*journal).contains("capture_id")) set(*journal,"capture_id",Value{capture.id});
    if (number(*journal,"running_task_id") != run || number(*journal,"task_id") != number(owner,"task_id") ||
        text(*journal,"capture_id") != capture.id || field(*journal,"task_uuid") != field(*pending,"task_uuid"))
        throw Error("failed backup journal belongs to another capture or NAS run");
    auto evidence = capture_journal_value(capture);
    if (fields(*journal).contains("capture_failure")) {
        const auto& recorded = field(*journal,"capture_failure");
        for (const auto* key : {"id","boot_id","plan"})
            if (field(recorded,key) != field(evidence,key)) throw Error("failed backup capture evidence changed");
        evidence = recorded;
    }
    if (snapshot_missing && !fields(*journal).contains("snapshot_missing"))
        set(*journal,"snapshot_missing",Value{Value::Object{
            {"log_time",Value{server_time_now()}},{"reported",Value{std::uint64_t{0}}},
            {"volume_name",field(field(capture.plan,"root"),"mount_path")}}});
    set(*journal,"capture_failure",evidence);
    if (!fields(*journal).contains("nas_phase") && fields(*pending).contains("preparation")) {
        const auto prepared = prepared_backup_from_value(field(*pending,"preparation"));
        set(*journal,"version_id",Value{prepared.run.version_id});
        set(*journal,"result_id",Value{prepared.run.result_id});
        set(*journal,"data_format",Value{prepared.run.data_format});
        set(*journal,"nas_phase",Value{std::string("prepared")});
    }
    store.write(filename.c_str(),*journal);
    if (!finish_failed_backup(endpoint,auth,*journal,script_directory(*journal),
        [&](const Value& saved) { store.write(filename.c_str(),saved); })) return false;
    auto catalog = machine_snapshots(store);
    if (catalog.capture(capture.id)) {
        if (capture.phase == CapturePhase::ready) catalog.attach(number(*pending,"local_snapshot_id"),capture);
        catalog.version(capture.id,number(*journal,"version_id"));
        save_machine_snapshots(store,catalog);
    }
    store.write(("service-machine-skipped-"+std::to_string(run)+".pstream").c_str(),
        Value{Value::Object{{"task_owner",owner},{"run",Value{run}},{"capture_id",Value{capture.id}},
            {"result_id",field(*journal,"result_id")},{"nas_outcome",field(*journal,"nas_outcome")}}});
    store.write(("machine-aborted-"+capture.id+".pstream").c_str(),evidence);
    if (capture.phase == CapturePhase::recovery_required)
        store.write(("service-machine-cleanup-"+capture.id+".pstream").c_str(),*pending);
    store.remove("service-machine-pending.pstream");
    if (fields(*pending).contains("preparation")) store.remove("service-machine-event.pstream");
    std::cout << "Machine capture event retired; service continuing.\n" << std::flush;
    return true;
}

void restore_machine_event(Store& store, const Value& owner, const Value& source) {
    if (!fields(source).contains("preparation")) return;
    const auto preparation = prepared_backup_from_value(field(source,"preparation"));
    const auto catalog = machine_snapshots(store);
    const auto* snapshot = catalog.capture(text(source,"capture_id"));
    if (!snapshot) throw Error("recaptured event has no local snapshot catalog row");
    store.write("service-machine-event.pstream",Value{Value::Object{
        {"task_owner",owner},{"run",Value{preparation.run.running_task_id}},{"task_uuid",field(source,"task_uuid")},
        {"base_version_id",Value{preparation.base_version_id}},
        {"base_snapshot_id",Value{snapshot->base_snapshot_id}},
        {"handshake_sent",Value{std::uint64_t{1}}},{"preparation",field(source,"preparation")}}});
}

void retire_recaptured_machine(Store& store, const Value& owner, std::optional<Value>& binding) {
    const auto intent = store.read("service-machine-recapture.pstream",backup_limits);
    if (!intent) return;
    if (field(*intent,"task_owner") != owner) throw Error("machine recapture intent belongs to another NAS task");
    const auto& source = field(*intent,"source");
    for (const auto key : {"ds_id","device_uuid","username","task_id","task_uuid"})
        if (field(source,key) != field(owner,key)) throw Error("recaptured source belongs to another NAS task");
    const auto& job = field(*intent,"job");
    const auto id = text(source,"capture_id");
    const auto run = number(source,"claimed_run");
    if (binding && *binding != source) throw Error("machine source changed during recapture retirement");
    if (const auto current = store.read("backup-job.pstream",backup_limits); current && *current != job)
        throw Error("backup job changed during recapture retirement");
    store.write(("service-recapture-"+std::to_string(run)+"-"+id+".pstream").c_str(),job,backup_limits);
    store.write(("service-source-unusable-"+id+".pstream").c_str(),source);
    if (const auto scripts = store.read(script_run_name(run).c_str())) {
        store.write(("backup-scripts-"+std::to_string(run)+"-"+id+".pstream").c_str(),*scripts);
        store.remove(script_run_name(run).c_str());
    }
    try { finish_machine_capture(text(source,"capture_directory")); }
    catch (const Error& error) { std::cerr << "Superseded snapshot cleanup deferred: " << error.what() << std::endl; }
    restore_machine_event(store,owner,source);
    store.remove("backup-job.pstream");
    store.remove("service-source.pstream");
    binding.reset();
    store.remove("service-machine-recapture.pstream");
}

std::optional<PreparedBackup> prepare_machine_event(Store& store, const Value& owner,
    const Value& task, std::uint64_t run, const Endpoint& endpoint, const SavedAuth& auth,
    const RegisterRunningResult& register_result) {
    auto intent = store.read("service-machine-event.pstream");
    if (!intent) {
        const auto catalog = machine_snapshots(store);
        const auto requested = backup_base_version(endpoint,auth,number(owner,"task_id"));
        const auto* base = catalog.base(text(task,"task_uuid"),requested);
        intent = Value{Value::Object{{"task_owner",owner},{"run",Value{run}},
            {"task_uuid",field(task,"task_uuid")},{"base_version_id",Value{base ? requested : 0}},
            {"base_snapshot_id",Value{base ? base->id : 0}},{"handshake_sent",Value{std::uint64_t{0}}}}};
        store.write("service-machine-event.pstream",*intent);
    }
    if (field(*intent,"task_owner") != owner || number(*intent,"run") != run ||
        field(*intent,"task_uuid") != field(task,"task_uuid"))
        throw Error("machine handshake belongs to another backup event");
    const auto event = backup_event_state(endpoint,auth,number(owner,"task_id"),run);
    if (!event || event->status == 3 || event->status == 5 || event->error_code) return {};
    const auto base = number(*intent,"base_version_id");
    if (!fields(*intent).contains("preparation")) {
        if (number(*intent,"handshake_sent") && event->run.version_id && event->run.result_id) {
            set(*intent,"preparation",prepared_backup_value({event->run,base}));
            store.write("service-machine-event.pstream",*intent);
        } else {
            const auto before_send = [&] {
                set(*intent,"handshake_sent",Value{std::uint64_t{1}});
                store.write("service-machine-event.pstream",*intent);
            };
            const auto prepared = base ? prepare_incremental_backup(endpoint,auth,number(owner,"task_id"),
                run,base,before_send) : prepare_full_backup(endpoint,auth,run,before_send);
            set(*intent,"preparation",prepared_backup_value({prepared,base}));
            store.write("service-machine-event.pstream",*intent);
            register_result({prepared.running_task_id,number(owner,"task_id"),
                prepared.version_id,prepared.result_id});
            return {}; // The job handshake first returns response 3.
        }
    }
    const auto prepared = prepared_backup_from_value(field(*intent,"preparation"));
    if (event->run.version_id != prepared.run.version_id || event->run.result_id != prepared.run.result_id ||
        event->run.data_format != prepared.run.data_format)
        throw Error("NAS machine preparation identity changed");
    // The job handshake / active-job checks and Resume-state updates
    // and event checkpoint lookup gate resource rotation.
    if (event->status != 1 || event->worker_active) return {};
    register_result({prepared.run.running_task_id,number(owner,"task_id"),
        prepared.run.version_id,prepared.run.result_id});
    return prepared;
}

std::vector<std::filesystem::path> machine_internal_files(Store& store);
void prepare_service_machine(Store& store, const Value& owner, std::optional<Value>& binding,
                             const Endpoint& endpoint, const SavedAuth& auth, const TaskView& task_view,
                             const RegisterRunningResult& register_result) {
    validate_machine_task_owner(owner,auth);
    retire_recaptured_machine(store,owner,binding);
    for (const auto& name : store.names()) {
        if (!name.starts_with("service-machine-cleanup-") || !name.ends_with(".pstream")) continue;
        const auto cleanup = *store.read(name.c_str());
        validate_machine_task_owner(field(cleanup,"task_owner"),auth);
        try { recover_machine_cleanup(store,name,cleanup); }
        catch (const Error& error) { std::cerr << "Capture cleanup deferred: " << error.what() << '\n'; }
    }
    // A transport retry can follow confirmed cleanup without restarting the
    // process. Reconcile its pending ownership before reserving another image.
    if (auto failed = recover_pending_machine(store,owner,binding)) {
        const auto pending = *store.read("service-machine-pending.pstream");
        const auto run = number(pending,"run");
        const auto event = backup_event_state(endpoint,auth,number(owner,"task_id"),run);
        if (event && event->worker_active) throw BackupRetry("previous NAS backup worker is still active");
        const auto scripts = store.read(script_run_name(run).c_str());
        const bool script_failed = scripts && backup_scripts_failed(*scripts);
        if (!script_failed && reusable_capture_snapshot(*failed)) {
            const auto directory = text(failed->reservation,"directory");
            const auto abandon = [&] {
                try { return inspect_machine_capture(directory,true); }
                catch (const Error& error) {
                    std::cerr << "Capture cleanup deferred: " << error.what() << '\n';
                    return inspect_machine_capture(directory);
                }
            };
            if (event && event->status != 3 && !event->error_code) {
                if (scripts) {
                    auto retained = *scripts;
                    validate_script_owner(retained,owner);
                    set(retained,"snapshot_reused",Value{std::uint64_t{1}});
                    store.write(script_run_name(run).c_str(),retained);
                }
                try {
                    (void)resume_machine_capture(directory,*failed,endpoint.cancelled,[] { return service_stop.load() || service_reload.load(); });
                    (void)recover_pending_machine(store,owner,binding);
                    return;
                } catch (const CaptureInterrupted&) { throw Cancelled(); }
                catch (const Error& error) {
                    std::cerr << "Snapshot reuse failed: " << error.what() << '\n';
                    *failed = abandon();
                }
            } else {
                *failed = abandon();
            }
        }
        const bool reporting = scripts && fields(*scripts).contains("nas_phase");
        // Cleanup progress is not a failed capture. In particular a lost
        // snapshot after reboot must follow the NAS checkpoint decision even
        // when best-effort retirement remains pending.
        const bool failed_here = failed->failure_disposition == "failure" &&
            (!fields(pending).contains("observation") || text(pending,"observation") != "uncertain");
        if (script_failed || reporting || (event && (failed_here || !event->resume_info.empty()))) {
            (void)finish_failed_machine(store,owner,*failed,endpoint,auth,
                !script_failed && !failed_here && event && !event->resume_info.empty());
            return;
        }
        // An interrupted acquisition with no NAS checkpoint is a new snapshot
        // attempt. Archive the old boundary, including any incomplete scripts,
        // before removing ownership so a crash repeats this same retirement.
        store.write(("machine-aborted-"+failed->id+".pstream").c_str(),capture_journal_value(*failed));
        if (failed->phase == CapturePhase::recovery_required)
            store.write(("service-machine-cleanup-"+failed->id+".pstream").c_str(),pending);
        if (scripts) {
            store.write(("backup-scripts-"+std::to_string(run)+"-"+failed->id+".pstream").c_str(),*scripts);
            store.remove(script_run_name(run).c_str());
        }
        store.remove("service-machine-pending.pstream");
        if (!event || event->status == 3 || event->error_code) {
            store.write(("service-machine-skipped-"+std::to_string(run)+".pstream").c_str(),
                Value{Value::Object{{"task_owner",owner},{"run",Value{run}}}});
        }
    }
    if (binding) {
        if (!number(*binding,"claimed_run")) {
            const auto job = store.read("backup-job.pstream",backup_limits);
            if (job && fields(*job).contains("service_source") &&
                field(*job,"service_source") == service_source_id(*binding)) return;
            try { (void)open_service_machine(*binding); }
            catch (const Error& error) {
                const auto id = text(*binding,"capture_id");
                const auto run = number(*binding,"queued_run");
                store.write(("service-source-unusable-"+id+".pstream").c_str(),*binding);
                if (const auto scripts = store.read(script_run_name(run).c_str())) {
                    validate_script_owner(*scripts,owner);
                    store.write(("backup-scripts-"+std::to_string(run)+"-"+id+".pstream").c_str(),*scripts);
                    store.remove(script_run_name(run).c_str());
                }
                restore_machine_event(store,owner,*binding);
                store.remove("service-source.pstream");
                binding.reset();
                std::cerr << "Unused capture source unavailable: " << error.what() << "; capturing again.\n";
            }
        }
        if (binding && number(*binding,"claimed_run")) {
            const auto claimed = number(*binding,"claimed_run");
            const auto job = store.read("backup-job.pstream",backup_limits);
            if (!job || number(*job,"running_task_id") != claimed ||
                !fields(*job).contains("service_source") || field(*job,"service_source") != service_source_id(*binding))
                throw Error("automatic capture cannot replace an unmatched claimed backup");
            const auto summary = backup_job_status(*job,auth);
            if (!number(summary,"terminal")) {
                try { (void)open_service_machine(*binding); return; }
                catch (const Error&) {
                    const auto event = backup_event_state(endpoint,auth,number(owner,"task_id"),claimed);
                    if (event && event->worker_active) throw BackupRetry("previous NAS backup worker is still active");
                    if (!event || event->status == 3 || event->error_code || !event->resume_info.empty()) return;
                    // the official agent recaptures only when the NAS has no persisted intervals.
                    store.write("service-machine-recapture.pstream",Value{Value::Object{
                        {"task_owner",owner},{"source",*binding},{"job",*job}}},backup_limits);
                    retire_recaptured_machine(store,owner,binding);
                }
            }
            if (binding && text(summary,"phase") != "retired") {
                const auto outcome = backup_result(endpoint,auth,number(*job,"task_id"),number(*job,"result_id"));
                if (outcome == "incomplete") return;
                if (outcome != text(summary,"phase")) throw Error("NAS outcome differs from the previous machine backup");
            }
            try { if (binding) finish_machine_capture(text(*binding,"capture_directory")); }
            catch (const Error& error) { std::cerr << "Machine snapshot completion deferred: " << error.what() << std::endl; }
        }
    }
    const auto task = number(owner,"task_id");
    const auto running = task_view.running(endpoint);
    auto queued = queued_machine_run(running,task);
    if (const auto intent = store.read("service-machine-event.pstream")) {
        if (field(*intent,"task_owner") != owner) throw Error("machine event belongs to another NAS task");
        const auto active_run = number(*intent,"run");
        const auto active = std::find_if(running.begin(),running.end(),
            [&](const Value& event) { return number(event,"id") == active_run; });
        if (active == running.end() || number(*active,"status") == 3 || number(*active,"status") == 5) {
            store.write(("service-machine-skipped-"+std::to_string(active_run)+".pstream").c_str(),
                Value{Value::Object{{"task_owner",owner},{"run",Value{active_run}}}});
            store.remove("service-machine-event.pstream");
            return;
        }
        queued = active_run;
    }
    if (!queued) return;
    if (binding && (number(*binding,"claimed_run") == *queued ||
        (fields(*binding).contains("queued_run") && number(*binding,"queued_run") == *queued))) return;
    if (store.read(service_run_archive(*queued).c_str())) return;
    const auto skipped = "service-machine-skipped-"+std::to_string(*queued)+".pstream";
    if (store.read(skipped.c_str())) return;
    if (const auto job = store.read("backup-job.pstream",backup_limits);
        job && !number(backup_job_status(*job,auth),"terminal")) throw BackupRetry("previous backup is awaiting its NAS outcome");
    bool assigned = false;
    Value execution_task;
    for (const auto& entry : task_view.tasks(endpoint)) if (number(entry,"id") == task) {
        assigned = true;
        (void)validate_task_policy(entry,true);
        execution_task = entry;
    }
    if (!assigned || field(execution_task,"task_uuid") != field(owner,"task_uuid"))
        throw Error("automatic machine task is no longer assigned with the same identity");
    const auto prepared = prepare_machine_event(store,owner,execution_task,*queued,endpoint,auth,register_result);
    if (!prepared) return;
    auto capture_endpoint = endpoint;
    capture_endpoint.prepared_backup = prepared;
    const auto queued_event = std::find_if(running.begin(),running.end(),
        [&](const Value& event) { return number(event,"id") == *queued; });
    const auto policy = backup_scripts(execution_task);
    const auto script_filename = script_run_name(*queued);
    auto script_journal = store.read(script_filename.c_str());
    if (script_journal) {
        validate_script_owner(*script_journal,owner);
        if (fields(*script_journal).contains("capture_id")) {
            validate_script_run(*script_journal,retained_backup_scripts(*script_journal),
                task,*queued,text(execution_task,"task_uuid"));
            const auto id = text(*script_journal,"capture_id");
            if (id.size() != 32 || id.find_first_not_of("0123456789abcdef") != std::string::npos)
                throw Error("invalid scripted capture identity");
            const auto directory = machine_working_directory()/("capture-"+id);
            const auto capture = inspect_machine_capture(directory);
            if (capture.id != id) throw Error("scripted capture directory belongs to another attempt");
            check_machine_capture_directory(capture.plan);
            // Recover the original handoff window using its typed capture ID
            // and owned journal, then let normal pending recovery decide from
            // the NAS checkpoint on the next service pass.
            Value pending{Value::Object{
                {"task_owner",owner},{"run",Value{*queued}},{"task_uuid",field(*script_journal,"task_uuid")},
                {"capture",capture_journal_value(capture)}}};
            if (fields(*script_journal).contains("local_snapshot_id")) {
                set(pending,"local_snapshot_id",field(*script_journal,"local_snapshot_id"));
                set(pending,"base_version_id",field(*script_journal,"base_version_id"));
                if (fields(*script_journal).contains("preparation"))
                    set(pending,"preparation",field(*script_journal,"preparation"));
            }
            store.write("service-machine-pending.pstream",pending);
            return;
        }
        validate_script_run(*script_journal,policy,task,*queued,text(execution_task,"task_uuid"));
    } else if (policy.enabled()) {
        script_journal = new_script_run(policy,task,*queued,text(execution_task,"task_uuid"));
        for (auto key : {"ds_id","device_uuid","username"}) set(*script_journal,key,field(owner,key));
        store.write(script_filename.c_str(),*script_journal);
    }
    if (binding) {
        const auto run = number(*binding,"claimed_run") ? number(*binding,"claimed_run") : number(*binding,"queued_run");
        store.write(service_run_archive(run).c_str(),*binding);
        store.remove("service-source.pstream"); binding.reset();
    }
    endpoint.service_status->backup_started(*queued);
    std::cout << "Capturing machine for NAS job " << *queued << '\n' << std::flush;
    QueuedCaptureOutcome outcome;
    const auto save_scripts = [&](const Value& saved) {
        try { store.write(script_filename.c_str(),saved); }
        catch (const std::exception& error) { throw CapturePersistenceError(error.what()); }
    };
    try {
    outcome = run_queued_machine_capture(capture_endpoint,task_view,task,*queued,[&](const std::function<bool()>& cancelled) {
        auto catalog = machine_snapshots(store);
        const auto intent = *store.read("service-machine-event.pstream");
        const auto base_version = prepared->base_version_id;
        const auto base_id = number(intent,"base_snapshot_id");
        const auto local_snapshot = catalog.prepare(task,text(execution_task,"task_uuid"),*queued,base_id,
            cleanup_machine_snapshot_resource,
            [&](const MachineSnapshotCatalog& saved) { save_machine_snapshots(store,saved); },
            prepared->run.version_id);
        preflight_service_machine();
        const MachineJobPlan job_plan{execution_task,*queued_event,
            service_machine_capture_provider().plan(machine_working_directory().string(),execution_task),prepared};
        service_machine_capture_provider().capture(ServiceMachineCaptureRequest{
            job_plan,
            [&](const CaptureJournal& reserved) {
                store.write("service-machine-pending.pstream",Value{Value::Object{
                    {"task_owner",owner},{"run",Value{*queued}},{"task_uuid",field(execution_task,"task_uuid")},
                    {"local_snapshot_id",Value{local_snapshot}},{"base_version_id",Value{base_version}},
                    {"preparation",prepared_backup_value(*prepared)},
                    {"capture",capture_journal_value(reserved)}}});
                catalog.attach(local_snapshot,reserved);
                save_machine_snapshots(store,catalog);
                if (script_journal) {
                    set(*script_journal,"capture_id",Value{reserved.id});
                    set(*script_journal,"local_snapshot_id",Value{local_snapshot});
                    set(*script_journal,"base_version_id",Value{base_version});
                    set(*script_journal,"preparation",prepared_backup_value(*prepared));
                    store.write(script_filename.c_str(),*script_journal);
                }
            },cancelled,[&](const Value& plan) {
                check_machine_capture_directory(plan);
                (void)validate_machine_task_policy(execution_task,plan,true);
            },SnapshotBoundaryHooks{
                [&] {
                    record_backup_start(*queued_event);
                    if (script_journal) {
                        set(*script_journal,"boundary_entered",Value{std::uint64_t{1}});
                        save_scripts(*script_journal);
                    }
                    try {
                        if (script_journal) run_backup_script_once(*script_journal,policy,true,
                            script_directory(*script_journal),
                            save_scripts,cancelled);
                    } catch (const BackupScriptFailed& error) { throw CaptureFailed(error.what()); }
                    catch (const Cancelled&) { throw CaptureStopRequested(); }
                },
                [&] {
                    // Post is application cleanup even if snapshot creation or
                    // NAS cancellation failed. Service shutdown still cancels it.
                    try {
                        if (script_journal) run_backup_script_once(*script_journal,policy,false,
                            script_directory(*script_journal),
                            save_scripts,
                            endpoint.cancelled);
                    } catch (const BackupScriptFailed& error) { throw CaptureFailed(error.what()); }
                    catch (const Cancelled&) { throw CaptureStopRequested(); }
                },
                [&](std::uint64_t elapsed) {
                    *endpoint.backup_performance = BackupPerformance{*queued,elapsed};
                },
                [&](const Value& plan) { return machine_task_missing_mounts(execution_task,plan); }},
                machine_internal_files(store),[] { return service_stop.load() || service_reload.load(); }});
    });
    } catch (...) {
        // A proven capture abort cannot hide an observer, shutdown, or cleanup
        // error on a later restart.
        if (auto pending = store.read("service-machine-pending.pstream")) {
            set(*pending,"observation",Value{std::string(
                endpoint.cancelled && endpoint.cancelled() ? "interrupted" : "uncertain")});
            store.write("service-machine-pending.pstream",*pending);
        }
        if (endpoint.cancelled && endpoint.cancelled()) throw;
        try { throw; }
        catch (const TransportError&) { throw; }
        catch (const Error& error) { throw BackupRetry(error.what()); }
    }
    if (outcome == QueuedCaptureOutcome::failed) {
        const auto failed = recover_pending_machine(store,owner,binding);
        if (!failed) throw Error("failed capture has no durable failure evidence");
        (void)finish_failed_machine(store,owner,*failed,endpoint,auth);
        return;
    }
    if (outcome == QueuedCaptureOutcome::cancelled) {
        // Persist retirement first: a crash before clearing pending ownership
        // must never publish this cancelled attempt or capture that run again.
        store.write(skipped.c_str(),Value{Value::Object{{"task_owner",owner},{"run",Value{*queued}}}});
        recover_pending_machine(store,owner,binding,false);
        std::cout << "Queued backup cancelled before preparation; capture retained and service continuing.\n" << std::flush;
        return;
    }
    recover_pending_machine(store,owner,binding);
}

#include "service_schedule_dispatch.inc"
#include "service_cache.inc"

void cleanup_removed_machine_tasks(Store& store, const Value::Array& tasks,
                                   std::optional<Value>& binding) {
    auto catalog = machine_snapshots(store);
    if (catalog.empty()) return;
    std::vector<std::string> uuids;
    for (const auto& task : tasks) uuids.push_back(text(task,"task_uuid"));
    const auto removed = catalog.removed_tasks(uuids);
    std::vector<Value> points;
    for (const auto& name : store.names())
        if (name.starts_with("backup-cache-") && name.ends_with(".pstream"))
            points.push_back(*store.read(name.c_str(),backup_limits));
    const auto clean_cache = [&](Value& point) {
        try {
            if (fields(point).contains("images"))
                for (const auto& image : std::get<Value::Array>(field(point,"images").data))
                    remove_backup_cache_image(cache_point_directory(point),field(image,"files"));
        } catch (const std::exception& error) {
            std::cerr << "Cached snapshot resource cleanup failed: " << error.what() << std::endl;
        }
        set(point,"cache_state",Value{std::string("merged")});
        save_cache_point(store,point);
    };
    const auto belongs = [](const MachineSnapshot& snapshot, std::string_view id) {
        return (snapshot.capture && snapshot.capture->id == id) ||
            std::any_of(snapshot.superseded.begin(),snapshot.superseded.end(),
                [&](const CaptureJournal& capture) { return capture.id == id; });
    };
    for (const auto& snapshot : removed) {
        // Resource cleanup orders snapshot resources, cached files,
        // then journal removal.
        cleanup_machine_snapshot_resource(snapshot);
        for (auto& point : points)
            if (fields(point).contains("source_capture") &&
                belongs(snapshot,text(field(point,"source_capture"),"id"))) clean_cache(point);
        catalog.erase(snapshot.id);
        save_machine_snapshots(store,catalog);
    }
    for (auto& point : points) {
        if (!fields(point).contains("source_capture") || !cache_point_ready(point)) continue;
        const auto* snapshot = catalog.capture(text(field(point,"source_capture"),"id"));
        if (!snapshot) continue;
        const auto task = std::find_if(tasks.begin(),tasks.end(),[&](const Value& current) {
            return text(current,"task_uuid") == snapshot->task_uuid;
        });
        if (task != tasks.end() && !backup_cache_policy(*task).enabled) clean_cache(point);
    }
    if (binding && std::any_of(removed.begin(),removed.end(),
        [&](const MachineSnapshot& snapshot) { return belongs(snapshot,text(*binding,"capture_id")); })) {
        store.write(("service-source-unusable-"+text(*binding,"capture_id")+".pstream").c_str(),*binding);
        store.remove("service-source.pstream");
        binding.reset();
    }
}

std::optional<Value> active_machine_task(Store& store,const SavedAuth& auth,
    const std::optional<Value>& binding,const Value::Array& tasks,const Value::Array& running) {
    // One worker owns in-flight preparation before accepting another task.
    // A completed binding does not pin subsequent NAS-assigned work.
    for (const auto name : {"service-machine-pending.pstream","service-machine-recapture.pstream",
                            "service-machine-event.pstream"}) {
        if (const auto intent = store.read(name,backup_limits)) {
            auto identity = field(*intent,"task_owner");
            validate_machine_task_owner(identity,auth);
            return identity;
        }
    }
    if (binding) {
        const auto job = store.read("backup-job.pstream",backup_limits);
        if (!number(*binding,"claimed_run") || !job || !number(backup_job_status(*job,auth),"terminal")) {
            Value identity{Value::Object{{"format",Value{std::uint64_t{2}}}}};
            for (const auto key : {"ds_id","device_uuid","username","task_id","task_uuid"})
                set(identity,key,field(*binding,key));
            validate_machine_task_owner(identity,auth);
            return identity;
        }
    }
    for (const auto& run : running) {
        if (number(run,"type") != 0 || number(run,"status") != 0) continue;
        const auto id = number(run,"id");
        if (store.read(service_run_archive(id).c_str()) ||
            store.read(("service-machine-skipped-"+std::to_string(id)+".pstream").c_str())) continue;
        const auto task = std::find_if(tasks.begin(),tasks.end(),[&](const Value& item) {
            return number(item,"id") == number(run,"task_id");
        });
        if (task != tasks.end()) return machine_task_identity(auth,*task);
    }
    return {};
}
void refresh_machine_cache_tasks(Store& store,Value::Array& tasks,
    const Endpoint& endpoint,const SavedAuth& auth) {
    for (auto& task : tasks) {
        refresh_cache_task(store,machine_task_identity(auth,task),tasks,endpoint,auth);
        if (const auto policy = store.read(cache_task_name(number(task,"id")).c_str(),backup_limits))
            task = field(*policy,"task");
    }
    for (const auto& name : store.names()) {
        if (!name.starts_with("service-cache-task-") || !name.ends_with(".pstream")) continue;
        const auto record = *store.read(name.c_str(),backup_limits);
        const auto& identity = field(record,"task_owner");
        validate_machine_task_owner(identity,auth);
        if (std::none_of(tasks.begin(),tasks.end(),[&](const Value& task) {
                return field(task,"task_uuid") == field(identity,"task_uuid");
            })) refresh_cache_task(store,identity,tasks,endpoint,auth);
    }
}
bool service_machine_cache_tick(Store& store,std::optional<Value>& binding,const SavedAuth& auth,
    const Endpoint& endpoint,const RegisterRunningResult& register_result,const TaskView& task_view,bool online,std::uint64_t connected_at) {
    for (const auto& name : store.names()) {
        if (!name.starts_with("service-cache-task-") || !name.ends_with(".pstream")) continue;
        const auto record = *store.read(name.c_str(),backup_limits);
        const auto& identity = field(record,"task_owner");
        validate_machine_task_owner(identity,auth);
        if (service_cache_tick(store,identity,binding,auth,endpoint,register_result,task_view,online,connected_at)) return true;
    }
    return false;
}

int service_command(int argc, char** argv) {
    const bool check = argc == 3 && std::string_view(argv[2]) == "check";
    const bool daemon = argc == 3 && std::string_view(argv[2]) == "start";
    if (!check && !daemon && (argc != 3 || std::string_view(argv[2]) != "run"))
        throw Error("usage: opensabba service start|run|check");
    std::optional<Signals> signals;
    if (!check) signals.emplace();
    std::optional<ServicePidFile> pid_file;
    if (daemon) pid_file.emplace("/run/opensabba.pid");
    if (!check) (void)disconnect_timeout();
    Store store; // Own token rotation for the service lifetime. Atomic readers remain allowed.
    auto session = store.read("session.pstream");
    if (!session) throw Error("no saved session; log in first");
    if (text(*session, "registration_state") != "confirmed")
        throw Error("confirm registration or reconnect before starting the service");
    auto inbox = load_inbox(store, auth_from(*session));
    auto binding = store.read("service-source.pstream");
    if (binding) validate_service_source(*binding, auth_from(*session));
    const auto readiness = [] {
        return service_machine_capture_provider().driver_status();
    };
    if (check) {
        const bool pending = store.read("service-machine-pending.pstream").has_value();
        const std::string state = pending ? "capture-recovery-required" :
            readiness() == DriverStatus::enabled ? "ready" : "resume-required";
        print_json(std::cout,Value{Value::Object{{"state",Value{state}},{"nas_checked",Value{false}}}});
        std::cout << '\n';
        return 0;
    }
    const auto service_status = std::make_shared<ServiceStatus>();
    ServiceControl control(store,*session,service_status);
    ServiceSchedules schedules(store,auth_from(*session));
    auto pause = [](std::chrono::seconds duration, const auto& cancelled) {
        const auto deadline = std::chrono::steady_clock::now() + duration;
        while (!cancelled() && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
    };
    unsigned startup_retry = 1;
    const auto backup_performance = std::make_shared<BackupPerformance>();
    while (!service_stop) {
        try {
            if (const auto pending = store.read("service-machine-pending.pstream")) {
                const auto& identity = field(*pending,"task_owner");
                validate_machine_task_owner(identity,auth_from(*session));
                recover_pending_machine(store,identity,binding);
            }
            break;
        } catch (const Cancelled&) {
            if (!service_stop && !service_reload) throw;
            if (service_reload) break;
        } catch (const TransportError& error) {
            std::cerr << "Startup connection interrupted: " << error.what()
                      << "; retrying in " << startup_retry << " seconds.\n";
            pause(std::chrono::seconds{startup_retry}, [] { return service_stop || service_reload; });
            startup_retry = std::min(startup_retry * 2, 60U);
        } catch (const BackupRetry& error) {
            std::cerr << "Capture cleanup deferred: " << error.what() << '\n';
            // Keep the network agent online while the owned cleanup retries.
            break;
        }
    }
    if (service_stop) { std::cout << "Service stopped.\n"; return 0; }
    std::cout << "Service starting with NAS-assigned machine tasks and persistent change tracking.\n" << std::flush;
    std::atomic<DriverStatus> driver{DriverStatus::disabled};
    auto withdraw_readiness = [&] {
        driver = DriverStatus::disabled;
        try {
            auto endpoint = endpoint_from(*session);
            endpoint.timeout = std::chrono::seconds{5};
            heartbeat(endpoint, auth_from(*session), DriverStatus::disabled);
        } catch (const std::exception& error) {
            std::cerr << "Could not withdraw service driver readiness: " << error.what() << '\n';
        }
    };
    // the official agent resume offsets and upload/ACK queues live only for this process.
    std::map<std::uint64_t,Value> file_restores;
    bool first_token_auth_done = false;
    unsigned retry = 1;
    std::uint64_t cache_connected_at = 0;
    std::atomic<std::uint64_t> cache_last_online{0};
    // The store is exclusively held for the lifetime of this service. Recheck
    // retention once per completed generation, and again after process restart.
    std::optional<std::string> cleaned_generation;
    try {
        while (!service_stop) {
            control.apply_generated_event(store,auth_from(*session));
            if (service_reload.exchange(false)) {
                control.apply_edit(store,*session);
                retry = 1;
                historical_service_event(storage_path(false),HistoricalEvent::reload);
                std::cout << "Service reload: reconnecting and refreshing NAS tasks.\n" << std::flush;
            }
            std::atomic_bool cycle_stop{false};
            auto endpoint = endpoint_from(*session);
            endpoint.backup_performance = backup_performance;
            endpoint.service_status = service_status;
            endpoint.cancelled = [&] { return service_stop || service_reload || cycle_stop.load(); };
            // The connection worker stops all old workers on an edited
            // connection. Durable work resumes after settings are committed.
            auto observer = endpoint;
            observer.cancelled = [&] { return service_stop || cycle_stop.load() || service_reload.load(); };
            const auto started = std::chrono::steady_clock::now();
            try {
                historical_service_event(storage_path(false),HistoricalEvent::connection_attempt);
                driver = readiness();
                control.authenticate([&] {
                    const auto result = reconnect(endpoint, auth_from(*session), device_metadata(),
                                                  driver.load(), !first_token_auth_done);
                    first_token_auth_done = true;
                    set(*session, "token", Value{result.token});
                    set(*session, "ds_id", Value{result.ds_id});
                    store.write("session.pstream", *session);
                    control.publish_connection(*session);
                });
                auto auth = auth_from(*session);
                struct TokenState { std::mutex mutex; std::string value; };
                auto current_token = std::make_shared<TokenState>();
                current_token->value = auth.token;
                auth.token_value = [current_token] {
                    std::lock_guard lock(current_token->mutex);
                    return current_token->value;
                };
                service_status->connected();
                std::cout << "Service connected; saved session updated.\n" << std::flush;
                cache_connected_at = static_cast<std::uint64_t>(std::time(nullptr));
                cache_last_online = cache_connected_at;
                historical_service_event(storage_path(false),HistoricalEvent::connected);
                TimeoutChecker timezone_refresh(180);
                if (timezone_refresh.check(std::time(nullptr))) refresh_server_time(store,endpoint,auth);
                // Token authentication and heartbeat dispatch have independent clocks.
                auto routine = std::async(std::launch::async,[&,timezone_refresh = std::move(timezone_refresh)]() mutable {
                    try {
                        while (!endpoint.cancelled()) {
                            pause(std::chrono::seconds{60},endpoint.cancelled);
                            if (endpoint.cancelled()) break;
                            control.authenticate([&] {
                                const auto result = reconnect(endpoint,auth,device_metadata(),driver.load(),false);
                                {
                                    std::lock_guard lock(current_token->mutex);
                                    current_token->value = result.token;
                                }
                                set(*session,"token",Value{result.token});
                                store.write("session.pstream",*session);
                                control.publish_connection(*session);
                            });
                            cache_last_online = static_cast<std::uint64_t>(std::time(nullptr));
                            if (timezone_refresh.check(std::time(nullptr))) refresh_server_time(store,endpoint,auth);
                        }
                    } catch (...) { cycle_stop = true; throw; }
                });
                auto beats = std::async(std::launch::async,[&] {
                    try {
                        while (!endpoint.cancelled()) {
                            heartbeat(endpoint,auth,driver.load());
                            cache_last_online = static_cast<std::uint64_t>(std::time(nullptr));
                            pause(std::chrono::seconds{5+std::rand()%3},endpoint.cancelled);
                        }
                    } catch (...) { cycle_stop = true; throw; }
                });
                std::exception_ptr observation_error;
                try {
                    with_service_events(store,inbox,observer,auth,cycle_stop,schedules,
                        [&](ServiceObservations& observations,const RegisterRunningResult& register_result,const auto& retry_result) {
                            const TaskView task_view{
                                [&](const Endpoint&) { return observations.snapshot().execution_tasks; },
                                [&](const Endpoint&) { return observations.snapshot().running; }};
                            std::optional<Value> previous;
                            while (!observer.cancelled()) {
                                control.apply_generated_event(store,auth);
                                retry_result();
                                const auto observed = observations.snapshot();
                                const auto time_state = store.read("server-time.pstream");
                                service_status->tasks(observed.tasks,
                                    time_state ? server_time_offset(server_time_from_value(*time_state)) : std::nullopt);
                                Value snapshot{Value::Object{
                                    {"task_list",Value{observed.tasks}},
                                    {"running_task_list",Value{observed.running}}}};
                                if (!previous || *previous != snapshot) {
                                    std::cout << "Tasks refreshed: " << observed.tasks.size()
                                              << " assigned, " << observed.running.size()
                                              << " current NAS jobs." << std::endl;
                                    previous = snapshot;
                                }
                                const auto& current_runs = observed.running;
                                std::set<std::uint64_t> active_tasks;
                                for (const auto& run : current_runs)
                                    if (number(run,"type") == 0 && number(run,"status") < 3)
                                        active_tasks.insert(number(run,"task_id"));
                                schedules.active(std::move(active_tasks));
                                const bool cache_owned = [&] {
                                    auto restore_runs = std::get<Value::Array>(field(snapshot,"running_task_list").data);
                                    // Finished jobs may still have process-local activity to report.
                                    for (const auto& [id,saved] : file_restores) {
                                        if (std::get<Value::Array>(field(saved,"pending_logs").data).empty()) continue;
                                        if (std::none_of(restore_runs.begin(),restore_runs.end(),
                                            [&](const Value& job) { return number(job,"id") == id; }))
                                            restore_runs.push_back(field(saved,"running"));
                                    }
                                    for (const auto& job : restore_runs) {
                                        if (number(job,"type") != 1 || endpoint.cancelled()) continue;
                                        const auto id = number(job,"id");
                                        std::optional<Value> saved;
                                        if (const auto found = file_restores.find(id); found != file_restores.end())
                                            saved = found->second;
                                        const auto outcome = run_service_file_restore(endpoint,auth,task_view,job,saved,[&](const Value& record) {
                                            file_restores[id] = record;
                                            service_status->file_restore(record);
                                            if (text(record,"phase") == "download") {
                                                const auto summary = file_restore_job_status(record,auth);
                                                register_result({number(summary,"running_task_id"),number(summary,"task_id"),
                                                    number(summary,"version_id"),number(summary,"result_id")});
                                            }
                                            if (!saved || field(*saved,"phase") != field(record,"phase") ||
                                                number(*saved,"current_size") != number(record,"current_size") ||
                                                number(*saved,"current_count") != number(record,"current_count")) {
                                                std::cout << "File restore " << number(job,"id") << ": " << text(record,"phase")
                                                          << ", " << number(record,"current_size") << " bytes, "
                                                          << number(record,"current_count") << " records.\n" << std::flush;
                                            }
                                            saved = record;
                                        });
                                        std::cout << "File restore " << number(job,"id") << ": " << outcome << ".\n" << std::flush;
                                        if ((outcome == "complete" || outcome == "partial" ||
                                             outcome == "error" || outcome == "cancel") &&
                                            std::get<Value::Array>(field(file_restores.at(id),"pending_logs").data).empty())
                                            file_restores.erase(id);
                                    }
                                    cleanup_removed_machine_tasks(store,
                                        std::get<Value::Array>(field(snapshot,"task_list").data),binding);
                                    driver = readiness();
                                    driver = DriverStatus::disabled;
                                    if (service_machine_cache_tick(store,binding,auth,endpoint,register_result,task_view,true,cache_connected_at))
                                        return true;
                                    service_schedule_tick(store,auth,endpoint,
                                        std::get<Value::Array>(field(snapshot,"task_list").data),current_runs,binding,register_result);
                                    if (const auto identity = active_machine_task(store,auth,binding,
                                        std::get<Value::Array>(field(snapshot,"task_list").data),current_runs)) {
                                        try { prepare_service_machine(store,*identity,binding,endpoint,auth,task_view,register_result); }
                                        catch (const BackupRetry& error) {
                                            std::cerr << "Backup event deferred: " << error.what() << "; retrying." << std::endl;
                                            return false;
                                        }
                                    }
                                    if (binding) {
                                        dispatch_source(store, *binding, endpoint, auth, register_result,task_view);
                                        if (number(*binding,"claimed_run")) {
                                            const auto job = store.read("backup-job.pstream",backup_limits);
                                            if (job && number(backup_job_status(*job,auth),"terminal")) {
                                                try { finish_machine_capture(text(*binding,"capture_directory")); }
                                                catch (const Error& error) { std::cerr << "Machine snapshot cleanup deferred: " << error.what() << std::endl; }
                                            }
                                        }
                                    }
                                    return false;
                                }();
                                if (cache_owned) {
                                    pause(std::chrono::seconds{5},observer.cancelled);
                                    continue;
                                }
                                driver = readiness();
                                if (observer.cancelled()) break;
                                // The agent ticks every second
                                // after every handler outcome, including an empty queue
                                // and terminal error. The control worker's long-poll result is
                                // an observation; neither its outstanding request nor a
                                // reply from an earlier handler can park this worker.
                                pause(std::chrono::seconds{1}, [&] {
                                    return observer.cancelled() || control.event_pending();
                                });
                            }
                    });
                } catch (...) { observation_error = std::current_exception(); }
                cycle_stop = true;
                std::exception_ptr routine_error;
                for (auto* worker : {&beats,&routine}) {
                    try { worker->get(); }
                    catch (const Cancelled&) {}
                    catch (...) { if (!service_stop) routine_error = std::current_exception(); }
                }
                if (routine_error) std::rethrow_exception(routine_error);
                if (observation_error) std::rethrow_exception(observation_error);
            } catch (const Cancelled&) {
                if (!service_stop && !service_reload) throw;
            } catch (const TransportError& error) {
                service_status->disconnected();
                if (service_stop) break;
                cache_connected_at = 0;
                for (const auto& name : store.names()) {
                    if (!name.starts_with("service-cache-task-") || !name.ends_with(".pstream")) continue;
                    auto policy = *store.read(name.c_str(),backup_limits);
                    if (cache_last_online.load() > number(policy,"last_online")) {
                        set(policy,"last_online",Value{cache_last_online.load()});
                        store.write(name.c_str(),policy,backup_limits);
                    }
                }
                auto offline = endpoint;
                offline.cancelled = [] { return service_stop || service_reload; };
                const TaskView offline_view{
                    [](const Endpoint&) { return Value::Array{}; },
                    [](const Endpoint&) { return Value::Array{}; }};
                try { (void)service_machine_cache_tick(store,binding,auth_from(*session),
                    offline,[&](EventInbox::RunningResult result) {
                        inbox.register_running_result(std::move(result));
                    },offline_view,false,0); }
                catch (const BackupRetry& deferred) { std::cerr << "Offline capture deferred: " << deferred.what() << '\n'; }
                catch (const Error& failure) { std::cerr << "Offline cache failed: " << failure.what() << '\n'; }
                historical_service_event(storage_path(false),HistoricalEvent::connection_interrupted);
                if (std::chrono::steady_clock::now() - started > std::chrono::minutes{1}) retry = 1;
                std::cerr << "Connection interrupted: " << error.what()
                          << "; reconnecting in " << retry << " seconds.\n";
                pause(std::chrono::seconds{retry}, [&] {
                    return service_stop || service_reload || control.event_pending();
                });
                retry = std::min(retry * 2, 60U);
            } catch (const BackupRetry& error) {
                if (service_stop) break;
                std::cerr << "Backup event deferred: " << error.what() << "; retrying.\n";
                pause(std::chrono::seconds{5}, [] { return service_stop || service_reload; });
            }
        }
    } catch (...) {
        withdraw_readiness();
        throw;
    }
    withdraw_readiness();
    historical_service_event(storage_path(false),HistoricalEvent::stopped);
    std::cout << "Service stopped.\n";
    return 0;
}
} // namespace

int export_logs_command(const std::filesystem::path& output, bool quiet) {
    return export_log_archive(output,quiet);
}

void load_saved_server_time() {
    if (std::filesystem::symlink_status(storage_path(false)).type() == std::filesystem::file_type::not_found) return;
    Store store(false,false);
    if (const auto saved = store.read("server-time.pstream")) set_server_time(server_time_from_value(*saved));
}

Endpoint saved_endpoint() {
    Store store(false);
    auto session = store.read("session.pstream");
    if (!session) throw Error("no saved session; use --connect --address HOST --username USER");
    return endpoint_from(*session);
}

int session_command(int argc, char** argv,const SessionInvocation& invocation) {
    load_saved_server_time();
    const std::string_view command(argv[1]);
    if (command == "service") return service_command(argc, argv);
    if (command == "reload") {
        return edit_connection_command(argc,argv,invocation);
    }
    if (command == "status" || command == "logout") {
        bool disconnect = command == "logout", stop = command == "logout", quiet = false, skip_portal = false;
        LoginCredentials admin;
        bool password_supplied = false;
        struct WipeAdmin {
            LoginCredentials& value;
            ~WipeAdmin() {
                OPENSSL_cleanse(value.password.data(),value.password.size());
                OPENSSL_cleanse(value.otp.data(),value.otp.size());
            }
        } wipe_admin{admin};
        for (int i = 2; i < argc; ++i) {
            const std::string_view option(argv[i]);
            if (command == "status" && option == "--skip-portal" && !skip_portal) skip_portal = true;
            else if (command == "logout" && option == "--quiet" && !quiet) quiet = true;
            else if (command == "logout" && (option == "--username" || option == "--password" ||
                     option == "--otp")) {
                if (++i == argc) throw Error("missing option value");
                if (option == "--username") admin.username = argv[i];
                else if (option == "--password") { admin.password = argv[i]; password_supplied = true; }
                else if (option == "--otp") { admin.otp = argv[i]; }
            }
            else throw Error("usage: --status | --logout [--username USER --password PASSWORD]");
        }
        const bool authorize = command == "logout";
        Store store(false);
        if (command == "status") {
            const auto status = request_service_status(store,skip_portal);
            if ((number(status,"status")&0xf000) == 0x1000) throw CliError(5,"No connection found");
            print_service_status(std::cout,status);
            return 0;
        }
        const bool owns_session = authorize && store.try_lock();
        std::string authorization;
        std::optional<SavedAuth> authorized_identity;
        if (authorize) {
            const auto session = store.read("session.pstream");
            if (!session) throw CliError(5,"No connection found");
            const bool unattended = quiet || invocation.noninteractive_credentials;
            if (unattended && (admin.username.empty() || !password_supplied))
                throw CliError(1,"quiet logout requires --username and --password");
            if (!unattended) {
                if (!terminal_confirmation("Once signed out, this device will be disconnected. Are you sure you want to continue? [y/n](default: y):")) {
                    std::cout << "Cancelled.\n";
                    return 0;
                }
            }
            if (admin.username.empty()) admin.username = secret("Enter admin username:",false);
            if (!password_supplied)
                admin.password = secret("Enter admin password:",false);
            if (admin.password.empty()) throw Error("password cannot be empty");
            const auto endpoint = endpoint_from(*session);
            const auto auth = auth_from(*session);
            auto authorize_admin = [&] {
                if (owns_session) authorize_logout(endpoint,auth,admin);
                else authorization = request_service_authorization(store,admin);
            };
            try {
                authorize_admin();
            } catch (const ServerError& error) {
                if (unattended || error.code != 4101) throw CliError(3,error.what());
                admin.otp = secret("OTP retry (Enter to cancel): ",true);
                try { authorize_admin(); }
                catch (const ServerError& retry) { throw CliError(3,retry.what()); }
            }
            authorized_identity = auth;
            disconnect = true;
            stop = true;
        }
        if (command == "logout") {
            if (!owns_session) {
                request_service_control(store, "stop:" + authorization);
                std::cout << "Service stop requested; waiting for session ownership.\n" << std::flush;
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{30};
                while (!store.try_lock()) {
                    if (std::chrono::steady_clock::now() >= deadline)
                        throw Error("service has not released session ownership; logout not performed; inspect service and retry");
                    std::this_thread::sleep_for(std::chrono::milliseconds{100});
                }
            }
            const auto session = store.read("session.pstream");
            if (session) {
                const auto auth = auth_from(*session);
                if (authorized_identity && (authorized_identity->username != auth.username ||
                    authorized_identity->device_uuid != auth.device_uuid || authorized_identity->ds_id != auth.ds_id))
                    throw Error("connection changed after administrator authorization; logout not performed");
                if (const auto job = store.read("backup-job.pstream",backup_limits);
                    job && !number(backup_job_status(*job,auth),"terminal")) {
                    try {
                        recover_backup_job(endpoint_from(*session),auth,*job,true,[&](const Value& saved) {
                            store.write("backup-job.pstream",saved,backup_limits);
                        });
                    } catch (const Error& error) {
                        throw Error("unfinished backup could not be cancelled: "+std::string(error.what())+"; saved token retained");
                    }
                }
                if (const auto pending = store.read("service-machine-pending.pstream")) {
                    const auto& identity = field(*pending,"task_owner");
                    validate_machine_task_owner(identity,auth);
                    auto binding = store.read("service-source.pstream");
                    (void)recover_pending_machine(store,identity,binding,false);
                }
                for (const auto& name : store.names()) {
                    if (!name.starts_with("service-machine-cleanup-") || !name.ends_with(".pstream")) continue;
                    const auto cleanup = *store.read(name.c_str());
                    validate_machine_task_owner(field(cleanup,"task_owner"),auth);
                    recover_machine_cleanup(store,name,cleanup);
                }
                if (const auto binding = store.read("service-source.pstream");
                    binding) {
                    validate_service_source(*binding,auth);
                    finish_machine_capture(text(*binding,"capture_directory"));
                }
                if (disconnect) {
                    Signals signals;
                    auto endpoint = endpoint_from(*session);
                    endpoint.cancelled = [] { return service_stop || service_reload; };
                    try {
                        unlink_connection(endpoint, auth);
                        std::cout << "NAS disconnect acknowledged. ";
                    } catch (const Error& error) {
                        if (!authorized_identity) throw;
                        std::cerr << "NAS disconnect failed: " << error.what() << '\n';
                    }
                }
            }
            store.logout();
            if (authorized_identity) {
                store.remove("events.pstream");
                for (const auto& name : store.names())
                    if (name.starts_with("service-cache-task-") && name.ends_with(".pstream")) store.remove(name.c_str());
                store.remove("service-source.pstream");
            }
            std::cout << "Saved token removed locally; device identity retained. Server token not revoked.\n";
            return 0;
        }
    }
    if (command != "connect") throw Error("unsupported session command");
    Endpoint endpoint;
    LoginCredentials credentials;
    std::string proxy_username;
    bool quiet = false;
    bool supplied_password = false, supplied_proxy_password = false;
    std::string proxy_password;
    int index = 2;
    for (; index < argc; index += 2) {
        const std::string_view option(argv[index]);
        if (option == "--quiet") {
            if (quiet) throw Error("duplicate --quiet");
            quiet = true;
            --index;
            continue;
        }
        if (index + 1 == argc) throw Error("missing option value");
        if (option == "--address") endpoint.host = argv[index+1];
        else if (option == "--username") credentials.username = argv[index + 1];
        else if (option == "--password") {
            credentials.password = argv[index+1];
            supplied_password = true;
        }
        else if (option == "--otp") {
            credentials.otp = argv[index+1];
        }
        else if (option == "--proxy-password") {
            proxy_password = argv[index+1];
            supplied_proxy_password = true;
        }
        else if (option == "--proxy-address") endpoint.proxy_host = argv[index+1];
        else if (option == "--proxy-username") proxy_username = argv[index+1];
        else if (option == "--proxy-port")
            endpoint.proxy_port = static_cast<std::uint16_t>(option_number(argv[index+1],65535));
        else throw Error("unknown connect option");
    }
    const bool unattended = quiet || invocation.noninteractive_credentials;
    if (unattended && (endpoint.host.empty() || credentials.username.empty() || !supplied_password))
        throw Error("quiet connect requires --address, --username and --password");
    if (endpoint.host.empty()) endpoint.host = secret("Enter server address:", false);
    if (credentials.username.empty()) credentials.username = secret("Enter username:", false);
    if (endpoint.proxy_host.empty() != (endpoint.proxy_port == 0))
        throw Error("proxy host and port must be supplied together");
    if (supplied_proxy_password && (proxy_username.empty() || endpoint.proxy_host.empty()))
        throw Error("proxy credentials require --proxy-username and a proxy endpoint");
    if (!proxy_username.empty() && !supplied_proxy_password && unattended)
        throw Error("quiet proxy authentication requires --proxy-password");
    Store store;
    auto identity = store.read("identity.pstream");
    if (!identity) {
        identity = Value{Value::Object{{"device_uuid", Value{new_uuid()}}}};
        store.write("identity.pstream", *identity);
    }
    credentials.device_uuid = text(*identity, "device_uuid");
    const auto device = device_metadata();
    credentials.host_name = device.host_name;
    credentials.os_name = device.os_name;
    struct Wipe {
        LoginCredentials& credentials;
        Endpoint& endpoint;
        ~Wipe() {
            OPENSSL_cleanse(credentials.password.data(), credentials.password.size());
            OPENSSL_cleanse(credentials.otp.data(), credentials.otp.size());
            if (endpoint.proxy_credentials)
                OPENSSL_cleanse(endpoint.proxy_credentials->password.data(), endpoint.proxy_credentials->password.size());
        }
    } wipe{credentials, endpoint};
    if (!supplied_password)
        credentials.password = secret("Enter password:", false);
    if (credentials.password.empty()) throw Error("password cannot be empty");
    if (!proxy_username.empty()) {
        endpoint.proxy_credentials = ProxyCredentials{proxy_username,
            supplied_proxy_password ? std::move(proxy_password) :
            secret("Enter proxy user password:", true)};
    }
    if (invocation.prepare_endpoint) invocation.prepare_endpoint(endpoint);
    configure_certificate_trust(endpoint,!unattended,quiet);
    const auto authenticate = [&] {
        try {
            return login(endpoint, credentials);
        } catch (const CertificateError&) {
            throw;
        } catch (const CliError&) {
            throw;
        } catch (const ServerError&) {
            throw;
        } catch (const Error& error) {
            throw CliError(3, error.what());
        }
    };
    const auto result = [&] {
        try {
            return authenticate();
        } catch (const ServerError& error) {
            if (unattended || (error.code != 4101 && error.code != 4102)) throw;
            std::cerr << error.what() << '\n';
            OPENSSL_cleanse(credentials.otp.data(), credentials.otp.size());
            credentials.otp = secret("OTP retry (Enter to cancel): ", true);
            if (credentials.otp.empty()) throw;
            // One retry only; do not loop on repeated failures or retry passwords.
            return authenticate();
        }
    }();
    Value session{Value::Object{
        {"format", Value{std::uint64_t{2}}}, {"host", Value{endpoint.host}},
        {"port", Value{std::uint64_t{endpoint.port}}}, {"ca_file", Value{endpoint.ca_file}},
        {"username", Value{credentials.username}}, {"device_uuid", Value{credentials.device_uuid}},
        {"token", Value{result.token}}, {"ds_id", Value{result.ds_id}},
        {"auth_type", Value{result.auth_type}},
        {"registration_state", Value{std::string(result.auth_type == 5 ? "confirmed" : "pending")}},
    }};
    if (result.backup_type) {
        set(session, "backup_type", Value{*result.backup_type});
        set(session, "task_template", result.task_template);
    }
    if (!endpoint.proxy_host.empty()) {
        set(session, "proxy_host", Value{endpoint.proxy_host});
        set(session, "proxy_port", Value{std::uint64_t{endpoint.proxy_port}});
    }
    if (endpoint.proxy_credentials) {
        set(session,"proxy_username",Value{endpoint.proxy_credentials->username});
        set(session,"proxy_password",Value{endpoint.proxy_credentials->password});
        set(session,"proxy_auth",Value{endpoint.proxy_credentials->scheme});
        if (endpoint.proxy_credentials->scheme == "ntlm") {
            set(session,"proxy_domain",Value{endpoint.proxy_credentials->domain});
            set(session,"proxy_workstation",Value{endpoint.proxy_credentials->workstation});
            set(session,"proxy_ntlm_version",Value{std::uint64_t{endpoint.proxy_credentials->ntlm_version}});
        }
    }
    store.write("session.pstream", session);
    if (result.auth_type != 5) complete_connection(store,session,endpoint,quiet,result.confirmation_display);
    else if (!quiet) std::cout << "Successfully connected\n";
    return 0;
}
#endif
} // namespace opensabba
