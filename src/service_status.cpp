#include "opensabba/service_status.hpp"
#include "opensabba/server_time.hpp"
#include "opensabba/task_schedule.hpp"
#include <ostream>
#include <iomanip>
#include <sstream>

namespace opensabba {
namespace {
using pstream::Value;
const Value::Object& fields(const Value& value) { return std::get<Value::Object>(value.data); }
std::uint64_t number(const Value& value, const char* key) { return std::get<std::uint64_t>(fields(value).at(key).data); }
std::string text(const Value& value, const char* key) { return std::get<std::string>(fields(value).at(key).data); }
}
ServiceStatus::ServiceStatus() : backup_result_(Value{Value::Object{
    {"last_success_time",Value{std::uint64_t{0}}},{"last_backup_status",Value{std::string{}}}}}) {}
void ServiceStatus::connected() {
    std::lock_guard lock(mutex_);
    status_ = 0x2000;
    content_.clear();
    run_ = 0;
}
void ServiceStatus::disconnected() {
    std::lock_guard lock(mutex_);
    status_ = 0xf000;
    content_ = Value::Object{{"error",Value{Value::Object{{"code",Value{std::uint64_t{53248}}}}}}};
}
void ServiceStatus::progress(std::uint64_t current, std::uint64_t total, std::uint64_t status, std::time_t now) {
    if (now == progress_at_) return;
    const auto previous = current_;
    const auto previous_at = progress_at_;
    current_ = current;
    total_ = total;
    progress_at_ = now;
    speed_ = previous_at && current >= previous ? (current-previous)/static_cast<std::uint64_t>(now-previous_at) : 0;
    if (previous_at && current >= previous) status_ = status;
}
void ServiceStatus::result(const Value& result, std::time_t now) {
    std::lock_guard lock(mutex_);
    const auto& reply = fields(result);
    if (reply.contains("backup_result")) backup_result_ = reply.at("backup_result");
    if (!reply.contains("running_task_result")) return;
    const auto& activity = reply.at("running_task_result");
    if (text(activity,"job_action") == "unknown" || text(activity,"status") == "incomplete") return;
    status_ = 0x2000;
    content_.clear();
    progress(0,0,0x2000,now);
}
void ServiceStatus::backup(const Value& job, std::time_t) {
    std::lock_guard lock(mutex_);
    const auto phase = text(job,"phase");
    if (phase == "complete" || phase == "partial" || phase == "error" || phase == "cancel") {
        status_ = 0x2000;
        content_.clear();
        return;
    }
    const auto run = number(job,"running_task_id");
    if (run_ != run) { run_ = run; status_ = 0x3000; content_.clear(); }
    // A job save supplies lifecycle and identity, never transfer counters.
}
void ServiceStatus::backup_transfer(std::uint64_t current, std::uint64_t total, std::time_t now) {
    std::lock_guard lock(mutex_);
    progress(current,total,0x3000,now);
}
void ServiceStatus::file_restore(const Value& job, std::time_t now) {
    std::lock_guard lock(mutex_);
    const auto phase = text(job,"phase");
    if (phase == "complete" || phase == "partial" || phase == "error" || phase == "cancel") {
        status_ = 0x2000;
        content_.clear();
        return;
    }
    const auto run = number(job,"running_task_id");
    if (run_ != run) { run_ = run; status_ = 0x4000; content_.clear(); }
    const auto& task = fields(fields(job).at("running")).at("file_restore_task");
    progress(number(job,"current_size"),number(task,"total_size"),0x4000,now);
}
void ServiceStatus::tasks(const Value::Array& tasks, std::optional<std::int64_t> server_offset, std::time_t now) {
    std::uint64_t next = 0;
    if (server_offset) for (const auto& task : tasks) {
        const auto scheduled = next_task_schedule(task,static_cast<std::uint64_t>(now),*server_offset);
        if (scheduled && (!next || *scheduled < next)) next = *scheduled;
    }
    std::lock_guard lock(mutex_);
    next_ = next;
}
Value ServiceStatus::snapshot() const {
    std::lock_guard lock(mutex_);
    auto content = content_;
    auto last = backup_result_;
    if (fields(last).contains("last_success_time")) {
        auto& time = std::get<Value::Object>(last.data).at("last_success_time");
        const auto epoch = std::get<std::uint64_t>(time.data);
        if (epoch) time = Value{static_cast<std::uint64_t>(to_client_time(static_cast<std::int64_t>(epoch)))};
    }
    content["last_backup_result"] = std::move(last);
    content["next_backup_time"] = Value{next_};
    if ((status_&0xf000) == 0x3000 || (status_&0xf000) == 0x4000)
        content["transfer"] = Value{Value::Object{{"progress",Value{current_}},{"total",Value{total_}},{"speed",Value{speed_}}}};
    return Value{Value::Object{{"status",Value{status_}},{"content",Value{std::move(content)}}}};
}
}

namespace opensabba {
namespace {
std::string date(std::uint64_t epoch) {
    if (!epoch) return " - ";
    const auto time = static_cast<std::time_t>(epoch);
    char result[32];
    const auto* local = std::localtime(&time);
    if (!local) return {};
    std::strftime(result,sizeof(result),"%Y-%m-%d %H:%M",local);
    return result;
}
std::string units(std::uint64_t bytes) {
    double value;
    const char* unit;
    if (bytes >= 1073741824000ULL) { value = static_cast<double>(bytes>>30)/1024; unit = "TB"; }
    else if (bytes >= 1048576000) { value = static_cast<double>(bytes>>20)/1024; unit = "GB"; }
    else if (bytes >= 1024000) { value = static_cast<double>(bytes>>10)/1024; unit = "MB"; }
    else if (bytes >= 1000) { value = static_cast<double>(bytes)/1024; unit = "KB"; }
    else { value = static_cast<double>(bytes); unit = "Bytes"; }
    std::ostringstream formatted;
    formatted << std::fixed << std::setprecision(2) << value << ' ' << unit;
    return formatted.str();
}
std::uint64_t optional_number(const Value& value, const char* key) {
    if (!fields(value).contains(key)) return 0;
    return number(value,key);
}
std::string optional_text(const Value& value, const char* key) {
    if (!fields(value).contains(key)) return {};
    return text(value,key);
}
std::string status_error(const Value& content) {
    if (!fields(content).contains("error")) return {};
    const auto code = optional_number(fields(content).at("error"),"code");
    switch (code) {
    case 4096: case 4098: return "The username or password you entered is incorrect. Please make sure you enter the correct information and try again.";
    case 4099: return "This IP address has been blocked because it has reached the maximum number of failed login attempts allowed within a specific time period. Please contact the system administrator.";
    case 4100: return "Your account has been disabled. Please contact the administrator.";
    case 4101: case 4102: return "The verification code you entered is incorrect. Please make sure you enter the correct information and try again.";
    case 4103: return "Please log in to DSM and set up your 2-step verification first.";
    case 4104: return "The username you entered has been modified. Please contact the administrator for the latest username information.";
    case 4105: return "You don't have enough permissions to use the backup agent. Contact the system administrator for assistance. (Learn more: https://sy.to/chhfs)";
    case 4106: return "The current device has been removed from the server. Please contact your administrator for further assistance.";
    case 4108: return "Failed to create a task. The destination may be encrypted or not in Btrfs volume. Please contact the admin for help.";
    case 4109: return "The task cannot be created due to an unexpected error. Please contact Synology Technical Support.";
    case 4110: return "Cannot connect to the domain or LDAP server. Please make sure the domain or LDAP server is on.";
    case 4111: return "Cannot create a task. The selected backup destination's format is not supported. Go to Settings > Template, change the backup destination setting, and try again.";
    case 4112: return "Quota reached on the backup destination.";
    case 4113: return "Backup destination is out of free space.";
    case 4114: return "Couldn't create the task because the shared folder already contains backup data. Go to Storage and relink the folder.";
    case 4115: return "Cannot create a task since the shared folder already contains backup data. Please select another shared folder.";
    case 4116: return "Unable to create the task owing to data corruption of the storage.";
    case 12289: return "You have used up your quota of capacity. Please contact the administrator for extra space.";
    case 12290: return "The disk on the server is full. Please contact the administrator to fix this problem.";
    case 12294: return "Version incompatibility found. Data version on the backup target is too old to proceed backup.";
    case 12295: return "The current package version on the server is older. Please update the package on the server via Package Center or Download Center to match the data version of backup target.";
    case 16385: return "The current version of the agent is outdated. Please update to the latest version through Download Center (https://sy.to/pkgdownload).";
    case 16386: return "The current version of Active Backup for Business Agent is newer than Active Backup for Business on the Synology NAS. Please update the package to the newest version through Download Center (https://sy.to/pkgdownload) or Package Center. If you wish to update the package later, you can install the compatible version of Active Backup for Business Agent downloaded from Download Center to continue protecting your device.";
    case 16387: return "The DSM version of your backup destination is incompatible. Go to the destination NAS and update your DSM to the latest version.";
    case 53249: return "This IP address is not authorized for connection. Please enter a valid IP address.";
    case 53250: return "Connecting to a different server is not allowed. To change to another server, please log out to proceed.";
    case 53252: return "Untrusted SSL certificate";
    case 53253: return "SSL certificate has been changed.";
    case 53254: return "The hostname does not match the certificate's common name.";
    case 53255: return "Unable to connect to Synology ActiveProtect appliance.";
    default: return (code&0xff00) == 0xd000 ? "Internet error. Please check your Internet connection. If the problem remains, please contact the administrator to check the Internet status of the server." :
        "Unknown error. Please contact Synology Technical Support.";
    }
}
}
void print_service_status(std::ostream& output, const Value& snapshot) {
    const auto& connection = fields(snapshot).at("connection");
    const auto& content = fields(snapshot).at("content");
    const auto& last = fields(content).at("last_backup_result");
    auto next = date(optional_number(content,"next_backup_time"));
    std::string status, detail;
    switch (number(snapshot,"status")&0xf000) {
    case 0x2000:
        status = "Idle";
        if (const auto result = optional_text(last,"last_backup_status"); result == "complete") detail = "Completed";
        else if (result == "partial_success") detail = "Partially complete";
        else if (result == "cancel") detail = "Canceled";
        else if (result == "failure") detail = "Failed";
        break;
    case 0x3000: status = "Backing up..."; break;
    case 0x4000: status = "Restoring...\xc2\xa0"; break;
    case 0xf000: status = "Error\xc2\xa0"; detail = status_error(content); break;
    }
    if ((number(snapshot,"status")&0xf000) == 0x3000 || (number(snapshot,"status")&0xf000) == 0x4000) {
        next = " - ";
        const auto& transfer = fields(content).at("transfer");
        detail = units(optional_number(transfer,"progress"))+" / "+units(optional_number(transfer,"total"))+
                 " ("+units(optional_number(transfer,"speed"))+"/s)";
    }
    output << "Server address: " << std::left << std::setw(15) << text(connection,"address")
           << " \t\t Username: " << text(connection,"username") << '\n'
           << "Last backup time: " << std::setw(13) << date(optional_number(last,"last_success_time"))
           << " \t\t Next backup time: " << next << '\n'
           << "Service Status: " << status;
    if (!detail.empty()) output << " - " << detail;
    output << "\n\nRecovery portal: " << (fields(snapshot).contains("url") ? text(snapshot,"url") : " - ")
           << "\n\n";
    output << "For detailed activity logs, please refer to the system logs. Depending on the operating system of your Linux device, "
              "you can find the logs in var/log/message, var/log/syslog, or by entering the command journalctl.\n";
    output << "Retrieved service status successfully\n";
}
}
