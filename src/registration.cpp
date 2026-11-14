#include "opensabba/registration.hpp"
#include <algorithm>
#include <string>

namespace opensabba {
bool confirm_connection_template(std::istream& input, std::ostream& output) {
    output << "Confirm authentication? [y/n](default: y): " << std::flush;
    for (;;) {
        std::string answer;
        std::getline(input, answer);
        std::transform(answer.begin(),answer.end(),answer.begin(),[](unsigned char ch) {
            return ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch-'A'+'a') : static_cast<char>(ch);
        });
        if (answer.empty() || answer == "y" || answer == "yes") return true;
        if (answer == "n" || answer == "no") return false;
        output << "Enter [y/n](default: y): " << std::flush;
    }
}
}

#include "json.hpp"
#include <array>
#include <charconv>
#include <optional>

namespace opensabba {
namespace {
using pstream::Value;
using json_detail::Json;
const Value& item(const Value& value, const char* key) {
    static const Value empty;
    const auto* object = std::get_if<Value::Object>(&value.data);
    if (!object) return empty; // the official agent missing/null map lookup yields empty.
    const auto found = object->find(key);
    return found == object->end() ? empty : found->second;
}
std::string string(const Value& value) {
    const auto* text = std::get_if<std::string>(&value.data);
    return text ? *text : "";
}
std::uint64_t number(const Value& value) {
    const auto* result = std::get_if<std::uint64_t>(&value.data);
    return result ? *result : 0;
}
const Json& member(const Json& json, const char* key) {
    static const Json empty;
    const auto found = json.members.find(key);
    return found == json.members.end() ? empty : found->second;
}
std::int64_t number(const Json& value) {
    if (value.kind == Json::boolean) return value.scalar == "true";
    std::int64_t result = 0;
    if (value.kind == Json::number)
        std::from_chars(value.scalar.data(),value.scalar.data()+value.scalar.size(),result);
    return result;
}
std::optional<Json> json(const Value& value) {
    // the official agent JSON parsing failure returns an empty formatted field.
    const auto text = string(value);
    try { return json_detail::Parser(text).parse(false); }
    catch (const pstream::Error&) { return std::nullopt; }
}
const char* enabled(bool flag) { return flag ? "Enable" : "Disabled"; } // IDs62/60.
std::string source(std::uint64_t type, const Json& custom) {
    if (type == 1) return "Entire device backup"; // ID42.
    if (type == 2) return "System volumes backup"; // ID45.
    if (type != 3 || custom.kind != Json::array) return "";
    std::string volumes;
    for (const auto& volume : custom.elements) {
        if (!volumes.empty()) volumes += ", ";
        volumes += volume.scalar;
    }
    return "Custom volume " + volumes; // ID43.
}
std::string schedule(const Json& value) {
    if (!(number(member(value,"schedule_setting_type")) & 1)) return "Manual backup"; //1275.
    const auto& weekdays = member(value,"run_weekday").elements;
    std::string days;
    if (weekdays.size() == 7) days = "Daily";
    else {
        static constexpr std::array names{"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"};
        for (const auto& day : weekdays) {
            const auto index = number(day);
            if (index < 0 || index >= 7) continue; // the official agent switch has no default text.
            if (!days.empty()) days += ", ";
            days += names[static_cast<std::size_t>(index)];
        }
        days = "every " + days;
    }
    const auto pad = [](std::int64_t value) {
        auto result = std::to_string(value);
        if (result.size() <= 1) result.insert(0,"0");
        return result;
    };
    const auto minute = pad(number(member(value,"run_min")));
    if (number(member(value,"repeat_hour")))
        return "Start at " + minute + " mins past each hour (Hourly)";
    return "Start at " + pad(number(member(value,"run_hour"))) + ": " + minute + " (" + days + ")";
}
void normal_template(std::ostream& out, const Value& task) {
    const auto line = [&](const char* label,const std::string& value) { out << label << ": " << value << '\n'; };
    line("Applied template",string(item(task,"template_name"))); //110.
    line("Backup destination",string(item(task,"share_name"))); //40.
    const auto custom = json(item(task,"custom_volume"));
    line("Source type",source(number(item(task,"source_type")),custom ? *custom : Json{})); //41.
    std::string names;
    for (const auto key : {"users_permissioned_by_name","groups_permissioned_by_name"}) {
        if (const auto* values = std::get_if<Value::Array>(&item(task,key).data))
            for (const auto& value : *values) { if (!names.empty()) names += ", "; names += string(value); }
    }
    line("Restoration privilege",names); //1361.
    const auto& fields = std::get_if<Value::Object>(&task.data);
    if (!fields) return;
    const auto formatted = [&](const char* key, const char* label, const auto& render) {
        if (!fields->contains(key)) return;
        const auto parsed = json(item(task,key));
        line(label,parsed ? render(*parsed) : "");
    };
    formatted("sched_content","Back up by time",schedule); //348.
    formatted("retention_policy","Retention policy",[](const Json& value) {
        return number(member(value,"keep_all")) ? "Keep all versions" : "Advanced retention policy settings";
    });
    formatted("sched_content","Backup window",[](const Json& value) { return enabled(number(member(value,"enable_backup_window"))); });
    const auto flag = [&](const char* key, const char* label) {
        if (fields->contains(key)) line(label,enabled(number(item(task,key)) != 0));
    };
    flag("enable_compress_transfer","Data transfer compression"); //337.
    flag("enable_encrypt_transfer","Data transfer encryption"); //338.
    formatted("bandwidth_content","Bandwidth consumption limit",[](const Json& value) {
        if (!number(member(value,"enable")) || !value.members.contains("backup_bandwidth_number") ||
                !value.members.contains("backup_bandwidth_base")) return std::string("Disabled");
        return member(value,"backup_bandwidth_number").scalar +
            (number(member(value,"backup_bandwidth_base")) ? " MB/s" : " KB/s");
    });
    flag("storage_compress","Compression at backup destination"); //387.
    flag("storage_encrypt","Encryption at backup destination"); //388.
    flag("enable_verification","Backup verification"); //345.
    formatted("pre_post_script_setting","Pre/post script",[](const Json& value) { return enabled(number(member(value,"script_exec_mode"))); });
}
}
void show_connection_template(std::ostream& out, const pstream::Value& content) {
    out << "\nServer address: " << string(item(content,"server_name")) << '\n'; //30.
    const auto& device = item(content,"temp_device");
    if (!std::holds_alternative<std::monostate>(device.data)) {
        out << "Username: " << string(item(device,"user_name")) << '\n'; //115.
        out << "Backup type: " << (number(item(device,"backup_type")) == 2 ? "PC" : "Server") << '\n'; //47.
    }
    const auto& task = item(content,"task_template");
    if (!number(item(content,"cms_managed"))) { normal_template(out,task); return; }
    // prints only destination/storage/transport policy and scope tasks.
    out << "Backup destination: " << string(item(task,"share_name")) << '\n';
    const auto* fields = std::get_if<Value::Object>(&task.data);
    for (const auto& [key,label] : {std::pair{"storage_compress","Compression at backup destination"},
            {"storage_encrypt","Encryption at backup destination"},{"enable_compress_transfer","Data transfer compression"},
            {"enable_encrypt_transfer","Data transfer encryption"}})
        if (fields && fields->contains(key)) out << label << ": " << enabled(number(item(task,key)) != 0) << '\n';
    out << "\nAll Tasks:\n";
    if (const auto* scope = std::get_if<Value::Array>(&item(content,"scope").data)) {
        std::size_t index = 0;
        for (const auto& value : *scope) {
            out << " Item " << ++index << '\n'; // ID241.
            const auto parsed = json(value);
            const auto& config = parsed ? member(*parsed,"config") : Json{};
            const auto type = number(member(config,"source_type"));
            if (type >= 1 && type <= 3)
                out << "  Source type: " << source(static_cast<std::uint64_t>(type),member(config,"custom_volume")) << '\n';
            if (config.members.contains("sched_content"))
                out << "  Back up by time: " << schedule(member(config,"sched_content")) << '\n';
        }
    }
}
}
