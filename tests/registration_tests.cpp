#include "opensabba/registration.hpp"
#include <sstream>
#include <stdexcept>
#include <iostream>
int main() {
    const std::string prompt = "Confirm authentication? [y/n](default: y): ";
    for (const auto& [text,result] : {std::pair{"",true},{"\n",true},{"y\n",true},
             {"YES\n",true},{"n\n",false},{"No\n",false},{" no\nn\n",false},
             {"invalid\n\n",true},{"invalid",true}}) {
        std::istringstream input(text);
        std::ostringstream output;
        const auto expected = prompt + ((std::string(text).starts_with("invalid") || text[0] == ' ') ?
            "Enter [y/n](default: y): " : "");
        if (opensabba::confirm_connection_template(input,output) != result || output.str() != expected)
            throw std::runtime_error("official registration prompt mismatch");
    }
    using opensabba::pstream::Value;
    Value content{Value::Object{
        {"server_name",Value{std::string("NAS")}},
        {"temp_device",Value{Value::Object{{"user_name",Value{std::string("alice")}},
            {"backup_type",Value{std::uint64_t{3}}}}}},
        {"task_template",Value{Value::Object{
            {"id",Value{std::uint64_t{27}}},{"template_name",Value{std::string("Linux")}},
            {"share_name",Value{std::string("backups")}},{"source_type",Value{std::uint64_t{3}}},
            {"custom_volume",Value{std::string("[\"/\",\"/home\"]")}},
            {"users_permissioned_by_name",Value{Value::Array{Value{std::string("alice")}}}},
            {"groups_permissioned_by_name",Value{Value::Array{Value{std::string("admins")}}}},
            {"sched_content",Value{std::string(R"({"schedule_setting_type":1,"run_weekday":[1,3],"run_hour":3,"run_min":5,"enable_backup_window":true})")}},
            {"retention_policy",Value{std::string(R"({"keep_all":true})")}},
            {"enable_compress_transfer",Value{std::uint64_t{1}}},
            {"enable_encrypt_transfer",Value{std::uint64_t{0}}},
            {"bandwidth_content",Value{std::string(R"({"enable":true,"backup_bandwidth_base":0,"backup_bandwidth_number":128})")}},
            {"storage_compress",Value{std::uint64_t{1}}},
            {"storage_encrypt",Value{std::uint64_t{0}}},
            {"enable_verification",Value{std::uint64_t{0}}},
            {"pre_post_script_setting",Value{std::string(R"({"script_exec_mode":1})")}},
            {"password",Value{std::string("never-print")}}
        }}}
    }};
    std::ostringstream display;
    opensabba::show_connection_template(display,content);
    if (display.str() !=
        "\nServer address: NAS\nUsername: alice\nBackup type: Server\n"
        "Applied template: Linux\nBackup destination: backups\nSource type: Custom volume /, /home\n"
        "Restoration privilege: alice, admins\nBack up by time: Start at 03: 05 (every Monday, Wednesday)\n"
        "Retention policy: Keep all versions\nBackup window: Enable\nData transfer compression: Enable\n"
        "Data transfer encryption: Disabled\nBandwidth consumption limit: 128 KB/s\n"
        "Compression at backup destination: Enable\nEncryption at backup destination: Disabled\n"
        "Backup verification: Disabled\nPre/post script: Enable\n")
        throw std::runtime_error("official template fields/order/labels mismatch");
    display.str("");
    opensabba::show_connection_template(display,Value{});
    if (display.str() != "\nServer address: \nApplied template: \nBackup destination: \nSource type: \nRestoration privilege: \n")
        throw std::runtime_error("official absent-template display mismatch");
    std::get<Value::Object>(content.data)["cms_managed"] = Value{std::uint64_t{1}};
    std::get<Value::Object>(content.data)["scope"] = Value{Value::Array{
        Value{std::string(R"({"config":{"source_type":2,"sched_content":{"schedule_setting_type":0}}})")}}};
    display.str("");
    opensabba::show_connection_template(display,content);
    if (display.str() != "\nServer address: NAS\nUsername: alice\nBackup type: Server\n"
        "Backup destination: backups\nCompression at backup destination: Enable\n"
        "Encryption at backup destination: Disabled\nData transfer compression: Enable\n"
        "Data transfer encryption: Disabled\n\nAll Tasks:\n Item 1\n"
        "  Source type: System volumes backup\n  Back up by time: Manual backup\n")
        throw std::runtime_error("official CMS field scope/order mismatch");
    std::cout << "official confirmation input/default/EOF/retry behavior passed\n";
}
