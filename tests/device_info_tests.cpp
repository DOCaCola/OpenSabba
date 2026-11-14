#include "opensabba/device_info.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
}

int main() {
    const auto directory = std::filesystem::temp_directory_path() /
        ("opensabba-device-info-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directory(directory);
    try {
        auto release = [&](const std::string& content) {
            std::ofstream(directory / "os-release") << content;
        };
        const struct { const char* id; const char* version; const char* expected; } cases[] = {
            {"debian","12","Debian 12"}, {"debian","13","Debian"},
            {"debian","11.9","Debian 11"}, {"ubuntu","16.04","Ubuntu 16.04"},
            {"ubuntu","24.10","Ubuntu 24.04"}, {"ubuntu","25.04","Ubuntu"},
            {"centos","4","CentOS 4/5"}, {"centos","5","CentOS"},
            {"centos","6.10","CentOS 6"}, {"centos","9","CentOS Stream 9"},
            {"centos","10","CentOS"}, {"rhel","2","RedHat Enterprise 2"},
            {"rhel","9.4","RedHat Enterprise 9"}, {"rhel","10","RedHat Enterprise"},
            {"sles","8","SUSE Enterprise 8/9"}, {"sles","9","SUSE Enterprise"},
            {"sles","12.5","SUSE Enterprise 12"}, {"sles","15.6","SUSE Enterprise 15"},
            {"fedora","30","RedHat Fedora 30"}, {"fedora","40","RedHat Fedora 40"},
            {"fedora","41","RedHat Fedora"}, {"ol","4","Oracle 4"},
            {"ol","5","Oracle"}, {"ol","8.9","Oracle 8"}, {"ol","9","Oracle"},
            {"raspbian","12","Linux"}, {"opensuse-leap","15","Linux"},
        };
        for (const auto& item : cases) {
            release(std::string("ID=\"") + item.id + "\"\nVERSION_ID=\"" + item.version + "\"\n");
            check(opensabba::linux_os_name(directory,"x86_64") ==
                std::string(item.expected) + " (64-bit)", "distribution mapping differs from official");
        }
        release("PRETTY_NAME=\"Ubuntu 16.04\"\nID=debian\nVERSION_ID=12\n");
        check(opensabba::linux_os_name(directory,"x86_64") == "Debian 12 (64-bit)",
              "display name must not select the recovery distribution");
        release("VERSION_ID=\"12.9\" # comment\nID=\"debian\"\nID=ubuntu\n");
        check(opensabba::linux_os_name(directory,"i686") == "Debian 12 (32-bit)",
              "quoted tokens or field ordering differ from official");
        check(opensabba::linux_os_name(directory,"aarch64") == "Debian 12 (32-bit)",
              "official architecture classification changed");
        release("ID=debian\n");
        check(opensabba::linux_os_name(directory,"x86_64") == "Debian (64-bit)",
              "missing version must retain the distribution family");
        std::filesystem::remove(directory / "os-release");
        std::ofstream(directory / "redhat-release") << "unparsed legacy text";
        check(opensabba::linux_os_name(directory,"x86_64") == "RedHat Enterprise 6 (64-bit)",
              "legacy redhat marker must select official version 6");
        std::ofstream(directory / "centos-release") << "unparsed legacy text";
        check(opensabba::linux_os_name(directory,"x86_64") == "CentOS 6 (64-bit)",
              "centos marker must precede redhat");
        release("ID=custom\nVERSION_ID=12\n");
        check(opensabba::linux_os_name(directory,"x86_64") == "Linux (64-bit)",
              "legacy markers must not override os-release");
        std::filesystem::remove_all(directory);
    } catch (const std::exception& error) {
        std::filesystem::remove_all(directory);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
