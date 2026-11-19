#include "opensabba/device_info.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
void check(bool condition, const std::string& message) {
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
        auto name = [&](const char* machine, const char* kernel = "6.1.0-28-amd64") {
            return opensabba::linux_os_name(directory, machine, kernel);
        };
        const struct { const char* id; const char* version; const char* expected; } cases[] = {
            {"debian", "12", "Debian 12"}, {"debian", "13", "Debian"},
            {"debian", "11.9", "Debian 11"}, {"raspbian", "12", "Debian 12"},
            {"ubuntu", "16.04", "Ubuntu 16.04"}, {"ubuntu", "24.10", "Ubuntu 24.04"},
            {"ubuntu", "25.04", "Ubuntu"}, {"centos", "4", "CentOS 4/5"},
            {"centos", "5", "CentOS 4/5"}, {"centos", "6.10", "CentOS 6"},
            {"centos", "9", "CentOS Stream 9"}, {"centos", "10", "CentOS"},
            {"rhel", "2", "RedHat Enterprise 2"}, {"rhel", "9.4", "RedHat Enterprise 9"},
            {"rhel", "10", "RedHat Enterprise"}, {"sles", "9", "SUSE Enterprise 8/9"},
            {"sles", "15.6", "SUSE Enterprise 15"}, {"sles", "16", "SUSE Enterprise 16"},
            {"sles", "13", "SUSE Enterprise"}, {"fedora", "39", "RedHat Fedora 39"},
            {"fedora", "40", "RedHat Fedora"}, {"ol", "9", "Oracle 9"}, {"ol", "5", "Oracle"},
            {"opensuse-leap", "15.6", "openSUSE"}, {"rocky", "9.4", "Rocky Linux"},
            {"almalinux", "9", "AlmaLinux"}, {"amzn", "2", "Amazon Linux 2"},
            {"amzn", "2023", "Amazon Linux 3"}, {"amzn", "1", "Linux 6.x"},
            {"photon", "5.0", "VMware Photon"}, {"custom", "12", "Linux 6.x"},
        };
        for (const auto& item : cases) {
            release(std::string("ID=\"") + item.id + "\"\nVERSION_ID=\"" + item.version + "\"\n");
            const auto actual = name("x86_64");
            check(actual == std::string(item.expected) + " (64-bit)",
                  std::string(item.id) + " " + item.version + " reported as " + actual);
        }
        release("ID=linuxmint\nVERSION_ID=\"21.3\"\nID_LIKE=\"ubuntu debian\"\n");
        check(name("x86_64") == "Ubuntu (64-bit)", "derivative must use its first known family");
        release("PRETTY_NAME=\"Ubuntu 16.04\"\nID=debian\nVERSION_ID=12\n");
        check(name("x86_64") == "Debian 12 (64-bit)", "display name must not select the distribution");
        release("VERSION_ID=\"12.9\" # comment\nID=\"debian\"\nID=ubuntu\n");
        check(name("i686") == "Debian 12 (32-bit)", "first ID and quoted value must apply");
        check(name("aarch64") == "Debian 12 (64-bit)", "aarch64 is a 64-bit architecture");
        check(name("armv7l") == "Debian 12 (32-bit)", "armv7l is a 32-bit architecture");
        release("ID=debian\n");
        check(name("x86_64") == "Debian (64-bit)", "missing version must retain the family");
        release("ID=custom\n");
        check(name("x86_64", "5.15.0-1") == "Linux 5.x (64-bit)", "unknown distribution uses the kernel series");
        check(name("x86_64", "7.0.1") == "Linux (64-bit)", "unlisted kernel series uses Linux");
        std::filesystem::remove(directory / "os-release");
        std::ofstream(directory / "redhat-release") << "unparsed legacy text";
        check(name("x86_64") == "RedHat Enterprise 6 (64-bit)", "redhat marker selects version 6");
        std::ofstream(directory / "centos-release") << "unparsed legacy text";
        check(name("x86_64") == "CentOS 6 (64-bit)", "centos marker must precede redhat");
        std::filesystem::remove_all(directory);
    } catch (const std::exception& error) {
        std::filesystem::remove_all(directory);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
