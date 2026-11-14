#include "opensabba/device_info.hpp"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace opensabba {
namespace {
std::string distro_name(std::string_view id, double version) {
    if (id == "ubuntu") {
        if (version == 16 || version == 18 || version == 20 || version == 22 || version == 24)
            return "Ubuntu " + std::to_string(static_cast<int>(version)) + ".04";
        return "Ubuntu";
    }
    if (id == "centos") {
        if (version == 4) return "CentOS 4/5";
        if (version == 9) return "CentOS Stream 9";
        if (version >= 6 && version <= 8)
            return "CentOS " + std::to_string(static_cast<int>(version));
        return "CentOS";
    }
    if (id == "rhel") {
        if (version >= 2 && version <= 9)
            return "RedHat Enterprise " + std::to_string(static_cast<int>(version));
        return "RedHat Enterprise";
    }
    if (id == "sles") {
        if (version == 8) return "SUSE Enterprise 8/9";
        if ((version >= 10 && version <= 12) || version == 15)
            return "SUSE Enterprise " + std::to_string(static_cast<int>(version));
        return "SUSE Enterprise";
    }
    if (id == "fedora") {
        if (version >= 30 && version <= 40)
            return "RedHat Fedora " + std::to_string(static_cast<int>(version));
        return "RedHat Fedora";
    }
    if (id == "debian") {
        if (version >= 4 && version <= 12)
            return "Debian " + std::to_string(static_cast<int>(version));
        return "Debian";
    }
    if (id == "ol") {
        if (version == 4 || version == 6 || version == 7 || version == 8)
            return "Oracle " + std::to_string(static_cast<int>(version));
        return "Oracle";
    }
    return "Linux";
}
}

std::string linux_os_name(const std::filesystem::path& etc, std::string_view machine) {
    std::string id;
    double version = 0;
    const auto release = etc / "os-release";
    if (std::filesystem::exists(release)) {
        std::ifstream input(release);
        std::string line;
        bool have_id = false, have_version = false;
        while ((!have_id || !have_version) && std::getline(input, line)) {
            const auto separator = line.find('=');
            if (separator == std::string::npos) continue;
            const auto key = std::string_view(line).substr(0, separator);
            if (key != "ID" && key != "VERSION_ID") continue;
            std::istringstream value_stream(line.substr(separator + 1));
            std::string value;
            if (!(value_stream >> value)) continue;
            std::erase(value, '"');
            if (key == "ID") {
                id = value;
                have_id = true;
            } else {
                version = std::floor(std::strtod(value.c_str(), nullptr));
                have_version = true;
            }
        }
    } else if (std::filesystem::exists(etc / "centos-release")) {
        id = "centos";
        version = 6;
    } else if (std::filesystem::exists(etc / "redhat-release")) {
        id = "rhel";
        version = 6;
    }
    return distro_name(id, version) + (machine == "x86_64" ? " (64-bit)" : " (32-bit)");
}
}
