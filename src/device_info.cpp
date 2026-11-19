#include "opensabba/device_info.hpp"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <sstream>

namespace opensabba {
namespace {
// Linux names the NAS maps to a virtual machine guest type. The NAS strips the
// trailing bitness and looks the remainder up exactly, so reporting a name from
// this list keeps instant restore and backup verification able to pick a type.
constexpr std::string_view guest_names[] = {
    "Linux", "Linux 2.x", "Linux 3.x", "Linux 4.x", "Linux 5.x", "Linux 6.x",
    "Amazon Linux 2", "Amazon Linux 3", "AlmaLinux", "Rocky Linux",
    "Ubuntu", "Ubuntu 16.04", "Ubuntu 18.04", "Ubuntu 20.04", "Ubuntu 22.04", "Ubuntu 24.04",
    "RedHat Enterprise", "RedHat Enterprise 2", "RedHat Enterprise 3", "RedHat Enterprise 4",
    "RedHat Enterprise 5", "RedHat Enterprise 6", "RedHat Enterprise 7", "RedHat Enterprise 8",
    "RedHat Enterprise 9",
    "RedHat Fedora", "RedHat Fedora 31", "RedHat Fedora 33", "RedHat Fedora 35",
    "RedHat Fedora 36", "RedHat Fedora 37", "RedHat Fedora 38", "RedHat Fedora 39",
    "SUSE Enterprise", "SUSE Enterprise 8/9", "SUSE Enterprise 10", "SUSE Enterprise 11",
    "SUSE Enterprise 12", "SUSE Enterprise 15", "SUSE Enterprise 16", "openSUSE",
    "CentOS", "CentOS 4/5", "CentOS 6", "CentOS 7", "CentOS 8", "CentOS Stream 9",
    "Debian", "Debian 4", "Debian 5", "Debian 6", "Debian 7", "Debian 8", "Debian 9",
    "Debian 10", "Debian 11", "Debian 12",
    "Oracle", "Oracle 4", "Oracle 6", "Oracle 7", "Oracle 8", "Oracle 9",
    "VMware Photon",
};

struct Family {
    std::string_view id;
    std::string_view name;
};

// os-release ID and ID_LIKE values. Raspbian releases carry Debian's version.
constexpr Family families[] = {
    {"ubuntu", "Ubuntu"}, {"debian", "Debian"}, {"raspbian", "Debian"},
    {"rhel", "RedHat Enterprise"}, {"centos", "CentOS"}, {"fedora", "RedHat Fedora"},
    {"sles", "SUSE Enterprise"}, {"suse", "SUSE Enterprise"}, {"opensuse", "openSUSE"},
    {"opensuse-leap", "openSUSE"}, {"opensuse-tumbleweed", "openSUSE"}, {"ol", "Oracle"},
    {"rocky", "Rocky Linux"}, {"almalinux", "AlmaLinux"}, {"amzn", "Amazon Linux"},
    {"photon", "VMware Photon"},
};

bool is_guest_name(std::string_view name) {
    return std::ranges::find(guest_names, name) != std::end(guest_names);
}

std::string versioned_name(std::string_view family, int major) {
    const auto number = std::to_string(major);
    if (family == "Ubuntu") return "Ubuntu " + number + ".04";
    if (family == "CentOS" && (major == 4 || major == 5)) return "CentOS 4/5";
    if (family == "CentOS" && major == 9) return "CentOS Stream 9";
    if (family == "SUSE Enterprise" && (major == 8 || major == 9)) return "SUSE Enterprise 8/9";
    if (family == "Amazon Linux" && major == 2023) return "Amazon Linux 3";
    return std::string(family) + " " + number;
}

std::optional<std::string> family_name(std::string_view id, int major) {
    const auto family = std::ranges::find(families, id, &Family::id);
    if (family == std::end(families)) return std::nullopt;
    if (major > 0) {
        auto name = versioned_name(family->name, major);
        if (is_guest_name(name)) return name;
    }
    if (is_guest_name(family->name)) return std::string(family->name);
    return std::nullopt;
}

std::string kernel_name(std::string_view kernel_release) {
    const auto name = "Linux " + std::to_string(std::atoi(std::string(kernel_release).c_str())) + ".x";
    return is_guest_name(name) ? name : "Linux";
}

bool is_64bit_machine(std::string_view machine) {
    constexpr std::string_view names[] = {
        "x86_64", "aarch64", "aarch64_be", "arm64", "ppc64", "ppc64le", "s390x",
        "riscv64", "mips64", "loongarch64", "sparc64", "alpha", "ia64",
    };
    return std::ranges::find(names, machine) != std::end(names);
}

// os-release value: a quoted string or the first unquoted token.
std::string release_value(std::string_view raw) {
    if (!raw.empty() && (raw.front() == '"' || raw.front() == '\'')) {
        const auto end = raw.find(raw.front(), 1);
        return std::string(raw.substr(1, end == std::string_view::npos ? end : end - 1));
    }
    return std::string(raw.substr(0, raw.find_first_of(" \t")));
}

std::string distribution_name(const std::filesystem::path& etc, std::string_view kernel_release) {
    const auto release = etc / "os-release";
    if (!std::filesystem::exists(release)) {
        if (std::filesystem::exists(etc / "centos-release")) return "CentOS 6";
        if (std::filesystem::exists(etc / "redhat-release")) return "RedHat Enterprise 6";
        return kernel_name(kernel_release);
    }
    std::optional<std::string> id, id_like, version;
    std::ifstream input(release);
    std::string line;
    while (std::getline(input, line)) {
        const auto separator = line.find('=');
        if (separator == std::string::npos) continue;
        const auto key = std::string_view(line).substr(0, separator);
        auto* field = key == "ID" ? &id : key == "ID_LIKE" ? &id_like
                    : key == "VERSION_ID" ? &version : nullptr;
        if (field && !*field) *field = release_value(std::string_view(line).substr(separator + 1));
    }
    const int major = version ? static_cast<int>(std::floor(std::strtod(version->c_str(), nullptr))) : 0;
    if (id)
        if (auto name = family_name(*id, major)) return *name;
    if (id_like) {
        // A derivative's version numbers are its own, so only the family applies.
        std::istringstream tokens(*id_like);
        std::string token;
        while (tokens >> token)
            if (auto name = family_name(token, 0)) return *name;
    }
    return kernel_name(kernel_release);
}
}

std::string linux_os_name(const std::filesystem::path& etc, std::string_view machine,
                          std::string_view kernel_release) {
    return distribution_name(etc, kernel_release) +
           (is_64bit_machine(machine) ? " (64-bit)" : " (32-bit)");
}
}
