#pragma once
#include <filesystem>
#include <string>
#include <string_view>

namespace opensabba {
// Device OS name reported to the NAS: the closest Linux guest name the NAS
// recognizes for etc/os-release (or the kernel series), followed by the
// machine architecture's bitness.
std::string linux_os_name(const std::filesystem::path& etc, std::string_view machine,
                          std::string_view kernel_release);
}
