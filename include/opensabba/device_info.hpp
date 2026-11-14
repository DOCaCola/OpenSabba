#pragma once
#include <filesystem>
#include <string>
#include <string_view>

namespace opensabba {
// Linux agent 3.2.1-5059 Device initialization.
std::string linux_os_name(const std::filesystem::path& etc, std::string_view machine);
}
