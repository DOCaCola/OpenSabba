#pragma once
#include <string_view>

namespace opensabba {
constexpr bool supported_machine_boot_mount(std::string_view path) noexcept {
    return path == "/boot" || path == "/boot/efi" || path == "/boot/firmware";
}
}
