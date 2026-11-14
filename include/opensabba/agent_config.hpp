#pragma once
#include <cstdint>
#include <filesystem>

namespace opensabba {
inline constexpr const char* official_agent_config =
    "/opt/Synology/ActiveBackupforBusiness/bin/agent.config";
std::uint32_t read_disconnect_timeout(const std::filesystem::path&);
// the official agent worker configuration is loaded once per service process.
std::uint32_t disconnect_timeout();
bool backup_disconnect_expired(std::uint64_t start, std::uint32_t timeout, std::int64_t now);
}
