#pragma once
#include "opensabba/pstream.hpp"
#include <filesystem>
#include <optional>
#include <string_view>

namespace opensabba {
enum class HistoricalEvent { connection_attempt, connected, connection_interrupted, reload, stopped };
void historical_service_event(const std::filesystem::path& storage, HistoricalEvent);
// the official agent is local local activities/syslog only; it never queues a NAS log.
std::optional<pstream::Value> backup_start_activity(std::string_view task_name,
    std::uint64_t trigger_type, std::uint64_t trigger_event, std::uint64_t log_time);
void historical_backup_start(const std::filesystem::path& storage, std::string_view task_name,
    std::uint64_t trigger_type, std::uint64_t trigger_event);
// Event fields are projected through the diagnostic allowlist. Never pass
// console output, exception text, command arguments or script output here.
void historical_journal_event(const std::filesystem::path& storage,
                              std::string_view journal, const pstream::Value&);
class HistoricalLogRun {
    std::filesystem::path storage_;
    std::string command_;
    int exceptions_;
public:
    explicit HistoricalLogRun(std::string_view command);
    ~HistoricalLogRun();
    HistoricalLogRun(const HistoricalLogRun&) = delete;
    HistoricalLogRun& operator=(const HistoricalLogRun&) = delete;
};
}
