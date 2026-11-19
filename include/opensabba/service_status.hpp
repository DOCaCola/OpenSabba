#pragma once
#include "opensabba/pstream.hpp"
#include <cstdint>
#include <ctime>
#include <mutex>
#include <iosfwd>
#include <optional>

namespace opensabba {
// Process-local data served by the daemon's status IPC. Journals remain owned
// by their transfer workers and are never used as a replacement for this state.
class ServiceStatus {
public:
    ServiceStatus();
    void connected();
    void disconnected();
    void result(const pstream::Value&, std::time_t now = std::time(nullptr));
    void backup_started(std::uint64_t run);
    void backup(const pstream::Value&, std::time_t now = std::time(nullptr));
    void backup_transfer(std::uint64_t current, std::uint64_t total,
                         std::time_t now = std::time(nullptr));
    void file_restore(const pstream::Value&, std::time_t now = std::time(nullptr));
    void tasks(const pstream::Value::Array&, std::optional<std::int64_t> server_offset = std::nullopt,
               std::time_t now = std::time(nullptr));
    pstream::Value snapshot() const;
private:
    void progress(std::uint64_t current, std::uint64_t total, std::uint64_t status, std::time_t now);
    mutable std::mutex mutex_;
    std::uint64_t status_ = 0x1000, run_ = 0, current_ = 0, total_ = 0, speed_ = 0;
    std::time_t progress_at_ = 0;
    pstream::Value::Object content_;
    pstream::Value backup_result_;
    std::uint64_t next_ = 0;
};
void print_service_status(std::ostream&, const pstream::Value&);
}
