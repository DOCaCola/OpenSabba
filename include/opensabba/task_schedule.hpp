#pragma once
#include "opensabba/client.hpp"
#include "opensabba/server_time.hpp"
#include <optional>
#include <functional>
#include <vector>

namespace opensabba {
// First scheduled Unix time strictly after `after`. Pass the NAS combined
// server_time_offset (timezone plus clock difference), in seconds.
// Empty/non-scheduled policies return nullopt; malformed policies throw Error.
std::optional<std::uint64_t> next_task_schedule(const pstream::Value& task,
    std::uint64_t after, std::int64_t server_offset_seconds = 0);
}

namespace opensabba {
inline constexpr std::uint64_t scheduled_trigger_type = 2;
// The job handshake creates a new NAS run for client-originated scheduled events.
BackupRun trigger_scheduled_backup(const Endpoint&, const SavedAuth&, std::uint64_t task,
    std::uint64_t base_version, const std::function<void()>& before_send);

struct ScheduledTask {
    pstream::Value task;
    std::uint64_t due;
};
// Task and timezone updates recalculate next triggers. Both task next times and
// queued backup events are persisted by the official agent service.
class TaskScheduler {
public:
    using Now = std::function<std::uint64_t()>;
    explicit TaskScheduler(Now now = {});
    void update(const pstream::Value::Array& tasks, std::int64_t server_offset_seconds);
    std::vector<ScheduledTask> poll();
    std::vector<ScheduledTask> timezone(std::int64_t offset, std::int64_t timezone_delta);
    pstream::Value state() const;
    void restore(const pstream::Value&);
private:
    struct Entry { pstream::Value task; std::optional<std::uint64_t> next; };
    Now now_;
    std::vector<Entry> entries_;
    TimeoutChecker cadence_{60};
    std::int64_t offset_ = 0;
};
}
