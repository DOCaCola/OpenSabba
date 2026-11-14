#pragma once
#include "opensabba/pstream.hpp"
#include <chrono>
#include <functional>
#include <span>
#include <mutex>
#include <optional>

namespace opensabba {
// the official agent applies each completed query/handshake under the same mutex.
class BackupBandwidthPolicy {
public:
    std::uint64_t rate() const;
    void update(std::optional<std::uint64_t> rate);
private:
    mutable std::mutex mutex_;
    std::uint64_t rate_ = 0;
};

// Pace encoded upload bytes, not logical image bytes. Zero means unlimited.
// Hooks allow deterministic timing/cancellation tests without wall-clock sleeps.
struct UploadPacing {
    using Clock = std::chrono::steady_clock;
    std::function<Clock::time_point()> now;
    std::function<void(Clock::duration)> sleep;
    // Policy publication starts its timer before the record is serialized.
    std::optional<Clock::time_point> started;
};
void paced_upload(std::span<const std::uint8_t>, std::uint64_t bytes_per_second,
                  const std::function<void(std::span<const std::uint8_t>)>& write,
                  const std::function<bool()>& cancelled = {},
                  UploadPacing timing = {});
}
