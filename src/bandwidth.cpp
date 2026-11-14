#include "opensabba/bandwidth.hpp"
#include "opensabba/client.hpp"
#include <algorithm>
#include <thread>

namespace opensabba {
std::uint64_t BackupBandwidthPolicy::rate() const {
    std::lock_guard lock(mutex_);
    return rate_;
}
void BackupBandwidthPolicy::update(std::optional<std::uint64_t> rate) {
    if (!rate) return;
    std::lock_guard lock(mutex_);
    rate_ = *rate;
}
void paced_upload(std::span<const std::uint8_t> bytes, std::uint64_t rate,
                  const std::function<void(std::span<const std::uint8_t>)>& write,
                  const std::function<bool()>& cancelled, UploadPacing timing) {
    if (!timing.now) timing.now = [] { return UploadPacing::Clock::now(); };
    if (!timing.sleep) timing.sleep = [](auto duration) { std::this_thread::sleep_for(duration); };
    auto started = timing.started ? *timing.started : timing.now();
    while (!bytes.empty()) {
        if (cancelled && cancelled()) throw Cancelled();
        // Upload pacing uses the full bytes/second allowance.
        // A zero limit leaves the entire remaining write unrestricted.
        const auto count = rate ? static_cast<std::size_t>(
            std::min<std::uint64_t>(bytes.size(),rate)) : bytes.size();
        write(bytes.first(count));
        bytes = bytes.subspan(count);
        if (!rate) continue;
        // Post-write pacing subtracts time since timer start from
        // bytes/rate, sleeps once (at most one second), then restarts. the official agent
        // samples a fixed policy once per record, before Policy publication.
        const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            timing.now()-started).count();
        const auto target = static_cast<std::uint64_t>(count)*1000000/rate;
        if (target > static_cast<std::uint64_t>(elapsed))
            timing.sleep(std::chrono::microseconds(
                std::min<std::uint64_t>(target-static_cast<std::uint64_t>(elapsed),1000000)));
        started = timing.now();
    }
}
}
