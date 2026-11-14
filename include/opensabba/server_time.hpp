#pragma once
#include "opensabba/pstream.hpp"
#include <cstdint>
#include <string>
#include <optional>

namespace opensabba {
// the official agent routine-event timer: align successful checks to period boundaries.
class TimeoutChecker {
    std::int64_t period_, last_ = 0;
public:
    explicit TimeoutChecker(std::int64_t period) : period_(period) {}
    bool check(std::int64_t now);
};
struct ServerTime {
    std::string offset;
    std::int64_t difference = 0, timezone = 0;
    bool operator==(const ServerTime&) const = default;
};
ServerTime server_time_reply(const pstream::Value&, std::int64_t before, std::int64_t after);
pstream::Value server_time_value(const ServerTime&);
ServerTime server_time_from_value(const pstream::Value&);
// the official agent leaves the combined offset unset until a successful NAS refresh.
std::optional<std::int64_t> server_time_offset(const ServerTime&);
// The atomic difference is shared with the service heartbeat thread. Timezone
// and combined offset are persisted official agent state, never added to Unix epochs.
void set_server_time(const ServerTime&);
std::int64_t to_server_time(std::int64_t);
std::int64_t to_client_time(std::int64_t);
std::uint64_t server_time_now();
// Convert only NAS timestamp fields in display copies, retaining zero sentinels.
void client_display_times(pstream::Value&);
}
