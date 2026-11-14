#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <span>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace opensabba::pstream {
using Bytes = std::vector<std::uint8_t>;

struct Value {
    using Array = std::vector<Value>;
    using Object = std::map<std::string, Value>;
    using Storage = std::variant<std::monostate, std::uint64_t, std::string,
                                 Bytes, Array, Object>;
    Storage data;
    bool operator==(const Value&) const = default;
};

// Local resource policy, not a claimed limit of the Synology protocol.
struct Limits {
    std::size_t max_bytes = 16 * 1024 * 1024;
    std::size_t max_nodes = 100'000;
    std::size_t max_depth = 64;
};

class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Control-value subset only: streamed-file tags 0x30 and 0x43 are not implemented.
Bytes encode(const Value& value, Limits limits = {});
Value decode(std::span<const std::uint8_t> bytes, Limits limits = {});
// The callback must fill exactly the requested span or throw. Reads stop at the
// end of one value, leaving subsequent protocol/TLS bytes in the source.
using ReadExact = std::function<void(std::span<std::uint8_t>)>;
Value read(const ReadExact& source, Limits limits = {});
} // namespace opensabba::pstream
