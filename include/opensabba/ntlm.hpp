#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace opensabba {
struct ProxyCredentials;
namespace ntlm {
using Bytes = std::vector<std::uint8_t>;
Bytes negotiate();
Bytes authenticate(std::span<const std::uint8_t> negotiate_message,
                   std::span<const std::uint8_t> challenge_message,
                   const ProxyCredentials& credentials);
std::string encode(std::span<const std::uint8_t> message);
Bytes decode(std::string_view text);
}
}
