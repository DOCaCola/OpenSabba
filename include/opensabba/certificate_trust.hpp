#pragma once
#include "opensabba/client.hpp"

namespace opensabba {
// The store is read at each handshake so other connections observe renewals.
std::function<bool(const ServerCertificate&)> certificate_verifier(
    std::function<std::optional<std::string>()> read,
    std::function<void(const std::string&)> write,
    std::function<bool(const ServerCertificate&, bool changed)> prompt = {},
    bool quiet = false);
}
