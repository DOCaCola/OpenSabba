#include "opensabba/certificate_trust.hpp"

namespace opensabba {
std::function<bool(const ServerCertificate&)> certificate_verifier(
    std::function<std::optional<std::string>()> read,
    std::function<void(const std::string&)> write,
    std::function<bool(const ServerCertificate&, bool)> prompt,
    bool quiet) {
    return [read = std::move(read), write = std::move(write),
            prompt = std::move(prompt), quiet](const ServerCertificate& certificate) {
        const auto saved = read();
        if (saved && *saved == certificate.sha256) return true;
        const bool accept = certificate.verified || (!saved && quiet) ||
            (prompt && prompt(certificate, saved.has_value()));
        if (accept) write(certificate.sha256);
        return accept;
    };
}
}
