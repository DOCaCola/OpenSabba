#pragma once

#include <filesystem>
#include <optional>

namespace opensabba {
// Returns no value only in the detached grandchild. Both parents return their
// exit status: the launching process waits until the grandchild has written
// its PID file (systemd reads PIDFile= as soon as the launcher exits) and
// fails if the grandchild ends first. Like official agent, retains cwd, umask and the
// inherited standard descriptors.
std::optional<int> daemonize_service();

// Creating the PID file releases a launcher waiting in daemonize_service.

class ServicePidFile {
    std::filesystem::path path_;
public:
    explicit ServicePidFile(std::filesystem::path path);
    ~ServicePidFile();
    ServicePidFile(const ServicePidFile&) = delete;
    ServicePidFile& operator=(const ServicePidFile&) = delete;
};
}
