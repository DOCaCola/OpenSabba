#pragma once

#include <filesystem>

namespace opensabba {
// Returns true only in the detached grandchild; both parents return false.
// Like official agent, retains cwd, umask and the inherited standard descriptors.
bool daemonize_service();

class ServicePidFile {
    std::filesystem::path path_;
public:
    explicit ServicePidFile(std::filesystem::path path);
    ~ServicePidFile();
    ServicePidFile(const ServicePidFile&) = delete;
    ServicePidFile& operator=(const ServicePidFile&) = delete;
};
}
