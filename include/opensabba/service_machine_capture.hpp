#pragma once
#include "opensabba/machine_capture.hpp"
#include "opensabba/client.hpp"
namespace opensabba {
// OS/topology acquisition boundary. Event handshake, snapshot catalog, pending
// ownership and NAS transfer remain in the common service implementation.
struct MachineJobPlan {
    pstream::Value task;
    pstream::Value event;
    pstream::Value capture;
    std::optional<PreparedBackup> preparation;
};
struct ServiceMachineCaptureRequest {
    MachineJobPlan job;
    std::function<void(const CaptureJournal&)> reserved;
    std::function<bool()> cancelled;
    std::function<void(const pstream::Value&)> validate_plan;
    SnapshotBoundaryHooks hooks;
    std::vector<std::filesystem::path> cache_exclusions;
    std::function<bool()> stopping;
};
class ServiceMachineCaptureProvider {
public:
    virtual ~ServiceMachineCaptureProvider() = default;
    // Loaded-driver capability is independent of source ownership/free slots.
    virtual DriverStatus driver_status() = 0;
    virtual pstream::Value plan(const std::string& working_directory, const pstream::Value& task) = 0;
    virtual CaptureJournal capture(const ServiceMachineCaptureRequest&) = 0;
};
ServiceMachineCaptureProvider& service_machine_capture_provider();
}
