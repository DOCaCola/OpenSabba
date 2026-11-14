#include "opensabba/service_machine_capture.hpp"
#include "opensabba/machine.hpp"
#include "opensabba/task_policy.hpp"
namespace opensabba {
namespace {
class LinuxMachineCapture final : public ServiceMachineCaptureProvider {
public:
    DriverStatus driver_status() override {
        // Driver preflight checks module presence, not GET_FREE.
        return std::filesystem::exists("/sys/module/synosnap") ?
            DriverStatus::enabled : DriverStatus::disabled;
    }
    pstream::Value plan(const std::string& directory,const pstream::Value& task) override {
        return select_machine_inventory(discover_machine_inventory(directory),task);
    }
    CaptureJournal capture(const ServiceMachineCaptureRequest& request) override {
        return create_machine_capture_from_plan(request.job.capture,request.job.task,0,
            request.reserved,request.cancelled,request.validate_plan,request.hooks,true,
            request.cache_exclusions,request.stopping);
    }
};
}
ServiceMachineCaptureProvider& service_machine_capture_provider() {
    static LinuxMachineCapture provider;
    return provider;
}
}
