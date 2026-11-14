// Deterministic OS boundary for network/PTY/event fixtures. No host module,
// device or snapshot control may influence these tests. Common daemon code
// still performs all authentication, events, restore and writer coordination.
#include "opensabba/service_machine_capture.hpp"
namespace opensabba {
namespace {
class NoSnapshotDriver final : public ServiceMachineCaptureProvider {
public:
    DriverStatus driver_status() override { return DriverStatus::disabled; }
    pstream::Value plan(const std::string&,const pstream::Value&) override {
        throw pstream::Error("network fixture unexpectedly planned machine capture");
    }
    CaptureJournal capture(const ServiceMachineCaptureRequest&) override {
        throw pstream::Error("network fixture unexpectedly acquired a snapshot");
    }
};
}
ServiceMachineCaptureProvider& service_machine_capture_provider() {
    static NoSnapshotDriver provider;
    return provider;
}
}
