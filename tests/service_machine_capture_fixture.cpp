// Link-time OS provider for the real service executable. This file never reads
// or writes service state, NAS journals or the snapshot catalog.
#include "opensabba/service_machine_capture.hpp"
#include "opensabba/task_policy.hpp"
#include <cstdlib>
#include <fstream>
#include <sys/stat.h>
namespace opensabba {
namespace {
using pstream::Value;
using pstream::Error;
Value& field(Value& value, const char* key) { return std::get<Value::Object>(value.data).at(key); }
void set(Value& value, const char* key, Value next) { std::get<Value::Object>(value.data)[key] = std::move(next); }
const std::string& text(const Value& value, const char* key) {
    return std::get<std::string>(std::get<Value::Object>(value.data).at(key).data);
}
CaptureJournal specimen() {
    const auto* path = std::getenv("OPENSABBA_MACHINE_CAPTURE_FIXTURE");
    if (!path) throw Error("service OS specimen was not supplied");
    std::ifstream input(path,std::ios::binary);
    if (!input) throw Error("cannot read service OS specimen");
    const pstream::Bytes bytes{std::istreambuf_iterator<char>(input),{}};
    return capture_journal_from_value(pstream::decode(bytes));
}
void write(const std::filesystem::path& path, const CaptureJournal& journal) {
    const auto bytes = pstream::encode(capture_journal_value(journal));
    std::ofstream output(path,std::ios::binary|std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));
    output.close();
    if (!output || chmod(path.c_str(),0600)) throw Error("cannot save released OS specimen");
}
class SpecimenCapture final : public ServiceMachineCaptureProvider {
public:
    DriverStatus driver_status() override { return DriverStatus::enabled; }
    Value plan(const std::string& directory,const Value& task) override {
        auto journal = specimen();
        set(journal.plan,"cow_directory",Value{directory});
        (void)validate_machine_task_policy(task,journal.plan,true);
        return journal.plan;
    }
    CaptureJournal capture(const ServiceMachineCaptureRequest& request) override {
        const auto ready = specimen();
        const auto directory = std::filesystem::path(text(ready.reservation,"directory"));
        if (directory.parent_path() != text(request.job.capture,"cow_directory"))
            throw Error("acquired fixture differs from the private working area");
        auto expected = ready.plan;
        set(expected,"cow_directory",std::get<Value::Object>(request.job.capture.data).at("cow_directory"));
        if (request.job.capture != expected) throw Error("capture differs from its fresh NAS/discovery plan");
        const auto& task = std::get<Value::Object>(request.job.task.data);
        const auto& event = std::get<Value::Object>(request.job.event.data);
        if (!request.job.preparation || event.at("task_id") != task.at("id") ||
            std::get<std::uint64_t>(event.at("id").data) != request.job.preparation->run.running_task_id)
            throw Error("capture has no exact authenticated task/event/preparation identity");
        if (request.cancelled && request.cancelled()) throw CaptureCancelled();
        request.validate_plan(ready.plan);
        auto reserved = ready;
        reserved.phase = CapturePhase::prepared;
        reserved.snapshot = Value{};
        reserved.artifact = Value{};
        const auto clear_progress = [](Value& reservation) {
            auto& fields = std::get<Value::Object>(reservation.data);
            for (const auto* key : {"changes","previous_capture_id","previous_directory",
                                   "cow_unused","filesystem_unused","cache_unused","tracking_recovery"})
                fields.erase(key);
        };
        clear_progress(reserved.reservation);
        set(reserved.reservation,"snapshot_attempted",Value{std::uint64_t{0}});
        set(reserved.reservation,"snapshot_released",Value{std::uint64_t{0}});
        set(reserved.reservation,"snapshot_time",Value{std::uint64_t{0}});
        for (auto& extra : std::get<Value::Array>(field(reserved.reservation,"extras").data)) {
            clear_progress(extra);
            set(extra,"attempted",Value{std::uint64_t{0}});
            set(extra,"released",Value{std::uint64_t{0}});
            set(extra,"snapshot",Value{});
        }
        verify_machine_reservation(reserved,ready);
        request.reserved(reserved); // The common service reserves/attaches its real catalog row here.
        if (request.hooks.pre_snapshot) request.hooks.pre_snapshot();
        if (request.hooks.missing_custom_mounts && !request.hooks.missing_custom_mounts(ready.plan).empty())
            throw Error("fixture NAS selection has missing mounts");
        if (request.hooks.snapshot_elapsed) request.hooks.snapshot_elapsed(1);
        if (request.hooks.post_snapshot) request.hooks.post_snapshot();
        auto released = ready;
        set(released.reservation,"snapshot_released",Value{std::uint64_t{1}});
        for (auto& extra : std::get<Value::Array>(field(released.reservation,"extras").data))
            set(extra,"released",Value{std::uint64_t{1}});
        write(directory/"release.pstream",released);
        return ready;
    }
};
}
ServiceMachineCaptureProvider& service_machine_capture_provider() {
    static SpecimenCapture provider;
    return provider;
}
}
