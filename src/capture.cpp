#include "opensabba/capture.hpp"
#include "opensabba/machine.hpp"
#include "opensabba/server_time.hpp"
#include "opensabba/tracking_record.hpp"
#include <array>
#include <algorithm>
#include <chrono>
#include <exception>

namespace opensabba {
using pstream::Value;
using pstream::Error;
Value record_snapshot_acquisition_failure(CaptureJournal& journal, Value& reservation,
    bool root, const SnapshotAcquisitionError& error,
    const std::function<void()>& retire_unused,
    const std::function<void(const CaptureJournal&)>& persist) {
    auto& fields = std::get<Value::Object>(reservation.data);
    fields[root ? "snapshot_released" : "released"] = Value{std::uint64_t{1}};
    const Value omitted{Value::Object{
        {"acquisition_error",Value{static_cast<std::uint64_t>(error.error)}}}};
    if (root) journal.snapshot = omitted;
    else fields["snapshot"] = omitted;
    persist(journal);
    if (!dynamic_cast<const SnapshotPreviousCowError*>(&error)) retire_unused();
    return omitted;
}
namespace {
constexpr std::array names{
    "prepared", "static-copy-intent", "static-copied",
    "snapshot-intent", "snapshot-active",
    "root-copy-intent", "root-copied", "extra-copy-intent", "extra-copied",
    "seal-intent", "ready", "recovery-required", "aborted"};
std::string phase_name(CapturePhase phase) {
    const auto index = static_cast<std::size_t>(phase);
    if (index >= names.size()) throw Error("invalid capture phase");
    return names[index];
}
const Value::Object& object(const Value& value) {
    const auto* result = std::get_if<Value::Object>(&value.data);
    if (!result) throw Error("capture journal field must be an object");
    return *result;
}
const Value& field(const Value& value, const char* key) {
    const auto& fields = object(value);
    const auto found = fields.find(key);
    if (found == fields.end()) throw Error(std::string("capture journal is missing ")+key);
    return found->second;
}
std::string text(const Value& value, const char* key) {
    const auto* result = std::get_if<std::string>(&field(value, key).data);
    if (!result) throw Error(std::string("invalid capture journal string: ")+key);
    return *result;
}
void validate_schema(const CaptureJournal& journal) {
    if (journal.schema != 5) throw Error("unsupported capture journal schema");
}
void validate(const CaptureJournal& journal) {
    validate_schema(journal);
    if (journal.id.size() != 32 || journal.id.find_first_not_of("0123456789abcdef") != journal.id.npos)
        throw Error("invalid capture transaction identifier");
    const auto& boot = journal.boot_id;
    if (boot.size() != 36 || boot[8] != '-' || boot[13] != '-' || boot[18] != '-' || boot[23] != '-' ||
        boot.find_first_not_of("0123456789abcdef-") != boot.npos)
        throw Error("invalid capture boot identity");
    (void)phase_name(journal.phase);
    object(journal.plan);
    const auto cache_failures = [&](const Value& disk) {
        validate_machine_raw_cache_failures(disk);
        if (object(disk).contains("raw_cache_failures") &&
            journal.phase < CapturePhase::static_copy_intent)
            throw Error("raw cache failure precedes cache copy");
    };
    cache_failures(journal.plan);
    (void)machine_layout_regions(journal.plan);
    if (object(journal.plan).contains("additional_disks"))
        for (const auto& disk : std::get<Value::Array>(field(journal.plan,"additional_disks").data)) {
            cache_failures(disk);
            (void)machine_layout_regions(disk);
        }
    if (machine_bare_metal(journal.plan)) {
        (void)machine_static_regions(journal.plan);
        (void)machine_unused_extents(journal.plan);
        for (const auto& disk : std::get<Value::Array>(field(journal.plan,"additional_disks").data)) {
            if (!machine_bare_metal(disk)) throw Error("machine disk volume policy differs from capture");
            (void)machine_additional_static_regions(disk);
            (void)machine_unused_extents(disk);
        }
    }
    const auto& reservation = object(journal.reservation);
    const bool snapshot_required = journal.phase >= CapturePhase::snapshot_active &&
                                   journal.phase <= CapturePhase::ready;
    if (snapshot_required || !std::holds_alternative<std::monostate>(journal.snapshot.data))
        if (object(journal.snapshot).empty()) throw Error("capture snapshot identity is empty");
    const auto omission = [&](const Value& snapshot, const Value& reserved,
                              const char* attempted, const char* released) {
        if (!capture_snapshot_omitted(snapshot)) return;
        if (journal.phase < CapturePhase::snapshot_intent ||
            field(reserved,attempted) != Value{std::uint64_t{1}} ||
            field(reserved,released) != Value{std::uint64_t{1}})
            throw Error("omitted snapshot lacks confirmed acquisition retirement");
    };
    omission(journal.snapshot,journal.reservation,"snapshot_attempted","snapshot_released");
    if (reservation.contains("extras"))
        for (const auto& extra : std::get<Value::Array>(reservation.at("extras").data))
            omission(field(extra,"snapshot"),extra,"attempted","released");
    if (journal.phase == CapturePhase::ready || !std::holds_alternative<std::monostate>(journal.artifact.data))
        if (object(journal.artifact).empty()) throw Error("capture image identity is empty");
    if (journal.failure.size() > 16384) throw Error("capture diagnostic exceeds journal limit");
    if (journal.failure_disposition != "" &&
        journal.failure_disposition != "failure" && journal.failure_disposition != "interrupted" &&
        journal.failure_disposition != "uncertain")
        throw Error("invalid capture failure disposition");
}
std::string error_text() {
    try { throw; }
    catch (const std::exception& error) { return error.what(); }
    catch (...) { return "unknown capture error"; }
}
void transition(CaptureJournal& journal, CaptureOperations& operations, CapturePhase phase) {
    journal.phase = phase;
    try { operations.persist(journal); }
    catch (const std::exception& error) { throw CapturePersistenceError(error.what()); }
}
}

Value capture_journal_value(const CaptureJournal& journal) {
    validate(journal);
    Value::Object result{
        {"schema", Value{journal.schema}}, {"id", Value{journal.id}}, {"boot_id", Value{journal.boot_id}},
        {"phase", Value{phase_name(journal.phase)}}, {"plan", journal.plan},
        {"reservation", journal.reservation}, {"snapshot", journal.snapshot},
        {"artifact", journal.artifact}, {"failure", Value{journal.failure}}};
    result["failure_disposition"] = Value{journal.failure_disposition};
    result["logs"] = Value{journal.logs};
    return Value{std::move(result)};
}
bool capture_snapshot_omitted(const Value& snapshot) {
    const auto* fields = std::get_if<Value::Object>(&snapshot.data);
    if (!fields || !fields->contains("acquisition_error")) return false;
    const auto* error = std::get_if<std::uint64_t>(&fields->at("acquisition_error").data);
    if (fields->size() != 1 || !error || !*error || *error > 4095)
        throw Error("invalid omitted snapshot result");
    return true;
}
CaptureJournal capture_journal_from_value(const Value& value) {
    const auto* schema = std::get_if<std::uint64_t>(&field(value, "schema").data);
    if (!schema || *schema != 5)
        throw Error("unsupported capture journal schema");
    const auto name = text(value, "phase");
    std::size_t index = 0;
    while (index < names.size() && names[index] != name) ++index;
    if (index == names.size()) throw Error("unknown capture journal phase");
    CaptureJournal journal{text(value, "id"), text(value, "boot_id"), static_cast<CapturePhase>(index),
        field(value, "plan"), field(value, "reservation"), field(value, "snapshot"),
        field(value, "artifact"), text(value, "failure"), *schema,{},{}};
    journal.failure_disposition = text(value,"failure_disposition");
    journal.logs = std::get<Value::Array>(field(value,"logs").data);
    validate(journal);
    return journal;
}
bool capture_failure_reportable(const CaptureJournal& journal) {
    validate(journal);
    // NAS failure and local cleanup are separate. the official agent does not keep an event
    // running solely because best-effort snapshot destruction failed.
    if (journal.phase == CapturePhase::recovery_required) return true;
    if (journal.phase != CapturePhase::aborted) return false;
    const auto released = [](const Value& value, const char* attempted, const char* complete) {
        return !std::get<std::uint64_t>(field(value,attempted).data) ||
            std::get<std::uint64_t>(field(value,complete).data) == 1;
    };
    if (!released(journal.reservation,"snapshot_attempted","snapshot_released")) return false;
    for (const auto& extra : std::get<Value::Array>(field(journal.reservation,"extras").data))
        if (!released(extra,"attempted","released")) return false;
    return true;
}

void recover_machine_capture(CaptureJournal& journal, CaptureOperations& operations) {
    validate(journal);
    if (journal.phase == CapturePhase::ready || journal.phase == CapturePhase::aborted) return;
    const auto disposition = journal.failure_disposition;
    // Until all releases and the final abort write succeed, the durable state
    // must not authorize reporting a definitive failure after process death.
    journal.failure_disposition = "uncertain";
    // A persistence failure must not prevent releasing owned snapshots.
    std::string errors;
    const auto attempt = [&](const char* description, const auto& operation) {
        try { operation(); }
        catch (...) { errors += std::string(description)+": "+error_text()+"; "; }
    };
    attempt("record recovery intent", [&] { transition(journal, operations, CapturePhase::recovery_required); });
    attempt("release owned snapshot", [&] { operations.recover_snapshot(journal); });
    if (!errors.empty()) {
        journal.phase = CapturePhase::recovery_required;
        journal.failure_disposition = "uncertain";
        try { operations.persist(journal); } catch (...) { /* Already reporting persistence/recovery failure. */ }
        throw Error("machine capture requires recovery: "+errors);
    }
    journal.failure_disposition = disposition;
    transition(journal, operations, CapturePhase::aborted);
}

namespace {
[[noreturn]] void interrupt_capture(CaptureJournal& journal, CaptureOperations& operations) {
    // the official agent service abort joins workers and closes the snapshot library; it
    // neither destroys retained slots nor transitions them to incremental.
    // Keep the last acquisition phase so restart can inspect/reuse the same set.
    journal.failure_disposition = "interrupted";
    // A failed final persist must remain resumable rather than publish ready.
    if (journal.phase == CapturePhase::ready) journal.phase = CapturePhase::seal_intent;
    operations.persist(journal);
    throw CaptureInterrupted();
}
}

std::uint64_t CaptureOperations::snapshot_time() { return server_time_now(); }

void resume_machine_capture(CaptureJournal& journal, CaptureOperations& operations) {
    validate(journal);
    if (journal.phase < CapturePhase::snapshot_active || journal.phase > CapturePhase::seal_intent)
        throw Error("capture has no established snapshot set to resume");
    try {
        operations.verify_inputs();
        if (operations.cancelled() && !operations.stopping()) throw CaptureStopRequested();
        transition(journal,operations,CapturePhase::root_copy_intent);
        operations.prepare_snapshot_root(journal.snapshot);
        transition(journal,operations,CapturePhase::root_copied);
        transition(journal,operations,CapturePhase::extra_copy_intent);
        operations.prepare_extra_volumes();
        transition(journal,operations,CapturePhase::extra_copied);
        operations.verify_inputs();
        transition(journal,operations,CapturePhase::seal_intent);
        journal.artifact = operations.seal_raw_cache();
        if (operations.cancelled() && !operations.stopping()) throw CaptureStopRequested();
        journal.failure.clear();
        journal.failure_disposition.clear();
        transition(journal,operations,CapturePhase::ready);
    } catch (...) {
        journal.failure = error_text().substr(0,16384);
        if (operations.stopping()) interrupt_capture(journal,operations);
        journal.failure_disposition = "failure";
        try { throw; }
        catch (const CaptureStopRequested&) { journal.failure_disposition = "interrupted"; }
        catch (const CapturePersistenceError&) { journal.failure_disposition = "uncertain"; }
        catch (const CaptureUncertain&) { journal.failure_disposition = "uncertain"; }
        catch (...) {}
        journal.phase = CapturePhase::recovery_required;
        const auto failure = journal.failure;
        recover_machine_capture(journal,operations);
        throw CaptureFailed(failure);
    }
}

void run_machine_capture(CaptureJournal& journal, CaptureOperations& operations,
                         const SnapshotBoundaryHooks& hooks) {
    validate(journal);
    if (journal.phase != CapturePhase::prepared)
        throw Error("capture already started; reconcile its resources instead of repeating capture mutations");
    if (!std::holds_alternative<std::monostate>(journal.snapshot.data) ||
        !std::holds_alternative<std::monostate>(journal.artifact.data))
        throw Error("new capture already contains output identities");
    bool uncertain = false, interrupted = false, published = false;
    bool pre_finished = false, post_started = false;
    const auto post = [&] {
        post_started = true;
        if (hooks.post_snapshot) hooks.post_snapshot();
    };
    const auto verify = [&] {
        if (operations.cancelled() &&
            !(operations.stopping() && journal.phase >= CapturePhase::snapshot_active))
            throw CaptureStopRequested();
        uncertain = true;
        operations.verify_inputs();
        uncertain = false;
    };
    try {
        transition(journal,operations,CapturePhase::prepared);
        verify();
        if (hooks.pre_snapshot) hooks.pre_snapshot();
        pre_finished = true;
        const auto snapshot_started = std::chrono::system_clock::now();
        try {
            verify();
            journal.logs.push_back(Value{Value::Object{
                {"log_type",Value{std::uint64_t{7001}}},{"log_time",Value{server_time_now()}},
                {"parameters",Value{Value::Object{}}}}});
            if (object(journal.plan).contains("discovery_errors"))
                for (const auto& error : std::get<Value::Array>(field(journal.plan,"discovery_errors").data))
                    journal.logs.push_back(Value{Value::Object{
                        {"log_type",Value{std::uint64_t{7110}}},{"log_time",Value{server_time_now()}},
                        {"parameters",Value{Value::Object{{"disk_name",field(error,"disk")}}}}}});
            // Retain only small raw caches before the snapshot boundary.
            // FAT/type-2 data will be read from the disk during upload.
            transition(journal, operations, CapturePhase::static_copy_intent);
            operations.cache_raw_regions();
            transition(journal, operations, CapturePhase::static_copied);
            verify();
            if (hooks.missing_custom_mounts) {
                const auto missing = hooks.missing_custom_mounts(journal.plan);
                if (!missing.empty()) {
                    std::string paths;
                    for (const auto& mount : missing) {
                        if (!paths.empty()) paths += ", ";
                        paths += mount;
                    }
                    journal.logs.push_back(Value{Value::Object{
                        {"log_type",Value{std::uint64_t{7096}}},{"log_time",Value{server_time_now()}},
                        {"parameters",Value{Value::Object{{"mount_path",Value{paths}}}}}}});
                }
            }
            // This is the official agent snapshot acquisition boundary, after pre and analysis.
            // Persist the NAS-adjusted creation time before the first ioctl so
            // replay/publication always uses the same instant.
            std::get<Value::Object>(journal.reservation.data)["snapshot_time"] = Value{operations.snapshot_time()};
            transition(journal, operations, CapturePhase::snapshot_intent);
            const auto snapshot = operations.snapshot_root();
            if (object(snapshot).empty()) throw Error("capture snapshot identity is empty");
            journal.snapshot = snapshot;
            operations.snapshot_extra_volumes();
            if (capture_snapshot_omitted(journal.snapshot)) {
                const auto& extras = std::get<Value::Array>(field(journal.reservation,"extras").data);
                if (std::all_of(extras.begin(),extras.end(),[](const auto& extra) {
                        return capture_snapshot_omitted(field(extra,"snapshot"));
                    })) {
                    throw Error("no selected filesystem snapshot could be acquired");
                }
            }
            transition(journal, operations, CapturePhase::snapshot_active);
        } catch (...) {
            const auto original = std::current_exception();
            auto failure = error_text();
            try { std::rethrow_exception(original); }
            catch (const CapturePersistenceError&) { uncertain = true; }
            catch (const CaptureUncertain&) { uncertain = true; }
            catch (const CaptureStopRequested&) { interrupted = true; }
            catch (...) {}
            std::string errors;
            try { post(); }
            catch (...) {
                const auto post_error = error_text();
                try { throw; }
                catch (const CapturePersistenceError&) { uncertain = true; }
                catch (const CaptureUncertain&) { uncertain = true; }
                catch (const CaptureStopRequested&) { interrupted = true; }
                catch (...) {}
                errors += "; post snapshot: "+post_error;
            }
            if (!errors.empty()) throw Error(failure+errors);
            std::rethrow_exception(original);
        }
        if (hooks.snapshot_elapsed) hooks.snapshot_elapsed(static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::system_clock::now()-snapshot_started).count()));
        // the official agent device metadata construction and snapshot publication finish without a service-abort
        // gate. Publish the usable set before the post
        // wrapper, which may itself return service-abort.
        verify();
        transition(journal, operations, CapturePhase::root_copy_intent);
        operations.prepare_snapshot_root(journal.snapshot);
        transition(journal, operations, CapturePhase::root_copied);
        transition(journal, operations, CapturePhase::extra_copy_intent);
        operations.prepare_extra_volumes();
        transition(journal, operations, CapturePhase::extra_copied);
        verify();
        transition(journal, operations, CapturePhase::seal_intent);
        const auto artifact = operations.seal_raw_cache();
        if (object(artifact).empty()) throw Error("capture image identity is empty");
        journal.artifact = artifact;
        if (operations.cancelled() && !operations.stopping()) throw CaptureStopRequested();
        transition(journal, operations, CapturePhase::ready);
        published = true;
        post();
        if (operations.stopping()) throw CaptureInterrupted();
    } catch (...) {
        if (published) {
            // A post wrapper failure cannot undo official agent capture metadata publication.
            // Preserve the terminal CaptureFailed type as well: a mode-1
            // script failure stops this event without invalidating the set.
            if (operations.stopping()) throw CaptureInterrupted();
            throw;
        }
        std::string post_failure;
        if (pre_finished && !post_started) {
            try { post(); }
            catch (...) { post_failure = "; post snapshot: "+error_text(); }
        }
        bool cancelled = interrupted;
        try { throw; }
        catch (const CaptureStopRequested&) { cancelled = true; }
        catch (const CapturePersistenceError&) { uncertain = true; }
        catch (const CaptureUncertain&) { uncertain = true; }
        catch (...) {}
        auto failure = error_text()+post_failure;
        journal.failure = failure.substr(0, 16384);
        if (operations.stopping() && journal.phase >= CapturePhase::snapshot_active &&
            journal.phase <= CapturePhase::ready) interrupt_capture(journal,operations);
        journal.failure_disposition = uncertain ? "uncertain" : cancelled ? "interrupted" : "failure";
        // Even a lost final persist reply is an uncertain result. No caller is
        // told this capture is usable; recovery retains the artifact as evidence.
        journal.phase = CapturePhase::recovery_required;
        try { recover_machine_capture(journal, operations); }
        catch (...) { throw Error(failure+"; "+error_text()); }
        if (cancelled && !uncertain) throw CaptureCancelled();
        if (journal.failure_disposition == "failure") throw CaptureFailed(failure);
        throw Error(failure);
    }
}
}
