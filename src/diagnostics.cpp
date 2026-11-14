#include "opensabba/diagnostics.hpp"
#include <algorithm>
#include <array>

namespace opensabba {
namespace {
using pstream::Value;
Value string(const char* text) { return Value{std::string(text)}; }
Value summarize(const Value& value, unsigned depth = 0) {
    const auto* object = std::get_if<Value::Object>(&value.data);
    if (!object) throw pstream::Error("invalid diagnostic journal");
    Value::Object out;
    // Positive allowlist: never recursively copy arbitrary keys or values.
    for (auto key : {"format", "schema", "auth_type", "task_id", "running_task_id",
                     "result_id", "version_id", "image_size", "offset", "claimed_run",
                     "queued_run", "cow_mib", "rotate", "rotation_run", "incremental_transfer"}) {
        const auto entry = object->find(key);
        if (entry != object->end() && std::holds_alternative<std::uint64_t>(entry->second.data))
            out.emplace(key,entry->second);
    }
    constexpr std::array states{
        "planned", "prepare", "prepared", "metadata", "metadata-accepted",
        "upload", "uploaded", "finish", "complete", "partial", "cancel", "error",
        "create", "created", "download", "verified", "downloaded", "ready",
        "aborted", "recovery-required", "active", "released", "absent",
        "pending", "applying", "applied", "tracking", "captured",
        "snapshot-intent", "snapshot-active",
        "static-copy-intent", "static-copied",
        "root-copy-intent", "root-copied", "snapshot-release-intent", "snapshot-released",
        "seal-intent"};
    for (auto key : {"phase", "state", "compression"}) {
        const auto entry = object->find(key);
        if (entry == object->end()) continue;
        const auto* text = std::get_if<std::string>(&entry->second.data);
        const bool recognized = text && (std::string_view(key) == "compression"
            ? *text == "lz4" || *text == "none"
            : std::find(states.begin(),states.end(),*text) != states.end());
        out.emplace(key,recognized ? entry->second : string("unrecognized"));
    }
    for (auto key : {"receipts", "task_snapshot", "running_task_snapshot"}) {
        const auto entry = object->find(key);
        if (entry == object->end()) continue;
        if (const auto* array = std::get_if<Value::Array>(&entry->second.data))
            out.emplace(std::string(key)+"_count",Value{std::uint64_t{array->size()}});
    }
    if (depth < 2) {
        for (auto key : {"capture", "source_capture", "task_owner"}) {
            const auto entry = object->find(key);
            if (entry != object->end()) out.emplace(key,summarize(entry->second,depth+1));
        }
    }
    return Value{std::move(out)};
}
}
pstream::Value diagnostic_summary(const pstream::Value& value) { return summarize(value); }
pstream::Value diagnostic_report(const DiagnosticReader& read) {
    Value::Object journals;
    for (auto name : {"session.pstream", "identity.pstream", "backup-job.pstream",
                     "events.pstream", "service-source.pstream", "service-machine-pending.pstream",
                     "service-machine-event.pstream", "service-machine-recapture.pstream"}) {
        Value::Object entry;
        try {
            auto value = read(name);
            entry.emplace("status",string(value ? "read" : "missing"));
            if (value) entry.emplace("summary",summarize(*value));
        } catch (const pstream::Error&) {
            entry.clear();
            entry.emplace("status",string("unreadable"));
        }
        journals.emplace(name,Value{std::move(entry)});
    }
    return Value{Value::Object{
        {"format",Value{std::uint64_t{1}}},
        {"kind",string("opensabba-diagnostics")},
        {"consistency",string("individual atomic journals; not a cross-journal snapshot")},
        {"journals",Value{std::move(journals)}}}};
}
}
