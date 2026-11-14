#include "opensabba/machine_capture.hpp"
#include "opensabba/client.hpp"
#include "opensabba/machine.hpp"
#include "opensabba/tracking_record.hpp"
#include <algorithm>

namespace opensabba {
using pstream::Value;
using pstream::Error;
namespace {
const Value& field(const Value& v, const char* key) {
    const auto* o = std::get_if<Value::Object>(&v.data);
    if (!o || !o->contains(key)) throw Error(std::string("missing artifact field: ")+key);
    return o->at(key);
}
std::uint64_t number(const Value& v, const char* key) {
    const auto* n = std::get_if<std::uint64_t>(&field(v,key).data);
    if (!n) throw Error(std::string("invalid artifact number: ")+key);
    return *n;
}
}
namespace {
Value machine_target(const Value& plan, bool transfer) {
    Value::Object target;
    const auto& source = std::get<Value::Object>(plan.data);
    for (const auto* key : {"layout","cow_directory","cow_filesystem_uuid","other_disk_count",
                            "volume_policy","swap_page_size","layout_policy"})
        if (source.contains(key)) target.emplace(key,field(plan,key));
    if (!transfer)
        for (const auto* key : {"unselected_disks","unselected_logical"})
            if (source.contains(key)) target.emplace(key,field(plan,key));
    for (const auto* role : {"root","boot"}) {
        if (!source.contains(role)) continue;
        Value::Object partition;
        const auto& entry = field(plan,role);
        const auto& properties = std::get<Value::Object>(entry.data);
        if (properties.contains("lv_uuid")) {
            for (const auto* key : {"lv_name","lv_uuid","vg_uuid","image_name","length",
                                    "mount_path","filesystem","filesystem_uuid","segments"})
                if (!transfer || std::string_view(key) != "segments")
                    partition.emplace(key,field(entry,key));
        } else
            for (const auto* key : {"partition","offset","length","mount_path","filesystem","filesystem_uuid"})
                partition.emplace(key,field(entry,key));
        target.emplace(role,Value{std::move(partition)});
    }
    for (const auto* role : {"selected_extra","excluded"}) {
        if (!source.contains(role)) continue;
        const auto* entries = std::get_if<Value::Array>(&field(plan,role).data);
        if (!entries) throw Error("invalid machine partition selection");
        Value::Array normalized;
        for (const auto& entry : *entries) {
            Value::Object partition;
            const auto& properties = std::get<Value::Object>(entry.data);
            if (properties.contains("lv_uuid")) {
                for (const auto* key : {"lv_name","lv_uuid","vg_uuid","image_name","length",
                                        "mount_path","filesystem","filesystem_uuid","segments"})
                    if (!transfer || std::string_view(key) != "segments")
                        partition.emplace(key,field(entry,key));
            } else for (const auto* key : {"partition","offset","length","mount_path","filesystem"})
                partition.emplace(key,field(entry,key));
            if (!properties.contains("lv_uuid") && properties.contains("filesystem_uuid"))
                partition.emplace("filesystem_uuid",field(entry,"filesystem_uuid"));
            for (const auto* key : {"selected_raw","pv_uuid","vg_uuid","pv_wire_policy",
                                    "pv_metadata_length","pv_extent_length",
                                    "pv_mda_size","pv_mda_count","pv_metadata_sha256",
                                    "pv_tail_length","pv_tail_sha256"})
                if (properties.contains(key)) partition.emplace(key,field(entry,key));
            normalized.push_back(Value{std::move(partition)});
        }
        target.emplace(role,Value{std::move(normalized)});
    }
    if (source.contains("additional_disks")) {
        Value::Array disks;
        for (const auto& disk : std::get<Value::Array>(field(plan,"additional_disks").data)) {
            Value::Object normalized{{"layout",field(disk,"layout")}};
            for (const auto* key : {"volume_policy","swap_page_size","layout_policy"})
                if (std::get<Value::Object>(disk.data).contains(key))
                    normalized.emplace(key,field(disk,key));
            for (const auto* role : {"selected_extra","excluded"}) {
                Value::Array partitions;
                for (const auto& entry : std::get<Value::Array>(field(disk,role).data)) {
                    Value::Object part;
                    for (const auto* key : {"partition","offset","length","mount_path","filesystem"})
                        part.emplace(key,field(entry,key));
                    const auto& properties = std::get<Value::Object>(entry.data);
                    if (properties.contains("filesystem_uuid"))
                        part.emplace("filesystem_uuid",field(entry,"filesystem_uuid"));
                    for (const auto* key : {"selected_raw","pv_uuid","vg_uuid","pv_wire_policy",
                                            "pv_metadata_length","pv_extent_length",
                                            "pv_mda_size","pv_mda_count","pv_metadata_sha256",
                                            "pv_tail_length","pv_tail_sha256"})
                        if (properties.contains(key)) part.emplace(key,field(entry,key));
                    partitions.push_back(Value{std::move(part)});
                }
                normalized.emplace(role,Value{std::move(partitions)});
            }
            disks.push_back(Value{std::move(normalized)});
        }
        target.emplace("additional_disks",Value{std::move(disks)});
    }
    if (!transfer && source.contains("lvm")) {
        const auto& lvm = field(plan,"lvm");
        Value::Array groups;
        for (const auto& group : std::get<Value::Array>(field(lvm,"volume_groups").data)) {
            Value::Array pvs;
            for (const auto& pv : std::get<Value::Array>(field(group,"physical_volumes").data))
                pvs.push_back(Value{Value::Object{
                    {"uuid",field(pv,"uuid")},{"size",field(pv,"size")}}});
            groups.push_back(Value{Value::Object{
                {"name",field(group,"name")},{"uuid",field(group,"uuid")},
                {"extent_size",field(group,"extent_size")},
                {"mda_size",field(group,"mda_size")},
                {"total_size",field(group,"total_size")},
                {"physical_volumes",Value{std::move(pvs)}},
                {"logical_volumes",field(group,"logical_volumes")}}});
        }
        target.emplace("lvm",Value{Value::Object{
            {"volume_groups",Value{std::move(groups)}},
            {"selected_lvs",field(lvm,"selected_lvs")}}});
    }
    return Value{std::move(target)};
}
}
Value machine_capture_target(const Value& plan) {
    return machine_target(plan,false);
}
Value machine_incremental_target(const Value& plan) {
    // An LV image uses logical coordinates. Its physical mapping and the
    // inventory of unselected LVs validate live sources, not inherited bytes.
    // Generation ancestry remains independently required by the CBT planner.
    auto target = machine_target(plan,true);
    auto& fields = std::get<Value::Object>(target.data);
    fields.erase("cow_directory");
    fields.erase("cow_filesystem_uuid");
    fields.erase("other_disk_count");
    for (const auto* key : {"selected_extra","excluded","additional_disks"})
        if (fields.contains(key) && std::get<Value::Array>(fields.at(key).data).empty())
            fields.erase(key);
    return target;
}
void verify_machine_reservation(const CaptureJournal& reserved, const CaptureJournal& current) {
    auto current_plan = current.plan;
    const auto cache_progress = [&](Value& disk) {
        validate_machine_raw_cache_failures(disk);
        auto& fields = std::get<Value::Object>(disk.data);
        if (!fields.contains("raw_cache_failures")) return;
        if (current.schema != 5 || current.phase < CapturePhase::static_copy_intent)
            throw Error("raw cache failure precedes cache copy");
        fields.erase("raw_cache_failures");
    };
    cache_progress(current_plan);
    if (std::get<Value::Object>(current_plan.data).contains("additional_disks"))
        for (auto& disk : std::get<Value::Array>(
                std::get<Value::Object>(current_plan.data).at("additional_disks").data))
            cache_progress(disk);
    if (reserved.phase != CapturePhase::prepared || reserved.id != current.id ||
        reserved.plan != current_plan || reserved.boot_id != current.boot_id || reserved.schema != current.schema)
        throw Error("pending machine capture ownership changed");
    auto before = reserved.reservation, after = current.reservation;
    const auto recovery_progress = [&](const Value& original, const Value& progress,
                                       const Value& acquired, const Value* volume,
                                       const char* attempted, const char* released) {
        const auto& initial = std::get<Value::Object>(original.data);
        const auto& observed = std::get<Value::Object>(progress.data);
        const bool marker = observed.contains("tracking_recovery");
        if (initial.contains("tracking_recovery"))
            throw Error("prepared tracking reservation already contains recovery progress");
        const bool durable = initial.contains("prior") &&
            std::get<Value::Object>(field(original,"prior").data).contains("durable_owner");
        if (!durable) {
            if (marker) throw Error("tracking recovery has no durable reservation owner");
            return;
        }
        if (current.schema != 5 || !volume)
            throw Error("tracking recovery has no selected origin");
        const auto& prior = field(original,"prior");
        const auto& owner = field(prior,"durable_owner");
        require_machine_tracking_owner(owner,*volume,field(prior,"snapshot"));
        if (!machine_tracking_owner_reservation(owner,prior))
            throw Error("tracking recovery prior differs from its durable owner");
        for (const auto* key : {"changes","previous_capture_id","previous_directory"})
            if (initial.contains(key) || observed.contains(key))
                throw Error("durable tracking recovery cannot invent capture ancestry");
        const auto expected_marker = [&](std::string_view expected) {
            if (marker && field(progress,"tracking_recovery") != Value{std::string(expected)})
                throw Error("tracking recovery marker differs from its generation transition");
        };
        const bool initialized = !std::get<Value::Object>(owner.data).contains("phase");
        if (marker && field(progress,"tracking_recovery") != Value{std::string("durable-owner-fresh-chain")} &&
            field(progress,"tracking_recovery") != Value{std::string("durable-owner-renewed-without-history")})
            throw Error("unknown tracking recovery progress");
        const bool started = number(progress,attempted) == 1;
        const bool has_result = !std::holds_alternative<std::monostate>(acquired.data);
        if ((marker || has_result) && (!started || current.phase < CapturePhase::snapshot_intent))
            throw Error("tracking recovery precedes snapshot acquisition");
        if (!has_result) {
            // The acquisition callback persists its marker before snapshot_root
            // returns the identity. A crash/cleanup can retain this intent.
            if (started && current.phase >= CapturePhase::snapshot_active && current.phase <= CapturePhase::ready)
                throw Error("tracking recovery is missing its acquired generation");
            if (marker && field(progress,"tracking_recovery") ==
                    Value{std::string("durable-owner-renewed-without-history")} &&
                (!initialized || !machine_tracking_healthy(field(prior,"snapshot")) ||
                 std::get<Value::Object>(prior.data).contains("cow_missing")))
                throw Error("tracking renewal intent has no healthy initialized owner");
            return;
        }
        if (capture_snapshot_omitted(acquired)) {
            if (number(progress,released) != 1)
                throw Error("omitted tracking recovery lacks confirmed retirement");
            // Fresh setup may fail after the old slot was reset. Renewal's
            // completed marker is published only after a returned generation.
            expected_marker("durable-owner-fresh-chain");
            return;
        }
        if (field(acquired,"minor") != field(original,"minor") ||
            field(acquired,"cow_path") != field(original,"cow_relative") ||
            field(acquired,"origin_path") != field(*volume,"device"))
            throw Error("tracking recovery acquired a different reserved origin or COW");
        const auto* uuid = std::get_if<std::string>(&field(acquired,"uuid").data);
        if (!uuid || uuid->size() != 32 || uuid->find_first_not_of("0123456789abcdef") != uuid->npos ||
            *uuid == std::string(32,'0'))
            throw Error("tracking recovery has no initialized generation UUID");
        const auto sequence = number(acquired,"sequence");
        const bool fresh = sequence == 1 &&
            (!initialized || field(acquired,"uuid") != field(field(owner,"snapshot"),"uuid"));
        const bool renewed = initialized &&
            machine_tracking_healthy(field(prior,"snapshot")) &&
            !std::get<Value::Object>(prior.data).contains("cow_missing") &&
            field(acquired,"uuid") == field(field(owner,"snapshot"),"uuid") &&
            number(field(owner,"snapshot"),"sequence") < UINT64_MAX &&
            sequence == number(field(owner,"snapshot"),"sequence")+1;
        if (!fresh && !renewed)
            throw Error("tracking recovery generation is neither fresh nor a consecutive owned renewal");
        // A reconciled lost reply can establish the result without the
        // optional progress marker. A present marker must agree exactly.
        expected_marker(fresh ? "durable-owner-fresh-chain" : "durable-owner-renewed-without-history");
    };
    const auto tracking_progress = [&](Value& original, Value& progress, const Value& acquired,
                                       const Value* volume, const char* attempted, const char* released) {
        recovery_progress(original,progress,acquired,volume,attempted,released);
        std::get<Value::Object>(progress.data).erase("tracking_recovery");
        std::get<Value::Object>(progress.data).erase("cache_unused");
        if (std::get<Value::Object>(progress.data).contains("filesystem_unused")) {
            if (current.phase < CapturePhase::root_copy_intent)
                throw Error("filesystem allocation precedes snapshot copy");
            std::get<Value::Object>(progress.data).erase("filesystem_unused");
        }
        if (!std::get<Value::Object>(original.data).contains("cow_path")) return;
        for (const auto key : {"changes","previous_capture_id","previous_directory","cow_unused"})
            std::get<Value::Object>(progress.data).erase(key);
    };
    const auto& planned = std::get<Value::Object>(reserved.plan.data);
    tracking_progress(before,after,current.snapshot,
        planned.contains("root") ? &planned.at("root") : nullptr,"snapshot_attempted","snapshot_released");
    // A new reservation has no creation instant. Only the capture boundary
    // assigns it; sealed artifacts and backup resumes retain that value.
    if (reserved.schema >= 3) {
        if (number(before,"snapshot_time") ||
            (current.phase < CapturePhase::snapshot_intent && number(after,"snapshot_time")) ||
            (current.phase >= CapturePhase::snapshot_intent && current.phase <= CapturePhase::ready &&
             !number(after,"snapshot_time")))
            throw Error("invalid machine capture creation time");
        std::get<Value::Object>(before.data).erase("snapshot_time");
        std::get<Value::Object>(after.data).erase("snapshot_time");
    }
    for (auto key : {"snapshot_attempted","snapshot_released"}) {
        if (number(before,key) != 0 || number(after,key) > 1)
            throw Error("invalid machine capture reservation progress");
        std::get<Value::Object>(before.data).erase(key);
        std::get<Value::Object>(after.data).erase(key);
    }
    if (std::get<Value::Object>(before.data).contains("extras") !=
        std::get<Value::Object>(after.data).contains("extras"))
        throw Error("machine capture extra reservation changed");
    if (std::get<Value::Object>(before.data).contains("extras")) {
    std::vector<const Value*> selected;
    const auto append = [&](const Value& plan) {
        const auto& fields = std::get<Value::Object>(plan.data);
        if (fields.contains("selected_extra"))
            for (const auto& volume : std::get<Value::Array>(fields.at("selected_extra").data))
                selected.push_back(&volume);
    };
    append(reserved.plan);
    if (planned.contains("additional_disks"))
        for (const auto& disk : std::get<Value::Array>(planned.at("additional_disks").data)) append(disk);
    auto& before_extras = std::get<Value::Array>(std::get<Value::Object>(before.data).at("extras").data);
    auto& after_extras = std::get<Value::Array>(std::get<Value::Object>(after.data).at("extras").data);
    if (before_extras.size() != after_extras.size()) throw Error("machine capture extra reservation changed");
    for (std::size_t index = 0; index < before_extras.size(); ++index) {
        tracking_progress(before_extras[index],after_extras[index],field(after_extras[index],"snapshot"),
            index < selected.size() ? selected[index] : nullptr,"attempted","released");
        auto& original = std::get<Value::Object>(before_extras[index].data);
        auto& progress = std::get<Value::Object>(after_extras[index].data);
        if (number(before_extras[index],"attempted") || number(before_extras[index],"released") ||
            number(after_extras[index],"attempted") > 1 ||
            number(after_extras[index],"released") > number(after_extras[index],"attempted"))
            throw Error("invalid extra capture progress");
        for (auto key : {"attempted","released","snapshot"}) {
            original.erase(key);
            progress.erase(key);
        }
    }
    }
    if (number(current.reservation,"snapshot_released") > number(current.reservation,"snapshot_attempted") ||
        before != after) throw Error("pending machine capture reservation changed");
}
std::optional<std::uint64_t> queued_machine_run(const Value::Array& jobs, std::uint64_t task) {
    std::optional<std::uint64_t> run;
    for (const auto& job : jobs) {
        if (number(job,"task_id") != task || number(job,"type") != 0 || number(job,"status") != 0) continue;
        if (run) throw Error("multiple queued backups match automatic machine capture");
        run = number(job,"id");
        if (!*run) throw Error("invalid queued machine backup identity");
    }
    return run;
}
void verify_machine_artifact(const CaptureJournal& journal, ImageSource& source,
                             const std::function<bool()>& cancelled) {
    if (journal.schema != 5 || journal.phase != CapturePhase::ready || !journal.failure.empty() ||
        !source.direct_intervals()) throw Error("machine capture is not a ready direct interval source");
    if (cancelled && cancelled()) throw Cancelled();
    const auto sector = number(journal.artifact,"sector_size");
    const bool logical = std::get<Value::Object>(journal.plan.data).contains("lv_uuid");
    const auto expected_length = logical ? number(journal.plan,"length") :
        number(field(journal.plan,"layout"),"length");
    const auto expected_sector = logical ? std::uint64_t{512} :
        number(field(journal.plan,"layout"),"sector_size");
    if ((sector != 512 && sector != 4096) || sector != expected_sector ||
        source.size() != expected_length || source.size() != number(journal.artifact,"length") ||
        source.size() % sector || !number(journal.reservation,"snapshot_time"))
        throw Error("machine capture artifact geometry or time is invalid");
    if (std::get<std::string>(field(journal.artifact,"sha256").data) != "")
        throw Error("direct machine capture cannot carry a whole-image digest");
    source.verify_unchanged();
}
}
