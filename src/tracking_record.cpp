#include "opensabba/tracking_record.hpp"
#include <filesystem>
#include <algorithm>

namespace opensabba {
using pstream::Value;
using pstream::Error;
namespace {
constexpr std::string_view prefix = "# opensabba-tracking-owner-v2 ";
const Value& field(const Value& value, const char* key) {
    return std::get<Value::Object>(value.data).at(key);
}
std::uint64_t number(const Value& value, const char* key) {
    return std::get<std::uint64_t>(field(value,key).data);
}
const std::string& text(const Value& value, const char* key) {
    return std::get<std::string>(field(value,key).data);
}
void validate(const Value& owner) {
    const auto& cow = field(owner,"cow");
    const auto& properties = std::get<Value::Object>(owner.data);
    const auto path = std::filesystem::path(text(owner,"cow_relative"));
    if (number(owner,"format") != 2 || text(owner,"device").empty() ||
        text(owner,"device").front() != '/' || text(owner,"filesystem_uuid").empty() ||
        number(owner,"minor") >= 255 || path.parent_path().generic_string() != "/.synosnap_data" ||
        path.filename().empty() || path.filename() == "." || path.filename() == ".." ||
        !number(cow,"inode") || !std::holds_alternative<std::uint64_t>(field(cow,"device").data))
        throw Error("invalid durable machine tracking owner");
    if (properties.contains("phase")) {
        if (text(owner,"phase") != "reserved" || properties.contains("snapshot"))
            throw Error("invalid reserved machine tracking owner");
    } else {
        const auto& snapshot = field(owner,"snapshot");
        if (text(snapshot,"uuid").size() != 32 ||
            text(snapshot,"uuid").find_first_not_of("0123456789abcdef") != std::string::npos ||
            !number(snapshot,"sequence"))
            throw Error("invalid durable machine tracking generation");
    }
}
std::string quote(std::string_view value) {
    std::string result = "'";
    for (const auto c : value) {
        if (c == '\n' || c == '\r' || c == '\0') throw Error("invalid reload command path");
        result += c == '\'' ? "'\\''" : std::string(1,c);
    }
    return result+"'";
}
}
const std::string& machine_tracking_device(const Value& volume) {
    return text(volume,std::get<Value::Object>(volume.data).contains("lv_uuid") ? "logical_path" : "device");
}
Value machine_tracking_owner(const Value& volume, const Value& reservation, const Value& snapshot) {
    Value result{Value::Object{{"format",Value{std::uint64_t{2}}},
        {"device",Value{machine_tracking_device(volume)}},{"filesystem_uuid",field(volume,"filesystem_uuid")},{"minor",field(reservation,"minor")},
        {"cow_relative",field(reservation,"cow_relative")},{"cow",field(reservation,"cow")},
        {"snapshot",Value{Value::Object{{"uuid",field(snapshot,"uuid")},
                                      {"sequence",field(snapshot,"sequence")}}}}}};
    validate(result);
    return result;
}
Value machine_tracking_reservation_owner(const Value& volume, const Value& reservation) {
    Value result{Value::Object{{"format",Value{std::uint64_t{2}}},
        {"device",Value{machine_tracking_device(volume)}},{"filesystem_uuid",field(volume,"filesystem_uuid")},{"minor",field(reservation,"minor")},
        {"cow_relative",field(reservation,"cow_relative")},{"cow",field(reservation,"cow")},
        {"phase",Value{std::string("reserved")}}}};
    validate(result);
    return result;
}
std::string machine_tracking_record(const Value& owner, std::string_view executable, bool active) {
    validate(owner);
    if (std::get<Value::Object>(owner.data).contains("phase"))
        throw Error("tracking reload record requires a successful snapshot generation");
    if (executable.empty() || executable.front() != '/') throw Error("reload executable must be absolute");
    constexpr char hex[] = "0123456789abcdef";
    std::string result = "#!/bin/sh\n"+std::string(prefix);
    for (const auto byte : pstream::encode(owner)) {
        result += hex[byte >> 4];
        result += hex[byte & 15];
    }
    result += "\nexec "+quote(executable)+" snapshot reload-"+
        (active ? "snapshot " : "incremental ")+
        quote(text(owner,"device"))+" "+
        quote(text(owner,"cow_relative"))+" "+std::to_string(number(owner,"minor"))+"\n";
    return result;
}
std::optional<Value> machine_tracking_record_owner(std::string_view record) {
    // Existing command-only hooks carry no durable ownership. They remain
    // executable boot records; an independent journal must establish ownership.
    constexpr std::string_view shebang = "#!/bin/sh\n";
    if (!record.starts_with(shebang)) return std::nullopt;
    record.remove_prefix(shebang.size());
    if (!record.starts_with(prefix)) return std::nullopt;
    record.remove_prefix(prefix.size());
    const auto end = record.find('\n');
    if (end == record.npos || end > 32768 || end%2) throw Error("invalid tracking owner encoding");
    const auto hex = record.substr(0,end);
    pstream::Bytes bytes;
    for (std::size_t at = 0; at < hex.size(); at += 2) {
        const auto digit = [](char c) -> unsigned {
            if (c >= '0' && c <= '9') return static_cast<unsigned>(c-'0');
            if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c-'a'+10);
            throw Error("invalid tracking owner encoding");
        };
        bytes.push_back(static_cast<std::uint8_t>(digit(hex[at])*16+digit(hex[at+1])));
    }
    auto owner = pstream::decode(bytes,{16384,128,8});
    validate(owner);
    if (std::get<Value::Object>(owner.data).contains("phase"))
        throw Error("tracking reload record requires a successful snapshot generation");
    // The command and ownership must agree; otherwise this is not the atomic
    // record this writer publishes. Never infer ownership from shell text.
    const auto command = record.substr(end+1);
    if (!command.starts_with("exec '"))
        throw Error("tracking reload command differs from its owner");
    std::size_t marker = 6;
    while (marker < command.size()) {
        if (command[marker] != '\'') { ++marker; continue; }
        if (command.substr(marker,4) == "'\\''") { marker += 4; continue; }
        ++marker;
        break;
    }
    const auto suffix = quote(text(owner,"device"))+" "+
        quote(text(owner,"cow_relative"))+" "+std::to_string(number(owner,"minor"))+"\n";
    if (command.substr(marker) != " snapshot reload-snapshot "+suffix &&
        command.substr(marker) != " snapshot reload-incremental "+suffix)
        throw Error("tracking reload command differs from its owner");
    return owner;
}
void require_machine_tracking_owner(const Value& owner, const Value& volume, const Value& observed) {
    validate(owner);
    if (text(owner,"device") != machine_tracking_device(volume) ||
        field(owner,"filesystem_uuid") != field(volume,"filesystem_uuid") ||
        field(observed,"origin_path") != field(volume,"device") ||
        field(owner,"minor") != field(observed,"minor") ||
        field(owner,"cow_relative") != field(observed,"cow_path"))
        throw Error("driver slot differs from durable machine tracking owner");
    if (std::get<Value::Object>(owner.data).contains("phase")) {
        if (!number(observed,"unverified") || !number(observed,"snapshot_mode") ||
            number(observed,"active") || text(observed,"error_code") == "0")
            throw Error("reserved tracking ownership cannot authorize an initialized driver generation");
    } else if (!number(observed,"unverified") &&
               (field(field(owner,"snapshot"),"uuid") != field(observed,"uuid") ||
                field(field(owner,"snapshot"),"sequence") != field(observed,"sequence"))) {
        throw Error("driver generation differs from durable machine tracking owner");
    }
}
bool machine_tracking_owner_reservation(const Value& owner, const Value& reserved) {
    validate(owner);
    return field(owner,"filesystem_uuid") == field(reserved,"tracking_filesystem_uuid") &&
        field(owner,"cow_relative") == field(reserved,"cow_relative") &&
        field(owner,"minor") == field(reserved,"minor") &&
        field(field(owner,"cow"),"inode") == field(field(reserved,"cow"),"inode");
}
Value machine_tracking_recovery_prior(const Value& owner, const Value& volume,
                                      const Value& observed, const std::optional<Value>& cow) {
    require_machine_tracking_owner(owner,volume,observed);
    if (cow && (field(*cow,"inode") != field(field(owner,"cow"),"inode") ||
                field(*cow,"filesystem_uuid") != field(owner,"filesystem_uuid")))
        throw Error("durable machine tracking COW identity changed");
    const auto path = std::filesystem::path(text(volume,"mount_path"))/
        std::filesystem::path(text(owner,"cow_relative")).relative_path();
    Value::Object prior{{"snapshot",observed},{"cow_path",Value{path.generic_string()}},
        {"cow_relative",field(owner,"cow_relative")},{"minor",field(owner,"minor")},
        {"cow",field(owner,"cow")},{"tracking_filesystem_uuid",field(owner,"filesystem_uuid")},
        {"durable_owner",owner}};
    if (!cow) prior["cow_missing"] = Value{std::uint64_t{1}};
    return Value{std::move(prior)};
}
bool machine_tracking_healthy(const Value& observed) {
    return !number(observed,"snapshot_mode") && number(observed,"active") &&
        !number(observed,"unverified") && !number(observed,"cancelled") &&
        text(observed,"error_code") == "0";
}
std::int32_t machine_tracking_free_minor(std::span<const std::uint32_t> history) {
    for (std::uint32_t minor = 0; minor < 255; ++minor)
        if (std::find(history.begin(),history.end(),minor) == history.end())
            return static_cast<std::int32_t>(minor);
    return -1;
}
MachineTrackingDatabase::MachineTrackingDatabase(const Value& saved) {
    if (number(saved,"format") != 1 || !(next_id_ = number(saved,"next_id")))
        throw Error("invalid machine tracking history database");
    std::uint64_t previous = 0;
    for (const auto& row : std::get<Value::Array>(field(saved,"rows").data)) {
        const auto id = number(row,"history_id");
        if (id <= previous || id >= next_id_) throw Error("invalid tracking history row order");
        previous = id;
        rows_.push_back(row);
    }
}
Value MachineTrackingDatabase::value() const {
    return Value{Value::Object{{"format",Value{std::uint64_t{1}}},
        {"next_id",Value{next_id_}},{"rows",Value{rows_}}}};
}
std::optional<Value> MachineTrackingDatabase::last(const Value& volume) const {
    for (auto row = rows_.rbegin(); row != rows_.rend(); ++row)
        if (text(*row,"device") == machine_tracking_device(volume)) return *row;
    return std::nullopt;
}
void MachineTrackingDatabase::add(Value prior) {
    if (next_id_ == UINT64_MAX) throw Error("tracking history row IDs exhausted");
    std::get<Value::Object>(prior.data)["history_id"] = Value{next_id_++};
    rows_.push_back(std::move(prior));
}
std::vector<std::uint32_t> MachineTrackingDatabase::minors() const {
    std::vector<std::uint32_t> result;
    for (const auto& row : rows_)
        result.push_back(static_cast<std::uint32_t>(number(row,"minor")));
    return result;
}
Value::Array MachineTrackingDatabase::remove_before(const Value& prior) {
    Value::Array removed;
    std::erase_if(rows_,[&](const auto& row) {
        if (field(row,"device") != field(prior,"device") ||
            number(row,"history_id") > number(prior,"history_id")) return false;
        removed.push_back(row);
        return true;
    });
    return removed;
}
Value::Array MachineTrackingDatabase::delete_snapshot(const Value& reserved) {
    // History retirement marks only the requested snapshot.
    // Unmarked rows are live; the sparse flag is written when deletion is
    // requested, independently of whether an older live row blocks removal.
    auto target = std::find_if(rows_.begin(),rows_.end(),[&](const auto& row) {
        return field(row,"tracking_filesystem_uuid") == field(reserved,"tracking_filesystem_uuid") &&
            field(row,"cow_relative") == field(reserved,"cow_relative");
    });
    if (target == rows_.end()) return {};
    const auto device = field(*target,"device");
    std::get<Value::Object>(target->data)["to_be_deleted"] = Value{std::uint64_t{1}};
    const auto marked = [](const Value& row) {
        return std::get<Value::Object>(row.data).contains("to_be_deleted") && number(row,"to_be_deleted") == 1;
    };
    // Related-history lookup walks newest first. A candidate
    // can remove its whole prefix only without an earlier unmarked row
    // (live predecessor checks / predecessor removal ).
    for (auto row = rows_.rbegin(); row != rows_.rend(); ++row) {
        if (field(*row,"device") != device || !marked(*row)) continue;
        const auto id = number(*row,"history_id");
        if (std::none_of(rows_.begin(),rows_.end(),[&](const auto& earlier) {
                return field(earlier,"device") == device && number(earlier,"history_id") < id && !marked(earlier);
            })) {
            const auto through = *row;
            return remove_before(through);
        }
    }
    return {};
}
std::optional<Value> prepare_machine_tracking(MachineTrackingDatabase& history,
    const Value& volume, MachineTrackingControl& control) {
    auto prior = history.last(volume); // Latest origin history.
    if (!prior) return {};
    const auto minor = static_cast<std::uint32_t>(number(*prior,"minor"));
    const auto info = control.information(minor);
    if (!info || !machine_tracking_healthy(*info)) {
        control.release(info ? *info : field(*prior,"snapshot"));
        // the official agent skips DB deletion if destroy left the slot alive, then still
        // attempts setup with Free-minor selection from the unchanged history.
        if (control.information(minor)) return {};
        control.retire_record(volume,*prior); // Bad-state cleanup.
        history.remove_before(*prior);
        return {};
    }
    // Snapshot renewal tests the saved minor's mode only.
    // A healthy tracking slot is renewed even if UUID, sequence or COW path
    // differ from the history row. Keep the row's actual prior COW evidence.
    return prior;
}
Value transition_machine_tracking(Value& reserved, const Value& volume, std::uint64_t mib,
                                  MachineTrackingControl& control) {
    const auto minor = static_cast<std::uint32_t>(number(reserved,"minor"));
    const auto validate_slot = [&](const Value& current) {
        if (field(current,"minor") != field(reserved,"minor") ||
            field(current,"origin_path") != field(volume,"device") ||
            field(current,"cow_path") != field(reserved,"cow_relative"))
            throw Error("machine tracking slot differs from its on-origin reservation");
    };
    const auto same_generation = [](const Value& a, const Value& b) {
        return field(a,"uuid") == field(b,"uuid") && field(a,"sequence") == field(b,"sequence");
    };
    const bool has_prior = std::get<Value::Object>(reserved.data).contains("prior");
    auto observed = has_prior ? control.information(minor) : std::optional<Value>{};
    bool renew = false;
    auto& properties = std::get<Value::Object>(reserved.data);
    if (has_prior) {
        const auto& prior = field(reserved,"prior");
        const auto& expected = field(prior,"snapshot");
        const auto& prior_properties = std::get<Value::Object>(prior.data);
        bool reset = !observed;
        if (!observed) {
            control.release(expected);
            if (control.information(minor)) throw Error("owned tracking slot still exists after release");
        }
        // A prior renewal may have failed while compressing the old COW. The
        // driver then has a snapshot which never entered history. the official agent checks
        // its mode using the saved history's minor, then destroys that slot.
        if (observed && number(*observed,"snapshot_mode") &&
            field(*observed,"cow_path") != field(reserved,"cow_relative") &&
            field(*observed,"minor") == field(expected,"minor") &&
            field(*observed,"origin_path") == field(expected,"origin_path")) {
            control.release(*observed);
            if (control.information(minor)) throw Error("owned tracking slot still exists after release");
            observed.reset();
            reset = true;
        }
        if (observed && ((!prior_properties.contains("durable_owner") && machine_tracking_healthy(*observed)) ||
            (same_generation(*observed,expected) &&
            field(*observed,"minor") == field(expected,"minor") &&
            field(*observed,"cow_path") == field(expected,"cow_path") &&
            field(*observed,"origin_path") == field(expected,"origin_path")))) {
            const bool restored_owner = prior_properties.contains("durable_owner");
            if (restored_owner) {
                // Reload files are replaceable boot commands, not leases.
                // The saved exact owner/COW evidence remains valid after a
                // different origin takes its basename (official agent ).
                require_machine_tracking_owner(field(prior,"durable_owner"),volume,*observed);
                control.verify_prior_cow(prior);
            }
            renew = machine_tracking_healthy(*observed);
            if (!renew) {
                control.release(*observed);
                if (control.information(minor))
                    throw Error("owned tracking slot still exists after release");
                observed.reset();
                reset = true;
            }
        } else if (observed) {
            validate_slot(*observed);
            if (number(*observed,"snapshot_mode") && number(*observed,"active") &&
                same_generation(*observed,expected))
                throw Error("machine tracking renewal did not advance its generation");
        }
        if (reset) {
            // Snapshot renewal calls Bad-state cleanup
            // even when the saved driver minor has disappeared.
            Value old = prior;
            auto& old_properties = std::get<Value::Object>(old.data);
            old_properties["minor"] = field(expected,"minor");
            old_properties["cow_relative"] = field(expected,"cow_path");
            control.retire_record(volume,old);
        }
        if (renew) control.renew(*observed,text(reserved,"cow_path"),mib);
    }
    if (!renew && !observed)
        control.create(minor,machine_tracking_device(volume),text(reserved,"cow_path"),mib);
    const auto current = control.information(minor);
    if (!current) throw Error("machine snapshot creation left no driver slot");
    validate_slot(*current);
    if (properties.contains("prior")) {
        const auto& prior = field(reserved,"prior");
        const auto& expected = field(prior,"snapshot");
        const bool owner = std::get<Value::Object>(prior.data).contains("durable_owner");
        const bool resumed_renewal = observed &&
            field(*observed,"cow_path") == field(reserved,"cow_relative") && number(*observed,"snapshot_mode");
        if ((!owner && (renew || resumed_renewal)) ||
            (owner && std::get<Value::Object>(prior.data).contains("cow_missing") &&
             field(expected,"uuid") == field(*current,"uuid") &&
             number(expected,"sequence")+1 == number(*current,"sequence"))) {
            // the official agent transitions the driver before compressing the previous COW.
            // Failure leaves the new active snapshot, old history and reload.
            auto changes = control.close_prior(prior,*current,volume);
            if (!std::get<Value::Object>(prior.data).contains("durable_owner")) {
                properties["changes"] = std::move(changes);
                properties["previous_capture_id"] = field(prior,"capture_id");
                properties["previous_directory"] = field(prior,"directory");
            }
        }
    }
    if (properties.contains("prior") &&
        std::get<Value::Object>(field(reserved,"prior").data).contains("durable_owner")) {
        const auto& prior = field(reserved,"prior");
        const auto& expected = field(prior,"snapshot");
        const auto& owner = field(prior,"durable_owner");
        const bool renewed_without_history = !std::get<Value::Object>(owner.data).contains("phase") &&
            field(expected,"uuid") == field(*current,"uuid") &&
            number(expected,"sequence")+1 == number(*current,"sequence");
        properties["tracking_recovery"] = Value{std::string(renewed_without_history ?
            "durable-owner-renewed-without-history" : "durable-owner-fresh-chain")};
    }
    return *current;
}
}
