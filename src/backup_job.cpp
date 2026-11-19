#include "opensabba/backup_job.hpp"
#include "opensabba/job_recovery.hpp"
#include "opensabba/capture.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <set>

namespace opensabba {
namespace {
using pstream::Value;
using pstream::Error;
constexpr std::array phases{
    "planned", "prepare", "prepared", "metadata", "metadata-accepted",
    "upload", "uploaded", "finish", "complete", "partial", "cancel", "error"};
std::string fingerprint(ImageSource& source, const Endpoint& endpoint) {
    if (source.direct_intervals()) { source.verify_unchanged(); return {}; }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digest(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!digest || EVP_DigestInit_ex(digest.get(), EVP_sha256(), nullptr) != 1)
        throw Error("cannot initialize image fingerprint");
    for (std::uint64_t at = 0; at < source.size();) {
        if (endpoint.cancelled && endpoint.cancelled()) throw Cancelled();
        auto bytes = source.read(at, static_cast<std::size_t>(std::min<std::uint64_t>(1024*1024, source.size()-at)));
        if (EVP_DigestUpdate(digest.get(), bytes.data(), bytes.size()) != 1)
            throw Error("cannot fingerprint image");
        at += bytes.size();
    }
    std::array<unsigned char, 32> bytes{};
    unsigned int size = 0;
    if (EVP_DigestFinal_ex(digest.get(), bytes.data(), &size) != 1 || size != bytes.size())
        throw Error("cannot finalize image fingerprint");
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (auto b : bytes) { result += hex[b >> 4]; result += hex[b & 15]; }
    source.verify_unchanged();
    return result;
}
std::string terminal(BackupOutcome outcome) {
    switch (outcome) {
    case BackupOutcome::complete: return "complete";
    case BackupOutcome::partial: return "partial";
    case BackupOutcome::cancelled: return "cancel";
    case BackupOutcome::error: return "error";
    }
    throw Error("invalid backup outcome");
}
const Value::Object& object(const Value& value) {
    auto p = std::get_if<Value::Object>(&value.data);
    if (!p) throw Error("invalid backup journal object");
    return *p;
}
const Value& field(const Value::Object& fields, const char* name) {
    auto p = fields.find(name);
    if (p == fields.end()) throw Error(std::string("backup journal missing ") + name);
    return p->second;
}
const std::string& text(const Value::Object& fields, const char* name, bool empty = false) {
    auto p = std::get_if<std::string>(&field(fields, name).data);
    if (!p || (!empty && p->empty())) throw Error(std::string("invalid backup journal text: ") + name);
    return *p;
}
std::uint64_t number(const Value::Object& fields, const char* name) {
    auto p = std::get_if<std::uint64_t>(&field(fields, name).data);
    if (!p) throw Error(std::string("invalid backup journal number: ") + name);
    return *p;
}
TransferCompression journal_compression(const Value::Object& fields) {
    const auto schema = number(fields, "schema");
    if (schema == 1) {
        // Schema 1 predates compression and specifies a raw transfer.
        if (fields.contains("compression")) throw Error("schema 1 backup journal cannot specify compression");
        return TransferCompression::none;
    }
    if (schema != 2 && schema != 3 && schema != 4 && schema != 5 &&
        schema != 6 && schema != 7 && schema != 8 && schema != 9)
        throw Error("unsupported backup journal schema");
    const auto& mode = text(fields, "compression");
    if (mode == "none") return TransferCompression::none;
    if (mode == "lz4") return TransferCompression::lz4;
    throw Error("unsupported backup journal compression");
}
std::vector<ChangedExtent> unused_ranges_from(const Value&, std::uint64_t);
Value unused_ranges_value(std::span<const ChangedExtent>);
void machine_policy_from(const Value::Object& item, IncrementalBackup& incremental,
                         const std::string& name) {
    if (!item.contains("machine_policy")) return;
    const auto& policy = object(field(item,"machine_policy"));
    if (number(policy,"format") != 1 || text(policy,"image_name") != name ||
        number(policy,"is_cbt") > 1 || !incremental.plan.filesystem_allocation)
        throw Error("invalid machine interval policy");
    const auto& base = text(policy,"base_image_name",true);
    if (!base.empty()) validate_image_options(base,1024*1024);
    bool cbt = true;
    std::set<std::string> origins;
    for (const auto& value : std::get<Value::Array>(field(policy,"origins").data)) {
        const auto& origin = object(value);
        const auto start = number(origin,"offset"), length = number(origin,"length");
        if (!origins.insert(text(origin,"filesystem_uuid")).second || !length ||
            start > incremental.plan.image_size || length > incremental.plan.image_size-start ||
            number(origin,"logical") > 1 || number(origin,"omitted") > 1 || number(origin,"is_cbt") > 1)
            throw Error("invalid machine origin correspondence");
        const bool omitted = number(origin,"omitted") != 0, context = number(origin,"is_cbt") != 0;
        const auto& previous = text(origin,"base_image_name",true);
        if (!previous.empty()) validate_image_options(previous,1024*1024);
        if (context && (omitted || previous != name || base != name))
            throw Error("machine CBT origin has no matching base image");
        if (!omitted) {
            cbt &= context;
            const bool full = std::any_of(incremental.reread_ranges.begin(),incremental.reread_ranges.end(),
                [&](const auto& range) { return range.offset <= start && range.offset+range.length >= start+length; });
            if (full == context) throw Error("machine origin context differs from its reread policy");
        }
    }
    if (number(policy,"is_cbt") != std::uint64_t{cbt})
        throw Error("machine completion CBT differs from its origin contexts");
    if (base.empty() && !(incremental.reread_ranges.size() == 1 && incremental.reread_ranges.front().offset == 0 &&
        incremental.reread_ranges.front().length == incremental.plan.image_size))
        throw Error("new machine image requires complete no-CBT coverage");
    incremental.machine_policy = field(item,"machine_policy");
}
IncrementalBackup incremental_from(const Value::Object& fields) {
    const auto& info = object(field(fields, "incremental"));
    IncrementalBackup result{number(info, "base_version_id"), number(info, "base_result_id"),
        number(info, "base_running_task_id"), text(info, "base_snapshot_id"), text(info, "base_image_sha256",true),
        delta_plan_from_value(field(info, "ranges"), number(fields, "image_size"))};
    if (!result.base_version_id || result.base_version_id > INT32_MAX ||
        !result.base_result_id || !result.base_running_task_id ||
        result.base_snapshot_id.size() != 32 ||
        result.base_snapshot_id.find_first_not_of("0123456789abcdef") != std::string::npos ||
        (!result.base_image_sha256.empty() && (result.base_image_sha256.size() != 64 ||
        result.base_image_sha256.find_first_not_of("0123456789abcdef") != std::string::npos)))
        throw Error("invalid incremental backup base identity");
    if (info.contains("filesystem_allocation")) {
        if (number(info,"filesystem_allocation") != 1) throw Error("invalid filesystem allocation policy");
        result.plan.filesystem_allocation = true;
        result.reread_ranges = unused_ranges_from(field(info,"reread_ranges"),result.plan.image_size);
        validate_reread_ranges(result.reread_ranges,result.plan);
    }
    machine_policy_from(info,result,text(fields,"image_name"));
    return result;
}
void validate_incremental_identity(const IncrementalBackup& info) {
    if (!info.base_version_id || info.base_version_id > INT32_MAX ||
        !info.base_result_id || !info.base_running_task_id ||
        info.base_snapshot_id.size() != 32 ||
        info.base_snapshot_id.find_first_not_of("0123456789abcdef") != std::string::npos ||
        (!info.base_image_sha256.empty() && (info.base_image_sha256.size() != 64 ||
        info.base_image_sha256.find_first_not_of("0123456789abcdef") != std::string::npos)))
        throw Error("invalid incremental backup base identity");
}
std::vector<IncrementalBackup> multi_incremental_from(const Value::Object& fields) {
    const auto& info = object(field(fields,"incremental"));
    const auto& entries = std::get<Value::Array>(field(fields,"images").data);
    std::vector<IncrementalBackup> result;
    result.reserve(entries.size());
    for (const auto& entry : entries) {
        const auto& item = object(entry);
        IncrementalBackup value{number(info,"base_version_id"),number(info,"base_result_id"),
            number(info,"base_running_task_id"),text(info,"base_snapshot_id"),
            text(item,"base_sha256",true),delta_plan_from_value(field(item,"ranges"),number(item,"size"))};
        if (item.contains("filesystem_allocation")) {
            if (number(item,"filesystem_allocation") != 1) throw Error("invalid filesystem allocation policy");
            value.plan.filesystem_allocation = true;
            value.reread_ranges = unused_ranges_from(field(item,"reread_ranges"),value.plan.image_size);
            validate_reread_ranges(value.reread_ranges,value.plan);
        }
        machine_policy_from(item,value,text(item,"name"));
        validate_incremental_identity(value);
        result.push_back(std::move(value));
    }
    return result;
}
Value unused_ranges_value(std::span<const ChangedExtent> ranges) {
    Value::Array result;
    for (const auto& range : ranges)
        result.push_back(Value{Value::Object{
            {"offset",Value{range.offset}},{"length",Value{range.length}}}});
    return Value{std::move(result)};
}
std::vector<ChangedExtent> unused_ranges_from(const Value& value, std::uint64_t size) {
    const auto* entries = std::get_if<Value::Array>(&value.data);
    if (!entries) throw Error("invalid saved unused image intervals");
    std::vector<ChangedExtent> result;
    for (const auto& entry : *entries) {
        const auto& item = object(entry);
        result.push_back({number(item,"offset"),number(item,"length")});
    }
    validate_unused_ranges(result,size);
    return result;
}
}

bool backup_completion_cbt(const Value& record) {
    const auto& fields = object(record);
    if (!fields.contains("incremental")) return false;
    const auto schema = number(fields,"schema");
    const auto plans = schema == 5 || schema == 7 ? multi_incremental_from(fields) :
        std::vector<IncrementalBackup>{incremental_from(fields)};
    const bool machine = plans.front().machine_policy.has_value();
    bool cbt = true;
    for (const auto& plan : plans) {
        if (plan.machine_policy.has_value() != machine) throw Error("mixed machine interval policy formats");
        if (machine) cbt &= number(object(*plan.machine_policy),"is_cbt") != 0;
    }
    return cbt;
}

static BackupRun prepare_image_backup(const Endpoint& endpoint, const SavedAuth& auth,
    std::uint64_t task, std::uint64_t run, std::uint64_t base, const std::function<void()>& before) {
    if (endpoint.prepared_backup) {
        const auto& prepared = *endpoint.prepared_backup;
        if (prepared.run.running_task_id != run || prepared.base_version_id != base)
            throw Error("prepared capture handshake differs from its image backup");
        return prepared.run;
    }
    return base ? prepare_incremental_backup(endpoint,auth,task,run,base,before) :
        prepare_full_backup(endpoint,auth,run,before);
}

static BackupOutcome image_job(const Endpoint& endpoint, const SavedAuth& auth,
                                 std::uint64_t target_id, bool create, ImageSource& source,
                                 std::string_view name, std::span<const std::uint8_t> metadata,
                                 const SaveBackupJob& save, BackupOutcome requested,
                                 TransferCompression compression, const IncrementalBackup* incremental = nullptr,
                                 std::uint64_t task_id = 0,
                                 std::span<const ChangedExtent> unused = {},
                                 std::span<const ChangedExtent> reread = {}) {
    if (!save) throw Error("backup job requires a durable journal");
    if (!target_id || auth.ds_id.empty() || auth.device_uuid.empty() ||
        auth.username.empty() || auth.token.empty())
        throw Error("backup job requires a running task and complete saved identity");
    validate_image_options(name, 1024*1024);
    if (compression != TransferCompression::none && compression != TransferCompression::lz4)
        throw Error("unsupported transfer compression");
    if (metadata.empty() || metadata.size() > 8*1024*1024 ||
        std::find(metadata.begin(), metadata.end(), 0) != metadata.end())
        throw Error("invalid snapshot JSON buffer");
    auto requested_text = terminal(requested);
    verify_unused_source(source,unused);
    Value record{Value::Object{
        {"schema", Value{std::uint64_t{unused.empty() ? (incremental ? 3U : 2U) :
            (incremental ? 9U : 8U)}}}, {"ds_id", Value{auth.ds_id}},
        {"compression", Value{std::string(compression == TransferCompression::lz4 ? "lz4" : "none")}},
        {"device_uuid", Value{auth.device_uuid}}, {"username", Value{auth.username}},
        {"running_task_id", Value{create ? std::uint64_t{0} : target_id}}, {"image_name", Value{std::string(name)}},
        {"image_size", Value{source.size()}}, {"image_sha256", Value{fingerprint(source, endpoint)}},
        {"snapshot_info", Value{pstream::Bytes(metadata.begin(), metadata.end())}},
        {"requested_outcome", Value{std::move(requested_text)}}}};
    auto& fields = std::get<Value::Object>(record.data);
    if (endpoint.cached_backup) fields["is_cache"] = Value{std::uint64_t{1}};
    if (endpoint.backup_app_aware) fields["app_aware_bkp"] = Value{std::uint64_t{1}};
    if (source.direct_intervals()) fields["direct_intervals"] = Value{std::uint64_t{1}};
    if (!unused.empty()) fields.emplace("unused_ranges",unused_ranges_value(unused));
    if (incremental) {
        if (!source.direct_intervals() && incremental->base_image_sha256.empty())
            throw Error("immutable image incremental base requires its digest");
        validate_delta_plan(incremental->plan, source.size());
        fields["incremental"] = Value{Value::Object{
            {"base_version_id", Value{incremental->base_version_id}},
            {"base_result_id", Value{incremental->base_result_id}},
            {"base_running_task_id", Value{incremental->base_running_task_id}},
            {"base_snapshot_id", Value{incremental->base_snapshot_id}},
            {"base_image_sha256", Value{incremental->base_image_sha256}},
            {"ranges", delta_plan_value(incremental->plan)}}};
        if (incremental->plan.filesystem_allocation) {
            auto& policy = std::get<Value::Object>(fields.at("incremental").data);
            policy["filesystem_allocation"] = Value{std::uint64_t{1}};
            policy["reread_ranges"] = unused_ranges_value(reread);
        }
        if (incremental->machine_policy)
            std::get<Value::Object>(fields.at("incremental").data)["machine_policy"] = *incremental->machine_policy;
        (void)incremental_from(fields);
    }
    if (create) fields["create_task_id"] = Value{target_id};
    auto persist = [&](const char* phase) {
        fields["phase"] = Value{std::string(phase)};
        save(record);
    };
    auto intent = [&](const char* phase) {
        source.verify_unchanged();
        persist(phase);
    };
    persist("planned");
    auto before = [&] { intent("prepare"); };
    auto run = incremental ? (create
                 ? create_incremental_backup(endpoint, auth, target_id, incremental->base_version_id, before)
                 : prepare_image_backup(endpoint,auth,task_id,target_id,incremental->base_version_id,before))
             : create ? create_full_backup(endpoint, auth, target_id, before)
                      : prepare_image_backup(endpoint,auth,task_id,target_id,0,before);
    fields["running_task_id"] = Value{run.running_task_id};
    fields["version_id"] = Value{run.version_id};
    fields["result_id"] = Value{run.result_id};
    fields["data_format"] = Value{run.data_format};
    persist("prepared");
    upload_backup_spec(endpoint, auth, run, metadata, [&] { intent("metadata"); });
    persist("metadata-accepted");
    intent("upload");
    upload_prepared_image(endpoint, auth, run.running_task_id, source, name, 1024*1024, {},
        compression, incremental ? &incremental->plan : nullptr,unused,reread);
    persist("uploaded");
    const auto outcome = finish_backup(endpoint, auth, run, requested, [&] { intent("finish"); }, backup_completion_cbt(record));
    persist(terminal(outcome).c_str());
    return outcome;
}

BackupOutcome run_full_image_job(const Endpoint& endpoint, const SavedAuth& auth,
                                 std::uint64_t run_id, ImageSource& source,
                                 std::string_view name, std::span<const std::uint8_t> metadata,
                                 const SaveBackupJob& save, BackupOutcome requested,
                                 TransferCompression compression,
                                 std::span<const ChangedExtent> unused) {
    return image_job(endpoint, auth, run_id, false, source, name, metadata, save, requested,
                     compression,nullptr,0,unused);
}
BackupOutcome create_full_image_job(const Endpoint& endpoint, const SavedAuth& auth,
                                    std::uint64_t task_id, ImageSource& source,
                                    std::string_view name, std::span<const std::uint8_t> metadata,
                                    const SaveBackupJob& save, TransferCompression compression) {
    return image_job(endpoint, auth, task_id, true, source, name, metadata, save, BackupOutcome::complete, compression);
}

BackupOutcome create_incremental_image_job(const Endpoint& endpoint, const SavedAuth& auth,
                                           std::uint64_t task, ImageSource& source,
                                           std::string_view name, std::span<const std::uint8_t> metadata,
                                           const IncrementalBackup& incremental, const SaveBackupJob& save,
                                           TransferCompression compression) {
    return image_job(endpoint, auth, task, true, source, name, metadata, save,
                     BackupOutcome::complete, compression, &incremental);
}

BackupOutcome run_incremental_image_job(const Endpoint& endpoint, const SavedAuth& auth,
                                        std::uint64_t task, std::uint64_t run, ImageSource& source,
                                        std::string_view name, std::span<const std::uint8_t> metadata,
                                        const IncrementalBackup& incremental, const SaveBackupJob& save,
                                        TransferCompression compression,
                                        std::span<const ChangedExtent> unused,
                                        std::span<const ChangedExtent> reread) {
    return image_job(endpoint, auth, run, false, source, name, metadata, save,
                     BackupOutcome::complete, compression, &incremental, task,unused,reread);
}

BackupOutcome resume_image_job(const Endpoint& endpoint, const SavedAuth& auth, ImageSource& source,
                                    const Value& record, const SaveBackupJob& save,
                                    std::span<const ChangedExtent> unused,
                                    std::span<const ChangedExtent> reread) {
    if (!save) throw Error("backup resume requires a durable journal");
    const auto summary = backup_job_status(record, auth);
    const auto& status = object(summary);
    const auto& phase = text(status, "phase");
    if (phase != "metadata-accepted" && phase != "upload" && phase != "uploaded")
        throw BackupStateError("backup is not in a resumable upload phase; reconcile uncertain preparation or completion first");
    const auto& original = object(record);
    if (number(original,"schema") == 4 || number(original,"schema") == 5 ||
        number(original,"schema") == 6 || number(original,"schema") == 7)
        throw BackupStateError("multi-disk backup requires all saved images for resume");
    if (original.contains("nas_cancel_requested"))
        throw BackupStateError("NAS requested cancellation; reconcile or cancel this backup before continuing");
    const auto& requested = text(original,"requested_outcome");
    const bool partial_cache = endpoint.cached_backup && original.contains("is_cache") && requested == "partial";
    if ((requested != "complete" && !partial_cache) || number(original, "data_format") != 1)
        throw BackupStateError("resume requires a complete-image backup with data format 1");
    const auto schema = number(original,"schema");
    if (schema == 8 || schema == 9) {
        if (unused_ranges_value(unused) != field(original,"unused_ranges"))
            throw BackupStateError("saved unused image intervals differ from capture");
        verify_unused_source(source,unused);
    } else if (!unused.empty())
        throw BackupStateError("saved backup predates unused image interval policy; configure a full backup");
    std::optional<IncrementalBackup> incremental;
    if (schema == 3 || schema == 9) incremental = incremental_from(original);
    if (incremental && incremental->plan.filesystem_allocation &&
        unused_ranges_value(reread) != unused_ranges_value(incremental->reread_ranges))
        throw BackupStateError("saved full-reread intervals differ from capture");
    if (source.size() != number(original, "image_size") ||
        fingerprint(source, endpoint) != text(original, "image_sha256",true))
        throw Error("resume source differs from the saved backup image; no upload was started");
    const BackupRun run{number(original, "running_task_id"), number(original, "version_id"),
                        number(original, "result_id"), number(original, "data_format")};
    const auto task = number(original, "task_id");
    if (backup_result(endpoint, auth, task, run.result_id) != "incomplete")
        throw Error("NAS backup already has an outcome; use backup reconcile");
    const auto name = text(original, "image_name");
    std::uint64_t transferred = 0;
    const auto offset = backup_checkpoint(endpoint, auth, run, task, name, source.size(),
                                           incremental ? incremental->base_version_id : 0,&transferred);
    source.verify_unchanged();
    auto saved = record;
    auto& fields = std::get<Value::Object>(saved.data);
    auto persist = [&](const char* phase) { fields["phase"] = Value{std::string(phase)}; save(saved); };
    fields["resume_offset"] = Value{offset};
    persist("upload");
    upload_prepared_image(endpoint, auth, run.running_task_id, source, name, 1024*1024, offset,
        journal_compression(original), incremental ? &incremental->plan : nullptr,unused,reread,transferred);
    persist("uploaded");
    const auto outcome = finish_backup(endpoint, auth, run, partial_cache ? BackupOutcome::partial : BackupOutcome::complete,
        [&] { source.verify_unchanged(); persist("finish"); }, backup_completion_cbt(saved));
    persist(terminal(outcome).c_str());
    return outcome;
}

static BackupOutcome images_job(const Endpoint& endpoint, const SavedAuth& auth,
                                std::uint64_t task_id, std::uint64_t run_id,
                                std::span<const BackupImage> images,
                                std::span<const IncrementalBackup> incremental,
                                std::span<const std::uint8_t> metadata,
                                const SaveBackupJob& save, TransferCompression compression,
                                BackupOutcome requested = BackupOutcome::complete) {
    if (!save || (!run_id && (!endpoint.cached_backup || !task_id || incremental.empty())) ||
        images.size() < 2 || metadata.empty() || metadata.size() > 8*1024*1024)
        throw Error("invalid multi-disk backup preparation");
    if (compression != TransferCompression::none && compression != TransferCompression::lz4)
        throw Error("unsupported multi-disk transfer compression");
    if (std::find(metadata.begin(),metadata.end(),0) != metadata.end())
        throw Error("invalid multi-disk snapshot JSON buffer");
    if (!incremental.empty() && (incremental.size() != images.size() || !task_id))
        throw Error("invalid multi-disk incremental preparation");
    Value::Array entries;
    std::set<std::string> names;
    const bool has_unused = std::any_of(images.begin(),images.end(),
        [](const BackupImage& image) { return !image.unused_ranges.empty(); });
    for (std::size_t index = 0; index < images.size(); ++index) {
        const auto& image = images[index];
        validate_image_options(image.name,1024*1024);
        if (!names.insert(image.name).second) throw Error("duplicate backup image name");
        verify_unused_source(*image.source,image.unused_ranges);
        Value::Object entry{
            {"name",Value{image.name}},{"size",Value{image.source->size()}},
            {"sha256",Value{fingerprint(*image.source,endpoint)}}};
        if (has_unused) entry.emplace("unused_ranges",unused_ranges_value(image.unused_ranges));
        if (!incremental.empty()) {
            const auto& info = incremental[index];
            if (!image.source->direct_intervals() && info.base_image_sha256.empty())
                throw Error("immutable image incremental base requires its digest");
            validate_incremental_identity(info);
            validate_delta_plan(info.plan,image.source->size());
            if (index && (info.base_version_id != incremental.front().base_version_id ||
                info.base_result_id != incremental.front().base_result_id ||
                info.base_running_task_id != incremental.front().base_running_task_id ||
                info.base_snapshot_id != incremental.front().base_snapshot_id))
                throw Error("multi-disk incremental images have different NAS bases");
            if (info.machine_policy) entry.emplace("machine_policy",*info.machine_policy);
            entry.emplace("base_sha256",Value{info.base_image_sha256});
            entry.emplace("ranges",delta_plan_value(info.plan));
            if (info.plan.filesystem_allocation) {
                entry.emplace("filesystem_allocation",Value{std::uint64_t{1}});
                entry.emplace("reread_ranges",unused_ranges_value(image.reread_ranges));
            }
        }
        entries.push_back(Value{std::move(entry)});
    }
    Value record{Value::Object{
        {"schema",Value{std::uint64_t{incremental.empty() ?
            (has_unused ? 6U : 4U) : (has_unused ? 7U : 5U)}}},{"ds_id",Value{auth.ds_id}},
        {"device_uuid",Value{auth.device_uuid}},{"username",Value{auth.username}},
        {"compression",Value{std::string(compression == TransferCompression::lz4 ? "lz4" : "none")}},
        {"running_task_id",Value{run_id}},
        {"image_name",Value{images.front().name}},{"image_size",Value{images.front().source->size()}},
        {"image_sha256",field(object(entries.front()),"sha256")},
        {"images",Value{std::move(entries)}},
        {"snapshot_info",Value{pstream::Bytes(metadata.begin(),metadata.end())}},
        {"requested_outcome",Value{terminal(requested)}}}};
    auto& fields = std::get<Value::Object>(record.data);
    if (endpoint.cached_backup) fields["is_cache"] = Value{std::uint64_t{1}};
    if (endpoint.backup_app_aware) fields["app_aware_bkp"] = Value{std::uint64_t{1}};
    if (!run_id) fields["create_task_id"] = Value{task_id};
    if (images.front().source->direct_intervals()) {
        if (std::any_of(images.begin(),images.end(),[](const auto& image) { return !image.source->direct_intervals(); }))
            throw Error("mixed direct and immutable backup image sources");
        fields["direct_intervals"] = Value{std::uint64_t{1}};
    }
    if (!incremental.empty()) {
        const auto& info = incremental.front();
        fields["incremental"] = Value{Value::Object{
            {"base_version_id",Value{info.base_version_id}},
            {"base_result_id",Value{info.base_result_id}},
            {"base_running_task_id",Value{info.base_running_task_id}},
            {"base_snapshot_id",Value{info.base_snapshot_id}}}};
        (void)multi_incremental_from(fields);
    }
    auto persist = [&](const char* phase) {
        fields["phase"] = Value{std::string(phase)};
        save(record);
    };
    auto intent = [&](const char* phase) {
        for (const auto& image : images) image.source->verify_unchanged();
        persist(phase);
    };
    persist("planned");
    const auto run = !run_id
        ? create_incremental_backup(endpoint,auth,task_id,incremental.front().base_version_id,
            [&] { intent("prepare"); })
        : prepare_image_backup(endpoint,auth,task_id,run_id,
            incremental.empty() ? 0 : incremental.front().base_version_id,[&] { intent("prepare"); });
    fields["running_task_id"] = Value{run.running_task_id};
    fields["version_id"] = Value{run.version_id};
    fields["result_id"] = Value{run.result_id};
    fields["data_format"] = Value{run.data_format};
    persist("prepared");
    upload_backup_spec(endpoint,auth,run,metadata,[&] { intent("metadata"); });
    persist("metadata-accepted");
    intent("upload");
    std::vector<UploadImage> uploads;
    uploads.reserve(images.size());
    for (std::size_t index = 0; index < images.size(); ++index) {
        uploads.push_back({images[index].source,images[index].name,{},
            compression,incremental.empty() ? nullptr : &incremental[index].plan,
            images[index].unused_ranges,images[index].reread_ranges});
    }
    upload_prepared_images(endpoint,auth,run.running_task_id,uploads);
    persist("uploaded");
    const auto outcome = finish_backup(endpoint,auth,run,requested,
        [&] { intent("finish"); },backup_completion_cbt(record));
    persist(terminal(outcome).c_str());
    return outcome;
}
BackupOutcome run_full_images_job(const Endpoint& endpoint, const SavedAuth& auth,
                                  std::uint64_t run_id, std::span<const BackupImage> images,
                                  std::span<const std::uint8_t> metadata,
                                  const SaveBackupJob& save, TransferCompression compression) {
    return images_job(endpoint,auth,0,run_id,images,{},metadata,save,compression);
}
BackupOutcome run_incremental_images_job(const Endpoint& endpoint, const SavedAuth& auth,
                                         std::uint64_t task_id, std::uint64_t run_id,
                                         std::span<const BackupImage> images,
                                         std::span<const IncrementalBackup> incremental,
                                         std::span<const std::uint8_t> metadata,
                                         const SaveBackupJob& save, TransferCompression compression) {
    return images_job(endpoint,auth,task_id,run_id,images,incremental,metadata,save,compression);
}
BackupOutcome create_cached_images_job(const Endpoint& endpoint, const SavedAuth& auth,
    std::uint64_t task_id, std::span<const BackupImage> images,
    std::span<const IncrementalBackup> incremental, std::span<const std::uint8_t> metadata,
    const SaveBackupJob& save, TransferCompression compression, BackupOutcome requested) {
    if (!endpoint.cached_backup || images.empty() || incremental.size() != images.size())
        throw Error("cached replay requires its complete incremental image set");
    if (requested != BackupOutcome::complete && requested != BackupOutcome::partial)
        throw Error("cached replay requires a successful complete or partial capture");
    if (images.size() > 1) return images_job(endpoint,auth,task_id,0,images,incremental,metadata,save,compression,requested);
    const auto& image = images.front();
    return image_job(endpoint,auth,task_id,true,*image.source,image.name,metadata,save,
        requested,compression,&incremental.front(),task_id,
        image.unused_ranges,image.reread_ranges);
}
BackupOutcome resume_images_job(const Endpoint& endpoint, const SavedAuth& auth,
                                std::span<const BackupImage> images, const Value& record,
                                const SaveBackupJob& save) {
    if (!save || images.size() < 2) throw Error("invalid multi-disk backup resume");
    const auto summary = backup_job_status(record,auth);
    const auto phase = text(object(summary),"phase");
    if (phase != "metadata-accepted" && phase != "upload" && phase != "uploaded")
        throw BackupStateError("multi-disk backup is not in a resumable upload phase");
    const auto& original = object(record);
    const auto schema = number(original,"schema");
    const auto& requested = text(original,"requested_outcome");
    const bool partial_cache = endpoint.cached_backup && original.contains("is_cache") && requested == "partial";
    if ((schema != 4 && schema != 5 && schema != 6 && schema != 7) ||
        original.contains("nas_cancel_requested") ||
        (requested != "complete" && !partial_cache) || number(original,"data_format") != 1)
        throw BackupStateError("multi-disk resume requires an unfinished image backup");
    const auto& entries = std::get<Value::Array>(field(original,"images").data);
    const auto incremental = schema == 5 || schema == 7 ? multi_incremental_from(original)
        : std::vector<IncrementalBackup>{};
    if (entries.size() != images.size()) throw BackupStateError("saved backup image count differs from capture");
    std::map<std::string,std::uint64_t> sizes;
    for (std::size_t index = 0; index < images.size(); ++index) {
        const auto& saved = object(entries[index]);
        if (images[index].name != text(saved,"name") ||
            images[index].source->size() != number(saved,"size") ||
            fingerprint(*images[index].source,endpoint) != text(saved,"sha256",true))
            throw Error("multi-disk resume source differs from saved backup");
        if (schema == 6 || schema == 7) {
            if (unused_ranges_value(images[index].unused_ranges) != field(saved,"unused_ranges"))
                throw BackupStateError("saved unused image intervals differ from capture");
            verify_unused_source(*images[index].source,images[index].unused_ranges);
        } else if (!images[index].unused_ranges.empty())
            throw BackupStateError("saved backup predates unused image interval policy");
        if (!incremental.empty() && incremental[index].plan.filesystem_allocation &&
            unused_ranges_value(images[index].reread_ranges) != unused_ranges_value(incremental[index].reread_ranges))
            throw BackupStateError("saved full-reread intervals differ from capture");
        sizes.emplace(images[index].name,images[index].source->size());
    }
    const BackupRun run{number(original,"running_task_id"),number(original,"version_id"),
        number(original,"result_id"),number(original,"data_format")};
    const auto task = number(original,"task_id");
    if (backup_result(endpoint,auth,task,run.result_id) != "incomplete")
        throw Error("NAS backup already has an outcome; use backup reconcile");
    std::map<std::string,std::uint64_t> transferred;
    const auto offsets = backup_checkpoint_images(endpoint,auth,run,task,sizes,
        incremental.empty() ? 0 : incremental.front().base_version_id,&transferred);
    auto saved = record;
    auto& fields = std::get<Value::Object>(saved.data);
    auto persist = [&](const char* next) {
        fields["phase"] = Value{std::string(next)};
        save(saved);
    };
    std::vector<UploadImage> uploads;
    uploads.reserve(images.size());
    for (std::size_t index = 0; index < images.size(); ++index) {
        auto& item = std::get<Value::Object>(std::get<Value::Array>(fields.at("images").data)[index].data);
        const auto offset = offsets.at(images[index].name);
        item["resume_offset"] = Value{offset};
        uploads.push_back({images[index].source,images[index].name,offset,
            journal_compression(original),incremental.empty() ? nullptr : &incremental[index].plan,
            images[index].unused_ranges,images[index].reread_ranges,transferred.at(images[index].name)});
    }
    persist("upload");
    upload_prepared_images(endpoint,auth,run.running_task_id,uploads);
    persist("uploaded");
    const auto outcome = finish_backup(endpoint,auth,run,partial_cache ? BackupOutcome::partial : BackupOutcome::complete,
        [&] {
            for (const auto& image : images) image.source->verify_unchanged();
            persist("finish");
        },backup_completion_cbt(saved));
    persist(terminal(outcome).c_str());
    return outcome;
}

Value backup_job_status(const Value& record, const SavedAuth& auth) try {
    const auto& fields = object(record);
    if (fields.contains("is_cache") && number(fields,"is_cache") != 1)
        throw Error("invalid cached backup journal policy");
    if (fields.contains("app_aware_bkp") && number(fields,"app_aware_bkp") != 1)
        throw Error("invalid application-aware backup journal policy");
    const auto compression = journal_compression(fields);
    const auto schema = number(fields,"schema");
    const bool incremental = schema == 3 || schema == 5 || schema == 7 || schema == 9;
    if (incremental != fields.contains("incremental"))
        throw Error("backup journal schema does not match its incremental mode");
    if (schema == 3 || schema == 9) (void)incremental_from(fields);
    if (schema == 8 || schema == 9)
        (void)unused_ranges_from(field(fields,"unused_ranges"),number(fields,"image_size"));
    else if (fields.contains("unused_ranges"))
        throw Error("backup journal schema cannot specify single-image unused intervals");
    if (schema != 4 && schema != 5 && schema != 6 && schema != 7 && fields.contains("images"))
        throw Error("single-image backup journal cannot specify multiple images");
    for (const auto& [key, expected] : std::array<std::pair<const char*, const std::string*>,3>{{
             {"ds_id", &auth.ds_id}, {"device_uuid", &auth.device_uuid}, {"username", &auth.username}}})
        if (text(fields, key) != *expected) throw Error("backup journal belongs to a different NAS, device or account");
    const auto& phase = text(fields, "phase");
    if (fields.contains("source_capture") && number(object(field(fields,"source_capture")),"schema") < 5 &&
        std::find(phases.begin()+8,phases.end(),phase) == phases.end())
        throw Error("pending sealed machine backup requires the previous OpenSabba version; direct snapshot upload cannot resume it");
    const auto pos = std::find(phases.begin(), phases.end(), phase);
    if (pos == phases.end()) throw Error("unknown backup journal phase");
    const bool creating = fields.contains("create_task_id");
    if (creating && (!number(fields, "create_task_id") ||
        (fields.contains("task_id") && number(fields, "task_id") != number(fields, "create_task_id"))))
        throw Error("invalid backup creation task identity");
    const auto run_id = number(fields, "running_task_id");
    if ((creating && pos < phases.begin()+2 ? run_id != 0 : run_id == 0) || !number(fields, "image_size") ||
        number(fields, "image_size") % 512) throw Error("invalid backup journal extent or running task");
    validate_image_options(text(fields, "image_name"), 1024*1024);
    const auto& hash = text(fields, "image_sha256",true);
    const bool direct = fields.contains("direct_intervals") && number(fields,"direct_intervals") == 1;
    if (fields.contains("direct_intervals") && !direct)
        throw Error("invalid direct interval source policy");
    // Transfer monitors also inspect the inner journal before the service
    // attaches its source binding. Persisted service records require both.
    if (direct && fields.contains("service_source") && (!fields.contains("source_capture") ||
        capture_journal_from_value(field(fields,"source_capture")).schema != 5))
        throw Error("direct interval backup requires its snapshot capture journal");
    if (direct ? !hash.empty() : (hash.size() != 64 || hash.find_first_not_of("0123456789abcdef") != hash.npos))
        throw Error("invalid backup journal image fingerprint");
    if (incremental && !direct) {
        if (schema == 3 || schema == 9) {
            if (incremental_from(fields).base_image_sha256.empty())
                throw Error("immutable image incremental base requires its digest");
        } else {
            for (const auto& image : multi_incremental_from(fields))
                if (image.base_image_sha256.empty())
                    throw Error("immutable image incremental base requires its digest");
        }
    }
    if (schema == 4 || schema == 5 || schema == 6 || schema == 7) {
        const auto* images = std::get_if<Value::Array>(&field(fields,"images").data);
        if (!images || images->size() < 2) throw Error("invalid multi-disk backup image list");
        std::set<std::string> names;
        for (const auto& image : *images) {
            const auto& item = object(image);
            const auto& name = text(item,"name");
            validate_image_options(name,1024*1024);
            if (!names.insert(name).second || !number(item,"size") || number(item,"size")%512)
                throw Error("invalid multi-disk backup image identity");
            const auto& digest = text(item,"sha256",true);
            if (direct ? !digest.empty() : (digest.size() != 64 || digest.find_first_not_of("0123456789abcdef") != digest.npos))
                throw Error("invalid multi-disk backup image digest");
            if (schema == 6 || schema == 7)
                (void)unused_ranges_from(field(item,"unused_ranges"),number(item,"size"));
            else if (item.contains("unused_ranges"))
                throw Error("legacy backup journal has unused image intervals");
            if (item.contains("resume_offset") && (number(item,"resume_offset") > number(item,"size") ||
                number(item,"resume_offset")%512))
                throw Error("invalid multi-disk transfer progress");
        }
        if (text(object(images->front()),"name") != text(fields,"image_name") ||
            number(object(images->front()),"size") != number(fields,"image_size") ||
            field(object(images->front()),"sha256") != field(fields,"image_sha256"))
            throw Error("primary backup image differs from multi-disk list");
        if (schema == 5 || schema == 7) (void)multi_incremental_from(fields);
    }
    auto metadata = std::get_if<pstream::Bytes>(&field(fields, "snapshot_info").data);
    if (!metadata || metadata->empty() || metadata->size() > 8*1024*1024 ||
        std::find(metadata->begin(), metadata->end(), 0) != metadata->end())
        throw Error("invalid backup journal snapshot buffer");
    const auto& requested = text(fields, "requested_outcome");
    if (std::find(phases.begin()+8, phases.end(), requested) == phases.end())
        throw Error("invalid backup journal requested outcome");
    Value::Object result;
    if (fields.contains("is_cache")) result.emplace("is_cache",field(fields,"is_cache"));
    if (fields.contains("nas_cancel_requested")) {
        if (pos < phases.begin()+2 || number(fields, "nas_cancel_requested") != 1)
            throw Error("invalid NAS cancellation request in backup journal");
        result.emplace("nas_cancel_requested", field(fields, "nas_cancel_requested"));
    }
    if (schema == 3 || schema == 9) {
        const auto info = incremental_from(fields);
        result.emplace("base_version_id", Value{info.base_version_id});
        result.emplace("transfer_bytes", Value{info.plan.transfer_bytes});
    } else if (schema == 5 || schema == 7) {
        const auto plans = multi_incremental_from(fields);
        std::uint64_t transfer = 0;
        Value::Array images;
        const auto& entries = std::get<Value::Array>(field(fields,"images").data);
        for (std::size_t index = 0; index < plans.size(); ++index) {
            const auto& item = object(entries[index]);
            transfer += plans[index].plan.transfer_bytes;
            Value::Object image{
                {"name",field(item,"name")},{"size",field(item,"size")},
                {"sha256",field(item,"sha256")},
                {"base_sha256",field(item,"base_sha256")},
                {"transfer_bytes",Value{plans[index].plan.transfer_bytes}}};
            if (item.contains("resume_offset")) image.emplace("resume_offset",field(item,"resume_offset"));
            images.push_back(Value{std::move(image)});
        }
        result.emplace("base_version_id",Value{plans.front().base_version_id});
        result.emplace("transfer_bytes",Value{transfer});
        result.emplace("images",Value{std::move(images)});
    }
    result.emplace("compression", Value{std::string(compression == TransferCompression::lz4 ? "lz4" : "none")});
    for (auto key : {"phase", "running_task_id", "image_name", "image_size", "image_sha256"})
        result.emplace(key, field(fields, key));
    if (fields.contains("resume_offset")) {
        const auto value = number(fields, "resume_offset");
        if (pos < phases.begin()+5 || value > number(fields, "image_size") || value % 512)
            throw Error("invalid backup transfer progress");
        result.emplace("resume_offset", Value{value});
    }
    if (creating) result.emplace("create_task_id", field(fields, "create_task_id"));
    if (fields.contains("task_id")) {
        if (!number(fields, "task_id")) throw Error("invalid backup journal task");
        result.emplace("task_id", field(fields, "task_id"));
    }
    if (pos >= phases.begin()+2) {
        if (!number(fields, "version_id") || !number(fields, "result_id"))
            throw Error("backup journal has no prepared identifiers");
        number(fields, "data_format");
        for (auto key : {"version_id", "result_id", "data_format"}) result.emplace(key, field(fields, key));
    } else if (fields.contains("version_id") || fields.contains("result_id") || fields.contains("data_format")) {
        throw Error("unprepared backup journal has prepared identifiers");
    }
    result["terminal"] = Value{std::uint64_t{pos >= phases.begin()+8}};
    Value summary{std::move(result)};
    apply_job_resolution(record, summary);
    return summary;
} catch (const Error& error) {
    throw BackupStateError(error.what());
}
}
