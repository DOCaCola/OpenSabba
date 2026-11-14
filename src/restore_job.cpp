#include "opensabba/restore_job.hpp"
#include "opensabba/job_recovery.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <limits>
#ifndef _WIN32
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace opensabba {
namespace {
using pstream::Value;
using pstream::Error;
constexpr std::array phases{"planned", "create", "created", "download", "verified",
                            "downloaded", "finish", "complete", "cancel", "error"};
const Value& field(const Value& value, const char* key) {
    const auto* object = std::get_if<Value::Object>(&value.data);
    if (!object || !object->contains(key)) throw Error(std::string("restore journal missing ") + key);
    return object->at(key);
}
std::uint64_t number(const Value& value, const char* key) {
    const auto* result = std::get_if<std::uint64_t>(&field(value, key).data);
    if (!result) throw Error(std::string("invalid restore journal number: ") + key);
    return *result;
}
std::string text(const Value& value, const char* key, bool empty = false) {
    const auto* result = std::get_if<std::string>(&field(value, key).data);
    if (!result || (!empty && result->empty())) throw Error(std::string("invalid restore journal text: ") + key);
    return *result;
}
#ifndef _WIN32
class Digest {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context_{EVP_MD_CTX_new(), EVP_MD_CTX_free};
public:
    Digest() {
        if (!context_ || EVP_DigestInit_ex(context_.get(), EVP_sha256(), nullptr) != 1)
            throw Error("cannot initialize restore fingerprint");
    }
    void update(std::span<const std::uint8_t> bytes) {
        if (EVP_DigestUpdate(context_.get(), bytes.data(), bytes.size()) != 1)
            throw Error("cannot fingerprint restored image");
    }
    std::string value() const {
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> copy(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        std::array<unsigned char, 32> hash{};
        unsigned int size = 0;
        if (!copy || EVP_MD_CTX_copy_ex(copy.get(), context_.get()) != 1 ||
            EVP_DigestFinal_ex(copy.get(), hash.data(), &size) != 1 || size != hash.size())
            throw Error("cannot finalize restore fingerprint");
        constexpr char hex[] = "0123456789abcdef";
        std::string result;
        for (auto b : hash) { result += hex[b >> 4]; result += hex[b & 15]; }
        return result;
    }
};
class Destination {
    int directory_ = -1, file_ = -1;
    std::uint64_t expected_, written_ = 0;
    std::filesystem::path name_;
    struct stat observed_{};
    Digest digest_;
    struct stat inspect() const {
        struct stat file{}, entry{};
        if (fstat(file_, &file) != 0 || !S_ISREG(file.st_mode) || file.st_uid != getuid() ||
            (file.st_mode & 0077) || file.st_nlink != 1 ||
            fstatat(directory_, name_.c_str(), &entry, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISREG(entry.st_mode) || entry.st_dev != file.st_dev || entry.st_ino != file.st_ino)
            throw Error("restore destination must remain the same private regular file");
        return file;
    }
    void unchanged(const struct stat& before) const {
        const auto after = inspect();
        if (before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
            before.st_mtim.tv_nsec != after.st_mtim.tv_nsec || before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
            before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
            throw Error("restore destination changed during verification");
    }
    void hash_prefix(Digest& digest, std::uint64_t length, const Endpoint& endpoint) {
        std::array<std::uint8_t, 1024*1024> bytes{};
        for (std::uint64_t offset = 0; offset < length;) {
            if (endpoint.cancelled && endpoint.cancelled()) throw Cancelled();
            const auto count = pread(file_, bytes.data(),
                static_cast<std::size_t>(std::min<std::uint64_t>(bytes.size(), length-offset)),
                static_cast<off_t>(offset));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) throw Error("cannot read restored image for verification");
            digest.update(std::span(bytes).first(static_cast<std::size_t>(count)));
            offset += static_cast<std::uint64_t>(count);
        }
    }
public:
    Destination(const std::filesystem::path& path, std::uint64_t size,
                const Value* checkpoint = nullptr, const Endpoint& endpoint = {})
        : expected_(size), name_(path.filename()) {
        if (!size || size > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()))
            throw Error("restore image size is outside the supported file range");
        directory_ = open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (directory_ < 0) throw Error("cannot open restore destination directory");
        file_ = openat(directory_, path.filename().c_str(),
                       O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK |
                       (checkpoint ? 0 : O_CREAT | O_EXCL), 0600);
        if (file_ < 0) {
            close(directory_);
            throw Error(checkpoint ? "cannot reopen the saved restore destination" :
                                    "cannot create restore destination; choose a new regular file");
        }
        try {
            observed_ = inspect();
            if (flock(file_, LOCK_EX | LOCK_NB) != 0) throw Error("restore destination is already in use");
            if (checkpoint) {
                written_ = number(*checkpoint, "offset");
                if (number(*checkpoint, "inode") != static_cast<std::uint64_t>(observed_.st_ino) ||
                    observed_.st_size < 0 || static_cast<std::uint64_t>(observed_.st_size) < written_ ||
                    static_cast<std::uint64_t>(observed_.st_size) > expected_)
                    throw Error("restore destination identity or length differs from its checkpoint");
                hash_prefix(digest_, written_, endpoint);
                unchanged(observed_);
                if (digest_.value() != text(*checkpoint, "sha256",true))
                    throw Error("restore checkpoint prefix SHA-256 does not match; file was not modified");
            }
        } catch (...) {
            close(file_); close(directory_); throw;
        }
    }
    ~Destination() { close(file_); close(directory_); }
    Destination(const Destination&) = delete;
    Destination& operator=(const Destination&) = delete;
    std::uint64_t offset() const { return written_; }
    void prepare_resume() {
        unchanged(observed_);
        if (ftruncate(file_, static_cast<off_t>(written_)) != 0 ||
            lseek(file_, static_cast<off_t>(written_), SEEK_SET) < 0)
            throw Error("cannot discard uncommitted restore tail");
    }
    Value checkpoint() {
        if (fsync(file_) != 0 || fsync(directory_) != 0) throw Error("cannot persist restore checkpoint");
        const auto file = inspect();
        if (file.st_size < 0 || static_cast<std::uint64_t>(file.st_size) != written_)
            throw Error("restore checkpoint length differs from destination");
        return Value{Value::Object{
            {"offset", Value{written_}}, {"sha256", Value{digest_.value()}},
            {"device", Value{static_cast<std::uint64_t>(file.st_dev)}},
            {"inode", Value{static_cast<std::uint64_t>(file.st_ino)}}}};
    }
    void append(std::span<const std::uint8_t> bytes) {
        if (bytes.size() > expected_ - written_) throw Error("restore exceeds expected image size");
        while (!bytes.empty()) {
            const auto count = write(file_, bytes.data(), bytes.size());
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) throw Error("cannot write restore destination");
            digest_.update(bytes.first(static_cast<std::size_t>(count)));
            written_ += static_cast<std::uint64_t>(count);
            bytes = bytes.subspan(static_cast<std::size_t>(count));
        }
    }
    void verify(std::string_view expected_hash, const Endpoint& endpoint) {
        if (written_ != expected_) throw Error("restore image is incomplete");
        if (fsync(file_) != 0 || fsync(directory_) != 0) throw Error("cannot persist restored image");
        const auto initial = inspect();
        if (initial.st_size < 0 || static_cast<std::uint64_t>(initial.st_size) != expected_)
            throw Error("restore destination changed");
        Digest actual;
        hash_prefix(actual, expected_, endpoint);
        unchanged(initial);
        if (actual.value() != (expected_hash.empty() ? digest_.value() : expected_hash)) throw Error("restored image SHA-256 does not match the saved backup");
    }
};
void download(const Endpoint& endpoint, const SavedAuth& auth, Destination& output, Value record,
              const SaveBackupJob& save, bool resuming = false) {
    auto& fields = std::get<Value::Object>(record.data);
    auto persist = [&](const char* phase) { fields["phase"] = Value{std::string(phase)}; save(record); };
    const auto run = number(record, "running_task_id"), size = number(record, "image_size");
    std::function<void()> validate_offline_resume;
    if (resuming) validate_offline_resume = [&] {
        const auto result = restore_result_id(endpoint, auth, run, number(record, "task_id"),
            number(record, "device_id"), number(record, "version_id"), true);
        if (result != number(record, "result_id"))
            throw Error("NAS restore result identity changed during resume");
    };
    persist("download");
    download_restore_image(endpoint, auth, run, text(record, "image_name"), size,
        [&](std::span<const std::uint8_t> bytes) {
            output.append(bytes);
            if (output.offset() % (4*1024*1024) == 0 || output.offset() == size) {
                fields["checkpoint"] = output.checkpoint();
                persist("download");
            }
        },
        [&] { output.verify(text(record, "image_sha256",true), endpoint); persist("verified"); }, output.offset(), validate_offline_resume);
    persist("downloaded");
    const auto outcome = finish_image_restore(endpoint, auth, run, [&] { persist("finish"); });
    fields["phase"] = Value{outcome};
    save(record);
    if (outcome != "complete") throw Error("NAS reported a non-complete restore outcome");
}
#endif
}

void restore_saved_image(const Endpoint& endpoint, const SavedAuth& auth, const Value& backup,
                         const std::filesystem::path& path,
                         std::optional<std::string_view> image_name, const SaveBackupJob& save) {
#ifdef _WIN32
    (void)endpoint; (void)auth; (void)backup; (void)path; (void)image_name; (void)save;
    throw Error("image restore currently requires Linux");
#else
    if (!save) throw Error("restore requires a durable journal");
    const auto source = backup_job_status(backup, auth);
    if (text(source, "phase") != "complete") throw Error("restore requires a completed fixed-image backup");
    if (image_name) validate_image_options(*image_name, 1024*1024);
    const auto task = number(source, "task_id"), version = number(source, "version_id");
    auto size = number(source, "image_size");
    auto name = text(source, "image_name"), hash = text(source, "image_sha256",true);
    if (image_name && *image_name != name) {
        if (!std::get<Value::Object>(backup.data).contains("images"))
            throw Error("image name is not in the completed backup");
        const auto& images = std::get<Value::Array>(field(backup, "images").data);
        const auto selected = std::find_if(images.begin(), images.end(), [&](const Value& image) {
            return text(image, "name") == *image_name;
        });
        if (selected == images.end()) throw Error("image name is not in the completed backup");
        name = text(*selected, "name");
        size = number(*selected, "size");
        hash = text(*selected, "sha256",true);
    }
    const auto destination = std::filesystem::absolute(path).lexically_normal();
    const auto device = restore_device(endpoint, auth, task);
    Destination output(destination, size);
    Value record{Value::Object{
        {"schema", Value{std::uint64_t{1}}}, {"ds_id", Value{auth.ds_id}},
        {"device_uuid", Value{auth.device_uuid}}, {"username", Value{auth.username}},
        {"task_id", Value{task}}, {"device_id", Value{device}}, {"version_id", Value{version}},
        {"image_name", Value{name}}, {"image_size", Value{size}}, {"image_sha256", Value{hash}},
        {"destination", Value{destination.string()}}, {"running_task_id", Value{std::uint64_t{0}}}}};
    auto& fields = std::get<Value::Object>(record.data);
    if (hash.empty()) fields["source_digest_absent"] = Value{std::uint64_t{1}};
    fields["checkpoint"] = output.checkpoint();
    auto persist = [&](std::string phase) { fields["phase"] = Value{std::move(phase)}; save(record); };
    persist("planned");
    const auto run = create_image_restore(endpoint, auth, task, device, version, [&] { persist("create"); });
    fields["running_task_id"] = Value{run};
    persist("created");
    fields["result_id"] = Value{restore_result_id(endpoint, auth, run, task, device, version)};
    // Bind the result durably before opening a transfer or completing the NAS
    // job. A failure here retains the created run for later read-only discovery.
    download(endpoint, auth, output, record, save);
#endif
}

void resume_saved_image(const Endpoint& endpoint, const SavedAuth& auth, const Value& record,
                        const SaveBackupJob& save) {
#ifdef _WIN32
    (void)endpoint; (void)auth; (void)record; (void)save;
    throw Error("image restore currently requires Linux");
#else
    if (!save) throw Error("restore resume requires a durable journal");
    const auto summary = restore_job_status(record, auth);
    const auto phase = text(summary, "phase");
    if (phase != "created" && phase != "download" && phase != "verified" && phase != "downloaded")
        throw Error("restore is not in a resumable download phase; reconcile uncertain completion or cancellation first");
    const auto& checkpoint = field(record, "checkpoint");
    Destination output(text(record, "destination"), number(record, "image_size"), &checkpoint, endpoint);
    const auto result = restore_result_id(endpoint, auth, number(record, "running_task_id"),
        number(record, "task_id"), number(record, "device_id"), number(record, "version_id"), true);
    auto saved = record;
    auto& fields = std::get<Value::Object>(saved.data);
    if (fields.contains("result_id") && number(saved, "result_id") != result)
        throw Error("NAS restore result identity differs from the saved job");
    if (restore_result(endpoint, auth, number(record, "task_id"), result) != "incomplete")
        throw Error("NAS restore already has an outcome; use restore reconcile");
    fields["result_id"] = Value{result};
    output.prepare_resume();
    download(endpoint, auth, output, saved, save, true);
#endif
}

Value restore_job_status(const Value& record, const SavedAuth& auth) {
    if (number(record, "schema") != 1) throw Error("unsupported restore journal schema");
    if (text(record, "ds_id") != auth.ds_id || text(record, "device_uuid") != auth.device_uuid ||
        text(record, "username") != auth.username)
        throw Error("restore journal belongs to a different NAS, device or account");
    const auto phase = text(record, "phase");
    const auto pos = std::find(phases.begin(), phases.end(), phase);
    if (pos == phases.end()) throw Error("unknown restore journal phase");
    const auto run = number(record, "running_task_id");
    if (pos < phases.begin()+2 ? run != 0 : run == 0) throw Error("invalid restore journal running task");
    for (auto key : {"task_id", "device_id", "version_id", "image_size"})
        if (!number(record, key)) throw Error("invalid restore journal identifier or size");
    if (number(record, "image_size") % 512) throw Error("invalid restore journal image size");
    validate_image_options(text(record, "image_name"), 1024*1024);
    const auto hash = text(record, "image_sha256",true);
    if (hash.empty() ? (!std::get<Value::Object>(record.data).contains("source_digest_absent") ||
        number(record,"source_digest_absent") != 1) :
        (hash.size() != 64 || hash.find_first_not_of("0123456789abcdef") != hash.npos))
        throw Error("invalid restore journal fingerprint");
    if (!std::filesystem::path(text(record, "destination")).is_absolute())
        throw Error("invalid restore journal destination");
    Value::Object result;
    for (auto key : {"phase", "running_task_id", "task_id", "device_id", "version_id",
                     "image_name", "image_size", "image_sha256", "destination"})
        result.emplace(key, field(record, key));
    if (std::get<Value::Object>(record.data).contains("result_id")) {
        if (pos < phases.begin()+2 || !number(record, "result_id"))
            throw Error("invalid restore journal activity result ID");
        result.emplace("result_id", field(record, "result_id"));
    }
    if (std::get<Value::Object>(record.data).contains("checkpoint")) {
        const auto& checkpoint = field(record, "checkpoint");
        const auto offset = number(checkpoint, "offset");
        const auto digest = text(checkpoint, "sha256",true);
        number(checkpoint, "device");
        if (!number(checkpoint, "inode") || offset > number(record, "image_size") || offset % 512 ||
            digest.size() != 64 || digest.find_first_not_of("0123456789abcdef") != digest.npos ||
            (pos < phases.begin()+3 && offset != 0) ||
            (pos >= phases.begin()+4 && offset != number(record, "image_size")))
            throw Error("invalid restore checkpoint");
        result.emplace("downloaded_bytes", Value{offset});
    }
    result["terminal"] = Value{std::uint64_t{pos >= phases.begin()+7}};
    result["verified"] = Value{std::uint64_t{pos >= phases.begin()+4}};
    Value summary{std::move(result)};
    apply_job_resolution(record, summary);
    return summary;
}
}
