#include "opensabba/file_restore_job.hpp"
#include "opensabba/server_time.hpp"
#include <lz4.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <fstream>
#include <future>
#include <iostream>
#include <limits>
#include <mutex>
#include <map>
#include <openssl/rand.h>
#include <system_error>
#include <thread>
#ifndef _WIN32
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utime.h>
#endif

namespace opensabba {
namespace {
using pstream::Value;
using pstream::Error;
const Value::Object& object(const Value& value) {
    const auto* result = std::get_if<Value::Object>(&value.data);
    if (!result) throw Error("file restore value must be an object");
    return *result;
}
const Value& field(const Value& value, const char* key) {
    const auto& fields = object(value);
    if (!fields.contains(key)) throw Error(std::string("file restore missing ") + key);
    return fields.at(key);
}
std::uint64_t number(const Value& value, const char* key) {
    const auto* result = std::get_if<std::uint64_t>(&field(value,key).data);
    if (!result) throw Error(std::string("invalid file restore number: ") + key);
    return *result;
}
std::string text(const Value& value, const char* key) {
    const auto* result = std::get_if<std::string>(&field(value,key).data);
    if (!result || result->find('\0') != result->npos)
        throw Error(std::string("invalid file restore text: ") + key);
    return *result;
}
const Value::Array& array(const Value& value, const char* key) {
    const auto* result = std::get_if<Value::Array>(&field(value,key).data);
    if (!result) throw Error(std::string("invalid file restore array: ") + key);
    return *result;
}
bool flag(const Value& value, const char* key) {
    const auto result = number(value,key);
    if (result > 1) throw Error(std::string("invalid file restore boolean: ") + key);
    return result != 0;
}
bool record_flag(const Value& value, const char* key) {
    const auto& fields = object(value);
    const auto found = fields.find(key);
    // Map lookup returns the empty object for an absent member;
    // Null-to-boolean conversion is false. Keep the NAS's numeric flags restricted to 0/1.
    if (found == fields.end() || std::holds_alternative<std::monostate>(found->second.data))
        return false;
    return flag(value,key);
}
bool terminal(std::string_view status) {
    return status == "complete" || status == "partial" || status == "cancel" || status == "error";
}
void same_run(const Value& current, const Value& expected) {
    for (auto key : {"id","type","task_id","device_id","version_id","result_id"})
        if (number(current,key) != number(expected,key))
            throw Error("file restore running task identity changed");
    const auto fresh = file_restore_task(current);
    const auto saved = file_restore_task(expected);
    for (auto key : {"running_task_id","source_device_id","version_time","target_path","source",
                     "destination","selected_paths","encryption","compression","conflict_handle"})
        if (field(fresh,key) != field(saved,key)) throw Error("file restore task parameters changed");
}
enum class Observation { running, waiting, cancelled, server_error, absent };
Observation observe(const Endpoint& endpoint, const TaskView& view, const Value& expected) {
    bool found = false;
    auto state = Observation::absent;
    for (const auto& job : view.running(endpoint)) {
        if (number(job,"id") != number(expected,"id")) continue;
        if (found) throw Error("duplicate file restore running task");
        found = true;
        same_run(job,expected);
        const auto task = file_restore_task(job);
        const auto status = number(job,"status");
        if (number(task,"error_code")) state = Observation::server_error;
        else if (status == 3) state = Observation::cancelled;
        else if (status == 1 || (status == 2 && number(job,"detail_status") == 6))
            state = Observation::running;
        else state = Observation::waiting;
    }
    return state;
}
std::filesystem::path destination(const Value& file) {
    const auto path = std::filesystem::path(text(file,"path"));
    if (!path.is_absolute()) throw Error("file restore destination is not absolute");
    for (const auto& part : path)
        if (part == "..") throw Error("file restore destination contains parent traversal");
    return path;
}
bool path_exists(const std::filesystem::path& path) {
    return std::filesystem::symlink_status(path).type() != std::filesystem::file_type::not_found;
}
std::filesystem::path temporary_path(const std::filesystem::path& path) {
    std::array<unsigned char,6> bytes{};
    if (RAND_bytes(bytes.data(),static_cast<int>(bytes.size())) != 1)
        throw Error("cannot generate file restore temporary name");
    constexpr char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
    std::string name = "ActiveBackupTemp_";
    for (std::size_t i = 0; i != bytes.size(); i += 3) {
        name += alphabet[bytes[i] >> 2];
        name += alphabet[((bytes[i] & 3) << 4) | (bytes[i+1] >> 4)];
        name += alphabet[((bytes[i+1] & 15) << 2) | (bytes[i+2] >> 6)];
        name += alphabet[bytes[i+2] & 63];
    }
    return path.parent_path() / name;
}
void durable(const std::filesystem::path& path, bool directory = false) {
#ifndef _WIN32
    const auto fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | (directory ? O_DIRECTORY : O_NOFOLLOW));
    if (fd < 0) throw std::system_error(errno,std::generic_category(),"open file restore checkpoint");
    const auto result = fsync(fd);
    const auto error = errno;
    close(fd);
    if (result) throw std::system_error(error,std::generic_category(),"persist file restore checkpoint");
#else
    (void)path; (void)directory;
#endif
}
void metadata(const Value& file) {
    const auto values = file_restore_metadata(file);
    const auto path = destination(values);
#ifndef _WIN32
    if (chown(path.c_str(),static_cast<uid_t>(number(values,"uid")),static_cast<gid_t>(number(values,"gid"))))
        throw std::system_error(errno,std::generic_category(),"restore file owner");
    if (chmod(path.c_str(),static_cast<mode_t>(number(values,"mode"))))
        throw std::system_error(errno,std::generic_category(),"restore file mode");
    utimbuf times{static_cast<time_t>(number(values,"atime")),static_cast<time_t>(number(values,"mtime"))};
    if (utime(path.c_str(),&times))
        throw std::system_error(errno,std::generic_category(),"restore file timestamps");
#endif
}
Value saved_metadata(const Value& file) {
    Value::Object saved;
    // Only the last chunk carries metadata. Earlier checkpoints need the
    // identity alone, and must not require fields the NAS has not sent yet.
    for (auto key : {"id","path"}) saved.emplace(key,field(file,key));
    for (auto key : {"uid","gid","mode","atime","mtime"})
        if (object(file).contains(key)) saved.emplace(key,field(file,key));
    return Value{std::move(saved)};
}
struct SkipItem {};
struct ParentConflict { std::filesystem::path path; bool missing; };
void parents(const std::filesystem::path& path, bool skip) {
    const auto parent = path.parent_path();
    const auto state = std::filesystem::symlink_status(parent);
    if (std::filesystem::is_directory(state)) return;
    if (skip) throw SkipItem{};
    throw ParentConflict{parent,state.type() == std::filesystem::file_type::not_found};
}
// JSON text goes to the NAS, so retain UTF-8 filename bytes. The diagnostic
// display serializer intentionally escapes those bytes for terminal output.
std::string activity_json(const Value::Object& values) {
    const auto quote = [](std::string_view value) {
        std::string result = "\"";
        constexpr char digits[] = "0123456789abcdef";
        for (const unsigned char ch : value) {
            if (ch == '"' || ch == '\\') { result += '\\'; result += static_cast<char>(ch); }
            else if (ch < 0x20) {
                result += "\\u00"; result += digits[ch >> 4]; result += digits[ch & 15];
            } else result += static_cast<char>(ch);
        }
        return result+'"';
    };
    std::string result = "{";
    for (const auto& [key,value] : values) {
        if (result.size() != 1) result += ',';
        result += quote(key)+':';
        if (const auto* integer = std::get_if<std::uint64_t>(&value.data)) result += std::to_string(*integer);
        else result += quote(std::get<std::string>(value.data));
    }
    return result+'}';
}
void queue_activity(Value& journal, std::uint64_t type, Value::Object parameters, bool upload = true) {
    auto& fields = std::get<Value::Object>(journal.data);
    const auto& running = field(journal,"running");
    parameters["id"] = field(journal,"event_id");
    parameters["running_task_id"] = field(journal,"running_task_id");
    parameters["task_id"] = field(running,"task_id");
    parameters["task_uuid"] = field(journal,"task_uuid");
    parameters["result_id"] = field(running,"result_id");
    Value entry{Value::Object{{"log_type",Value{type}},{"log_time",Value{server_time_now()}},
        {"other_params",Value{activity_json(parameters)}}}};
    if (upload) std::get<Value::Array>(fields.at("pending_logs").data).push_back(std::move(entry));
    else {
        // The official agent source-error activity (6018) is local only: its call to
        // Local source-error reporting explicitly disables result-detail upload.
        std::clog << "File restore activity " << type << ": " << text(entry,"other_params") << '\n';
        fields["last_local_log"] = std::move(entry);
    }
}
// The handler snapshots this map without holding the writer while the request
// is in flight. Only IDs from that snapshot are removed on a received reply.
class RestoreAcknowledgements {
    std::mutex mutex_;
    std::map<std::uint64_t,std::uint64_t> pending_;
public:
    void add(std::uint64_t id, std::uint64_t error) {
        std::lock_guard lock(mutex_);
        pending_[id] = error;
    }
    Value::Array snapshot() {
        std::lock_guard lock(mutex_);
        Value::Array result;
        for (const auto& [id,error] : pending_)
            result.push_back(Value{Value::Object{{"id",Value{id}},{"error",Value{error}}}});
        return result;
    }
    void flush(const Endpoint& endpoint, const SavedAuth& auth, std::uint64_t run) {
        const auto sent = snapshot();
        if (sent.empty()) return;
        try { acknowledge_restore_files(endpoint,auth,run,sent); }
        catch (const TransportError&) { return; }
        catch (const ServerError&) { return; } // Connection/identity preflight, before the ACK.
        std::lock_guard lock(mutex_);
        for (const auto& entry : sent) pending_.erase(number(entry,"id"));
    }
};
// NAS files arrive in record order; the single in-flight writer keeps at most
// one uncompressed 32 MiB chunk, while retaining directory metadata separately.
class Writer {
    Value& journal_;
    const SaveBackupJob& save_;
    const Endpoint& endpoint_;
    bool skip_;
    RestoreAcknowledgements& acknowledgements_;
    std::filesystem::path prefix_;
    Value::Object& fields() { return std::get<Value::Object>(journal_.data); }
    Value::Array& done() { return std::get<Value::Array>(fields().at("done_ids").data); }
    Value::Array& directories() { return std::get<Value::Array>(fields().at("directories").data); }
    std::filesystem::path target(const Value& file) const {
        const auto path = destination(file);
        const auto relative = path.lexically_relative(prefix_);
        if (relative.empty() || *relative.begin() == "..")
            throw Error("file restore record is outside the requested destination");
        return path;
    }
    void acknowledge(std::uint64_t id, std::uint64_t error) {
        auto& completed = std::get<Value::Array>(fields().at("completed_ids").data);
        if (std::any_of(completed.begin(),completed.end(),
            [&](const Value& entry) { return std::get<std::uint64_t>(entry.data) == id; })) return;
        completed.push_back(Value{id});
        done().push_back(Value{Value::Object{{"id",Value{id}},{"error",Value{error}}}});
        acknowledgements_.add(id,error);
        fields()["current_count"] = Value{number(journal_,"current_count")+1};
        save_(journal_);
    }
    void activity(const Value& file, std::uint64_t type, Value::Object extra = {}, bool upload = true) {
        extra["path"] = field(file,"path");
        queue_activity(journal_,type,std::move(extra),upload);
        save_(journal_);
    }
    void complete(const Value& file, std::uint64_t error, std::uint64_t log, Value::Object extra = {}) {
        activity(file,log,std::move(extra));
        acknowledge(number(file,"id"),error);
    }
    void partial_reset() {
        if (fields().contains("partial")) {
            const auto temp = std::filesystem::path(text(fields().at("partial"),"temp_path"));
            std::filesystem::remove(temp);
            const auto progress = number(fields().at("partial"),"progress");
            const auto current = number(journal_,"current_size");
            if (current < progress) throw Error("invalid file restore byte checkpoint");
            fields()["current_size"] = Value{current-progress};
            fields().erase("partial");
            save_(journal_);
        }
    }
    void restore_metadata(const Value& file) {
        try { metadata(file); }
        catch (const std::system_error& error) {
            // the official agent logs metadata failures independently of content success.
            fields()["last_metadata_error"] = Value{std::string(error.what())};
            activity(file,6019);
        }
    }
    void install(const Value& file, const std::filesystem::path& temp) {
        const auto path = target(file);
        // The destination can appear while the download runs. Recheck at
        // installation before removing or replacing it.
        const bool exists = path_exists(path);
        if (!skip_ || !exists) {
            if (exists) std::filesystem::remove_all(path);
            std::error_code error;
            std::filesystem::rename(temp,path,error);
            if (error) {
                std::filesystem::copy_file(temp,path);
                durable(path);
                std::filesystem::remove(temp);
            }
            restore_metadata(file);
        } else std::filesystem::remove(temp);
        durable(path.parent_path(),true);
        fields().erase("partial");
        complete(file,0,skip_ && exists ? 6004 : exists ? 6005 : 6003);
    }
    void write_file(const Value& file, bool compression) {
        const auto id = number(file,"id"), size = number(file,"size");
        const auto offset = number(file,"offset"), length = number(file,"length");
        if (length > 32*1024*1024 || offset > size || length > size-offset ||
            size > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max()))
            throw Error("invalid file restore chunk range");
        const auto path = target(file);
        parents(path,skip_);
        if (skip_ && path_exists(path)) {
            if (fields().contains("partial") && text(fields().at("partial"),"path") == path.string())
                partial_reset();
            complete(file,0,6004);
            return;
        }
        const auto* buffer = std::get_if<pstream::Bytes>(&field(file,"buffer").data);
        if (!buffer) throw Error("file restore chunk is missing its binary buffer");
        pstream::Bytes decoded;
        auto bytes = std::span<const std::uint8_t>(*buffer);
        if (compression) {
            if (buffer->size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
                throw Error("compressed file restore chunk exceeds LZ4 limits");
            decoded.resize(static_cast<std::size_t>(length));
            const auto count = LZ4_decompress_safe(reinterpret_cast<const char*>(buffer->data()),
                reinterpret_cast<char*>(decoded.data()),static_cast<int>(buffer->size()),static_cast<int>(length));
            if (count < 0 || static_cast<std::uint64_t>(count) != length)
                throw Error("file restore LZ4 decoded length mismatch");
            bytes = decoded;
        } else if (buffer->size() != length) throw Error("file restore buffer length mismatch");
        if (!fields().contains("partial")) {
            if (offset) throw Error("file restore starts after an unsaved prefix");
            const auto temp = temporary_path(path);
            if (path_exists(temp)) throw Error("unowned file restore temporary path already exists");
#ifndef _WIN32
            const auto fd = open(temp.c_str(),O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,0600);
            if (fd < 0) throw std::system_error(errno,std::generic_category(),"create file restore temporary file");
            close(fd);
#else
            std::ofstream created(temp,std::ios::binary);
            if (!created) throw std::system_error(std::make_error_code(std::errc::io_error),"create restore temporary file");
#endif
            fields()["partial"] = Value{Value::Object{{"path",Value{path.string()}},
                {"temp_path",Value{temp.string()}},{"id",Value{id}},{"size",Value{size}},
                {"progress",Value{std::uint64_t{0}}},{"metadata",saved_metadata(file)}}};
            save_(journal_);
        }
        auto& partial = fields().at("partial");
        if (text(partial,"path") != path.string() || number(partial,"id") != id ||
            number(partial,"size") != size || number(partial,"progress") != offset)
            throw Error("file restore chunk differs from its saved partial record");
        const auto temp = std::filesystem::path(text(partial,"temp_path"));
#ifndef _WIN32
        const auto fd = open(temp.c_str(),O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) throw std::system_error(errno,std::generic_category(),"open restore temporary file");
        struct Close { int fd; ~Close() { close(fd); } } close_file{fd};
        struct stat state{};
        if (fstat(fd,&state) || !S_ISREG(state.st_mode) || state.st_size < 0 ||
            static_cast<std::uint64_t>(state.st_size) != offset)
            throw Error("file restore temporary file length changed");
        auto remaining = bytes;
        auto position = offset;
        while (!remaining.empty()) {
            if (endpoint_.cancelled && endpoint_.cancelled()) throw Cancelled();
            const auto count = pwrite(fd,remaining.data(),remaining.size(),static_cast<off_t>(position));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) throw std::system_error(errno,std::generic_category(),"write restore temporary file");
            position += static_cast<std::uint64_t>(count);
            remaining = remaining.subspan(static_cast<std::size_t>(count));
        }
        if (fsync(fd)) throw std::system_error(errno,std::generic_category(),"persist restore temporary file");
#else
        std::fstream output(temp,std::ios::binary | std::ios::in | std::ios::out);
        if (!output) throw std::system_error(std::make_error_code(std::errc::io_error),"open restore temporary file");
        output.seekp(static_cast<std::streamoff>(offset));
        output.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));
        output.flush();
        if (!output) throw std::system_error(std::make_error_code(std::errc::io_error),"write restore temporary file");
        output.close();
        durable(temp);
#endif
        durable(temp.parent_path(),true);
        std::get<Value::Object>(partial.data)["progress"] = Value{offset+length};
        std::get<Value::Object>(partial.data)["metadata"] = saved_metadata(file);
        fields()["current_size"] = Value{number(journal_,"current_size")+length};
        save_(journal_);
        if (offset+length != size) return;
        install(file,temp);
    }
public:
    Writer(Value& journal, const SaveBackupJob& save, const Endpoint& endpoint, bool skip,
           RestoreAcknowledgements& acknowledgements)
        : journal_(journal),save_(save),endpoint_(endpoint),skip_(skip), acknowledgements_(acknowledgements),
          prefix_(std::filesystem::path(text(field(field(journal,"running"),"file_restore_task"),
                                            "destination")).lexically_normal()) {}
    std::optional<Value> resume() {
        if (!fields().contains("partial")) return {};
        const auto& partial = fields().at("partial");
        const auto path = target(partial);
        const auto temp = std::filesystem::path(text(partial,"temp_path"));
        if (!number(partial,"id") || number(partial,"progress") > number(partial,"size") ||
            temp.parent_path() != path.parent_path() ||
            !temp.filename().string().starts_with("ActiveBackupTemp_"))
            throw Error("invalid file restore temporary checkpoint");
        if (!std::filesystem::is_regular_file(std::filesystem::symlink_status(temp)) ||
            std::filesystem::file_size(temp) != number(partial,"progress")) {
            partial_reset();
            return {};
        }
        if (number(partial,"progress") == number(partial,"size")) {
            const auto file = field(partial,"metadata");
            if (text(file,"path") != path.string() || number(file,"id") != number(partial,"id"))
                throw Error("file restore completion metadata differs from checkpoint");
            install(file,temp);
            return {};
        }
        return Value{Value::Object{{"path",field(partial,"path")},{"progress",field(partial,"progress")}}};
    }
    void receive(const Value& file) {
        if (endpoint_.cancelled && endpoint_.cancelled()) throw Cancelled();
        const auto id = number(file,"id"), type = number(file,"file_type");
        if (!id) throw Error("invalid file restore record ID");
        const auto& completed = std::get<Value::Array>(fields().at("completed_ids").data);
        if (std::any_of(completed.begin(),completed.end(),
            [&](const Value& entry) { return std::get<std::uint64_t>(entry.data) == id; })) return;
        if (type == 2 || type == 9998 || type == 9999) {
            if (type == 2) {
                partial_reset();
                fields()["last_source_error"] = field(file,"error_code");
                const auto& error = field(file,"error_code");
                const auto code = std::holds_alternative<std::string>(error.data) ? text(file,"error_code")
                    : std::to_string(number(file,"error_code"));
                activity(file,6018,{{"error_code",Value{code}}},false);
                acknowledge(id,1);
            } else {
                complete(file,2,type == 9998 ? 6021 : 6011);
            }
            return;
        }
        if (type != 0 && type != 1) throw Error("unknown file restore record type");
        const auto flags = file_restore_record_flags(file);
        target(file);
        if (flags.skip) {
            if (fields().contains("partial") && number(fields().at("partial"),"id") == id) partial_reset();
            complete(file,0,6004);
            return;
        }
        try {
            if (type == 0) write_file(file,flags.compression);
            else {
                const auto path = target(file);
                parents(path,skip_);
                const bool exists = path_exists(path);
                if (skip_ && exists) { complete(file,0,6004); return; }
                const bool replace = exists && !std::filesystem::is_directory(std::filesystem::symlink_status(path));
                if (replace)
                    std::filesystem::remove_all(path);
                std::filesystem::create_directory(path);
                const auto found = std::find_if(directories().begin(),directories().end(),
                    [&](const Value& entry) { return number(entry,"id") == id; });
                if (found == directories().end()) directories().push_back(saved_metadata(file));
                complete(file,0,replace ? 6005 : 6003);
            }
        } catch (const SkipItem&) {
            if (fields().contains("partial") && number(fields().at("partial"),"id") == id) partial_reset();
            complete(file,0,6004);
        } catch (const ParentConflict& error) {
            fields()["last_record_error"] = Value{std::string(error.missing
                ? "restore parent does not exist" : "restore parent is not a directory")};
            if (fields().contains("partial") && number(fields().at("partial"),"id") == id) partial_reset();
            complete(file,1,error.missing ? 6015 : 6016,{{"parent_path",Value{error.path.string()}}});
        } catch (const std::system_error& error) {
            fields()["last_record_error"] = Value{std::string(error.what())};
            if (fields().contains("partial") && number(fields().at("partial"),"id") == id) partial_reset();
            complete(file,1,6006);
        }
    }
    void finish_directories() {
        while (!directories().empty()) {
            const auto entry = directories().back();
            restore_metadata(entry);
            directories().pop_back();
            save_(journal_);
        }
    }
};
}

FileRestoreRecordFlags file_restore_record_flags(const Value& file) {
    return {record_flag(file,"skip"),record_flag(file,"compression")};
}
Value file_restore_metadata(const Value& file) {
    const auto& fields = object(file);
    Value::Object result;
    for (auto key : {"id","path"}) result.emplace(key,field(file,key));
    for (auto key : {"uid","gid","mode","atime","mtime"}) {
        const auto found = fields.find(key);
        const auto value = found == fields.end() ? std::numeric_limits<std::uint32_t>::max()
            : std::holds_alternative<std::monostate>(found->second.data) ? std::uint32_t{0}
            : static_cast<std::uint32_t>(number(file,key));
        result.emplace(key,Value{static_cast<std::uint64_t>(value)});
    }
    return Value{std::move(result)};
}

Value file_restore_task(const Value& running) {
    if (number(running,"type") != 1 || !number(running,"id"))
        throw Error("file restore requires a type-1 running task");
    for (auto key : {"task_id","device_id","version_id","result_id"})
        if (!number(running,key)) throw Error("file restore requires complete running task identity");
    const auto& task = field(running,"file_restore_task");
    Value::Object selected;
    for (auto key : {"running_task_id","source_device_id","version_time","total_count","current_count",
                     "total_size","current_size","error_count","error_code"}) {
        (void)number(task,key);
        selected.emplace(key,field(task,key));
    }
    if (number(task,"running_task_id") != number(running,"id") || !number(task,"source_device_id"))
        throw Error("file restore nested running task identity differs");
    for (auto key : {"device_name","task_name","target_path","source","destination","conflict_handle"}) {
        (void)text(task,key);
        selected.emplace(key,field(task,key));
    }
    const auto conflict = text(task,"conflict_handle");
    if (conflict != "overwrite" && conflict != "skip") throw Error("unsupported file restore conflict handling");
    if (!std::filesystem::path(text(task,"destination")).is_absolute())
        throw Error("file restore destination prefix must be absolute");
    for (auto key : {"encryption","compression"}) {
        (void)flag(task,key);
        selected.emplace(key,field(task,key));
    }
    for (const auto& path : array(task,"selected_paths")) {
        const auto* name = std::get_if<std::string>(&path.data);
        if (!name || name->find('\0') != name->npos) throw Error("invalid selected file restore path");
    }
    selected.emplace("selected_paths",field(task,"selected_paths"));
    return Value{std::move(selected)};
}

Value file_restore_job_status(const Value& journal, const SavedAuth& auth) {
    const auto& running = field(journal,"running");
    (void)file_restore_task(running);
    if (number(journal,"running_task_id") != number(running,"id") ||
        text(journal,"ds_id") != auth.ds_id || text(journal,"device_uuid") != auth.device_uuid ||
        text(journal,"username") != auth.username)
        throw Error("file restore journal belongs to a different run, NAS, device or account");
    (void)array(journal,"done_ids"); (void)array(journal,"directories");
    (void)number(journal,"event_id"); (void)text(journal,"task_uuid");
    for (const auto& log : array(journal,"pending_logs")) {
        (void)number(log,"log_type"); (void)number(log,"log_time"); (void)text(log,"other_params");
    }
    for (const auto& id : array(journal,"completed_ids"))
        if (!std::get_if<std::uint64_t>(&id.data)) throw Error("invalid completed file restore ID");
    const auto phase = text(journal,"phase");
    if (!terminal(phase) && phase != "planned" && phase != "download" && phase != "finish" &&
        phase != "cancel-pending" && phase != "server-error") throw Error("unknown file restore journal phase");
    return Value{Value::Object{{"task_id",field(running,"task_id")},
        {"version_id",field(running,"version_id")},{"result_id",field(running,"result_id")},
        {"running_task_id",field(journal,"running_task_id")},{"phase",Value{phase}},
        {"terminal",Value{std::uint64_t{terminal(phase)}}}}};
}

std::string run_service_file_restore(const Endpoint& endpoint, const SavedAuth& auth, const TaskView& view,
    const Value& running, std::optional<Value> previous, const SaveBackupJob& publish) {
    if (!publish) throw Error("file restore requires a progress observer");
    const auto& save = publish;
    const auto task = file_restore_task(running);
    if (!previous && file_restore_device(endpoint,auth) != number(running,"device_id"))
        throw Error("file restore destination is not the saved device");
    const auto run = number(running,"id");
    std::string task_uuid;
    if (!previous && number(task,"source_device_id") == number(running,"device_id")) {
        bool found = false;
        for (const auto& candidate : view.tasks(endpoint)) {
            if (number(candidate,"id") != number(running,"task_id")) continue;
            if (found) throw Error("duplicate file restore source task");
            task_uuid = text(candidate,"task_uuid");
            found = true;
        }
        if (!found) throw Error("file restore source task is not available on the destination device");
    }
    static std::atomic_uint64_t next_event{0};
    Value::Object bound;
    for (auto key : {"id","type","task_id","device_id","version_id","result_id","job_id","bandwidth",
                     "create_time","start_time","trigger_uid","status","detail_status"})
        if (object(running).contains(key)) {
            (void)number(running,key);
            bound.emplace(key,field(running,key));
        }
    bound["file_restore_task"] = task;
    Value journal{Value::Object{{"ds_id",Value{auth.ds_id}},
        {"device_uuid",Value{auth.device_uuid}},{"username",Value{auth.username}},
        {"running_task_id",Value{run}},{"running",Value{std::move(bound)}},{"phase",Value{std::string("planned")}},
        {"done_ids",Value{Value::Array{}}},{"completed_ids",Value{Value::Array{}}},
        {"directories",Value{Value::Array{}}},
        {"event_id",Value{previous ? number(*previous,"event_id") : next_event.fetch_add(1)}},
        {"task_uuid",Value{task_uuid}},{"pending_logs",Value{Value::Array{}}},
        {"current_count",field(task,"current_count")},{"current_size",field(task,"current_size")}}};
    if (previous) {
        (void)file_restore_job_status(*previous,auth);
        same_run(field(*previous,"running"),running);
        journal = *previous;
        if (!terminal(text(journal,"phase"))) {
            // The worker constructs a new handler/context on each attempt.
            // Only the manager's partial-file and activity queues survive.
            auto& resumed = std::get<Value::Object>(journal.data);
            for (const auto* key : {"done_ids","completed_ids","directories"})
                resumed[key] = Value{Value::Array{}};
        }
    }
    auto& fields = std::get<Value::Object>(journal.data);
    auto persist = [&](std::string phase) { fields["phase"] = Value{std::move(phase)}; save(journal); };
    const auto flush_logs = [&] {
        auto& pending = std::get<Value::Array>(fields.at("pending_logs").data);
        while (!pending.empty()) {
            const auto entry = pending.front();
            try {
                // The existing result-detail transport is identical for script
                // and file-restore activity records.
                report_script_activity(endpoint,auth,run,number(entry,"log_type"),
                    number(entry,"log_time"),text(entry,"other_params"));
            } catch (const TransportError& error) {
                fields["log_report_error"] = Value{std::string(error.what())};
                save(journal);
                return;
            } catch (const ServerError& error) {
                fields["log_report_error"] = Value{std::string(error.what())};
                save(journal);
                return;
            }
            pending.erase(pending.begin());
            fields.erase("log_report_error");
            save(journal);
        }
    };
    flush_logs();
    auto reconcile = [&]() {
        const auto result = restore_result(endpoint,auth,number(running,"task_id"),number(running,"result_id"));
        if (!terminal(result)) throw Error("file restore outcome is still incomplete; retained exact run for reconciliation");
        persist(result);
        return result;
    };
    const auto phase = text(journal,"phase");
    if (terminal(phase)) return phase;
    if (phase == "cancel-pending" || phase == "server-error") return reconcile();
    if (phase != "planned" && phase != "download" && phase != "finish") throw Error("unknown file restore journal phase");
    save(journal);
    std::atomic<Observation> observed{observe(endpoint,view,running)};
    RestoreAcknowledgements acknowledgements;
    if (observed == Observation::waiting) return "waiting";
    if (observed != Observation::running) {
        persist(observed == Observation::cancelled ? "cancel-pending" : "server-error");
        return reconcile();
    }
    std::atomic_bool finished{false}, interrupted{false};
    std::mutex mutex;
    std::condition_variable changed;
    std::exception_ptr observer_error;
    auto control = endpoint;
    control.timeout = std::chrono::seconds{5};
    control.cancelled = [&] { return finished || (endpoint.cancelled && endpoint.cancelled()); };
    auto transfer = endpoint;
    transfer.cancelled = [&] { return interrupted || (endpoint.cancelled && endpoint.cancelled()); };
    std::thread observer([&] {
        try {
            std::unique_lock lock(mutex);
            while (!finished) {
                if (changed.wait_for(lock,std::chrono::seconds{5},[&] { return finished.load(); })) break;
                lock.unlock();
                const auto state = observe(control,view,running);
                lock.lock();
                if (state != Observation::running) { observed = state; interrupted = true; break; }
            }
        } catch (...) {
            if (!finished) { observer_error = std::current_exception(); interrupted = true; }
        }
    });
    std::exception_ptr failure, acknowledgement_error;
    std::atomic_bool pipeline_finished{false}, pipeline_aborted{false};
    auto ack_endpoint = endpoint;
    ack_endpoint.timeout = std::chrono::seconds{10};
    std::thread reporter([&] {
        try {
            for (;;) {
                std::this_thread::sleep_for(std::chrono::milliseconds{300});
                const bool stopped = pipeline_finished.load();
                if (pipeline_aborted || observed != Observation::running || transfer.cancelled()) {
                    if (stopped) break;
                    continue;
                }
                acknowledgements.flush(ack_endpoint,auth,run);
                if (stopped) {
                    acknowledgements.flush(ack_endpoint,auth,run);
                    break;
                }
            }
        } catch (...) { acknowledgement_error = std::current_exception(); interrupted = true; }
    });
    bool disconnected = false, nas_error = false;
    try {
        Writer writer(journal,save,transfer,text(task,"conflict_handle") == "skip",acknowledgements);
        const auto resume = writer.resume();
        persist("download");
        download_restore_files(transfer,auth,run,resume,[&](const Value& file) {
            writer.receive(file);
            flush_logs();
        },[&](const Value& request, const std::function<void()>& alive) {
            if (text(task,"conflict_handle") != "skip") throw Error("unexpected file restore skip precheck");
            if (text(request,"destination") != text(task,"destination"))
                throw Error("file restore precheck destination changed");
            alive();
            auto checking = std::async(std::launch::async,[&] {
                Value::Array paths;
                for (const auto& candidate : array(request,"paths")) {
                    if (transfer.cancelled()) throw Cancelled();
                    const auto* path = std::get_if<std::string>(&candidate.data);
                    if (!path || path->find('\0') != path->npos) throw Error("invalid file restore precheck path");
                    auto prefix = text(request,"destination");
                    if (prefix == "/") prefix.clear();
                    if (path_exists(std::filesystem::path(prefix+*path))) paths.push_back(candidate);
                }
                return paths;
            });
            while (checking.wait_for(std::chrono::seconds{1}) != std::future_status::ready) alive();
            return checking.get();
        });
        if (transfer.cancelled()) throw Cancelled();
        if (fields.contains("partial")) throw Error("file restore stream ended with an incomplete file");
        writer.finish_directories();
        while (!array(journal,"pending_logs").empty()) {
            if (transfer.cancelled()) throw Cancelled();
            flush_logs();
            if (!array(journal,"pending_logs").empty())
                std::this_thread::sleep_for(std::chrono::milliseconds{300});
        }
    } catch (const TransportError&) { disconnected = true; failure = std::current_exception(); }
    catch (const Cancelled&) { failure = std::current_exception(); }
    catch (const ServerError&) { nas_error = true; failure = std::current_exception(); }
    catch (...) { failure = std::current_exception(); }
    pipeline_aborted = static_cast<bool>(failure);
    pipeline_finished = true;
    reporter.join();
    fields["done_ids"] = Value{acknowledgements.snapshot()};
    {
        std::lock_guard lock(mutex);
        finished = true;
    }
    changed.notify_all();
    observer.join();
    save(journal);
    // Ack requests use the control endpoint after closing the data channel.
    if (observed != Observation::running || nas_error) {
        if (observed == Observation::waiting && !nas_error) return "waiting";
        if (fields.contains("partial")) {
            std::filesystem::remove(std::filesystem::path(text(fields.at("partial"),"temp_path")));
            fields.erase("partial");
        }
        persist(observed == Observation::cancelled ? "cancel-pending" : "server-error");
        return reconcile();
    }
    if (observer_error) std::rethrow_exception(observer_error);
    if (acknowledgement_error) std::rethrow_exception(acknowledgement_error);
    if ((endpoint.cancelled && endpoint.cancelled()) || disconnected) {
        if (failure) std::rethrow_exception(failure);
        throw Cancelled();
    }
    if (failure) {
        try { std::rethrow_exception(failure); }
        catch (const Cancelled&) { throw; }
        catch (const std::exception& error) { fields["local_error"] = Value{std::string(error.what())}; }
    }
    const auto outcome = finish_file_restore(endpoint,auth,run,failure ? "error" : "complete",
                                             [&] { persist("finish"); });
    persist(outcome);
    return outcome;
}
}
