#include "opensabba/file_restore_job.hpp"
#include <iostream>

int main() {
    using opensabba::pstream::Value;
    using opensabba::pstream::Error;
    try {
        Value::Object task;
        for (auto key : {"running_task_id","source_device_id","version_time","total_count","current_count",
                         "total_size","current_size","error_count","error_code","compression","encryption"})
            task[key] = Value{std::uint64_t{0}};
        task["running_task_id"] = Value{std::uint64_t{8}};
        task["source_device_id"] = Value{std::uint64_t{4}};
        for (auto key : {"device_name","task_name","target_path","source"}) task[key] = Value{std::string{}};
        task["destination"] = Value{std::filesystem::current_path().string()};
        task["conflict_handle"] = Value{std::string("overwrite")};
        task["selected_paths"] = Value{Value::Array{Value{std::string("/folder")}}};
        task["private_server_field"] = Value{std::string("never persist")};
        Value::Object running{{"id",Value{std::uint64_t{8}}},{"type",Value{std::uint64_t{1}}},
            {"task_id",Value{std::uint64_t{2}}},{"device_id",Value{std::uint64_t{3}}},
            {"version_id",Value{std::uint64_t{9}}},{"result_id",Value{std::uint64_t{5}}},
            {"file_restore_task",Value{task}}};
        const auto decoded = opensabba::file_restore_task(Value{running});
        const auto& fields = std::get<Value::Object>(decoded.data);
        if (fields.contains("private_server_field") || fields.size() != 18 ||
            std::get<std::uint64_t>(fields.at("compression").data) != 0)
            throw Error("restore parser failed allowlisting or changed explicit false flags");
        for (auto key : {"skip","compression"}) {
            for (const auto& false_value : {Value{},Value{std::uint64_t{0}}}) {
                const auto flags = opensabba::file_restore_record_flags(
                    Value{Value::Object{{key,false_value}}});
                if (flags.skip || flags.compression)
                    throw Error("null/zero record flags did not decode as false");
            }
            const auto flags = opensabba::file_restore_record_flags(
                Value{Value::Object{{key,Value{std::uint64_t{1}}}}});
            if (flags.skip != (std::string(key) == "skip") ||
                flags.compression != (std::string(key) == "compression"))
                throw Error("record flags did not preserve explicit true");
            for (const auto& bad : {Value{std::uint64_t{2}},Value{std::string("0")},
                                   Value{Value::Array{}},Value{opensabba::pstream::Bytes{}}}) {
                bool rejected = false;
                try { (void)opensabba::file_restore_record_flags(Value{Value::Object{{key,bad}}}); }
                catch (const Error&) { rejected = true; }
                if (!rejected) throw Error("invalid record flag accepted");
            }
        }
        const auto absent_flags = opensabba::file_restore_record_flags(Value{Value::Object{}});
        if (absent_flags.skip || absent_flags.compression)
            throw Error("absent record flags did not decode as false");
        Value::Object metadata{{"id",Value{std::uint64_t{10}}},{"path",Value{std::string("/fixture")}},
            {"uid",Value{std::uint64_t{0x1'0000'0007}}},{"mode",Value{std::uint64_t{0100640}}},
            {"acl",Value{std::string("ignored Synology ACL")}},
            {"xattrs",Value{Value::Object{{"security.capability",Value{opensabba::pstream::Bytes{1,2}}}}}}};
        const auto restored = std::get<Value::Object>(opensabba::file_restore_metadata(Value{metadata}).data);
        if (restored.size() != 7 || restored.at("uid") != Value{std::uint64_t{7}} ||
            restored.at("mode") != Value{std::uint64_t{0100640}} ||
            restored.at("gid") != Value{std::uint64_t{0xffffffff}} ||
            restored.at("atime") != Value{std::uint64_t{0xffffffff}} ||
            restored.at("mtime") != Value{std::uint64_t{0xffffffff}})
            throw Error("official optional uint32 metadata decoding or ignored extended fields differ");
        metadata["mtime"] = Value{std::uint64_t{0x1'6000'0001}};
        if (std::get<Value::Object>(opensabba::file_restore_metadata(Value{metadata}).data).at("mtime")
                != Value{std::uint64_t{0x60000001}})
            throw Error("official metadata timestamp was not decoded as uint32");
        metadata["mtime"] = Value{};
        if (std::get<Value::Object>(opensabba::file_restore_metadata(Value{metadata}).data).at("mtime")
                != Value{std::uint64_t{0}})
            throw Error("official explicitly null uint32 metadata was not decoded as zero");
        const opensabba::SavedAuth auth{"user","device","token","nas"};
        Value journal{Value::Object{{"schema",Value{std::uint64_t{2}}},
            {"ds_id",Value{auth.ds_id}},{"device_uuid",Value{auth.device_uuid}},{"username",Value{auth.username}},
            {"running_task_id",Value{std::uint64_t{8}}},{"running",Value{running}},
            {"phase",Value{std::string("download")}},{"done_ids",Value{Value::Array{}}},
            {"event_id",Value{std::uint64_t{0}}},{"task_uuid",Value{std::string("task")}},
            {"pending_logs",Value{Value::Array{}}},
            {"directories",Value{Value::Array{}}},{"completed_ids",Value{Value::Array{}}}}};
        const auto history = std::get<Value::Object>(opensabba::file_restore_job_status(journal,auth).data);
        if (history.at("task_id") != Value{std::uint64_t{2}} ||
            history.at("version_id") != Value{std::uint64_t{9}} ||
            history.at("result_id") != Value{std::uint64_t{5}} ||
            history.at("terminal") != Value{std::uint64_t{0}})
            throw Error("file restore history identity differs from its saved running task");
        auto reject = [&](const Value::Object& changed) {
            auto candidate = running;
            candidate["file_restore_task"] = Value{changed};
            try { (void)opensabba::file_restore_task(Value{candidate}); }
            catch (const Error&) { return; }
            throw Error("invalid restore task accepted");
        };
        auto changed = task;
        changed["running_task_id"] = Value{std::uint64_t{7}};
        reject(changed);
        changed = task; changed.erase("compression"); reject(changed);
        changed = task; changed["compression"] = Value{}; reject(changed);
        changed = task; changed["encryption"] = Value{std::uint64_t{2}}; reject(changed);
        changed = task; changed["destination"] = Value{std::string("relative")}; reject(changed);
        changed = task; changed["selected_paths"] = Value{Value::Array{Value{opensabba::pstream::Bytes{1}}}};
        reject(changed);
        changed = task; changed["source"] = Value{std::string("path\0suffix",11)}; reject(changed);
        changed = task; changed["conflict_handle"] = Value{std::string("invented")}; reject(changed);
        running["type"] = Value{std::uint64_t{0}};
        try { (void)opensabba::file_restore_task(Value{running}); }
        catch (const Error&) { return 0; }
        throw Error("backup run accepted as a restore");
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
