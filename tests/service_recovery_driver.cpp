#include "opensabba/service_backup.hpp"
#include "opensabba/snapshot_driver.hpp"
#include "opensabba/source_read.hpp"
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
using namespace opensabba;
using pstream::Value;
using pstream::Error;
namespace {
void check(bool condition) { if (!condition) throw Error("service recovery invariant failed"); }
std::string text(const Value& value, const char* key) {
    return std::get<std::string>(std::get<Value::Object>(value.data).at(key).data);
}
Value n(std::uint64_t value) { return Value{value}; }
}
int main(int argc, char** argv) {
#ifdef SIGPIPE
    std::signal(SIGPIPE,SIG_IGN);
#endif
    try {
        check(argc == 6);
        const std::string mode(argv[4]);
        Endpoint endpoint{"127.0.0.1",static_cast<std::uint16_t>(std::stoul(argv[1])),argv[2]};
        endpoint.backup_task_uuid = "test-task-uuid";
        endpoint.backup_app_aware = std::string_view(argv[5]) == "seed" && mode.starts_with("app-aware");
        const SavedAuth auth{"test-user","test-device","test-token","test-nas"};
        const opensabba::TaskView task_view{
            [&](const opensabba::Endpoint& connection) { return opensabba::tasks(connection,auth); },
            [&](const opensabba::Endpoint& connection) { return opensabba::running_tasks(connection,auth); }};
        const std::filesystem::path path(argv[3]);
        Value saved;
        const auto save = [&](const Value& record) {
            saved = pstream::decode(pstream::encode(record));
            std::ofstream output(path,std::ios::binary|std::ios::trunc);
            const auto bytes = pstream::encode(saved);
            output.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());
            output.close();
            check(output.good());
        };
        if (std::string_view(argv[5]) == "seed") {
            ImageSource source(pstream::Bytes(512,42));
            try {
                run_full_image_job(endpoint,auth,27,source,"test-image",pstream::Bytes{'{','}'},
                    [&](const Value& record) { saved = record; throw Error("seed"); });
            } catch (const Error& error) { check(std::string_view(error.what()) == "seed"); }
            auto& fields = std::get<Value::Object>(saved.data);
            fields["task_id"] = n(2);
            fields["phase"] = Value{mode.starts_with("app-aware") ? std::string("prepared") :
                mode == "metadata-resume" ? std::string("metadata") :
                mode == "timeout" || mode == "source-missing" || mode == "operation-error" || mode.starts_with("read-") ? std::string("upload") :
                mode == "active" || mode == "missing" ? std::string("prepare") :
                mode.starts_with("finish") ? std::string("finish") : mode};
            if (text(saved,"phase") != "prepare") {
                fields["version_id"] = n(9); fields["result_id"] = n(112);
                fields["data_format"] = n(mode == "app-aware-format2" ? 2 : 1);
            }
            if (mode == "timeout") fields["disconnect_start_time"] = n(std::time(nullptr)-1800);
            (void)backup_job_status(saved,auth);
            save(saved);
            return 0;
        }
        std::ifstream input(path,std::ios::binary);
        const pstream::Bytes bytes{std::istreambuf_iterator<char>(input),{}};
        auto journal = pstream::decode(bytes);
        if (mode == "active") {
            bool deferred = false;
            try { recover_service_backup(endpoint,auth,journal,save); }
            catch (const BackupRetry&) { deferred = true; }
            check(deferred && pstream::encode(journal) == bytes);
        } else {
            if (mode == "source-missing") fail_service_backup(endpoint,auth,journal,save,"/");
            else if (mode.starts_with("read-")) {
                unsigned attempts = 0, skipped = 0;
                const auto started = std::chrono::steady_clock::now();
                run_service_backup(endpoint,auth,task_view,2,journal,[&](const Value& record) {
                    journal = record; save(record);
                },[&](const Endpoint& transfer, const SaveBackupJob& persist) {
                    std::shared_ptr<SnapshotReader> reader;
#ifdef __linux__
                    if (const auto* identity_path = std::getenv("OPENSABBA_READ_IDENTITY")) {
                        std::ifstream identity_input(identity_path,std::ios::binary);
                        const pstream::Bytes data{std::istreambuf_iterator<char>(identity_input),{}};
                        reader = std::make_shared<SnapshotReader>(pstream::decode(data));
                    }
#endif
                    ImageSource source(8192,[&](auto at, auto length, auto*) -> pstream::Bytes {
                        ++attempts;
                        if (reader) {
                            try { return reader->read(at,length); }
                            catch (const SourceReadError& error) {
                                if (error.snapshot_error) {
                                    bool typed_health = false;
                                    try { reader->verify(); }
                                    catch (const SourceReadError& state) {
                                        typed_health = state.error == 5 && state.snapshot_error == error.snapshot_error;
                                    }
                                    check(typed_health);
                                }
                                throw;
                            }
                        }
                        if (mode == "read-eio-skip" && (at+length <= 512 || at >= 1024))
                            return pstream::Bytes(length,42);
                        throw SourceReadError(mode == "read-enodata" ? 61 : 5,
                            "/dev/synosnap0","/dev/source",at,512,
                            mode == "read-eio-fatal" ? -5 : mode == "read-cow" ? -27 : 0);
                    },[] {});
                    stream_image(source,"test-image",4096,[&](const Value& block) {
                        const auto& fields = std::get<Value::Object>(block.data);
                        if (!fields.contains("buffer")) {
                            check(std::get<std::uint64_t>(fields.at("offset").data) == 512 &&
                                std::get<std::uint64_t>(fields.at("length").data) == 512 &&
                                std::get<std::uint64_t>(fields.at("used").data) == 1 &&
                                std::get<std::uint64_t>(fields.at("changed").data) == 1 &&
                                std::get<std::uint64_t>(fields.at("changed_length").data) == 0);
                            ++skipped;
                        }
                    },transfer.cancelled,0,TransferCompression::none,nullptr,{}, {},{},transfer.source_read_activity);
                    check(mode == "read-eio-skip" && skipped == 1);
                    const auto outcome = finish_backup(transfer,auth,{27,9,112,1},BackupOutcome::complete,[] {});
                    check(outcome == BackupOutcome::complete);
                    // The image job owns a separate checkpoint record; a later
                    // save must retain activities appended by the read worker.
                    auto complete = pstream::decode(bytes);
                    std::get<Value::Object>(complete.data)["phase"] = Value{std::string("complete")};
                    persist(complete);
                });
                if (mode == "read-enodata") {
                    check(attempts == 31);
                    check(std::chrono::steady_clock::now()-started >= std::chrono::seconds{30});
                } else check(attempts == (mode == "read-eio-skip" ? 10U : 1U));
                const auto& fields = std::get<Value::Object>(journal.data);
                const auto log_count = std::get<Value::Array>(fields.at("source_read_logs").data).size();
                check(log_count == (mode == "read-eio-fatal" || mode == "read-cow" ? 2U : 1U) &&
                    std::get<std::uint64_t>(fields.at("source_read_logs_reported").data) == log_count);
            }
            else if (mode == "operation-error")
                run_service_backup(endpoint,auth,task_view,2,journal,[&](const Value& record) {
                    journal = record;
                    save(record);
                },[](const Endpoint&, const SaveBackupJob&) { throw Error("image read failed"); });
            else recover_service_backup(endpoint,auth,journal,save);
            const auto phase = text(backup_job_status(journal,auth),"phase");
            check(phase == (mode == "missing" ? "retired" : mode == "timeout" ? "cancel" :
                mode == "read-eio-skip" ? "complete" :
                mode == "source-missing" || mode == "operation-error" || mode.starts_with("read-") ? "error" : mode.starts_with("finish") ? "complete" : "metadata-accepted"));
            // Re-entry must not replay preparation/metadata/completion.
            recover_service_backup(endpoint,auth,journal,save);
        }
        check(run_queued_machine_capture(endpoint,task_view,2,28,
            [](const std::function<bool()>&) {}) == QueuedCaptureOutcome::complete);
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
