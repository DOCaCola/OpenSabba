#include "image_delta_fixture.hpp"
#include "opensabba/service_backup.hpp"
#include "opensabba/capture.hpp"
#include "opensabba/task_policy.hpp"
#include "opensabba/backup_job.hpp"
#include <iostream>
#include <thread>
#include <atomic>
#include <array>
#include <algorithm>
#include <csignal>
#include <openssl/evp.h>

int main(int argc, char** argv) {
    using namespace opensabba;
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN); // Report peer disconnects as transport errors.
#endif
    try {
        if (argc != 4) throw pstream::Error("invalid test arguments");
        std::string mode(argv[3]);
        const bool direct = mode.starts_with("direct-");
        if (direct) mode.erase(0,7);
        std::atomic_bool shutdown{false};
        bool entered = false, rejected = false;
        auto outcome = QueuedCaptureOutcome::complete;
        Endpoint endpoint{"127.0.0.1",static_cast<std::uint16_t>(std::stoul(argv[1])),argv[2],std::chrono::seconds{2},
            [&] { return shutdown.load(); }};
        const SavedAuth auth{"test-user","test-device","test-token","test-nas"};
        const opensabba::TaskView task_view{
            [&](const opensabba::Endpoint& connection) { return opensabba::tasks(connection,auth); },
            [&](const opensabba::Endpoint& connection) { return opensabba::running_tasks(connection,auth); }};
        if (mode == "base-selection") {
            for (const auto expected : {0U,0U,0U,0U,0U,103U,103U,UINT32_MAX})
                if (backup_base_version(endpoint,auth,2) != expected)
                    throw pstream::Error("official base-version conversion differs");
            return 0;
        }
        if (mode.starts_with("single-unused")) {
            constexpr std::size_t mib = 1024*1024;
            if (mode.ends_with("prepared"))
                endpoint.prepared_backup = PreparedBackup{prepare_full_backup(endpoint,auth,27,[] {}),0};
            const bool allocation = mode.ends_with("allocation");
            const bool incremental = mode.ends_with("incremental") || allocation;
            pstream::Bytes bytes(5*mib,0xa5);
            std::fill(bytes.begin()+mib,bytes.begin()+3*mib,0);
            ImageSource source(bytes);
            const std::vector<ChangedExtent> unused{{mib,2*mib}};
            IncrementalBackup info{8,13,26,std::string(32,'a'),std::string(64,'b'),
                DeltaPlan{5*mib,2*mib,{{0,mib,true},{mib,3*mib,false},{4*mib,mib,true}}}};
            info.plan.filesystem_allocation = allocation;
            pstream::Value saved;
            const auto save = [&](const pstream::Value& record) {
                saved = record;
                std::get<pstream::Value::Object>(saved.data)["task_id"] =
                    pstream::Value{std::uint64_t{2}};
            };
            try {
                const pstream::Bytes metadata{'{','}'};
                if (incremental) run_incremental_image_job(endpoint,auth,2,27,source,
                    "single-disk",metadata,info,save,TransferCompression::none,unused);
                else run_full_image_job(endpoint,auth,27,source,"single-disk",metadata,save,
                    BackupOutcome::complete,TransferCompression::none,unused);
                throw pstream::Error("interrupted unused upload unexpectedly completed");
            } catch (const pstream::Error& error) {
                if (std::string_view(error.what()).find("unexpectedly completed") != std::string_view::npos)
                    throw;
            }
            const auto& fields = std::get<pstream::Value::Object>(saved.data);
            if (std::get<std::uint64_t>(fields.at("schema").data) != (incremental ? 9U : 8U) ||
                std::get<std::string>(fields.at("phase").data) != "upload" ||
                std::get<pstream::Value::Array>(fields.at("unused_ranges").data).size() != 1)
                throw pstream::Error("single-image unused journal was not retained");
            (void)backup_job_status(saved,auth);
            if (resume_image_job(endpoint,auth,source,saved,save,unused) != BackupOutcome::complete)
                throw pstream::Error("single-image unused resume did not complete");
            const auto& final = std::get<pstream::Value::Object>(saved.data);
            if (std::get<std::uint64_t>(final.at("resume_offset").data) != 2*mib+512 ||
                std::get<std::string>(final.at("phase").data) != "complete")
                throw pstream::Error("single-image unused checkpoint was not retained");
            return 0;
        }
        if (mode.starts_with("multi-incremental")) {
            constexpr std::size_t mib = 1024*1024;
            pstream::Bytes old0(4*mib,0xa5), old1(4*mib,0x5a);
            auto now0 = old0, now1 = old1;
            now0[mib+4096] = 0x13;
            now1[2*mib+8192] = 0x27;
            auto sha = [](const pstream::Bytes& bytes) {
                unsigned char digest[32];
                unsigned length = 0;
                if (EVP_Digest(bytes.data(),bytes.size(),digest,&length,EVP_sha256(),nullptr) != 1 ||
                    length != sizeof(digest))
                    throw pstream::Error("cannot hash incremental fixture base");
                constexpr char hex[] = "0123456789abcdef";
                std::string result;
                for (auto byte : digest) { result += hex[byte>>4]; result += hex[byte&15]; }
                return result;
            };
            ImageSource base0(old0), base1(old1), first(now0), second(now1);
            std::array<BackupImage,2> images{{{&first,"disk-0"},{&second,"disk-1"}}};
            std::array<IncrementalBackup,2> plans{{
                {8,13,26,std::string(32,'a'),sha(old0),image_delta_plan(base0,first)},
                {8,13,26,std::string(32,'a'),sha(old1),image_delta_plan(base1,second)}}};
            std::uint64_t read_bytes = 0;
            std::array<std::unique_ptr<ImageSource>,2> live;
            CaptureJournal capture{std::string(32,'c'),"11223344-5566-7788-99aa-bbccddeeff00",
                CapturePhase::ready,pstream::Value{pstream::Value::Object{}},
                pstream::Value{pstream::Value::Object{}},
                pstream::Value{pstream::Value::Object{{"owned",pstream::Value{std::uint64_t{1}}}}},
                pstream::Value{pstream::Value::Object{{"direct",pstream::Value{std::uint64_t{1}}}}},{}};
            if (direct) {
                for (std::size_t index = 0; index < live.size(); ++index) {
                    plans[index].base_image_sha256.clear();
                    const auto bytes = index ? now1 : now0;
                    const auto plan = plans[index].plan;
                    live[index] = std::make_unique<ImageSource>(bytes.size(),
                        [&,bytes,plan](std::uint64_t at,std::size_t count,std::uint64_t*) {
                            const auto found = std::find_if(plan.ranges.begin(),plan.ranges.end(),[&](const auto& range) {
                                return range.changed && range.offset <= at && at+count <= range.offset+range.length;
                            });
                            if (found == plan.ranges.end()) throw pstream::Error("direct reader touched an inherited interval");
                            read_bytes += count;
                            return pstream::Bytes(bytes.begin()+at,bytes.begin()+at+count);
                        },[] {});
                    images[index].source = live[index].get();
                }
            }
            pstream::Value saved;
            const auto save = [&](const pstream::Value& record) {
                saved = record;
                auto& fields = std::get<pstream::Value::Object>(saved.data);
                fields["task_id"] = pstream::Value{std::uint64_t{2}};
                if (direct) fields["source_capture"] = capture_journal_value(capture);
                if (direct && std::get<std::string>(fields.at("phase").data) == "planned" && read_bytes)
                    throw pstream::Error("direct preparation read image payload");
            };
            auto stale = plans;
            for (auto& entry : stale) entry.base_version_id = 7;
            bool rejected = false;
            try {
                const pstream::Bytes metadata{'{','}'};
                (void)run_incremental_images_job(endpoint,auth,2,27,images,stale,metadata,save,
                    TransferCompression::none);
            } catch (const pstream::Error& error) {
                rejected = std::string_view(error.what()).find("NAS-selected base changed") !=
                    std::string_view::npos;
            }
            if (!rejected || std::get<std::string>(
                    std::get<pstream::Value::Object>(saved.data).at("phase").data) != "planned")
                throw pstream::Error("stale multi-disk NAS base reached preparation");
            try {
                const pstream::Bytes metadata{'{','}'};
                (void)run_incremental_images_job(endpoint,auth,2,27,images,plans,metadata,save,
                    mode.ends_with("lz4") ? TransferCompression::lz4 : TransferCompression::none);
                throw pstream::Error("interrupted incremental unexpectedly completed");
            } catch (const pstream::Error& error) {
                if (std::string_view(error.what()).find("unexpectedly completed") != std::string_view::npos)
                    throw;
            }
            const auto& fields = std::get<pstream::Value::Object>(saved.data);
            if (std::get<std::uint64_t>(fields.at("schema").data) != 5 ||
                std::get<std::string>(fields.at("phase").data) != "upload")
                throw pstream::Error("multi-incremental journal was not retained during interruption");
            const auto& entries = std::get<pstream::Value::Array>(fields.at("images").data);
            for (std::size_t index = 0; index < entries.size(); ++index) {
                const auto& item = std::get<pstream::Value::Object>(entries[index].data);
                if (std::get<std::string>(item.at("base_sha256").data) != plans[index].base_image_sha256 ||
                    item.at("ranges") != delta_plan_value(plans[index].plan))
                    throw pstream::Error("multi-incremental per-image base or ranges were not saved");
            }
            auto malformed = saved;
            auto& bad_entries = std::get<pstream::Value::Array>(
                std::get<pstream::Value::Object>(malformed.data).at("images").data);
            std::get<pstream::Value::Object>(bad_entries[1].data)["ranges"] =
                pstream::Value{std::string("invalid")};
            rejected = false;
            try { (void)backup_job_status(malformed,auth); } catch (const pstream::Error&) { rejected = true; }
            if (!rejected) throw pstream::Error("malformed second-image ranges accepted");
            malformed = saved;
            auto& bad_base = std::get<pstream::Value::Object>(
                std::get<pstream::Value::Array>(
                    std::get<pstream::Value::Object>(malformed.data).at("images").data)[1].data);
            bad_base["base_sha256"] = pstream::Value{std::string(64,'z')};
            rejected = false;
            try { (void)backup_job_status(malformed,auth); } catch (const pstream::Error&) { rejected = true; }
            if (!rejected) throw pstream::Error("malformed second-image base fingerprint accepted");
            rejected = false;
            try { (void)resume_images_job(endpoint,auth,std::span(images).first(1),saved,save); }
            catch (const pstream::Error&) { rejected = true; }
            if (!rejected) throw pstream::Error("missing incremental image accepted");
            auto wrong_order = images;
            std::swap(wrong_order[0],wrong_order[1]);
            rejected = false;
            try { (void)resume_images_job(endpoint,auth,wrong_order,saved,save); }
            catch (const pstream::Error& error) {
                rejected = std::string_view(error.what()).find("source differs") != std::string_view::npos;
            }
            if (!rejected) throw pstream::Error("reordered incremental images accepted");
            ImageSource changed(pstream::Bytes(4*mib,0x44));
            const std::array<BackupImage,2> wrong_source{{images[0],{&changed,"disk-1"}}};
            rejected = false;
            try { (void)resume_images_job(endpoint,auth,wrong_source,saved,save); }
            catch (const pstream::Error& error) {
                rejected = std::string_view(error.what()).find("source differs") != std::string_view::npos;
            }
            if (!rejected) throw pstream::Error("changed incremental source accepted");
            rejected = false;
            try { (void)resume_images_job(endpoint,auth,images,saved,save); }
            catch (const pstream::Error& error) {
                rejected = std::string_view(error.what()).find("different incremental base") != std::string_view::npos;
            }
            if (!rejected) throw pstream::Error("foreign NAS incremental base accepted");
            if (resume_images_job(endpoint,auth,images,saved,save) != BackupOutcome::complete)
                throw pstream::Error("multi-incremental resume did not complete");
            const auto& final = std::get<pstream::Value::Object>(saved.data);
            const auto& progress = std::get<pstream::Value::Array>(final.at("images").data);
            if (std::get<std::string>(final.at("phase").data) != "complete" ||
                std::get<std::uint64_t>(std::get<pstream::Value::Object>(progress[0].data).at("resume_offset").data) != 4*mib ||
                std::get<std::uint64_t>(std::get<pstream::Value::Object>(progress[1].data).at("resume_offset").data) != mib+mib/2)
                throw pstream::Error("multi-incremental checkpoints were not retained per image");
            return 0;
        }
        if (mode == "multi-upload") {
            ImageSource first(pstream::Bytes(4096,0xa5)), second(pstream::Bytes(4096,0x5a));
            const std::array<UploadImage,2> images{{
                {&first,"disk-0",{}, {},TransferCompression::none,nullptr},
                {&second,"disk-1",{}, {},TransferCompression::none,nullptr}}};
            upload_prepared_images(endpoint,auth,27,images,4096);
            return 0;
        }
        if (mode == "multi-job") {
            endpoint.backup_performance = std::make_shared<BackupPerformance>(
                BackupPerformance{27,123456789});
            ImageSource first(pstream::Bytes(4096,0xa5)), second(pstream::Bytes(4096,0x5a));
            const std::array<BackupImage,2> images{{{&first,"disk-0"},{&second,"disk-1"}}};
            pstream::Value saved;
            const pstream::Bytes metadata{'{','}'};
            const auto result = run_full_images_job(endpoint,auth,27,images,metadata,
                [&](const pstream::Value& record) { saved = record; },TransferCompression::none);
            if (result != BackupOutcome::complete ||
                endpoint.backup_performance->snapshot_nanoseconds != 0 ||
                std::get<std::string>(std::get<pstream::Value::Object>(saved.data).at("phase").data) != "complete" ||
                std::get<std::uint64_t>(std::get<pstream::Value::Object>(saved.data).at("schema").data) != 4)
                throw pstream::Error("multi-disk job did not complete");
            return 0;
        }
        if (mode == "multi-interrupt-resume") {
            using pstream::Value;
            ImageSource first(pstream::Bytes(4096,0xa5)), second(pstream::Bytes(2*1024*1024,0x5a));
            const std::array<BackupImage,2> images{{{&first,"disk-0"},{&second,"disk-1"}}};
            Value saved;
            const auto save = [&](const Value& record) {
                saved = record;
                std::get<Value::Object>(saved.data)["task_id"] = Value{std::uint64_t{2}};
            };
            try {
                const pstream::Bytes metadata{'{','}'};
                (void)run_full_images_job(endpoint,auth,27,images,metadata,save,TransferCompression::none);
                throw pstream::Error("interrupted multi-image upload unexpectedly completed");
            } catch (const pstream::Error& error) {
                if (std::string_view(error.what()).find("unexpectedly completed") != std::string_view::npos)
                    throw;
            }
            if (std::get<std::string>(std::get<Value::Object>(saved.data).at("phase").data) != "upload")
                throw pstream::Error("interrupted second image did not retain upload journal");
            const std::array<BackupImage,2> wrong{{{&first,"disk-0"},{&second,"wrong-disk"}}};
            try {
                (void)resume_images_job(endpoint,auth,wrong,saved,save);
                throw pstream::Error("wrong resumed image identity was accepted");
            } catch (const pstream::Error& error) {
                if (std::string_view(error.what()).find("source differs") == std::string_view::npos)
                    throw;
            }
            try {
                (void)resume_images_job(endpoint,auth,images,saved,save);
                throw pstream::Error("foreign NAS checkpoint was accepted");
            } catch (const pstream::Error& error) {
                if (std::string_view(error.what()).find("different image") == std::string_view::npos)
                    throw;
            }
            const auto result = resume_images_job(endpoint,auth,images,saved,save);
            const auto& fields = std::get<Value::Object>(saved.data);
            const auto& entries = std::get<Value::Array>(fields.at("images").data);
            if (result != BackupOutcome::complete ||
                std::get<std::string>(fields.at("phase").data) != "complete" ||
                std::get<std::uint64_t>(std::get<Value::Object>(entries[0].data).at("resume_offset").data) != 4096 ||
                std::get<std::uint64_t>(std::get<Value::Object>(entries[1].data).at("resume_offset").data) != 1024*1024)
                throw pstream::Error("interrupted second-image resume used the wrong checkpoints");
            return 0;
        }
        if (mode == "multi-resume") {
            using pstream::Value;
            ImageSource first(pstream::Bytes(4096,0xa5)), second(pstream::Bytes(4096,0x5a));
            const std::array<BackupImage,2> images{{{&first,"disk-0"},{&second,"disk-1"}}};
            const std::string hash0 = "f600eca824e84a43f0691b267bd620e462c50da165c5b80e17aecb7a924f1fa8";
            const std::string hash1 = "f302957da5220938a7e3e51a8718c79b9e00dc13ab2119e8cfc978f041720382";
            Value saved{Value::Object{
                {"schema",Value{std::uint64_t{4}}},{"ds_id",Value{auth.ds_id}},
                {"device_uuid",Value{auth.device_uuid}},{"username",Value{auth.username}},
                {"compression",Value{std::string("none")}},{"phase",Value{std::string("upload")}},
                {"running_task_id",Value{std::uint64_t{27}}},{"task_id",Value{std::uint64_t{2}}},
                {"version_id",Value{std::uint64_t{1}}},{"result_id",Value{std::uint64_t{112}}},
                {"data_format",Value{std::uint64_t{1}}},
                {"image_name",Value{std::string("disk-0")}},{"image_size",Value{std::uint64_t{4096}}},
                {"image_sha256",Value{hash0}},
                {"images",Value{Value::Array{
                    Value{Value::Object{{"name",Value{std::string("disk-0")}},
                        {"size",Value{std::uint64_t{4096}}},{"sha256",Value{hash0}}}},
                    Value{Value::Object{{"name",Value{std::string("disk-1")}},
                        {"size",Value{std::uint64_t{4096}}},{"sha256",Value{hash1}}}}}}},
                {"snapshot_info",Value{pstream::Bytes{'{','}'}}},
                {"requested_outcome",Value{std::string("complete")}}}};
            try {
                (void)resume_image_job(endpoint,auth,first,saved,
                    [&](const Value&) { throw pstream::Error("single-image resume saved multi-disk job"); });
                throw pstream::Error("single-image resume accepted a multi-disk journal");
            } catch (const pstream::Error& error) {
                if (std::string_view(error.what()).find("requires all saved images") == std::string_view::npos)
                    throw;
            }
            const auto result = resume_images_job(endpoint,auth,images,saved,
                [&](const Value& record) { saved = record; });
            const auto& fields = std::get<Value::Object>(saved.data);
            const auto& entries = std::get<Value::Array>(fields.at("images").data);
            if (result != BackupOutcome::complete ||
                std::get<std::string>(fields.at("phase").data) != "complete" ||
                std::get<std::uint64_t>(std::get<Value::Object>(entries[0].data).at("resume_offset").data) != 4096 ||
                std::get<std::uint64_t>(std::get<Value::Object>(entries[1].data).at("resume_offset").data) != 2048)
                throw pstream::Error("multi-disk resume ignored NAS image checkpoints");
            return 0;
        }
        if (mode.starts_with("bandwidth")) {
            if (mode == "bandwidth-absent" || mode == "bandwidth-zero")
                endpoint.backup_bandwidth_policy->update(512);
            ImageSource source(pstream::Bytes(4096,0xa5));
            try {
                upload_prepared_image(endpoint,auth,27,source,"rate-test",4096);
                if (mode == "bandwidth-invalid") throw pstream::Error("invalid bandwidth accepted");
            } catch (const pstream::Error& error) {
                if (mode != "bandwidth-invalid" ||
                    std::string(error.what()).find("backup_bandwidth") == std::string::npos) throw;
            }
            return 0;
        }
        if (mode == "task-policy") {
            using pstream::Value;
            const auto list = tasks(endpoint,auth);
            if (list.size() != 1) throw pstream::Error("task discovery count mismatch");
            const auto& task = std::get<pstream::Value::Object>(list.front().data);
            if (task.contains("pre_post_script_setting") || task.contains("pre_script_content") ||
                task.at("pre_script_enabled") != pstream::Value{std::uint64_t{1}})
                throw pstream::Error("nested script policy was lost or exposed script contents");
            try { validate_machine_task_policy(list.front(),Value{Value::Object{
                {"boot",Value{Value::Object{{"mount_path",Value{std::string("/boot/firmware")}}}}},
                {"excluded",Value{Value::Array{}}},
                {"other_disk_count",Value{std::uint64_t{0}}}}}); }
            catch (const pstream::Error& error) {
                if (std::string(error.what()).find("pre_script_enabled") != std::string::npos) return 0;
                throw;
            }
            throw pstream::Error("script task accepted");
        }
        try {
            outcome = run_queued_machine_capture(endpoint,task_view,2,27,[&](const std::function<bool()>& cancelled) {
                entered = true;
                if (mode == "cleanup-error") throw pstream::Error("owned resource recovery failed");
                if (mode == "shutdown") shutdown = true;
                if (mode == "complete") { std::this_thread::sleep_for(std::chrono::milliseconds{100}); return; }
                const auto deadline = std::chrono::steady_clock::now()+std::chrono::seconds{4};
                while (!cancelled() && std::chrono::steady_clock::now() < deadline)
                    std::this_thread::sleep_for(std::chrono::milliseconds{5});
                if (!cancelled()) throw pstream::Error("test timed out waiting for queue cancellation");
                if (mode == "cancel-after-ready") return;
                if (mode == "cleanup-after-cancel") throw pstream::Error("owned resource recovery failed");
                throw CaptureCancelled();
            });
        } catch (const pstream::Error& error) {
            rejected = true;
            const std::string message(error.what());
            if (message.find("test timed out") != message.npos) throw;
            if ((mode == "cleanup-error" || mode == "cleanup-after-cancel") &&
                message != "owned resource recovery failed") throw;
        }
        const bool expected_error = mode == "foreign" || mode == "duplicate" || mode == "control-error" ||
            mode == "cleanup-error" || mode == "cleanup-after-cancel" || mode == "shutdown";
        if (rejected != expected_error || entered != (mode != "absent-initial") ||
            (!rejected && (outcome == QueuedCaptureOutcome::complete) != (mode == "complete")))
            throw pstream::Error("queue monitor result mismatch");
        if (mode == "cancel-then-next") {
            const auto next = run_queued_machine_capture(endpoint,task_view,2,28,
                [](const std::function<bool()>&) { std::this_thread::sleep_for(std::chrono::milliseconds{100}); });
            if (next != QueuedCaptureOutcome::complete) throw pstream::Error("next queued capture did not run");
        }
        std::cout << "queue monitor passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
