#include "opensabba/machine_capture.hpp"
#include "opensabba/machine_tracking.hpp"
#include "opensabba/snapshot_driver.hpp"
#include "opensabba/display.hpp"
#include "opensabba/backup_job.hpp"
#include "opensabba/filesystem.hpp"
#include <charconv>
#include <iostream>
using namespace opensabba;
using namespace opensabba::pstream;
int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string_view(argv[1]) == "status") {
            print_json(std::cout,snapshot_driver_status(0));
        } else if (argc == 6 && std::string_view(argv[1]) == "snapshot") {
            const std::string_view input(argv[5]);
            unsigned minor{};
            const auto [end,error] = std::from_chars(input.data(),input.data()+input.size(),minor);
            if (error != std::errc{} || end != input.data()+input.size()) throw Error("invalid reload minor");
            snapshot_driver_reload(minor,std::filesystem::canonical(argv[3]).string(),argv[4],
                std::string_view(argv[2]) == "reload-snapshot");
        } else if (argc == 5 && std::string_view(argv[1]) == "create") {
            const auto journal = create_machine_capture(argv[2],argv[3],64,
                [](const CaptureJournal&) {},{}, {},{argv[4]},false,{},true);
            print_json(std::cout,capture_journal_value(journal));
        } else if (argc == 4 && std::string_view(argv[1]) == "delta") {
            const auto before = inspect_machine_capture(argv[2]);
            ReadyMachineCapture after(argv[3]);
            Value::Array images;
            std::vector<std::string> current_names, base_names;
            for (std::size_t i = 0; i < after.disk_count(); ++i) current_names.push_back("probe-"+std::to_string(i)+".img");
            const auto& base_fields = std::get<Value::Object>(before.plan.data);
            auto base_count = std::size_t{1};
            if (base_fields.contains("additional_disks"))
                base_count += std::get<Value::Array>(base_fields.at("additional_disks").data).size();
            if (std::get<Value::Object>(base_fields.at("root").data).contains("lv_uuid")) ++base_count;
            if (base_fields.contains("selected_extra"))
                for (const auto& origin : std::get<Value::Array>(base_fields.at("selected_extra").data))
                    if (std::get<Value::Object>(origin.data).contains("lv_uuid")) ++base_count;
            for (std::size_t i = 0; i < base_count; ++i) base_names.push_back("probe-"+std::to_string(i)+".img");
            for (std::size_t i = 0; i < after.disk_count(); ++i) {
                std::vector<ChangedExtent> reread;
                const auto delta = machine_tracking_delta(after.journal(),before,i,current_names,base_names,&reread);
                const auto unused = machine_tracking_unused(after.journal(),i,true,reread);
                std::uint64_t data_bytes = 0, unused_bytes = 0;
                stream_image(after.source(i),"probe.img",65536,[&](const Value& block) {
                    const auto& fields = std::get<Value::Object>(block.data);
                    const auto at = std::get<std::uint64_t>(fields.at("offset").data);
                    const auto count = std::get<std::uint64_t>(fields.at("length").data);
                    if (!std::get<std::uint64_t>(fields.at("used").data)) { unused_bytes += count; return; }
                    if (std::get<std::uint64_t>(fields.at("changed").data)) { data_bytes += count; return; }
                },{},0,TransferCompression::none,&delta,unused,reread);
                images.push_back(Value{Value::Object{{"image",Value{std::uint64_t{i}}},
                    {"size",Value{delta.image_size}},{"transfer_bytes",Value{delta.transfer_bytes}},
                    {"data_bytes",Value{data_bytes}},{"unused_bytes",Value{unused_bytes}}}});
            }
            print_json(std::cout,Value{std::move(images)});
        } else if (argc == 3 && std::string_view(argv[1]) == "allocation") {
            unsigned minor{};
            const std::string_view input(argv[2]);
            const auto [end,error] = std::from_chars(input.data(),input.data()+input.size(),minor);
            if (error != std::errc{} || end != input.data()+input.size())
                throw Error("invalid allocation test minor");
            const auto identity = snapshot_driver_information(minor);
            if (!identity) throw Error("allocation test snapshot is absent");
            auto allocation_reader = std::make_shared<SnapshotReader>(*identity,true);
            ImageSource source(allocation_reader->size(),[allocation_reader](auto at,auto size,auto* elapsed) {
                return allocation_reader->read(at,size,elapsed);
            },[allocation_reader] { allocation_reader->verify(); },[allocation_reader](auto at,auto size) { return allocation_reader->read_metadata(at,size); });
            source.set_bad_clusters(allocation_reader->bad_clusters());
            const auto free = snapshot_used_context(std::get<std::string>(std::get<Value::Object>(identity->data).at("origin_path").data),
                allocation_reader->size(),[allocation_reader](auto at,auto size) { return allocation_reader->read_metadata(at,size); });
            const auto rounded = [&](std::uint64_t unit) {
                std::vector<ChangedExtent> result;
                for (const auto& range : free) {
                    const auto at = (range.offset+unit-1)/unit*unit;
                    const auto end_at = range.offset+range.length;
                    const auto end = end_at == source.size() ? end_at/4096*4096 : end_at/unit*unit;
                    if (end > at) result.push_back({at,end-at});
                }
                return result;
            };
            const auto full_unused = rounded(1024*1024), cbt_unused = rounded(65536);
            std::uint64_t full_payload = 0, full_free = 0, inherited_free = 0;
            stream_image(source,"allocation.img",1024*1024,[&](const Value& value) {
                const auto& fields = std::get<Value::Object>(value.data);
                const auto count = std::get<std::uint64_t>(fields.at("length").data);
                if (std::get<std::uint64_t>(fields.at("used").data)) full_payload += count;
                else full_free += count;
            },{},0,TransferCompression::none,nullptr,full_unused);
            DeltaPlan delta{source.size(),0,{{0,source.size(),false}}};
            delta.filesystem_allocation = true;
            stream_image(source,"allocation.img",1024*1024,[&](const Value& value) {
                const auto& fields = std::get<Value::Object>(value.data);
                if (!std::get<std::uint64_t>(fields.at("used").data)) {
                    if (std::get<std::uint64_t>(fields.at("changed").data) || fields.contains("buffer"))
                        throw Error("unchanged free snapshot interval has wrong flags");
                    inherited_free += std::get<std::uint64_t>(fields.at("length").data);
                }
            },{},0,TransferCompression::none,&delta,cbt_unused);
            const SavedAuth auth{"fixture-user","fixture-device","fixture-token","fixture-nas"};
            Value journal;
            try {
                run_full_image_job({"127.0.0.1",1},auth,77,source,"allocation.img",Bytes{'{','}'},
                    [&](const Value& saved) { journal = saved; throw Error("planned allocation probe"); });
            } catch (const Error& error) {
                if (std::string_view(error.what()) != "planned allocation probe") throw;
            }
            const auto& saved = std::get<Value::Object>(journal.data);
            if (std::get<std::uint64_t>(saved.at("schema").data) != 8 ||
                std::get<Value::Array>(saved.at("unused_ranges").data).size() != full_unused.size())
                throw Error("snapshot allocation was not retained by full job");
            // Open a second reader concurrently, as a multi-origin machine
            // image set does, and verify direct interval preparation is lazy.
            auto reader = std::make_shared<SnapshotReader>(*identity);
            std::uint64_t direct_payload = 0;
            ImageSource direct(reader->size(),[&](auto at,auto count,auto elapsed) {
                direct_payload += count;
                return reader->read(at,count,elapsed);
            },[reader] { reader->verify(); });
            constexpr std::uint64_t mib = 1024*1024;
            DeltaPlan direct_delta{reader->size(),2*mib,{
                {0,mib,true},{mib,reader->size()-2*mib,false},{reader->size()-mib,mib,true}}};
            stream_image(direct,"direct.img",65536,[](const Value&) {},{},0,
                TransferCompression::none,&direct_delta);
            if (direct_payload != 2*mib) throw Error("direct snapshot read inherited image data");
            direct_payload = 0;
            try {
                run_full_image_job({"127.0.0.1",1},auth,77,direct,"direct.img",Bytes{'{','}'},
                    [&](const Value& saved) {
                        const auto& fields = std::get<Value::Object>(saved.data);
                        if (!std::get<std::string>(fields.at("image_sha256").data).empty() || direct_payload)
                            throw Error("direct snapshot preparation hashed image data");
                        throw Error("planned direct probe");
                    });
            } catch (const Error& error) {
                if (std::string_view(error.what()) != "planned direct probe") throw;
            }
            print_json(std::cout,Value{Value::Object{{"full_payload",Value{full_payload}},
                {"full_free",Value{full_free}},{"inherited_free",Value{inherited_free}},
                {"size",Value{source.size()}}}});
        } else if (argc == 3 && std::string_view(argv[1]) == "resume") {
            const auto journal = inspect_machine_capture(argv[2]);
            print_json(std::cout,capture_journal_value(resume_machine_capture(argv[2],journal,{})));
        } else if (argc == 3 && std::string_view(argv[1]) == "prune") {
            const auto journal = inspect_machine_capture(argv[2],true);
            prune_machine_capture(journal);
        } else if (argc == 3 && std::string_view(argv[1]) == "release") {
            const auto journal = inspect_machine_capture(argv[2]);
            const auto& root = std::get<Value::Object>(journal.reservation.data);
            snapshot_driver_release(journal.snapshot);
            for (const auto& extra : std::get<Value::Array>(root.at("extras").data))
                snapshot_driver_release(std::get<Value::Object>(extra.data).at("snapshot"));
        } else throw Error("usage: machine_tracking_probe create DISK DIR SELECTED_MOUNT | delta BASE CURRENT | release CURRENT");
        std::cout << '\n';
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
