#include "opensabba/backup_job.hpp"
#include "opensabba/machine_tracking.hpp"
#include <algorithm>
#include <csignal>
#include <fstream>
#include <iostream>
using namespace opensabba;
using pstream::Value;
using pstream::Error;
namespace {
Value n(std::uint64_t x) { return Value{x}; }
void set(Value& v, const char* key, Value next) { std::get<Value::Object>(v.data)[key] = std::move(next); }
void check(bool condition) { if (!condition) throw Error("interval transfer fixture invariant failed"); }
constexpr std::uint64_t mib = 1024*1024;
Value volume(const char* uuid, std::uint64_t offset, std::uint64_t length, bool logical = false) {
    Value v{Value::Object{{"filesystem_uuid",Value{std::string(uuid)}},{"offset",n(offset)},
        {"length",n(length)},{"disk_index",n(0)}}};
    if (logical) set(v,"lv_uuid",Value{std::string(uuid)});
    return v;
}
Value snapshot(unsigned id, unsigned sequence) {
    return Value{Value::Object{{"uuid",Value{std::string(31,'a')+char('0'+id)}},{"sequence",n(sequence)}}};
}
}
int main(int argc, char** argv) {
#ifdef SIGPIPE
    std::signal(SIGPIPE,SIG_IGN);
#endif
    try {
        check(argc == 5);
        Endpoint endpoint{"127.0.0.1",static_cast<std::uint16_t>(std::stoul(argv[1])),argv[2]};
        const SavedAuth auth{"test-user","test-device","test-token","test-nas"};
        const std::string mode(argv[3]);
        const bool restart = mode.ends_with("resume");
        const auto disk_size = mode.starts_with("grow") ? 10*mib : 6*mib;
        const auto compression = mode.find("lz4") != mode.npos ? TransferCompression::lz4 : TransferCompression::none;
        CaptureJournal base, current;
        base.id = std::string(32,'a'); current.id = std::string(32,'b');
        const auto root = volume("root",mib,mib), sibling = volume("sibling",4*mib,mib);
        const auto rename = volume("rename",0,4*mib,true), keep = volume("keep",0,4*mib,true);
        base.plan = Value{Value::Object{{"layout",Value{Value::Object{{"length",n(8*mib)}}}},
            {"root",root},{"selected_extra",Value{Value::Array{sibling,rename,keep}}}}};
        current.plan = base.plan;
        set(std::get<Value::Object>(current.plan.data).at("layout"),"length",n(disk_size));
        auto moved = root; set(moved,"offset",n(2*mib)); set(current.plan,"root",moved);
        set(current.plan,"selected_extra",Value{Value::Array{keep,sibling,rename}});
        base.snapshot = snapshot(1,1); current.snapshot = snapshot(1,2);
        Value::Array base_extras;
        for (unsigned id = 2; id <= 4; ++id) base_extras.push_back(Value{Value::Object{{"snapshot",snapshot(id,1)}}});
        base.reservation = Value{Value::Object{{"extras",Value{std::move(base_extras)}}}};
        const auto reservation = [&](unsigned id, std::size_t bytes, bool changed) {
            pstream::Bytes bitmap(bytes,0);
            if (changed) bitmap.at(4) = 1;
            return Value{Value::Object{{"snapshot",snapshot(id,2)},{"filesystem_unused",Value{Value::Array{}}},
                {"previous_capture_id",Value{base.id}},{"changes",Value{std::move(bitmap)}},
                {"prior",Value{Value::Object{{"snapshot",snapshot(id,1)}}}}}};
        };
        current.reservation = reservation(1,2,false);
        set(current.reservation,"extras",Value{Value::Array{reservation(4,8,true),reservation(2,2,false),reservation(3,8,false)}});
        const std::vector<std::string> old_names{"disk.img","old.img","keep.img"}, names{"disk.img","keep.img","new.img"};
        std::vector<pstream::Bytes> payloads{pstream::Bytes(disk_size,0x40),pstream::Bytes(4*mib,0xb6),pstream::Bytes(4*mib,0xd7)};
        std::fill(payloads[0].begin()+2*mib,payloads[0].begin()+3*mib,0xa5);
        std::fill(payloads[1].begin()+2*mib,payloads[1].begin()+2*mib+65536,0xcc);
        std::fill(payloads[2].begin()+mib,payloads[2].begin()+2*mib,0);
        std::vector<std::unique_ptr<ImageSource>> sources;
        std::vector<BackupImage> images;
        std::vector<IncrementalBackup> deltas;
        const std::vector<std::vector<ChangedExtent>> allowed{{{0,4*mib},{5*mib,disk_size-5*mib}},
            {{2*mib,65536}},{{0,mib},{2*mib,2*mib}}};
        for (std::size_t i = 0; i < names.size(); ++i) {
            sources.push_back(std::make_unique<ImageSource>(payloads[i].size(),
                [&,i](std::uint64_t at,std::size_t length,std::uint64_t*) {
                    check(std::any_of(allowed[i].begin(),allowed[i].end(),[&](const auto& r) {
                        return at >= r.offset && at+length <= r.offset+r.length;
                    }));
                    return pstream::Bytes(payloads[i].begin()+at,payloads[i].begin()+at+length);
                },[] {}));
            std::vector<ChangedExtent> reread;
            Value policy;
            auto delta = machine_tracking_delta(current,base,i,names,old_names,&reread,false,&policy);
            delta.filesystem_allocation = true;
            if (!i) reread = {{0,4*mib},{5*mib,disk_size-5*mib}};
            const std::vector<ChangedExtent> unused = i == 2 ? std::vector<ChangedExtent>{{mib,mib}} : std::vector<ChangedExtent>{};
            images.push_back({sources.back().get(),names[i],unused,reread});
            deltas.push_back({8,13,26,base.id,"",std::move(delta),std::move(reread),std::move(policy)});
        }
        Value saved;
        const std::filesystem::path path(argv[4]);
        const auto persist = [&](const Value& value) {
            saved = pstream::decode(pstream::encode(value));
            set(saved,"task_id",n(2));
            (void)backup_job_status(saved,auth);
            const auto bytes = pstream::encode(saved);
            std::ofstream output(path,std::ios::binary|std::ios::trunc);
            output.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));
            check(output.good());
        };
        const pstream::Bytes metadata{'{','}'};
        bool interrupted = false;
        try {
            check(run_incremental_images_job(endpoint,auth,2,27,images,deltas,metadata,persist,compression) == BackupOutcome::complete);
        } catch (const TransportError&) {
            check(restart);
            interrupted = true;
        }
        if (restart) {
            check(interrupted);
            std::ifstream input(path,std::ios::binary);
            saved = pstream::decode(pstream::Bytes{std::istreambuf_iterator<char>(input),{}});
            check(!backup_completion_cbt(saved));
            // Corrupt correspondence and reread flags are refused before any
            // NAS action, even when the proposed new image would be full.
            auto altered = saved;
            auto& entry = std::get<Value::Object>(std::get<Value::Array>(std::get<Value::Object>(altered.data).at("images").data).back().data);
            auto& policy = std::get<Value::Object>(entry.at("machine_policy").data);
            set(std::get<Value::Array>(policy.at("origins").data).front(),"is_cbt",n(1));
            bool rejected = false;
            try { (void)resume_images_job(endpoint,auth,images,altered,persist); }
            catch (const BackupStateError&) { rejected = true; }
            check(rejected);
            auto changed_sources = images;
            changed_sources.back().reread_ranges = {{0,2*mib}};
            rejected = false;
            try { (void)resume_images_job(endpoint,auth,changed_sources,saved,persist); }
            catch (const BackupStateError&) { rejected = true; }
            check(rejected);
            check(resume_images_job(endpoint,auth,images,saved,persist) == BackupOutcome::complete);
        }
        check(!backup_completion_cbt(saved));
        check(std::get<std::string>(std::get<Value::Object>(saved.data).at("phase").data) == "complete");
        std::cout << "Mixed interval transfer and immutable resume passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
