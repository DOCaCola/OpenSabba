#include "opensabba/image.hpp"
#include "opensabba/backup_job.hpp"
#include <algorithm>
#include <iostream>
#include <array>

namespace {
using opensabba::pstream::Value;
using opensabba::pstream::Bytes;
using opensabba::pstream::Error;
void check(bool okay) { if (!okay) throw Error("unused interval protocol regression"); }
std::uint64_t number(const Value::Object& fields, const char* key) {
    return std::get<std::uint64_t>(fields.at(key).data);
}
template<class F> void rejects(F&& operation, std::string_view message) {
    try { operation(); }
    catch (const Error& error) {
        if (std::string_view(error.what()).find(message) == std::string_view::npos)
            throw Error(std::string("expected '")+std::string(message)+"', got '"+error.what()+"'");
        return;
    }
    throw Error("unused interval operation unexpectedly accepted");
}
void single_image_journals(opensabba::ImageSource& source,
                           std::span<const opensabba::ChangedExtent> unused,
                           const opensabba::DeltaPlan& delta) {
    using namespace opensabba;
    const SavedAuth auth{"test-user","test-device","test-token","test-nas"};
    const Endpoint endpoint{"127.0.0.1",1};
    const Bytes metadata{'{','}'};
    const IncrementalBackup incremental{8,13,26,std::string(32,'a'),std::string(64,'b'),delta};
    const auto plan = [&](bool cbt, std::span<const ChangedExtent> ranges) {
        Value saved;
        const auto save = [&](const Value& value) {
            saved = value;
            throw Error("stop before network");
        };
        rejects([&] {
            if (cbt) run_incremental_image_job(endpoint,auth,2,27,source,"disk.img",
                metadata,incremental,save,TransferCompression::lz4,ranges);
            else run_full_image_job(endpoint,auth,27,source,"disk.img",metadata,save,
                BackupOutcome::complete,TransferCompression::none,ranges);
        },"stop before network");
        (void)backup_job_status(saved,auth);
        return saved;
    };
    const auto full = plan(false,unused);
    const auto cbt = plan(true,unused);
    check(number(std::get<Value::Object>(full.data),"schema") == 8);
    check(number(std::get<Value::Object>(cbt.data),"schema") == 9);
    const auto& policy = std::get<Value::Object>(
        std::get<Value::Object>(cbt.data).at("incremental").data);
    check(policy.contains("filesystem_allocation") == delta.filesystem_allocation);
    if (delta.filesystem_allocation) {
        check(number(policy,"filesystem_allocation") == 1 &&
              std::get<Value::Array>(policy.at("reread_ranges").data).empty());
        auto invalid_policy = cbt;
        std::get<Value::Object>(std::get<Value::Object>(invalid_policy.data).at("incremental").data)
            ["filesystem_allocation"] = Value{std::uint64_t{0}};
        rejects([&] { (void)backup_job_status(invalid_policy,auth); },"allocation policy");
        const std::array<BackupImage,2> images{{
            {&source,"first.img",{unused.begin(),unused.end()}},
            {&source,"second.img",{unused.begin(),unused.end()}}}};
        const std::array<IncrementalBackup,2> deltas{{incremental,incremental}};
        Value multi;
        rejects([&] {
            run_incremental_images_job(endpoint,auth,2,27,images,deltas,metadata,
                [&](const Value& value) { multi = value; throw Error("planned multi allocation"); },
                TransferCompression::none);
        },"planned multi allocation");
        (void)backup_job_status(multi,auth);
        const auto& entries = std::get<Value::Array>(
            std::get<Value::Object>(multi.data).at("images").data);
        for (const auto& entry : entries) {
            const auto& item = std::get<Value::Object>(entry.data);
            check(number(item,"filesystem_allocation") == 1 &&
                  std::get<Value::Array>(item.at("reread_ranges").data).empty());
        }
    }
    check(number(std::get<Value::Object>(backup_job_status(cbt,auth).data),"base_version_id") == 8);
    for (bool incremental_mode : {false,true}) {
        auto legacy = plan(incremental_mode,{});
        auto& old = std::get<Value::Object>(legacy.data);
        check(number(old,"schema") == (incremental_mode ? 3 : 2) &&
              !old.contains("unused_ranges"));
        auto marked = legacy;
        std::get<Value::Object>(marked.data)["unused_ranges"] =
            std::get<Value::Object>(full.data).at("unused_ranges");
        rejects([&] { (void)backup_job_status(marked,auth); },"schema cannot specify");
        old["phase"] = Value{std::string("upload")};
        old["data_format"] = Value{std::uint64_t{1}};
        old["version_id"] = Value{std::uint64_t{9}};
        old["result_id"] = Value{std::uint64_t{112}};
        rejects([&] { resume_image_job(endpoint,auth,source,legacy,[](const Value&) {},unused); },
            "predates unused image interval policy");
    }
    for (auto record : {full,cbt}) {
        auto& fields = std::get<Value::Object>(record.data);
        fields["phase"] = Value{std::string("upload")};
        fields["data_format"] = Value{std::uint64_t{1}};
        fields["version_id"] = Value{std::uint64_t{9}};
        fields["result_id"] = Value{std::uint64_t{112}};
        auto malformed = record;
        std::get<Value::Object>(malformed.data).erase("unused_ranges");
        rejects([&] { (void)backup_job_status(malformed,auth); },"missing unused_ranges");
        malformed = record;
        auto& ranges = std::get<Value::Array>(
            std::get<Value::Object>(malformed.data).at("unused_ranges").data);
        std::get<Value::Object>(ranges.front().data)["length"] = Value{source.size()};
        rejects([&] { (void)backup_job_status(malformed,auth); },"unused");
        malformed = record;
        std::get<Value::Object>(malformed.data)["schema"] =
            Value{number(fields,"schema") == 8 ? std::uint64_t{9} : std::uint64_t{8}};
        rejects([&] { (void)backup_job_status(malformed,auth); },"incremental mode");
        rejects([&] { resume_image_job(endpoint,auth,source,record,[](const Value&) {}); },
            "saved unused image intervals differ");
        const std::vector<ChangedExtent> different{{unused.front().offset+512,
                                                  unused.front().length-512}};
        rejects([&] { resume_image_job(endpoint,auth,source,record,[](const Value&) {},different); },
            "saved unused image intervals differ");
        auto bytes = source.read(0,static_cast<std::size_t>(source.size()));
        bytes[unused.front().offset] = 1;
        ImageSource contaminated(bytes);
        rejects([&] { resume_image_job(endpoint,auth,contaminated,record,[](const Value&) {},unused); },
            "contains source data");
        bool saved = false;
        rejects([&] { run_full_image_job(endpoint,auth,27,contaminated,"disk.img",metadata,
            [&](const Value&) { saved = true; },BackupOutcome::complete,TransferCompression::none,unused); },
            "contains source data");
        check(!saved);
    }
}
void apply(Bytes& destination, const Value& block, bool incremental) {
    const auto& fields = std::get<Value::Object>(block.data);
    const auto offset = number(fields,"offset");
    const auto length = number(fields,"length");
    check(offset+length <= destination.size());
    if (!number(fields,"used")) {
        check(number(fields,"changed") == 1 && fields.find("buffer") == fields.end() &&
              number(fields,"changed_length") == 0);
        return; // the official agent recovery reads only used intervals; retain recreated PV metadata.
    }
    if (!number(fields,"changed")) {
        check(incremental && fields.find("buffer") == fields.end());
        return; // Inherit from the completed base, not from the current source.
    }
    const auto& payload = std::get<Bytes>(fields.at("buffer").data);
    check(payload.size() == length);
    std::copy(payload.begin(),payload.end(),destination.begin()+offset);
}
}

int main() {
    using namespace opensabba;
    try {
        constexpr std::size_t mib = 1024*1024;
        Bytes source_bytes(5*mib,0x64);
        std::fill(source_bytes.begin()+mib,source_bytes.begin()+4*mib,0);
        ImageSource source(source_bytes);
        const std::vector<ChangedExtent> unused{{mib,3*mib}};
        verify_unused_source(source,unused);
        Bytes target(source_bytes.size(),0x9c);
        std::fill(target.begin()+mib,target.begin()+mib+4096,0x4c); // New PV label/MDA.
        std::size_t skipped = 0;
        stream_image(source,"disk.img",mib,[&](const Value& block) {
            const auto& fields = std::get<Value::Object>(block.data);
            if (!number(fields,"used")) ++skipped;
            check(number(fields,"is_interval_cbt") == 0);
            apply(target,block,false);
        },{},0,TransferCompression::none,nullptr,unused);
        check(skipped == 3 && target[mib+512] == 0x4c &&
              target[4*mib] == 0x64 && target[2*mib] == 0x9c);
        // A base range marked inherited by CBT still has to be unused on the PV.
        DeltaPlan delta{source_bytes.size(),2*mib,{
            {0,mib,true},{mib,3*mib,false},{4*mib,mib,true}}};
        validate_delta_plan(delta,source_bytes.size());
        single_image_journals(source,unused,delta);
        Bytes resumed(source_bytes.size(),0x17);
        std::fill(resumed.begin()+mib,resumed.begin()+mib+4096,0x4c);
        std::uint64_t next = mib+512;
        stream_image(source,"disk.img",mib,[&](const Value& block) {
            const auto& fields = std::get<Value::Object>(block.data);
            check(number(fields,"offset") == next);
            next += number(fields,"length");
            check(number(fields,"is_interval_cbt") == 1);
            apply(resumed,block,true);
        },{},next,TransferCompression::none,&delta,unused);
        check(next == source_bytes.size() && resumed[mib+512] == 0x4c &&
              resumed[4*mib] == 0x64);
        // Filesystem allocation and CBT are independent contexts. In
        // particular, a previously used range which is now free must be
        // recorded unused even if the tracker did not observe a data write.
        delta.filesystem_allocation = true;
        delta.ranges = {{0,mib,true},{mib,mib,false},{2*mib,mib,true},
                        {3*mib,mib,false},{4*mib,mib,true}};
        delta.transfer_bytes = 3*mib;
        std::uint64_t read_bytes = 0, free_changed = 0, free_inherited = 0;
        next = mib+512;
        stream_image(source,"disk.img",65536,[&](const Value& block) {
            const auto& fields = std::get<Value::Object>(block.data);
            check(number(fields,"offset") == next && number(fields,"is_interval_cbt") == 1);
            next += number(fields,"length");
            if (!number(fields,"used")) {
                check(!fields.contains("buffer") && number(fields,"changed_length") == 0);
                (number(fields,"changed") ? free_changed : free_inherited) += number(fields,"length");
            }
        },{},next,TransferCompression::none,&delta,unused,{},
            [&](auto,auto count) { read_bytes += count; });
        check(read_bytes == mib && free_changed == mib && free_inherited == 2*mib-512);
        single_image_journals(source,unused,delta);
        // A live snapshot must never read free or inherited image payload,
        // including validation before upload and a sector-offset resume.
        std::uint64_t direct_reads = 0;
        ImageSource direct(source_bytes.size(),[&](auto at,auto count,auto) {
            if (at < 4*mib || at+count > 5*mib) throw Error("read outside sent direct interval");
            direct_reads += count;
            return Bytes(count,0x64);
        },[] {});
        verify_unused_source(direct,unused);
        check(direct_reads == 0);
        stream_image(direct,"disk.img",65536,[](const Value&) {},{},mib+512,
            TransferCompression::lz4,&delta,unused);
        check(direct_reads == mib);
        source_bytes[mib+123] = 0x55;
        ImageSource contaminated(source_bytes);
        bool rejected = false;
        try { verify_unused_source(contaminated,unused); }
        catch (const Error&) { rejected = true; }
        check(rejected);
        rejected = false;
        const std::vector<ChangedExtent> overlap{{mib,2*mib},{2*mib,mib}};
        try { validate_unused_ranges(overlap,source_bytes.size()); }
        catch (const Error&) { rejected = true; }
        check(rejected);
        std::cout << "Unused full, incremental and resumed intervals preserve target metadata\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
