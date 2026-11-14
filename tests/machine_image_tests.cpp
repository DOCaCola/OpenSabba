#include "image_delta_fixture.hpp"
#include "opensabba/snapshot.hpp"
#include "opensabba/machine.hpp"
#include "opensabba/client.hpp"
#include "opensabba/backup_resume.hpp"
#include "opensabba/filesystem.hpp"
#include <lz4.h>
#include <algorithm>
#include <iostream>

using namespace opensabba;
using namespace opensabba::pstream;
namespace {
void check(bool okay) { if (!okay) throw Error("machine image test failed"); }
std::string mount_map_json(const std::string& metadata) {
    const auto begin = metadata.find("\"mount_map\":");
    const auto end = metadata.find(",\"disk_layout\":",begin);
    check(begin != std::string::npos && end != std::string::npos);
    return metadata.substr(begin,end-begin);
}
void put(Bytes& b, std::size_t at, std::uint32_t n, unsigned width = 4) {
    for (unsigned i = 0; i < width; ++i) b.at(at+i) = static_cast<std::uint8_t>(n >> (8*i));
}
void short_allocation_reads(const Bytes& image) {
    std::vector<std::pair<std::uint64_t,std::size_t>> requests;
    (void)filesystem_unused_extents(image.size(),[&](auto at,auto count) {
        requests.emplace_back(at,count);
        return Bytes(image.begin()+static_cast<std::ptrdiff_t>(at),image.begin()+static_cast<std::ptrdiff_t>(at+count));
    });
    std::sort(requests.begin(),requests.end());
    requests.erase(std::unique(requests.begin(),requests.end()),requests.end());
    for (const auto& request : requests) for (const auto kept : {std::size_t{0},request.second-1}) {
        const auto short_read = [&](auto at,auto count) {
            if (std::pair<std::uint64_t,std::size_t>{at,count} == request) count = kept;
            return Bytes(image.begin()+static_cast<std::ptrdiff_t>(at),image.begin()+static_cast<std::ptrdiff_t>(at+count));
        };
        bool rejected = false;
        try { (void)filesystem_unused_extents(image.size(),short_read); }
        catch (const FilesystemAllocationError& error) {
            const std::string_view message(error.what());
            rejected = message.find("short") != message.npos || message == "unsupported allocation filesystem";
        }
        check(rejected && snapshot_used_context("short-metadata",image.size(),short_read).empty());
    }
}
void allocation_maps() {
    constexpr std::uint64_t block = 4096;
    Bytes ext(256*block,0);
    const auto sb = 1024U;
    put(ext,sb+4,256); put(ext,sb+0x18,2); put(ext,sb+0x1c,2);
    put(ext,sb+0x20,128); put(ext,sb+0x24,128); put(ext,sb+0x28,16);
    put(ext,sb+0x38,0xef53,2); put(ext,sb+0x4c,1); put(ext,sb+0x58,128,2);
    for (std::size_t g = 0; g < 2; ++g) {
        const auto gd = block+g*32;
        put(ext,gd,static_cast<std::uint32_t>(4+128*g));
        put(ext,gd+4,static_cast<std::uint32_t>(5+128*g));
        put(ext,gd+8,static_cast<std::uint32_t>(6+128*g));
        ext[(4+128*g)*block] = 0xff;
        ext[(4+128*g)*block+1] = 3;
    }
    const auto parse = [&](const Bytes& source) {
        return filesystem_unused_extents(source.size(),[&](auto at,auto n) {
            return Bytes(source.begin()+static_cast<std::ptrdiff_t>(at),
                source.begin()+static_cast<std::ptrdiff_t>(at+n));
        });
    };
    for (const unsigned fs : {2U,3U,4U}) {
        auto specimen = ext;
        put(specimen,sb+0x4c,fs == 2 ? 0 : 1);
        put(specimen,sb+0x5c,fs >= 3 ? 4 : 0);
        if (fs == 4) put(specimen,sb+0x60,0x40);
        short_allocation_reads(specimen);
    }
    auto ranges = parse(ext);
    check(ranges.size() == 2 && ranges[0].offset == 10*block && ranges[0].length == 118*block &&
          ranges[1].offset == 138*block && ranges[1].length == 118*block);
    // Bigalloc: one allocation bit covers a four-block cluster.
    auto bigalloc = ext;
    put(bigalloc,sb+0x1c,4); put(bigalloc,sb+0x24,32);
    bigalloc[4*block] = bigalloc[132*block] = 1;
    bigalloc[4*block+1] = bigalloc[132*block+1] = 0;
    ranges = parse(bigalloc);
    check(ranges.size() == 2 && ranges[0].offset == 4*block && ranges[0].length == 124*block);
    // An uninitialized group must retain its metadata even when its on-disk
    // bitmap has arbitrary contents. Legacy descriptor CRC16 protects the flag.
    auto lazy = ext;
    put(lazy,sb+0x64,0x10); put(lazy,block+32+18,2,2);
    const auto crc = [](std::uint16_t value, std::span<const std::uint8_t> bytes) {
        for (auto byte : bytes) {
            value ^= byte;
            for (unsigned i = 0; i < 8; ++i)
                value = static_cast<std::uint16_t>((value >> 1) ^ ((value & 1) ? 0xa001U : 0));
        }
        return value;
    };
    const Bytes group{1,0,0,0};
    const auto checksum = crc(crc(crc(0xffff,std::span(lazy).subspan(sb+0x68,16)),group),
        std::span(lazy).subspan(block+32,30));
    put(lazy,block+32+30,checksum,2);
    std::fill_n(lazy.begin()+132*block,16,0xff);
    ranges = parse(lazy);
    check(ranges.size() == 3 && ranges[1].offset == 130*block && ranges[1].length == 2*block &&
          ranges[2].offset == 135*block);
    lazy[block+32+30] ^= 1;
    bool refused = false;
    try { (void)parse(lazy); } catch (const Error&) { refused = true; }
    check(refused);
    // XFS v4/v5 allocation groups: internal bnobt root, linked leaves and
    // AGFL blocks all contribute to free space.
    for (bool v5 : {false,true}) {
        Bytes xfs(512*block,0);
        const auto be = [&](std::size_t at,std::uint32_t n,unsigned width = 4) {
            for (unsigned i = 0; i < width; ++i)
                xfs.at(at+i) = static_cast<std::uint8_t>(n >> (8*(width-i-1)));
        };
        be(0,0x58465342); be(4,block); be(12,512);
        be(84,256); be(88,2); be(102,512,2);
        const std::size_t header = v5 ? 56 : 16;
        for (std::size_t ag = 0; ag < 2; ++ag) {
            const auto at = ag*256*block;
            be(at+512,0x58414746); be(at+524,256); be(at+528,4);
            be(at+552,2); be(at+556,2); be(at+560,1);
            if (v5) be(at+1536,0x5841464c);
            be(at+1536+(v5 ? 36 : 0)+8,90);
            for (unsigned node = 4; node <= 6; ++node) {
                const auto pos = at+node*block;
                be(pos,v5 ? 0x41423342 : 0x41425442);
                be(pos+4,node == 4 ? 1U : 0U,2); be(pos+6,1,2);
                be(pos+12,node == 5 ? 6U : UINT32_MAX);
                if (node == 4) be(pos+header+((block-header)/12)*8,5);
                else { be(pos+header,node == 5 ? 40 : 100); be(pos+header+4,node == 5 ? 10 : 5); }
            }
        }
        short_allocation_reads(xfs);
        ranges = parse(xfs);
        check(ranges.size() == 6 && ranges[0].offset == 40*block && ranges[0].length == 10*block &&
              ranges[1].offset == 90*block && ranges[1].length == block &&
              ranges[3].offset == (256+40)*block);
        be(5*block+12,5); // A cycle cannot silently produce an incomplete map.
        refused = false;
        try { (void)parse(xfs); } catch (const Error&) { refused = true; }
        check(refused);
    }
}
constexpr std::size_t boot = 1024*1024;
struct Fixture {
    Bytes bytes;
    std::size_t root, fat, fat_copy;
};
// Synthetic metadata fixtures, not mountable filesystems or bootable OS images.
Fixture disk(bool fat32) {
    const std::size_t boot_size = (fat32 ? 36U : 8U)*1024*1024;
    const std::size_t root = boot+boot_size+1024*1024;
    Fixture f{Bytes(root+5*1024*1024), root,
              boot+(fat32 ? 32U : 1U)*512, 0};
    auto& b = f.bytes;
    b[0] = 0xfa; b[440] = 0x34; b[441] = 0x12;
    b[510] = 0x55; b[511] = 0xaa;
    b[446] = 0x80; b[450] = fat32 ? 0x0c : 0x06;
    put(b, 454, boot/512); put(b, 458, static_cast<std::uint32_t>(boot_size/512));
    b[466] = 0x83;
    put(b, 470, static_cast<std::uint32_t>(root/512)); put(b, 474, 8192);
    b[boot] = 0xeb; b[boot+2] = 0x90;
    put(b, boot+11, 512, 2); b[boot+13] = 1;
    put(b, boot+14, fat32 ? 32 : 1, 2); b[boot+16] = 2;
    b[boot+21] = 0xf8; b[boot+510] = 0x55; b[boot+511] = 0xaa;
    const unsigned fat_sectors = fat32 ? 600 : 64;
    f.fat_copy = f.fat+fat_sectors*512;
    if (fat32) {
        put(b, boot+32, static_cast<std::uint32_t>(boot_size/512));
        put(b, boot+36, fat_sectors); put(b, boot+44, 2);
        put(b, boot+48, 0xffff, 2); put(b, boot+50, 6, 2);
        b[boot+66] = 0x29; put(b, boot+67, 0x1234abcd);
        std::copy_n(b.begin()+boot, 512, b.begin()+boot+6*512);
        for (const auto at : {f.fat, f.fat_copy}) {
            put(b, at, 0x0ffffff8); put(b, at+4, 0x0fffffff); put(b, at+8, 0x0fffffff);
        }
    } else {
        put(b, boot+17, 512, 2); put(b, boot+19, 16384, 2);
        put(b, boot+22, fat_sectors, 2);
        b[boot+38] = 0x29; put(b, boot+39, 0x1234abcd);
        for (const auto at : {f.fat, f.fat_copy}) {
            put(b, at, 0xfff8, 2); put(b, at+2, 0xffff, 2);
        }
    }
    const auto sb = root+1024;
    put(b, sb+4, 1024); put(b, sb+0x18, 2);
    put(b, sb+0x38, 0xef53, 2); put(b, sb+0x3a, 1, 2);
    put(b, sb+0x4c, 1); put(b, sb+0x60, 0x40);
    for (unsigned i = 0; i < 16; ++i) b[sb+0x68+i] = static_cast<std::uint8_t>(i+1);
    // Mark bytes outside filesystem metadata, including both gaps and the tail.
    for (const auto at : {boot-17, root-23, root+4096, b.size()-1}) b[at] = 0xa7;
    return f;
}
std::string metadata(Bytes bytes) {
    ImageSource source(std::move(bytes));
    const auto result = fixed_image_metadata(source, 512, "pi-card", 1700000000);
    return {result.begin(), result.end()};
}
std::uint32_t crc(std::span<const std::uint8_t> bytes) {
    std::uint32_t n = 0xffffffff;
    for (auto b : bytes) {
        n ^= b;
        for (unsigned bit = 0; bit < 8; ++bit) n = (n >> 1) ^ ((n & 1) ? 0xedb88320 : 0);
    }
    return ~n;
}
Bytes gpt(Fixture f, bool lvm_pv = false, bool generic_type = false) {
    auto& b = f.bytes;
    if (lvm_pv) b.resize(f.root+13*1024*1024);
    const auto last = static_cast<std::uint32_t>(b.size()/512-1);
    std::fill(b.begin()+446, b.begin()+510, 0);
    b[450] = 0xee; put(b, 454, 1); put(b, 458, last);
    Bytes entries(16384);
    const Bytes esp{0x28,0x73,0x2a,0xc1,0x1f,0xf8,0xd2,0x11,0xba,0x4b,0,0xa0,0xc9,0x3e,0xc9,0x3b};
    const Bytes linux_type{0xaf,0x3d,0xc6,0x0f,0x83,0x84,0x72,0x47,0x8e,0x79,0x3d,0x69,0xd8,0x47,0x7d,0xe4};
    const Bytes lvm_type{0x79,0xd3,0xd6,0xe6,0x07,0xf5,0xc2,0x44,0xa2,0x3c,0x23,0x8f,0x2a,0x3d,0xf9,0x28};
    std::copy(esp.begin(), esp.end(), entries.begin());
    const auto& second_type = lvm_pv && !generic_type ? lvm_type : linux_type;
    std::copy(second_type.begin(),second_type.end(), entries.begin()+128);
    entries[16] = 1; entries[144] = 2;
    put(entries, 32, boot/512); put(entries, 40, (f.root-1024*1024)/512-1);
    put(entries, 160, f.root/512);
    put(entries, 168, (f.root+(lvm_pv ? 12 : 4)*1024*1024)/512-1);
    for (const auto lba : {1U, last}) {
        Bytes h(512);
        const std::string sig = "EFI PART";
        std::copy(sig.begin(), sig.end(), h.begin());
        put(h, 8, 0x10000); put(h, 12, 92);
        put(h, 24, lba); put(h, 32, lba == 1 ? last : 1);
        put(h, 40, 34); put(h, 48, last-33); h[56] = 9;
        const auto table = lba == 1 ? 2U : last-32;
        put(h, 72, table); put(h, 80, 128); put(h, 84, 128);
        put(h, 88, crc(entries)); put(h, 16, crc(std::span(h).first(92)));
        std::copy(h.begin(), h.end(), b.begin()+lba*512);
        std::copy(entries.begin(), entries.end(), b.begin()+table*512);
    }
    return b;
}
void reject(Bytes bytes, std::string_view reason) {
    try { metadata(std::move(bytes)); }
    catch (const Error& e) {
        if (std::string_view(e.what()).find(reason) == std::string_view::npos)
            throw Error(std::string("unexpected rejection: ")+e.what());
        return;
    }
    throw Error("invalid machine image accepted");
}
void transfer_source(ImageSource& source, const Bytes& original, TransferCompression compression, std::uint64_t start) {
    std::uint64_t next = start;
    stream_image(source, "pi-card", 1024*1024, [&](const Value& block) {
        const auto& obj = std::get<Value::Object>(block.data);
        const auto at = std::get<std::uint64_t>(obj.at("offset").data);
        const auto size = std::get<std::uint64_t>(obj.at("length").data);
        check(at == next && size <= original.size()-at);
        auto data = std::get<Bytes>(obj.at("buffer").data);
        if (compression == TransferCompression::lz4) {
            Bytes plain(size);
            check(LZ4_decompress_safe(reinterpret_cast<const char*>(data.data()),
                reinterpret_cast<char*>(plain.data()), static_cast<int>(data.size()),
                static_cast<int>(size)) == static_cast<int>(size));
            data = std::move(plain);
        }
        check(data.size() == size && std::equal(data.begin(), data.end(), original.begin()+at));
        next += size;
    }, {}, start, compression);
    check(next == original.size());
}
void transfer(const Bytes& original, TransferCompression compression, std::uint64_t start) {
    ImageSource source(original);
    transfer_source(source, original, compression, start);
}
void difference_transfer(const Fixture& fixture) {
    auto current = fixture.bytes;
    // Changes inside boot, root and the gap between partitions. Metadata stays
    // valid; both original and current are complete disk images.
    current[boot+2*1024*1024+17] ^= 0x5a;
    current[fixture.root-512] ^= 0x42;
    current[fixture.root+2*1024*1024+99] ^= 0xff;
    ImageSource base(fixture.bytes), source(current);
    const auto plan = image_delta_plan(base,source);
    check(plan.transfer_bytes < current.size());
    check(delta_plan_value(delta_plan_from_value(delta_plan_value(plan),source.size())) == delta_plan_value(plan));
    (void)fixed_image_metadata(source,512,"pi-card",1700000000,&plan);
    for (auto compression : {TransferCompression::none,TransferCompression::lz4}) {
        for (auto start : {std::uint64_t{0}, std::uint64_t{boot+512},
                           std::uint64_t{fixture.root+2*1024*1024+512}}) {
            auto rebuilt = fixture.bytes;
            std::copy_n(current.begin(),static_cast<std::size_t>(start),rebuilt.begin());
            std::uint64_t next = start, inherited = 0;
            stream_image(source,"pi-card",1024*1024,[&](const Value& block) {
                const auto& o = std::get<Value::Object>(block.data);
                const auto at = std::get<std::uint64_t>(o.at("offset").data);
                const auto length = std::get<std::uint64_t>(o.at("length").data);
                check(at == next);
                if (std::get<std::uint64_t>(o.at("changed").data)) {
                    auto bytes = std::get<Bytes>(o.at("buffer").data);
                    if (compression == TransferCompression::lz4) {
                        Bytes plain(length);
                        check(LZ4_decompress_safe(reinterpret_cast<const char*>(bytes.data()),
                            reinterpret_cast<char*>(plain.data()),static_cast<int>(bytes.size()),
                            static_cast<int>(length)) == static_cast<int>(length));
                        bytes = std::move(plain);
                    }
                    std::copy(bytes.begin(),bytes.end(),rebuilt.begin()+at);
                } else {
                    check(!o.contains("buffer"));
                    inherited += length;
                }
                next += length;
            },{},start,compression,&plan);
            check(next == current.size() && inherited && rebuilt == current);
        }
    }
    const auto unchanged = image_delta_plan(base,base);
    check(unchanged.transfer_bytes == 2*1024*1024);
    bool cancelled = false;
    try { image_delta_plan(base,source,[] { return true; }); }
    catch (const Cancelled&) { cancelled = true; }
    check(cancelled);
    ImageSource wrong(Bytes(current.size()+4096));
    bool rejected = false;
    try { image_delta_plan(base,wrong); } catch (const Error&) { rejected = true; }
    check(rejected);
}
void whole_pv_wire_fixture(bool mbr, bool generic_type) {
    constexpr std::uint64_t mib = 1024*1024;
    const auto fixture = disk(true);
    auto source_bytes = mbr ? fixture.bytes : gpt(fixture,true,generic_type);
    if (mbr) {
        source_bytes.resize(fixture.root+13*mib);
        source_bytes[466] = generic_type ? 0x83 : 0x8e;
        put(source_bytes,474,12*mib/512);
    }
    ImageSource source(source_bytes);
    const auto layout = layout_value(inspect_image_layout(source,512));
    const std::string root_uuid = "01020304-0506-0708-090a-0b0c0d0e0f10";
    const std::string selected_uuid = "14151617-1819-1a1b-1c1d-1e1f20212223";
    const auto root_bytes = Bytes(source_bytes.begin()+static_cast<std::ptrdiff_t>(fixture.root),
                                  source_bytes.begin()+static_cast<std::ptrdiff_t>(fixture.root+4*mib));
    auto selected_bytes = root_bytes;
    for (unsigned index = 0; index < 16; ++index)
        selected_bytes[1024+0x68+index] = static_cast<std::uint8_t>(20+index);
    for (const auto pe_start : {mib,2*mib}) {
        Value root{Value::Object{
            {"lv_uuid",Value{std::string("root-lv")}},
            {"vg_uuid",Value{std::string("source-vg")}},
            {"image_name",Value{std::string("source=root.img")}},
            {"logical_path",Value{std::string("/dev/source/root")}},
            {"length",Value{4*mib}},{"mount_path",Value{std::string("/")}},
            {"filesystem",Value{std::string("ext4")}},
            {"filesystem_uuid",Value{root_uuid}}}};
        Value selected{Value::Object{
            {"lv_uuid",Value{std::string("selected-lv")}},
            {"vg_uuid",Value{std::string("source-vg")}},
            {"image_name",Value{std::string("source=selected.img")}},
            {"logical_path",Value{std::string("/dev/source/selected")}},
            {"length",Value{4*mib}},{"mount_path",Value{std::string("/data")}},
            {"filesystem",Value{std::string("ext4")}},
            {"filesystem_uuid",Value{selected_uuid}}}};
        Value::Object group{
            {"name",Value{std::string("source")}},
            {"uuid",Value{std::string("source-vg")}},
            {"extent_size",Value{4*mib}},
            {"mda_size",Value{mib}},
            {"total_size",Value{12*mib-pe_start-mib}},
            {"physical_volumes",Value{Value::Array{Value{Value::Object{
                {"name",Value{std::string("/dev/sda2")}},
                {"uuid",Value{std::string("source-pv")}},
                {"size",Value{12*mib-pe_start-mib}}}}}}},
            {"logical_volumes",Value{Value::Array{}}}};
        Value plan{Value::Object{
            {"layout",layout},
            {"root",root},
            {"boot",Value{Value::Object{
                {"partition",Value{std::uint64_t{1}}},{"offset",Value{std::uint64_t{boot}}},
                {"device",Value{std::string("/dev/sda1")}},
                {"length",Value{std::uint64_t{36*mib}}},
                {"mount_path",Value{std::string("/boot/efi")}},
                {"filesystem",Value{std::string("vfat")}},
                {"filesystem_uuid",Value{std::string("1234-ABCD")}}}}},
            {"selected_extra",Value{Value::Array{selected}}},
            {"excluded",Value{Value::Array{Value{Value::Object{
                {"partition",Value{std::uint64_t{2}}},
                {"offset",Value{std::uint64_t{fixture.root}}},
                {"length",Value{12*mib}},
                {"device",Value{std::string("/dev/sda2")}},
                {"mount_path",Value{std::string("")}},
                {"filesystem",Value{std::string("LVM2_member")}},
                {"pv_uuid",Value{std::string("source-pv")}},
                {"vg_uuid",Value{std::string("source-vg")}},
                {"pv_wire_policy",Value{std::string("whole-partition-zero")}},
                {"pv_metadata_length",Value{pe_start}},
                {"pv_extent_length",Value{12*mib-pe_start-mib}},
                {"pv_tail_length",Value{mib}}}}}}},
            {"lvm",Value{Value::Object{
                {"volume_groups",Value{Value::Array{Value{std::move(group)}}}}}}}}};
        auto wire_bytes = source_bytes;
        const auto regions = machine_static_regions(plan);
        bool saw_pv = false;
        for (const auto& region : regions) if (!region.read_source) {
            check(region.offset == fixture.root && region.length == 12*mib);
            std::fill(wire_bytes.begin()+static_cast<std::ptrdiff_t>(region.offset),
                      wire_bytes.begin()+static_cast<std::ptrdiff_t>(region.offset+region.length),0);
            saw_pv = true;
        }
        check(saw_pv && std::all_of(
            wire_bytes.begin()+static_cast<std::ptrdiff_t>(fixture.root),
            wire_bytes.begin()+static_cast<std::ptrdiff_t>(fixture.root+12*mib),
            [](auto value) { return value == 0; }));
        ImageSource physical(std::move(wire_bytes)), root_image(root_bytes),
                    selected_image(selected_bytes);
        const MetadataDisk images[]{
            {&physical,512,"sda.img",&plan,nullptr},
            {&root_image,512,"source=root.img",&root,nullptr},
            {&selected_image,512,"source=selected.img",&selected,nullptr}};
        const auto result = fixed_machine_metadata(images,1700000000);
        const std::string wire(result.begin(),result.end());
        check(wire.find("\"is_bootable\":true") != std::string::npos);
        check(wire.find("\"file_system\":\"LVM2_member\"") != std::string::npos);
        check(wire.find("\"type\":5") != std::string::npos);
        check(wire.find("\"source=root.img\"") != std::string::npos);
        check(wire.find("\"source=selected.img\"") != std::string::npos);
        check(wire.find("\"physical_volumes\"") != std::string::npos);
        check(wire.find("\"disk_number\":\"-1\"") != std::string::npos);
        const auto captured_layout = inspect_image_layout(physical,512);
        check(mbr ? captured_layout.partitions[1].mbr_type == (generic_type ? 0x83 : 0x8e) :
            captured_layout.partitions[1].type_guid == (generic_type ?
                "0fc63daf-8483-4772-8e79-3d69d8477de4" :
                "e6d6d379-f507-44c2-a23c-238f2a3df928"));
        // A selected nonlinear LV still has one logical image; all VG PV
        // layouts travel separately with complete unused partition intervals.
        auto multi_plan = plan;
        auto& multi_group = std::get<Value::Object>(std::get<Value::Array>(
            std::get<Value::Object>(std::get<Value::Object>(multi_plan.data).at("lvm").data)
                .at("volume_groups").data).front().data);
        auto& multi_pvs = std::get<Value::Array>(multi_group.at("physical_volumes").data);
        multi_pvs.push_back(Value{Value::Object{
            {"name",Value{std::string("/dev/sdb2")}},
            {"uuid",Value{std::string("second-pv")}},
            {"size",Value{12*mib-pe_start-mib}}}});
        multi_group["total_size"] = Value{2*(12*mib-pe_start-mib)};
        auto second_pv = std::get<Value::Array>(
            std::get<Value::Object>(plan.data).at("excluded").data).front();
        auto& second_fields = std::get<Value::Object>(second_pv.data);
        second_fields["pv_uuid"] = Value{std::string("second-pv")};
        second_fields["device"] = Value{std::string("/dev/sdb2")};
        auto second_boot = std::get<Value::Object>(plan.data).at("boot");
        std::get<Value::Object>(second_boot.data)["mount_path"] = Value{std::string{}};
        Value second_plan{Value::Object{{"layout",layout},
            {"selected_extra",Value{Value::Array{}}},
            {"excluded",Value{Value::Array{second_boot,second_pv}}}}};
        auto second_bytes = physical.read(0,static_cast<std::size_t>(physical.size()));
        for (const auto& region : machine_additional_static_regions(second_plan))
            if (!region.read_source)
                std::fill(second_bytes.begin()+static_cast<std::ptrdiff_t>(region.offset),
                    second_bytes.begin()+static_cast<std::ptrdiff_t>(region.offset+region.length),0);
        ImageSource second_disk(std::move(second_bytes));
        auto nonlinear = selected;
        std::get<Value::Object>(nonlinear.data)["segments"] = Value{Value::Array{
            Value{Value::Object{{"type",Value{std::string("raid1")}},
                {"kernel_topology",Value{std::string("local source validation only")}}}}}};
        const MetadataDisk multi_images[]{
            {&physical,512,"sda.img",&multi_plan,nullptr},
            {&second_disk,512,"sdb.img",&second_plan,nullptr},
            {&root_image,512,"source=root.img",&root,nullptr},
            {&selected_image,512,"source=selected.img",&nonlinear,nullptr}};
        const auto multi_result = fixed_machine_metadata(multi_images,1700000000);
        const std::string multi_wire(multi_result.begin(),multi_result.end());
        check(multi_wire.find("\"name\":\"/dev/sdb2\"") != std::string::npos);
        check(multi_wire.find("\"uuid\":\"second-pv\"") != std::string::npos);
        check(multi_wire.find("\"sdb.img\"") != std::string::npos);
        check(multi_wire.find("kernel_topology") == std::string::npos);
        // VG metadata is global. An uncaptured sibling PV and an unrelated
        // scratch VG do not authorize payload or invalidate selected images.
        auto inventory_plan = multi_plan;
        auto& inventory_fields = std::get<Value::Object>(inventory_plan.data);
        auto& inventory_groups = std::get<Value::Array>(std::get<Value::Object>(
            inventory_fields.at("lvm").data).at("volume_groups").data);
        auto scratch = inventory_groups.front();
        auto& scratch_fields = std::get<Value::Object>(scratch.data);
        scratch_fields["name"] = Value{std::string("scratch")};
        scratch_fields["uuid"] = Value{std::string("scratch-vg")};
        scratch_fields["physical_volumes"] = Value{Value::Array{Value{Value::Object{
            {"name",Value{std::string("/dev/sdz1")}},{"uuid",Value{std::string("scratch-pv")}},
            {"size",Value{4*mib}}}}}};
        inventory_groups.push_back(scratch);
        auto unselected = second_plan;
        auto& unselected_fields = std::get<Value::Object>(unselected.data);
        unselected_fields["image_name"] = Value{std::string("sdb.img")};
        unselected_fields["disk_number"] = Value{std::uint64_t{1}};
        unselected_fields["layout_policy"] = Value{std::string("linux-layout-v1")};
        inventory_fields["unselected_disks"] = Value{Value::Array{unselected}};
        auto idle = selected;
        auto& idle_fields = std::get<Value::Object>(idle.data);
        idle_fields["lv_uuid"] = Value{std::string("idle-lv")};
        idle_fields["logical_path"] = Value{std::string("/dev/source/idle")};
        idle_fields["mount_path"] = Value{std::string{}};
        idle_fields["image_name"] = Value{std::string("source=idle.img")};
        inventory_fields["unselected_logical"] = Value{Value::Array{idle}};
        MetadataDisk selected_only[]{
            {&physical,512,"sda.img",&inventory_plan},
            {&root_image,512,"source=root.img",&root},
            {&selected_image,512,"source=selected.img",&selected}};
        const auto filtered = fixed_machine_metadata(selected_only,1700000000);
        const std::string selected_wire(filtered.begin(),filtered.end());
        check(selected_wire.find("\"need_upload\":false") != std::string::npos);
        check(selected_wire.find("\"uuid\":\"second-pv\"") != std::string::npos);
        check(selected_wire.find("\"uuid\":\"scratch-pv\"") != std::string::npos);
        check(selected_wire.find("\"image_name\":\"sdb.img\",\"length\"") == std::string::npos);
        check(selected_wire.find("\"image_name\":\"source=idle.img\",\"need_upload\":false") !=
            std::string::npos);
        // A logical snapshot origin needs no physical source or fabricated
        // disk image. Discovery metadata still accompanies its one LV image.
        auto logical_inventory = inventory_plan;
        std::get<Value::Object>(logical_inventory.data).erase("layout");
        std::get<Value::Object>(logical_inventory.data)["selected_extra"] = Value{Value::Array{}};
        MetadataDisk lv_only{&root_image,512,"source=root.img",&root};
        lv_only.machine_inventory = &logical_inventory;
        const auto logical_result = fixed_machine_metadata(std::span(&lv_only,1),1700000000);
        const std::string logical_wire(logical_result.begin(),logical_result.end());
        check(logical_wire.find("\"need_upload\":false") != std::string::npos);
        check(logical_wire.find("\"uuid\":\"scratch-pv\"") != std::string::npos);
        check(logical_wire.find("\"image_name\":\"sda.img\",\"length\"") == std::string::npos);
        auto contaminated = source_bytes;
        ImageSource wrong(std::move(contaminated));
        const MetadataDisk invalid[]{
            {&wrong,512,"sda.img",&plan,nullptr},
            {&root_image,512,"source=root.img",&root,nullptr},
            {&selected_image,512,"source=selected.img",&selected,nullptr}};
        bool rejected = false;
        try { (void)fixed_machine_metadata(invalid,1700000000); }
        catch (const Error& error) {
            rejected = std::string_view(error.what()).find("nonzero") != std::string_view::npos;
        }
        check(rejected);
    }
}
}
int main(int argc, char** argv) {
    try {
        if (argc == 2) {
            ImageSource source(argv[1]);
            for (const auto& range : filesystem_unused_extents(source.size(),[&](auto at,auto size) {
                return source.read(at,size);
            })) std::cout << range.offset << ' ' << range.length << std::endl;
            return 0;
        }
        allocation_maps();
        // Both table schemes preserve generic PV types while emitting the same
        // whole-partition-unused physical image and separate logical images.
        for (const bool mbr : {false,true})
            for (const bool generic_type : {false,true})
                whole_pv_wire_fixture(mbr,generic_type);
        {
            const auto f = disk(true);
            auto extra = f.bytes;
            std::fill(extra.begin()+boot,extra.begin()+f.root-1024*1024,0);
            ImageSource primary(f.bytes), secondary(extra);
            const auto layout = inspect_image_layout(secondary,512);
            Value::Object selected{
                {"partition",Value{std::uint64_t{2}}},
                {"device",Value{std::string("/dev/sdb2")}},
                {"offset",Value{std::uint64_t{f.root}}},
                {"length",Value{std::uint64_t{4*1024*1024}}},
                {"mount_path",Value{std::string("/data")}},
                {"filesystem",Value{std::string("ext4")}},
                {"filesystem_uuid",Value{std::string("01020304-0506-0708-090a-0b0c0d0e0f10")}}};
            Value::Object excluded{
                {"partition",Value{std::uint64_t{1}}},
                {"offset",Value{std::uint64_t{boot}}},
                {"length",Value{std::uint64_t{36*1024*1024}}},
                {"mount_path",Value{std::string("/unused")}},
                {"filesystem",Value{std::string("vfat")}}};
            Value extra_plan{Value::Object{
                {"layout",layout_value(layout)},
                {"selected_extra",Value{Value::Array{Value{std::move(selected)}}}},
                {"excluded",Value{Value::Array{Value{std::move(excluded)}}}}}};
            const MetadataDisk disks[]{
                {&primary,512,"primary",nullptr,nullptr},
                {&secondary,512,"secondary",&extra_plan,nullptr}};
            const auto wire = fixed_machine_metadata(disks,1700000000);
            const std::string json(wire.begin(),wire.end());
            check(json.find("\"disk_number\":\"1\"") != std::string::npos);
            check(json.find("\"image_name\":\"secondary\"") != std::string::npos);
            check(json.find("\"mount_path\":\"/data\"") != std::string::npos);
            check(json.find("\"is_excluded\":true") != std::string::npos);
            const auto expected_mount = "\"mount_map\":{\"/data\":{\"mount_path\":\"/data\","
                "\"object_id\":0,\"image_path\":\"secondary\",\"device_name\":\"/dev/sdb2\","
                "\"alias_name\":\"/data\",\"disk_number\":1,\"partition_number\":2,"
                "\"target_partition_number\":-1,\"volume_uuid\":\"\",\"fs_type\":\"\","
                "\"valid_offset_length\":true,\"is_system\":false,\"is_primary_partition\":true,"
                "\"offset\":\""+std::to_string(f.root)+"\",\"length\":\"4194304\",\"is_mbr\":true}}";
            check(mount_map_json(json) == expected_mount);
            auto raw_plan = extra_plan;
            auto& raw_fields = std::get<Value::Object>(raw_plan.data);
            raw_fields["volume_policy"] = Value{std::string("linux-bare-metal-v1")};
            raw_fields["swap_page_size"] = Value{std::uint64_t{4096}};
            auto& raw_boot = std::get<Value::Array>(raw_fields.at("excluded").data).front();
            auto& raw_boot_fields = std::get<Value::Object>(raw_boot.data);
            raw_boot_fields["mount_path"] = Value{std::string("/boot/extra")};
            raw_boot_fields["device"] = Value{std::string("/dev/sdb1")};
            record_machine_raw_volume_uuid(raw_boot,[] { return std::string("1234-ABCD"); });
            MetadataDisk raw_disks[]{disks[0],{&primary,512,"secondary",&raw_plan}};
            const auto raw_bytes = fixed_machine_metadata(raw_disks,1700000000);
            const std::string raw_json(raw_bytes.begin(),raw_bytes.end());
            check(mount_map_json(raw_json).find("\"/boot/extra\":{\"mount_path\":\"/boot/extra\","
                "\"object_id\":0,\"image_path\":\"secondary\",\"device_name\":\"/dev/sdb1\","
                "\"alias_name\":\"/boot/extra\",\"disk_number\":1,\"partition_number\":1") != std::string::npos);
            check(raw_json.find("\"type\":2") != std::string::npos);
            raw_boot_fields["filesystem_uuid"] = Value{std::uint64_t{7}};
            bool bad_uuid = false;
            try { (void)fixed_machine_metadata(raw_disks,1700000000); }
            catch (const Error& error) { bad_uuid = std::string_view(error.what()).find("invalid machine metadata text") != std::string_view::npos; }
            check(bad_uuid);
            raw_boot_fields.erase("filesystem_uuid");
            const auto unnamed_bytes = fixed_machine_metadata(raw_disks,1700000000);
            check(mount_map_json(std::string(unnamed_bytes.begin(),unnamed_bytes.end())).find(
                "\"/boot/extra\":{") == std::string::npos);
            raw_boot_fields["filesystem"] = Value{std::string("ntfs")};
            raw_boot_fields["filesystem_uuid"] = Value{std::string("0123456789ABCDEF")};
            const auto ntfs_bytes = fixed_machine_metadata(raw_disks,1700000000);
            const std::string ntfs_json(ntfs_bytes.begin(),ntfs_bytes.end());
            check(mount_map_json(ntfs_json).find("\"/boot/extra\":{") == std::string::npos);
            check(ntfs_json.find("\"type\":2") != std::string::npos); // Raw payload is still retained.
            // The generic first image has no captured mount identities, and
            // the excluded second-disk /unused partition is not mountable.
            const auto generic = fixed_image_metadata(primary,512,"generic",1700000000);
            check(mount_map_json(std::string(generic.begin(),generic.end())) == "\"mount_map\":{}");
            MetadataDisk omitted_disks[]{disks[0],disks[1]};
            omitted_disks[1].omitted_snapshots = {{f.root,4*1024*1024}};
            const auto omitted_bytes = fixed_machine_metadata(omitted_disks,1700000000);
            const std::string omitted_json(omitted_bytes.begin(),omitted_bytes.end());
            check(mount_map_json(omitted_json) == "\"mount_map\":{}");
            check(omitted_json.find("\"image_name\":\"secondary\",\"need_upload\":true") != std::string::npos);
            MetadataDisk duplicate_images[]{disks[0],disks[1]};
            duplicate_images[1].image_name = duplicate_images[0].image_name;
            bool duplicate_name = false;
            try { (void)fixed_machine_metadata(duplicate_images,1700000000); }
            catch (const Error& error) { duplicate_name = std::string_view(error.what()).find("duplicate machine image name") != std::string_view::npos; }
            check(duplicate_name);
            auto changed_primary = f.bytes, changed_secondary = extra;
            changed_primary[f.root+2*1024*1024+17] ^= 0x51;
            changed_secondary[f.root+1024*1024+23] ^= 0x32;
            changed_secondary[f.root+3*1024*1024+23] ^= 0x13;
            ImageSource primary_after(std::move(changed_primary));
            ImageSource secondary_after(std::move(changed_secondary));
            const auto first_delta = image_delta_plan(primary,primary_after);
            const auto second_delta = image_delta_plan(secondary,secondary_after);
            check(first_delta.transfer_bytes != second_delta.transfer_bytes);
            const MetadataDisk incremental_disks[]{
                {&primary_after,512,"primary",nullptr,&first_delta},
                {&secondary_after,512,"secondary",&extra_plan,&second_delta}};
            const auto delta_wire = fixed_machine_metadata(incremental_disks,1700000000);
            const std::string delta_json(delta_wire.begin(),delta_wire.end());
            check(delta_json.find("\"is_cbt\"") == std::string::npos);
            check(mount_map_json(delta_json) == expected_mount);
            check(delta_json.find("\"transfer_length\":\""+
                std::to_string(first_delta.transfer_bytes)+"\"") != std::string::npos);
            check(delta_json.find("\"transfer_length\":\""+
                std::to_string(second_delta.transfer_bytes)+"\"") != std::string::npos);
            const MetadataDisk partial_disks[]{
                {&primary_after,512,"primary",nullptr,&first_delta},
                {&secondary_after,512,"secondary",&extra_plan,nullptr}};
            bool missing_delta = false;
            try { (void)fixed_machine_metadata(partial_disks,1700000000); }
            catch (const Error&) { missing_delta = true; }
            check(missing_delta);
            auto& selected_fields = std::get<Value::Object>(
                std::get<Value::Array>(
                    std::get<Value::Object>(extra_plan.data).at("selected_extra").data
                ).front().data);
            for (const auto* wrong : {"ext2","ext3","xfs"}) {
                selected_fields["filesystem"] = Value{std::string(wrong)};
                bool mismatch = false;
                try { (void)fixed_machine_metadata(disks,1700000000); }
                catch (const Error& error) {
                    mismatch = std::string_view(error.what()).find("identity") != std::string_view::npos;
                }
                check(mismatch);
            }
            selected_fields["filesystem"] = Value{std::string("ext4")};
            selected_fields["filesystem_uuid"] =
                Value{std::string("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")};
            bool wrong_uuid = false;
            try { (void)fixed_machine_metadata(disks,1700000000); }
            catch (const Error& error) {
                wrong_uuid = std::string_view(error.what()).find("identity") != std::string_view::npos;
            }
            check(wrong_uuid);
            selected_fields["filesystem_uuid"] =
                Value{std::string("01020304-0506-0708-090a-0b0c0d0e0f10")};
            for (const auto* format : {"ext2","ext3"}) {
                auto compatible = extra;
                const auto sb = f.root+1024;
                put(compatible,sb+0x60,0); // No ext4-only feature.
                if (std::string_view(format) == "ext3") {
                    put(compatible,sb+0x5c,4); // Internal journal.
                    put(compatible,sb+0xe0,8);
                }
                ImageSource source(std::move(compatible));
                selected_fields["filesystem"] = Value{std::string(format)};
                const auto native = fixed_image_metadata(source,512,"compatible",1700000000,
                                                         nullptr,&extra_plan);
                const std::string native_json(native.begin(),native.end());
                check(native_json.find(std::string("\"file_system\":\"")+format+"\"") !=
                      std::string::npos);
                selected_fields["filesystem"] = Value{std::string("ext4")};
                const auto aliased = fixed_image_metadata(source,512,"compatible",1700000000,
                                                          nullptr,&extra_plan);
                const std::string aliased_json(aliased.begin(),aliased.end());
                check(aliased_json.find("\"file_system\":\"ext4\"") != std::string::npos);
                check(aliased_json.find(std::string("\"file_system\":\"")+format+"\"") ==
                      std::string::npos);
                selected_fields["filesystem"] = Value{std::string(
                    std::string_view(format) == "ext2" ? "ext3" : "ext2")};
                bool incompatible = false;
                try { (void)fixed_image_metadata(source,512,"compatible",1700000000,
                                                 nullptr,&extra_plan); }
                catch (const Error& error) {
                    incompatible = std::string_view(error.what()).find("identity") !=
                                   std::string_view::npos;
                }
                check(incompatible);
            }
            selected_fields["filesystem"] = Value{std::string("ext4")};
            std::map<std::string,std::uint64_t> transferred;
            const auto offsets = backup_resume_offsets(
                "{\"primary\":{\"current\":\"512\",\"transfer_current\":\"1\"},"
                "\"secondary\":{\"current\":\"1024\",\"transfer_current\":\"2\"}}",
                {{"primary",primary.size()},{"secondary",secondary.size()}},&transferred);
            check(offsets.at("primary") == 512 && offsets.at("secondary") == 1024);
            check(transferred.at("primary") == 1 && transferred.at("secondary") == 2);
            check(backup_resume_offsets(
                "{\"primary\":{\"current\":\"512\",\"transfer_current\":\"1\"}}",
                {{"primary",primary.size()},{"secondary",secondary.size()}}).at("secondary") == 0);
            bool duplicate = false;
            try {
                (void)backup_resume_offsets(
                    "{\"primary\":{\"current\":\"0\",\"transfer_current\":\"0\"},"
                    "\"primary\":{\"current\":\"0\",\"transfer_current\":\"0\"}}",
                    {{"primary",primary.size()}});
            } catch (const Error&) { duplicate = true; }
            check(duplicate);
        }
        for (const bool fat32 : {false, true}) {
            const auto f = disk(fat32);
            difference_transfer(f);
            const auto json = metadata(f.bytes);
            check(json.find("\"volume_name\":\"1234-ABCD\"") != std::string::npos);
            check(json.find("\"file_system\":\"vfat\"") != std::string::npos);
            check(json.find("\"file_system\":\"ext4\"") != std::string::npos);
            check(json.find("\"is_bootable\":false") != std::string::npos);
            check(json.find("\"offset\":\""+std::to_string(f.root)+"\"") != std::string::npos);
            transfer(f.bytes, TransferCompression::none, 0);
            transfer(f.bytes, TransferCompression::lz4, 0);
            transfer(f.bytes, TransferCompression::none, f.root-512);
            auto b = f.bytes; put(b, f.fat+(fat32 ? 4 : 2), 0, fat32 ? 4 : 2);
            reject(std::move(b), "dirty");
            b = f.bytes; put(b, f.fat_copy+(fat32 ? 4 : 2), 0, fat32 ? 4 : 2);
            reject(std::move(b), "dirty");
            b = f.bytes; b[boot+13] = 3; reject(std::move(b), "geometry");
            b = f.bytes; put(b, boot+11, 4096, 2); reject(std::move(b), "sector size");
            b = f.bytes; put(b, f.root+1024+0x3a, 0, 2); reject(std::move(b), "clean");
            b = f.bytes; b[450] = fat32 ? 0x06 : 0x0c; reject(std::move(b), "variant");
            b = f.bytes; b[450] = 0x07; reject(std::move(b), "unsupported partition");
            if (fat32) {
                b = f.bytes; b[boot+65] ^= 1; check(metadata(b) == json);
                b = f.bytes; b[boot+6*512+65] ^= 1; check(metadata(b) == json);
                b = f.bytes; b[boot+6*512+65] ^= 2; reject(std::move(b), "backup boot");
                b = f.bytes; put(b, f.fat+8, 0); reject(std::move(b), "root directory");
                b = f.bytes; b[boot+6*512+67] ^= 1; reject(std::move(b), "backup boot");
                b = f.bytes; put(b, boot+36, 1); reject(std::move(b), "cannot address");
                b = f.bytes; put(b, boot+32, 0xffffffff); reject(std::move(b), "exceeds");
            }
        }
        auto bytes = gpt(disk(true));
        auto gpt_fixture = disk(true);
        gpt_fixture.bytes = bytes;
        difference_transfer(gpt_fixture);
        check(metadata(bytes).find("\"disk_layout\":\"GPT\"") != std::string::npos);
        {
            ImageSource efi_source(bytes);
            const auto efi_plan = Value{Value::Object{
                {"layout",layout_value(inspect_image_layout(efi_source,512))},
                {"boot",Value{Value::Object{
                    {"partition",Value{std::uint64_t{1}}},
                    {"device",Value{std::string("/dev/nvme0n1p1")}},
                    {"offset",Value{std::uint64_t{boot}}},
                    {"length",Value{std::uint64_t{36*1024*1024}}},
                    {"mount_path",Value{std::string("/boot/efi")}},
                    {"filesystem",Value{std::string("vfat")}},
                    {"filesystem_uuid",Value{std::string("1234-ABCD")}}}}},
                {"root",Value{Value::Object{
                    {"partition",Value{std::uint64_t{2}}},
                    {"device",Value{std::string("/dev/nvme0n1p2")}},
                    {"offset",Value{std::uint64_t{gpt_fixture.root}}},
                    {"length",Value{std::uint64_t{4*1024*1024}}},
                    {"mount_path",Value{std::string("/")}},
                    {"filesystem",Value{std::string("ext4")}},
                    {"filesystem_uuid",Value{std::string("01020304-0506-0708-090a-0b0c0d0e0f10")}}}}}}};
            const auto descriptor_bytes = fixed_image_metadata(
                efi_source,512,"debian-gpt",1700000000,nullptr,&efi_plan);
            const std::string descriptor(descriptor_bytes.begin(),descriptor_bytes.end());
            check(descriptor.find("\"disk_layout\":\"GPT\"") != std::string::npos);
            check(descriptor.find("\"mount_path\":\"/boot/efi\"") != std::string::npos);
            check(descriptor.find("\"is_bootable\":true") != std::string::npos);
            const auto gpt_mounts = "\"mount_map\":{\"/\":{\"mount_path\":\"/\",\"object_id\":0,"
                "\"image_path\":\"debian-gpt\",\"device_name\":\"/dev/nvme0n1p2\",\"alias_name\":\"/\","
                "\"disk_number\":0,\"partition_number\":2,\"target_partition_number\":-1,"
                "\"volume_uuid\":\"\",\"fs_type\":\"\",\"valid_offset_length\":true,\"is_system\":true,"
                "\"is_primary_partition\":false,\"offset\":\""+std::to_string(gpt_fixture.root)+
                "\",\"length\":\"4194304\",\"is_mbr\":false},"
                "\"/boot/efi\":{\"mount_path\":\"/boot/efi\",\"object_id\":0,\"image_path\":\"debian-gpt\","
                "\"device_name\":\"/dev/nvme0n1p1\",\"alias_name\":\"/boot/efi\",\"disk_number\":0,"
                "\"partition_number\":1,\"target_partition_number\":-1,\"volume_uuid\":\"\",\"fs_type\":\"\","
                "\"valid_offset_length\":true,\"is_system\":true,\"is_primary_partition\":false,"
                "\"offset\":\"1048576\",\"length\":\"37748736\",\"is_mbr\":false}}";
            check(mount_map_json(descriptor) == gpt_mounts);
            {
                const ChangedExtent failed{gpt_fixture.root,4*1024*1024};
                ImageSource missing(bytes.size(),[&](std::uint64_t at,std::size_t count,auto*) {
                    if (at < failed.offset+failed.length && at+count > failed.offset)
                        throw Error("omitted filesystem was read");
                    return Bytes(bytes.begin()+static_cast<std::ptrdiff_t>(at),
                        bytes.begin()+static_cast<std::ptrdiff_t>(at+count));
                },[] {});
                MetadataDisk omitted{&missing,512,"debian-gpt",&efi_plan};
                omitted.omitted_snapshots = {failed};
                omitted.additional_unused = {failed};
                const auto result = fixed_machine_metadata(std::span(&omitted,1),1700000000);
                const std::string json(result.begin(),result.end());
                check(json.find("\"type\":4") != std::string::npos);
                check(json.find("\"path\":\"\",\"snapshot_id\":\"\",\"file_system\":\"ext4\"") != std::string::npos);
                check(json.find("\"/\":{\"mount_path\":\"/\"") == std::string::npos);
                check(json.find("\"is_bootable\":false") != std::string::npos);
                check(mount_map_json(json).find("\"/boot/efi\":{") != std::string::npos);
                check(json.find("\"image_name\":\"debian-gpt\",\"need_upload\":true") != std::string::npos);
                for (const bool incremental : {false,true}) {
                    DeltaPlan delta{missing.size(),missing.size(),{{0,missing.size(),true}}};
                    std::uint64_t no_payload = 0;
                    stream_image(missing,"debian-gpt",1024*1024,[&](const Value& block) {
                        const auto& fields = std::get<Value::Object>(block.data);
                        const auto at = std::get<std::uint64_t>(fields.at("offset").data);
                        if (at >= failed.offset && at < failed.offset+failed.length) {
                            check(fields.at("used") == Value{std::uint64_t{0}} &&
                                fields.at("changed") == Value{std::uint64_t{1}} && !fields.contains("buffer"));
                            no_payload += std::get<std::uint64_t>(fields.at("length").data);
                        }
                    },{},0,TransferCompression::none,incremental ? &delta : nullptr,omitted.additional_unused);
                    check(no_payload == failed.length);
                }
                omitted.omitted_snapshots.front().length -= 4096;
                bool rejected = false;
                try { (void)fixed_machine_metadata(std::span(&omitted,1),1700000000); }
                catch (const Error&) { rejected = true; }
                check(rejected);
            }
            {
                constexpr std::uint64_t mib = 1024*1024, gib = 1024*mib;
                const auto cursor = gpt_fixture.root+4*mib;
                const auto length = cursor+gib+4096+mib;
                const auto last = static_cast<std::uint32_t>(length/512-1);
                Bytes prefix(bytes.begin(),bytes.begin()+static_cast<std::ptrdiff_t>(cursor));
                Bytes tail(bytes.end()-static_cast<std::ptrdiff_t>(mib),bytes.end());
                put(prefix,458,last); // Protective MBR now spans the extended image.
                const auto update_header = [&](Bytes& image,std::size_t at,bool backup) {
                    put(image,at+24,backup ? last : 1);
                    put(image,at+32,backup ? 1 : last);
                    put(image,at+48,last-33);
                    put(image,at+72,backup ? last-32 : 2);
                    put(image,at+16,0);
                    put(image,at+16,crc(std::span(image).subspan(at,92)));
                };
                update_header(prefix,512,false);
                update_header(tail,tail.size()-512,true);
                auto head_source = std::make_shared<ImageSource>(std::move(prefix));
                auto zero_source = std::make_shared<ImageSource>(Bytes(mib));
                auto tail_source = std::make_shared<ImageSource>(std::move(tail));
                std::vector<ImageExtent> extents{{0,cursor,0,head_source}};
                for (std::uint64_t at = cursor; at < length-mib;) {
                    const auto count = std::min(mib,length-mib-at);
                    extents.push_back({at,count,0,zero_source});
                    at += count;
                }
                extents.push_back({length-mib,mib,0,tail_source});
                ImageSource captured(length,std::move(extents));
                auto large_tail_plan = efi_plan;
                auto& fields = std::get<Value::Object>(large_tail_plan.data);
                fields["layout"] = layout_value(inspect_image_layout(captured,512));
                fields["layout_policy"] = Value{std::string("linux-layout-v1")};
                fields["excluded"] = Value{Value::Array{}};
                fields["selected_extra"] = Value{Value::Array{}};
                const auto omitted = machine_unused_extents(large_tail_plan);
                check(omitted.size() == 1 && omitted.front().offset == cursor &&
                      omitted.front().length == gib+4096);
                const auto schedule = machine_static_regions(large_tail_plan);
                check(schedule.back().offset == length-mib && schedule.back().length == mib &&
                      schedule.back().read_source);
                // Full metadata validation reopens both GPT copies and checks
                // every omitted byte, exercising the same sealing validator.
                const auto sealed = fixed_image_metadata(
                    captured,512,"large-tail-gpt",1700000000,nullptr,&large_tail_plan);
                const std::string json(sealed.begin(),sealed.end());
                check(json.find("\"excluded_length\":\"1073745920\"") != std::string::npos &&
                      json.find("\"disk_layout\":\"GPT\"") != std::string::npos);
            }
        }
        transfer(bytes, TransferCompression::lz4, 0);
        bytes[bytes.size()-512-16384+16] ^= 1;
        reject(std::move(bytes), "checksum");
        // Assemble an original-layout disk from separately captured sources.
        // The static image's root region is deliberately empty: metadata and
        // transfer must obtain ext4 bytes solely from the root source.
        const auto f = disk(true);
        {
            auto partial = f.bytes;
            const auto extra_offset = f.root+4*1024*1024;
            // A swap/data partition can be present in the on-disk table while
            // its bytes remain absent from a system-volume capture.
            partial[482] = 0x82;
            put(partial,486,static_cast<std::uint32_t>(extra_offset/512));
            put(partial,490,2048);
            std::fill(partial.begin()+static_cast<std::ptrdiff_t>(extra_offset),partial.end(),0);
            ImageSource source(partial);
            const auto plan = Value{Value::Object{
                {"layout",layout_value(inspect_image_layout(source,512))},
                {"boot",Value{Value::Object{
                    {"partition",Value{std::uint64_t{1}}},{"offset",Value{std::uint64_t{boot}}},
                    {"device",Value{std::string("/dev/mmcblk0p1")}},
                    {"length",Value{std::uint64_t{f.root-boot-1024*1024}}},
                    {"mount_path",Value{std::string("/boot/firmware")}},
                    {"filesystem",Value{std::string("vfat")}},
                    {"filesystem_uuid",Value{std::string("1234-ABCD")}}}}},
                {"root",Value{Value::Object{
                    {"partition",Value{std::uint64_t{2}}},{"offset",Value{std::uint64_t{f.root}}},
                    {"device",Value{std::string("/dev/mmcblk0p2")}},
                    {"length",Value{std::uint64_t{4*1024*1024}}},
                    {"mount_path",Value{std::string("/")}},
                    {"filesystem",Value{std::string("ext4")}},
                    {"filesystem_uuid",Value{std::string("01020304-0506-0708-090a-0b0c0d0e0f10")}}}}},
                {"excluded",Value{Value::Array{Value{Value::Object{
                    {"partition",Value{std::uint64_t{3}}},
                    {"offset",Value{std::uint64_t{extra_offset}}},
                    {"length",Value{std::uint64_t{1024*1024}}},
                    {"mount_path",Value{std::string("/data")}},
                    {"filesystem",Value{std::string("swap")}}}}}}}}};
            const auto result = fixed_image_metadata(source,512,"pi-card",1700000000,nullptr,&plan);
            const std::string descriptor(result.begin(),result.end());
            check(descriptor.find("\"excluded_length\":\"1048576\"") != std::string::npos);
            check(descriptor.find("\"mount_path\":\"/data\"") != std::string::npos);
            check(descriptor.find("\"is_excluded\":true") != std::string::npos);
            check(descriptor.find("\"type\":5") != std::string::npos);
            check(descriptor.find("\"is_bootable\":true") != std::string::npos);
            {
                auto bare_plan = plan;
                auto& bare_fields = std::get<Value::Object>(bare_plan.data);
                bare_fields["volume_policy"] = Value{std::string("linux-bare-metal-v1")};
                bare_fields["swap_page_size"] = Value{std::uint64_t{4096}};
                bare_fields["selected_extra"] = Value{Value::Array{}};
                auto swap_bytes = partial;
                // Small swap body is retained in the sealed image, like the
                // official agent successful cache branch. Labels describe one partition.
                std::fill(swap_bytes.begin()+static_cast<std::ptrdiff_t>(extra_offset),
                          swap_bytes.end(),0xa5);
                ImageSource small_swap(swap_bytes);
                const auto small = fixed_image_metadata(
                    small_swap,512,"pi-card",1700000000,nullptr,&bare_plan);
                const std::string small_json(small.begin(),small.end());
                check(small_json.find("\"file_system\":\"swap_partition_header\"") != std::string::npos);
                check(small_json.find("\"file_system\":\"swap_partition_body\"") != std::string::npos);
                check(small_json.find("\"type\":2") != std::string::npos); // FAT boot raw fallback.
                check(small_json.find("\"excluded_length\":\"0\"") != std::string::npos);
                check(machine_unused_extents(bare_plan).empty());
                {
                    auto failed_cache = bare_plan;
                    machine_cache_raw_regions(failed_cache,[](const auto& region) {
                        if (region.label == "swap_partition_body")
                            throw MachineRawCacheCopyError("partial cache write");
                    },[] {},[] {});
                    auto omitted_bytes = swap_bytes;
                    std::fill(omitted_bytes.begin()+static_cast<std::ptrdiff_t>(extra_offset+4096),
                        omitted_bytes.end(),0);
                    ImageSource failed_source(std::move(omitted_bytes));
                    const auto metadata = fixed_image_metadata(
                        failed_source,512,"pi-card",1700000000,nullptr,&failed_cache);
                    const std::string descriptor(metadata.begin(),metadata.end());
                    check(descriptor.find("\"file_system\":\"swap_partition_body\"") != std::string::npos);
                    check(descriptor.find("\"type\":5") != std::string::npos);
                    const auto unused = machine_unused_extents(failed_cache);
                    check(unused.size() == 1 && unused.front().offset == extra_offset+4096 &&
                        unused.front().length == swap_bytes.size()-extra_offset-4096);
                }
                // Ordinary large swap keeps its first page, never its body.
                swap_bytes.resize(extra_offset+32*1024*1024,0);
                std::fill(swap_bytes.begin()+static_cast<std::ptrdiff_t>(extra_offset+4096),
                          swap_bytes.end(),0);
                put(swap_bytes,490,32*1024*1024/512);
                ImageSource large_swap(swap_bytes);
                bare_fields["layout"] = layout_value(inspect_image_layout(large_swap,512));
                std::get<Value::Object>(std::get<Value::Array>(
                    bare_fields.at("excluded").data).front().data)["length"] =
                        Value{std::uint64_t{32*1024*1024}};
                const auto unused = machine_unused_extents(bare_plan);
                check(unused.size() == 1 && unused.front().offset == extra_offset+4096 &&
                      unused.front().length == 32*1024*1024-4096);
                const auto large = fixed_image_metadata(
                    large_swap,512,"pi-card",1700000000,nullptr,&bare_plan);
                const std::string large_json(large.begin(),large.end());
                check(large_json.find("\"file_system\":\"swap_partition_body\"") != std::string::npos);
                check(large_json.find("\"excluded_length\":\"33550336\"") != std::string::npos);
                ImageSource base(swap_bytes);
                auto delta = image_delta_plan(base,large_swap);
                const auto reread = machine_reread_ranges(bare_plan,large_swap.size());
                check(!reread.empty());
                bool uncovered = false;
                try {
                    stream_image(large_swap,"pi-card",1024*1024,[](const Value&) {},{},0,
                        TransferCompression::none,&delta,unused,reread);
                } catch (const Error& error) {
                    uncovered = std::string_view(error.what()).find("not changed") != std::string_view::npos;
                }
                check(uncovered);
                machine_force_raw_changes(delta,bare_plan);
                std::uint64_t omitted_bytes = 0, header_bytes = 0, raw_bytes = 0;
                stream_image(large_swap,"pi-card",1024*1024,[&](const Value& block) {
                    const auto& fields = std::get<Value::Object>(block.data);
                    const auto offset = std::get<std::uint64_t>(fields.at("offset").data);
                    const auto length = std::get<std::uint64_t>(fields.at("length").data);
                    const bool used = fields.at("used") == Value{std::uint64_t{1}};
                    const bool raw = std::any_of(reread.begin(),reread.end(),[&](const auto& range) {
                        return range.offset <= offset && offset+length <= range.offset+range.length;
                    });
                    check(fields.at("is_interval_cbt") == Value{std::uint64_t{!(used && raw)}});
                    if (used && raw) {
                        check(fields.contains("buffer") && fields.at("changed") == Value{std::uint64_t{1}});
                        raw_bytes += length;
                    }
                    if (offset >= unused.front().offset) {
                        check(!fields.contains("buffer") &&
                              fields.at("used") == Value{std::uint64_t{0}} &&
                              fields.at("changed") == Value{std::uint64_t{1}});
                        omitted_bytes += length;
                    } else if (offset+length > extra_offset) {
                        check(fields.contains("buffer") &&
                              fields.at("changed") == Value{std::uint64_t{1}});
                        header_bytes += length;
                    }
                },{},0,TransferCompression::none,&delta,unused,reread);
                check(omitted_bytes == unused.front().length && header_bytes >= 4096);
                check(raw_bytes > 0);
            }
            auto efi_plan = plan;
            std::get<Value::Object>(std::get<Value::Object>(efi_plan.data).at("boot").data)
                ["mount_path"] = Value{std::string("/boot/efi")};
            const auto efi_bytes = fixed_image_metadata(
                source,512,"debian-efi",1700000000,nullptr,&efi_plan);
            const std::string efi_descriptor(efi_bytes.begin(),efi_bytes.end());
            check(efi_descriptor.find("\"mount_path\":\"/boot/efi\"") != std::string::npos);
            check(efi_descriptor.find("\"is_bootable\":true") != std::string::npos);
            auto wrong_efi_plan = efi_plan;
            std::get<Value::Object>(std::get<Value::Object>(wrong_efi_plan.data).at("boot").data)
                ["mount_path"] = Value{std::string("/boot/efi/hidden")};
            const auto nested_efi = fixed_image_metadata(source,512,"debian-efi",1700000000,nullptr,&wrong_efi_plan);
            check(std::string(nested_efi.begin(),nested_efi.end()).find("\"is_bootable\":true") != std::string::npos);
            auto invalid_plan = plan;
            std::get<Value::Object>(std::get<Value::Object>(invalid_plan.data).at("root").data)
                ["mount_path"] = Value{std::string("/data")};
            const auto nonroot = fixed_image_metadata(source,512,"pi-card",1700000000,nullptr,&invalid_plan);
            check(std::string(nonroot.begin(),nonroot.end()).find("\"is_bootable\":false") != std::string::npos);
            invalid_plan = plan;
            auto& incomplete = std::get<Value::Object>(invalid_plan.data);
            incomplete["selected_extra"] = Value{Value::Array{incomplete.at("boot")}};
            incomplete.erase("boot");
            const auto no_boot_role = fixed_image_metadata(source,512,"pi-card",1700000000,nullptr,&invalid_plan);
            check(std::string(no_boot_role.begin(),no_boot_role.end()).find("\"is_bootable\":true") != std::string::npos);
            invalid_plan = plan;
            auto& logical = std::get<Value::Object>(invalid_plan.data);
            auto physical = logical.at("root");
            std::get<Value::Object>(physical.data)["mount_path"] = Value{std::string("/data")};
            logical["selected_extra"] = Value{Value::Array{std::move(physical)}};
            logical["root"] = Value{Value::Object{
                {"lv_uuid",Value{std::string("root-lv")}},
                {"vg_uuid",Value{std::string("root-vg")}},
                {"image_name",Value{std::string("root-lv.img")}},
                {"mount_path",Value{std::string("/")}}}};
            bool missing_root_image = false;
            try { (void)fixed_image_metadata(source,512,"pi-card",1700000000,nullptr,&invalid_plan); }
            catch (const Error& error) {
                missing_root_image = std::string_view(error.what()).find(
                    "missing its root logical-volume image") != std::string_view::npos;
            }
            check(missing_root_image);
            auto& root_lv = std::get<Value::Object>(logical.at("root").data);
            root_lv["length"] = Value{std::uint64_t{4*1024*1024}};
            root_lv["logical_path"] = Value{std::string("/dev/root-vg/root")};
            root_lv["filesystem"] = Value{std::string("ext4")};
            root_lv["filesystem_uuid"] =
                Value{std::string("01020304-0506-0708-090a-0b0c0d0e0f10")};
            std::get<Value::Object>(logical.at("boot").data)["mount_path"] =
                Value{std::string("/boot/efi")};
            ImageSource root_lv_image(Bytes(
                f.bytes.begin()+static_cast<std::ptrdiff_t>(f.root),
                f.bytes.begin()+static_cast<std::ptrdiff_t>(f.root+4*1024*1024)));
            const MetadataDisk root_lv_set[]{
                {&source,512,"machine-disk",&invalid_plan,nullptr},
                {&root_lv_image,512,"root-lv.img",&logical.at("root"),nullptr}};
            const auto complete = fixed_machine_metadata(root_lv_set,1700000000);
            const std::string complete_json(complete.begin(),complete.end());
            check(complete_json.find("\"is_bootable\":true") != std::string::npos);
            check(complete_json.find("\"/\":{\"mount_path\":\"/\"") != std::string::npos);
            check(complete_json.find("\"image_path\":\"root-lv.img\"") != std::string::npos);
            ImageSource unavailable_root(4*1024*1024,[](auto,auto,auto*) -> Bytes {
                throw Error("omitted logical volume was read");
            },[] {});
            MetadataDisk omitted_lv_set[]{root_lv_set[0],root_lv_set[1]};
            omitted_lv_set[1].source = &unavailable_root;
            omitted_lv_set[1].omitted_snapshots = {{0,4*1024*1024}};
            const auto omitted_lv_bytes = fixed_machine_metadata(omitted_lv_set,1700000000);
            const std::string omitted_lv_json(omitted_lv_bytes.begin(),omitted_lv_bytes.end());
            check(omitted_lv_json.find("\"type\":4") != std::string::npos);
            check(omitted_lv_json.find("\"excluded_length\":\"4194304\"") != std::string::npos);
            check(omitted_lv_json.find("\"/\":{\"mount_path\":\"/\"") == std::string::npos);
            check(omitted_lv_json.find("\"is_bootable\":false") != std::string::npos);
            auto extra_lv_plan = logical.at("root");
            auto& extra_lv = std::get<Value::Object>(extra_lv_plan.data);
            extra_lv["lv_uuid"] = Value{std::string("extra-lv")};
            extra_lv["image_name"] = Value{std::string("extra-lv.img")};
            extra_lv["mount_path"] = Value{std::string("/data-lv")};
            extra_lv["logical_path"] = Value{std::string("/dev/root-vg/extra")};
            const auto inventory_lv = [](std::string name) {
                return Value{Value::Object{{"name",Value{name}},{"uuid",Value{name+"-lv"}},
                    {"file_system",Value{std::string("ext4")}},
                    {"size",Value{std::uint64_t{4*1024*1024}}}}};
            };
            Value group{Value::Object{
                {"name",Value{std::string("root-vg")}},{"uuid",Value{std::string("root-vg")}},
                {"extent_size",Value{std::uint64_t{4*1024*1024}}},
                {"logical_volumes",Value{Value::Array{inventory_lv("root"),inventory_lv("extra")}}}}};
            logical["lvm"] = Value{Value::Object{{"volume_groups",Value{Value::Array{group}}}}};
            MetadataDisk with_extra[]{root_lv_set[0],root_lv_set[1],
                {&root_lv_image,512,"extra-lv.img",&extra_lv_plan}};
            auto healthy = fixed_machine_metadata(with_extra,1700000000);
            const std::string healthy_json(healthy.begin(),healthy.end());
            check(healthy_json.find("\"/\":{\"mount_path\":\"/\"") != std::string::npos);
            check(healthy_json.find("\"/data-lv\":{\"mount_path\":\"/data-lv\"") != std::string::npos);
            check(healthy_json.find("\"is_bootable\":true") != std::string::npos);
            const auto healthy_mounts = mount_map_json(healthy_json);
            check(healthy_mounts.find("\"/\":{") < healthy_mounts.find("\"/boot/efi\":{") &&
                healthy_mounts.find("\"/boot/efi\":{") < healthy_mounts.find("\"/data\":{") &&
                healthy_mounts.find("\"/data\":{") < healthy_mounts.find("\"/data-lv\":{"));
            check(healthy_mounts.find("\"device_name\":\"/dev/mmcblk0p1\",\"alias_name\":\"/boot/efi\","
                "\"disk_number\":0,\"partition_number\":1") != std::string::npos);
            check(healthy_mounts.find("\"is_primary_partition\":true,\"offset\":\"1048576\","
                "\"length\":\"37748736\",\"is_mbr\":true") != std::string::npos);
            for (const std::size_t omitted_index : {std::size_t{1},std::size_t{2}}) {
                MetadataDisk partial_set[]{with_extra[0],with_extra[1],with_extra[2]};
                partial_set[omitted_index].source = &unavailable_root;
                partial_set[omitted_index].omitted_snapshots = {{0,4*1024*1024}};
                const auto result = fixed_machine_metadata(partial_set,1700000000);
                const std::string json(result.begin(),result.end());
                check((json.find("\"/\":{\"mount_path\":\"/\"") != std::string::npos) == (omitted_index != 1));
                check((json.find("\"/data-lv\":{\"mount_path\":\"/data-lv\"") != std::string::npos) == (omitted_index != 2));
                check((json.find("\"is_bootable\":true") != std::string::npos) == (omitted_index != 1));
                check(json.find("\"image_name\":\"root-lv.img\",\"need_upload\":true") != std::string::npos);
                check(json.find("\"image_name\":\"extra-lv.img\",\"need_upload\":true") != std::string::npos);
                check(json.find("\"type\":4") != std::string::npos);
                check(json.find("\"volume_groups\":[") != std::string::npos);
                check(json.find("\"uuid\":\"root-lv\"") != std::string::npos);
                check(json.find("\"uuid\":\"extra-lv\"") != std::string::npos);
            }
            MetadataDisk omitted_physical[]{with_extra[0],with_extra[1],with_extra[2]};
            omitted_physical[0].omitted_snapshots = {{f.root,4*1024*1024}};
            const auto physical_bytes = fixed_machine_metadata(omitted_physical,1700000000);
            const std::string physical_json(physical_bytes.begin(),physical_bytes.end());
            const auto physical_mounts = mount_map_json(physical_json);
            check(physical_mounts.find("\"/data\":{") == std::string::npos);
            check(physical_mounts.find("\"/\":{") != std::string::npos &&
                physical_mounts.find("\"/data-lv\":{") != std::string::npos);
            check(physical_json.find("\"is_bootable\":true") != std::string::npos);
            auto archive_bytes = f.bytes;
            std::fill(archive_bytes.begin()+boot,archive_bytes.begin()+f.root-1024*1024,0);
            ImageSource archive(std::move(archive_bytes));
            auto archive_volume = std::get<Value::Array>(logical.at("selected_extra").data).front();
            auto& archive_fields = std::get<Value::Object>(archive_volume.data);
            archive_fields["mount_path"] = Value{std::string("/archive")};
            archive_fields["device"] = Value{std::string("/dev/sdb2")};
            auto archive_unused = logical.at("boot");
            std::get<Value::Object>(archive_unused.data)["mount_path"] = Value{std::string{}};
            Value archive_plan{Value::Object{
                {"layout",layout_value(inspect_image_layout(archive,512))},
                {"selected_extra",Value{Value::Array{archive_volume}}},
                {"excluded",Value{Value::Array{archive_unused}}}}};
            MetadataDisk combined[]{with_extra[0],{&archive,512,"archive.img",&archive_plan},
                with_extra[1],with_extra[2]};
            const auto combined_bytes = fixed_machine_metadata(combined,1700000000);
            const auto combined_mounts = mount_map_json(std::string(combined_bytes.begin(),combined_bytes.end()));
            check(combined_mounts.find("\"/archive\":{\"mount_path\":\"/archive\",\"object_id\":0,"
                "\"image_path\":\"archive.img\",\"device_name\":\"/dev/sdb2\",\"alias_name\":\"/archive\","
                "\"disk_number\":1,\"partition_number\":2") != std::string::npos);
            combined[1].omitted_snapshots = {{f.root,4*1024*1024}};
            combined[3].source = &unavailable_root;
            combined[3].omitted_snapshots = {{0,4*1024*1024}};
            const auto mixed_bytes = fixed_machine_metadata(combined,1700000000);
            const std::string mixed_json(mixed_bytes.begin(),mixed_bytes.end());
            const auto mixed_mounts = mount_map_json(mixed_json);
            check(mixed_mounts.find("\"/archive\":{") == std::string::npos &&
                mixed_mounts.find("\"/data-lv\":{") == std::string::npos &&
                mixed_mounts.find("\"/\":{") != std::string::npos &&
                mixed_mounts.find("\"/boot/efi\":{") != std::string::npos);
            check(mixed_json.find("\"is_bootable\":true") != std::string::npos &&
                mixed_json.find("\"image_name\":\"archive.img\",\"need_upload\":true") != std::string::npos);
            // the official agent assigns simple mounts before LV mounts and keeps exact
            // path keys: "/data" and "/data/" are distinct on Linux.
            extra_lv["mount_path"] = Value{std::string("/data")};
            const auto shared_bytes = fixed_machine_metadata(with_extra,1700000000);
            const auto shared_mounts = mount_map_json(std::string(shared_bytes.begin(),shared_bytes.end()));
            check(shared_mounts.find("\"/data\":{\"mount_path\":\"/data\",\"object_id\":0,"
                "\"image_path\":\"extra-lv.img\"") != std::string::npos);
            extra_lv["mount_path"] = Value{std::string("/data/")};
            const auto trailing_bytes = fixed_machine_metadata(with_extra,1700000000);
            const auto trailing_mounts = mount_map_json(std::string(trailing_bytes.begin(),trailing_bytes.end()));
            check(trailing_mounts.find("\"/data\":{") != std::string::npos &&
                trailing_mounts.find("\"/data/\":{") != std::string::npos);
            MetadataDisk wrong_root_name[]{root_lv_set[0],root_lv_set[1]};
            wrong_root_name[1].image_name = "different-root.img";
            bool rejected_root_name = false;
            try { (void)fixed_machine_metadata(wrong_root_name,1700000000); }
            catch (const Error& error) {
                rejected_root_name = std::string_view(error.what()).find(
                    "logical volume image differs") != std::string_view::npos;
            }
            check(rejected_root_name);
            auto leaked = partial;
            leaked[extra_offset+79] = 0x5a;
            ImageSource wrong(std::move(leaked));
            bool rejected = false;
            try { (void)fixed_image_metadata(wrong,512,"pi-card",1700000000,nullptr,&plan); }
            catch (const Error& error) {
                rejected = std::string_view(error.what()).find("nonzero") != std::string_view::npos;
            }
            check(rejected);
            reject(partial,"unsupported partition");
        }
        auto static_bytes = f.bytes;
        const std::size_t root_length = 4*1024*1024;
        auto root_source = std::make_shared<ImageSource>(
            Bytes(f.bytes.begin()+f.root, f.bytes.begin()+f.root+root_length));
        {
            const std::string uuid = "01020304-0506-0708-090a-0b0c0d0e0f10";
            Value lv_plan{Value::Object{
                {"length",Value{std::uint64_t{root_length}}},
                {"image_name",Value{std::string("vg=selected.img")}},
                {"lv_uuid",Value{std::string("lv-uuid")}},
                {"vg_uuid",Value{std::string("vg-uuid")}},
                {"logical_path",Value{std::string("/dev/vg/selected")}},
                {"mount_path",Value{std::string("/data")}},
                {"filesystem",Value{std::string("ext4")}},
                {"filesystem_uuid",Value{uuid}}}};
            std::vector<MetadataDisk> disks{{root_source.get(),512,"vg=selected.img",&lv_plan}};
            const auto output = fixed_machine_metadata(disks,1700000000);
            const std::string json(output.begin(),output.end());
            check(json.find("\"image_name\":\"vg=selected.img\"") != std::string::npos);
            check(json.find("\"disk_number\":\"-1\"") != std::string::npos);
            check(json.find("\"disk_layout\":{}") != std::string::npos);
            check(json.find("\"/data\":{") != std::string::npos);
            auto root_lv_plan = lv_plan;
            std::get<Value::Object>(root_lv_plan.data)["mount_path"] = Value{std::string("/")};
            auto root_lv_disks = disks;
            root_lv_disks[0].machine_plan = &root_lv_plan;
            const auto root_lv_metadata = fixed_machine_metadata(root_lv_disks,1700000000);
            const std::string root_lv_json(root_lv_metadata.begin(),root_lv_metadata.end());
            check(root_lv_json.find("\"mount_map\":{\"/\":{") != std::string::npos);
            check(root_lv_json.find("\"is_system_drive\":true") != std::string::npos);
            check(root_lv_json.find("\"disk_number\":\"-1\"") != std::string::npos);
            auto changed = Bytes(f.bytes.begin()+f.root,f.bytes.begin()+f.root+root_length);
            changed[4096] ^= 0x5a;
            ImageSource current(changed);
            const auto delta = image_delta_plan(*root_source,current);
            disks[0].source = &current;
            disks[0].delta = &delta;
            const auto incremental = fixed_machine_metadata(disks,1700000001);
            const std::string incremental_json(incremental.begin(),incremental.end());
            check(incremental_json.find("\"is_cbt\"") == std::string::npos);
            std::get<Value::Object>(lv_plan.data)["filesystem_uuid"] =
                Value{std::string("different-uuid")};
            bool rejected = false;
            try { (void)fixed_machine_metadata(disks,1700000002); }
            catch (const Error& error) {
                rejected = std::string_view(error.what()).find("identity") != std::string_view::npos;
            }
            check(rejected);
        }
        std::fill(static_bytes.begin()+f.root, static_bytes.begin()+f.root+root_length, 0);
        auto static_source = std::make_shared<ImageSource>(std::move(static_bytes));
        const auto tail = f.root+root_length;
        ImageSource composite(f.bytes.size(), {
            {0, f.root, 0, static_source}, {f.root, root_length, 0, root_source},
            {tail, f.bytes.size()-tail, tail, static_source}});
        const auto descriptor = fixed_image_metadata(composite, 512, "pi-card", 1700000000);
        const std::string json(descriptor.begin(), descriptor.end());
        check(json == metadata(f.bytes));
        transfer_source(composite, f.bytes, TransferCompression::lz4, 0);
        transfer_source(composite, f.bytes, TransferCompression::none, f.root-512);
        std::cout << "Mixed FAT16/FAT32 and ext4 metadata and byte-exact raw/LZ4/resume passed\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
