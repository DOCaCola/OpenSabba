#include "opensabba/lvm.hpp"
#include "opensabba/machine.hpp"
#include "opensabba/image.hpp"
#include <algorithm>
#include <iostream>

using namespace opensabba;
using pstream::Error;
namespace {
constexpr std::uint64_t mib = 1024*1024;
const std::string vg_uuid = "q04wOI-lPGf-DSZg-TYVi-mTCu-zH1g-eph3oB";
const std::string pv_uuid = "cirf6F-63C1-Qk0t-XPzE-y9A8-2Cml-z4RX56";
const std::string lv_uuid = "MxX85h-78Vn-7Tc8-MS1V-33Hk-0HyZ-mglV98";
const std::string other_uuid = "dW8KcU-MfCo-awHT-Aqhj-CK4U-TPmW-51AfRb";
const std::string vgs =
    "  opensabba_lab_vg|"+vg_uuid+"|wz--n-|4194304|1988100096|1044480|3|1|2|0||\n";
const std::string pvs =
    "  /dev/sdb1|"+pv_uuid+"|"+vg_uuid+"|1988100096|1048576|1044480|a--|474|1|1992294400\n";
const std::string lvs =
    "selected|"+lv_uuid+"|"+vg_uuid+"|/dev/opensabba_lab_vg/selected|/dev/mapper/opensabba_lab_vg-selected|-wi-ao----|536870912|linear|0|536870912|/dev/sdb1:0-127|254|0\n"
    "excluded|"+other_uuid+"|"+vg_uuid+"|/dev/opensabba_lab_vg/excluded|/dev/mapper/opensabba_lab_vg-excluded|-wi-a-----|268435456|linear|0|268435456|/dev/sdb1:128-191|254|1\n";
void check(bool condition) { if (!condition) throw Error("LVM test failed"); }
template<class F> void reject(F action, std::string_view expected) {
    try { action(); }
    catch (const Error& error) {
        if (std::string_view(error.what()).find(expected) != std::string_view::npos) return;
        throw Error("unexpected LVM rejection: "+std::string(error.what()));
    }
    throw Error("unsafe LVM fixture was accepted");
}
std::string replace(std::string value, const std::string& before, const std::string& after) {
    const auto at = value.find(before);
    check(at != value.npos);
    value.replace(at,before.size(),after);
    return value;
}
LvmInventory fixture() { return parse_lvm_reports(vgs,pvs,lvs); }
LvmInventory kernel_fixture() {
    auto inventory = fixture();
    auto& pv = inventory.physical_volumes.front();
    pv.device = {8,17}; pv.parent_device = {8,16}; pv.parent_disk = "/dev/sdb";
    pv.partition_number = 1; pv.partition_offset = mib; pv.partition_length = pv.device_size;
    pv.disk_sequence = 4;
    return inventory;
}
const LvmLv& selected(const LvmInventory& inventory) {
    return *std::find_if(inventory.logical_volumes.begin(),inventory.logical_volumes.end(),
        [](const auto& lv) { return lv.name == "selected"; });
}
LvmDmIdentity identity() {
    return parse_lvm_dm_identity("opensabba_lab_vg-selected|LVM-q04wOIlPGfDSZgTYVimTCuzH1geph3oBMxX85h78Vn7Tc8MS1V33Hk0HyZmglV98|254|0|1|0|L--w\n");
}
void put32(pstream::Bytes& bytes,std::size_t at,std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) bytes[at+i] = static_cast<std::uint8_t>(value>>(i*8));
}
void put64(pstream::Bytes& bytes,std::size_t at,std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) bytes[at+i] = static_cast<std::uint8_t>(value>>(i*8));
}
void crc(pstream::Bytes& bytes, std::size_t sector = 1) {
    std::uint32_t value = 0xf597a6cf;
    for (std::size_t at = sector*512+20; at < (sector+1)*512; ++at) {
        value ^= bytes[at];
        for (unsigned bit = 0; bit < 8; ++bit)
            value = (value>>1) ^ ((value&1) ? 0xedb88320U : 0U);
    }
    put32(bytes,sector*512+16,value);
}
pstream::Bytes pv_header(std::size_t sector = 1, std::size_t header = 32) {
    pstream::Bytes bytes(2048);
    const std::string magic = "LABELONE", type = "LVM2 001", raw_uuid = "cirf6F63C1Qk0tXPzEy9A82Cmlz4RX56";
    const auto base = sector*512;
    std::copy(magic.begin(),magic.end(),bytes.begin()+base);
    put64(bytes,base+8,sector); put32(bytes,base+20,static_cast<std::uint32_t>(header));
    std::copy(type.begin(),type.end(),bytes.begin()+base+24);
    std::copy(raw_uuid.begin(),raw_uuid.end(),bytes.begin()+base+header);
    put64(bytes,base+header+32,1992294400);
    put64(bytes,base+header+40,mib);
    put64(bytes,base+header+72,4096); put64(bytes,base+header+80,1044480);
    crc(bytes,sector);
    return bytes;
}
}
int main(int argc,char**) {
    try {
        const auto inventory = fixture();
        check(inventory.volume_groups.size() == 1 && inventory.physical_volumes.size() == 1 &&
            inventory.logical_volumes.size() == 2);
        check(selected(inventory).segments.front().pv_offset == mib);
        check(inventory.physical_volumes.front().size == inventory.volume_groups.front().total_size);
        const auto plus_image = lvm_image_name("vg+prod","data+home");
        check(plus_image == "vg+prod=data+home.img");
        validate_image_options(plus_image,1024*1024);
        reject([&] { (void)lvm_image_name(std::string(120,'a'),"volume"); },
            "image name exceeds");
        reject([&] { (void)lvm_image_name("vg/foreign","data"); },"invalid LVM name");
        check(parse_lvm_reports("","","").volume_groups.empty());
        reject([&] { parse_lvm_reports(vgs+"invalid\n",pvs,lvs); },"column count");
        reject([&] { parse_lvm_reports(vgs,pvs,lvs+std::string(1,'\0')); },"NUL");
        reject([&] { parse_lvm_reports(replace(vgs,"|4194304|","|4194304.00|"),pvs,lvs); },"integer");
        reject([&] { parse_lvm_reports(replace(vgs,"|1|2|0||","|2|2|0||"),pvs,lvs); },"cover all PVs");
        reject([&] { parse_lvm_reports(replace(vgs,"|1|2|0||","|1|2|1||"),pvs,lvs); },"complete local");
        reject([&] { parse_lvm_reports(replace(vgs,"|0||","|0|sanlock|"),pvs,lvs); },"non-shared");
        reject([&] { parse_lvm_reports(replace(vgs,"|0||","|0||foreign"),pvs,lvs); },"non-shared");
        reject([&] { parse_lvm_reports(replace(vgs,"wz--n-","wzx-n-"),pvs,lvs); },"unexported");
        reject([&] { parse_lvm_reports(vgs,pvs+pvs,lvs); },"cover all PVs");
        reject([&] { parse_lvm_reports(vgs,replace(pvs,"a--","a-m"),lvs); },"complete allocated");
        reject([&] { parse_lvm_reports(vgs,replace(pvs,pv_uuid,"invalid"),lvs); },"UUID");
        for (const auto* type : {"thin","thin-pool","raid1","cache","snapshot","striped"}) {
            const auto layout = parse_lvm_reports(vgs,pvs,replace(lvs,"|linear|","|"+std::string(type)+"|"));
            check(selected(layout).segments.front().type == type);
        }
        reject([&] { parse_lvm_reports(vgs,pvs,replace(lvs,"-wi-ao----","-wi-------")); },"active");
        check(selected(parse_lvm_reports(vgs,pvs,replace(lvs,"-wi-ao----","owi-ao----"))).public_device);
        reject([&] { parse_lvm_reports(vgs,pvs,replace(lvs,"|254|0","|-1|-1")); },"active");
        reject([&] { parse_lvm_reports(vgs,pvs,replace(lvs,"0-127","0-128")); },"PE range");
        reject([&] { parse_lvm_reports(vgs,pvs,replace(lvs,"128-191","120-183")); },"overlap");
        reject([&] { parse_lvm_reports(vgs,pvs,replace(lvs,"|linear|0|","|linear|4194304|")); },"incomplete");
        reject([&] { parse_lvm_reports(vgs,pvs,replace(lvs,"/dev/sdb1:0-127","/dev/sdc1:0-127")); },"absent PV");
        reject([&] { parse_lvm_reports(vgs,pvs,replace(lvs,"|536870912|linear|","|540000000|linear|")); },"LV geometry");
        reject([&] { parse_lvm_reports(vgs,pvs,replace(lvs,"/dev/mapper/opensabba_lab_vg-selected","/dev/mapper/foreign")); },"LV identity");
        auto kernel = kernel_fixture();
        const auto table = parse_lvm_dm_table("0 1048576 linear 8:17 2048\n");
        validate_lvm_mapping(kernel,selected(kernel),identity(),table);
        reject([&] { validate_lvm_mapping(inventory,selected(inventory),identity(),table); },"partition geometry");
        auto wrong = identity(); wrong.uuid.back() = 'a';
        reject([&] { validate_lvm_mapping(kernel,selected(kernel),wrong,table); },"DM identity");
        wrong = identity(); wrong.device.minor = 3;
        reject([&] { validate_lvm_mapping(kernel,selected(kernel),wrong,table); },"DM identity");
        reject([&] { validate_lvm_mapping(kernel,selected(kernel),identity(),parse_lvm_dm_table("0 1048576 linear 8:18 2048\n")); },"mapping");
        reject([&] { validate_lvm_mapping(kernel,selected(kernel),identity(),parse_lvm_dm_table("0 1048576 linear 8:17 2049\n")); },"mapping");
        reject([&] { parse_lvm_dm_identity("vg-lv|uuid|254|0|1|0|Ls-w"); },"suspended");
        reject([&] { parse_lvm_dm_table("0 1048576 crypt 8:17 2048\n"); },"unsupported targets");
        reject([&] { parse_lvm_dm_table("0 1048576 linear 8:17 2048 extra\n"); },"linear targets");
        reject([&] { parse_lvm_dm_table("1 1048576 linear 8:17 2048\n"); },"logical ranges");
        reject([&] { parse_lvm_dm_table("0 18446744073709551615 linear 8:17 2048\n"); },"overflow");
        // Discontiguous two-segment LV with complete logical coverage.
        auto split = kernel;
        auto& lv = *std::find_if(split.logical_volumes.begin(),split.logical_volumes.end(),
            [](const auto& entry) { return entry.name == "selected"; });
        lv.segments = {{0,256*mib,mib,pv_uuid},{256*mib,256*mib,1025*mib,pv_uuid}};
        auto split_identity = identity(); split_identity.segments = 2;
        validate_lvm_mapping(split,lv,split_identity,
            parse_lvm_dm_table("0 524288 linear 8:17 2048\n524288 524288 linear 8:17 2099200\n"));
        auto header = pv_header();
        validate_lvm_pv_header(kernel.physical_volumes.front(),header);
        auto extended = kernel.physical_volumes.front();
        extended.device_size += 512*1024;
        extended.partition_length = extended.device_size;
        validate_lvm_pv_header(extended,header);
        check(extended.size == kernel.physical_volumes.front().size);
        for (const std::size_t sector : {0U,2U,3U})
            for (const std::size_t offset : {32U,48U,128U})
                try { validate_lvm_pv_header(kernel.physical_volumes.front(),pv_header(sector,offset)); }
                catch (const Error& error) {
                    throw Error("alternate LVM label sector "+std::to_string(sector)+
                                " offset "+std::to_string(offset)+": "+error.what());
                }
        header = pv_header(3,128);
        header[3*512+128] ^= 1; crc(header,3);
        reject([&] { validate_lvm_pv_header(kernel.physical_volumes.front(),header); },"UUID");
        header = pv_header();
        header[600] ^= 1;
        reject([&] { validate_lvm_pv_header(kernel.physical_volumes.front(),header); },"CRC");
        header = pv_header(); header[512+32] = 'x'; crc(header);
        reject([&] { validate_lvm_pv_header(kernel.physical_volumes.front(),header); },"UUID");
        header = pv_header(); put64(header,512+72,2*mib); crc(header);
        reject([&] { validate_lvm_pv_header(kernel.physical_volumes.front(),header); },"data area");
        header = pv_header(); put64(header,512+104,mib); crc(header);
        reject([&] { validate_lvm_pv_header(kernel.physical_volumes.front(),header); },"overlaps");
        header = pv_header(); put64(header,512+112,512); crc(header);
        reject([&] { validate_lvm_pv_header(kernel.physical_volumes.front(),header); },"size/count");
        auto duplicated = kernel.physical_volumes.front();
        duplicated.mda_count = 2;
        header = pv_header();
        const auto tail_offset = duplicated.pe_start+duplicated.size;
        put64(header,512+120,tail_offset);
        put64(header,512+128,duplicated.mda_size);
        crc(header);
        validate_lvm_pv_header(duplicated,header);
        header = pv_header();
        put64(header,512+120,tail_offset);
        put64(header,512+128,duplicated.mda_size);
        put64(header,512+120,duplicated.pe_start+duplicated.size-512);
        crc(header);
        reject([&] { validate_lvm_pv_header(duplicated,header); },"overlaps data");
#ifndef __linux__
        reject([] { inspect_lvm(); },"requires Linux");
#endif
        // Explicit opt-in read-only live probe for the disposable Linux VM.
        if (argc > 1) {
            const auto live = inspect_lvm();
            check(!live.volume_groups.empty());
            const auto& pv = live.physical_volumes.front();
            const auto& lv = selected(live);
            pstream::Value plan{pstream::Value::Object{
                {"disk",pstream::Value{pv.parent_disk}},
                {"cow_directory",pstream::Value{std::string("/lab/lvm-cow")}},
                {"root",pstream::Value{pstream::Value::Object{
                    {"partition",pstream::Value{std::uint64_t{2}}}}}},
                {"excluded",pstream::Value{pstream::Value::Array{
                    pstream::Value{pstream::Value::Object{
                        {"mount_path",pstream::Value{std::string{}}},
                        {"pv_uuid",pstream::Value{pv.uuid}}}}}}},
                {"selected_extra",pstream::Value{pstream::Value::Array{}}},
                {"external_volumes",pstream::Value{pstream::Value::Array{
                    pstream::Value{pstream::Value::Object{
                        {"mount_path",pstream::Value{std::string("/mnt/opensabba-lvm-selected")}},
                        {"disk",pstream::Value{pv.parent_disk}},
                        {"lv_uuid",pstream::Value{lv.uuid}}}}}}}}};
            const auto chosen = select_machine_extra_volumes(std::move(plan),
                {"/mnt/opensabba-lvm-selected"});
            const auto& fields = std::get<pstream::Value::Object>(chosen.data);
            check(std::get<pstream::Value::Array>(fields.at("selected_extra").data).size() == 1);
            check(std::get<pstream::Value::Array>(fields.at("excluded").data).size() == 1);
            check(std::get<pstream::Value::Array>(fields.at("additional_disks").data).empty());
            std::cout << "Read-only LVM probe: " << live.volume_groups.size() << " VG, "
                << live.physical_volumes.size() << " PV, " << live.logical_volumes.size() << " LV\n";
        }
        std::cout << "LVM tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
