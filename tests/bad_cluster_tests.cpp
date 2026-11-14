#include "opensabba/bad_cluster.hpp"
#include "opensabba/image.hpp"
#include "opensabba/snapshot.hpp"
#include <algorithm>
#include <iostream>
#include <sstream>
#ifdef __linux__
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
namespace {
int failing_descriptor = -1;
std::size_t failing_sector = 0;
}
extern "C" ssize_t pread(int descriptor,void* buffer,size_t size,off_t offset) {
    // Inspect the actual pointer passed to the syscall, including 512-byte
    // fallback lengths; vector storage is not sufficiently aligned.
    if ((fcntl(descriptor,F_GETFL,0) & O_DIRECT) &&
        reinterpret_cast<std::uintptr_t>(buffer)%4096)
        throw opensabba::pstream::Error("direct source buffer is not aligned to 4096");
    if (descriptor == failing_descriptor && offset < static_cast<off_t>(2*failing_sector) &&
        offset+static_cast<off_t>(size) > static_cast<off_t>(failing_sector)) {
        errno = EIO;
        return -1;
    }
    return static_cast<ssize_t>(syscall(SYS_pread64,descriptor,buffer,size,offset));
}
#endif
using namespace opensabba;
using pstream::Bytes;
using pstream::Value;
namespace {
void check(bool okay) { if (!okay) throw pstream::Error("bad-cluster invariant failed"); }
void put(Bytes& data, std::size_t at, std::uint64_t value, unsigned size = 4) {
    for (unsigned i = 0; i < size; ++i) data.at(at+i) = static_cast<std::uint8_t>(value >> (8*i));
}
std::uint64_t number(const Value& value, const char* key) {
    return std::get<std::uint64_t>(std::get<Value::Object>(value.data).at(key).data);
}
struct ExtImage {
    std::size_t block;
    Bytes data;
    explicit ExtImage(unsigned log, unsigned filesystem) : block(std::size_t{1024} << log), data(2048*block) {
        const auto first = block == 1024 ? 1U : 0U;
        put(data,1024,128);
        put(data,1024+4,2048);
        put(data,1024+0x14,first);
        put(data,1024+0x18,log);
        put(data,1024+0x1c,log);
        put(data,1024+0x20,2048);
        put(data,1024+0x24,2048);
        put(data,1024+0x28,128);
        put(data,1024+0x38,0xef53,2);
        put(data,1024+0x4c,filesystem == 2 ? 0 : 1);
        put(data,1024+0x58,256,2);
        if (filesystem >= 3) put(data,1024+0x5c,4);
        if (filesystem == 4) {
            put(data,1024+0x60,0xc0); // extents and 64-bit group descriptors
            put(data,1024+0xfe,64,2);
        }
        put(data,(first+1)*block,3); // block bitmap
        put(data,(first+1)*block+8,5); // inode table: inode 1 at block 5
        std::fill_n(data.begin()+static_cast<std::ptrdiff_t>(3*block),256,255);
    }
    void pointer(unsigned n, std::uint64_t value) { put(data,5*block+40+4*n,value); }
    BadClusterContext context(std::uint64_t fail_at = UINT64_MAX,
        std::vector<std::pair<std::uint64_t,std::size_t>>* reads = nullptr) const {
        return snapshot_bad_cluster_context("/scratch",data.size(),[&](auto at,auto count) {
            if (reads) reads->emplace_back(at,count);
            if (at == fail_at) throw pstream::Error("injected metadata failure");
            return Bytes(data.begin()+static_cast<std::ptrdiff_t>(at),
                         data.begin()+static_cast<std::ptrdiff_t>(at+count));
        });
    }
    BadClusterContext short_context(std::uint64_t fail_at, std::size_t request, std::size_t kept) const {
        return snapshot_bad_cluster_context("/scratch",data.size(),[&](auto at,auto count) {
            if (at == fail_at && count == request) count = kept;
            return Bytes(data.begin()+static_cast<std::ptrdiff_t>(at),data.begin()+static_cast<std::ptrdiff_t>(at+count));
        });
    }
};
void parsing() {
    for (auto log : {0U,2U}) for (auto fs : {2U,3U,4U}) {
        ExtImage image(log,fs);
        std::vector<std::pair<std::uint64_t,std::size_t>> metadata;
        check(image.context(UINT64_MAX,&metadata).ranges.empty());
        // One parser initialization reads SB, full GDT, bitmap, then inode 1.
        // allocation context owns a separate parser; bad-block context must not
        // reread either its own superblock or its cached group descriptor.
        check(metadata == std::vector<std::pair<std::uint64_t,std::size_t>>{
            {0,512},{1024,1024},{image.block == 1024 ? 2048U : 4096U,image.block},
            {3*image.block,256},{5*image.block,128}});
        // All twelve direct pointers, then single, double and triple indirect.
        for (unsigned i = 0; i < 12; ++i) image.pointer(i,200+i);
        image.pointer(12,20); image.pointer(13,21); image.pointer(14,22);
        put(image.data,20*image.block,212); put(image.data,20*image.block+4,220);
        put(image.data,21*image.block,23); put(image.data,23*image.block,221);
        put(image.data,22*image.block,24); put(image.data,24*image.block,25); put(image.data,25*image.block,300);
        const auto context = image.context();
        check(context.volume == "/scratch" && context.ranges.size() == 3);
        check(context.ranges[0].offset == 200*image.block && context.ranges[0].length == 13*image.block);
        check(context.ranges[1].offset == 220*image.block && context.ranges[1].length == 2*image.block);
        check(context.ranges[2].offset == 300*image.block && context.ranges[2].length == image.block);
        // Header/superblock/GDT/bitmap/inode truncation follows the same
        // official agent failure boundary as a failed syscall, before any field access.
        const auto gd = (image.block == 1024 ? 2U : 1U)*image.block;
        for (const auto request : std::vector<std::pair<std::uint64_t,std::size_t>>{
                {0,512},{1024,1024},{gd,image.block},{3*image.block,256},
                {5*image.block,128}})
            for (const auto kept : {std::size_t{0},request.second-1})
                check(image.short_context(request.first,request.second,kept).ranges.empty());
        for (const auto kept : {std::size_t{0},image.block-1}) {
            const auto short_tree = image.short_context(20*image.block,image.block,kept);
            check(short_tree.ranges.size() == 3 && short_tree.ranges[0].length == 12*image.block &&
                  short_tree.ranges[1].offset == 221*image.block);
        }
        // the official agent returns an empty inode vector on inode read failure; a tree
        // failure retains other direct/tree entries and continues walking.
        check(image.context(5*image.block).ranges.empty());
        const auto partial = image.context(20*image.block);
        check(partial.ranges.size() == 3 && partial.ranges[0].length == 12*image.block);
        check(partial.ranges[1].offset == 221*image.block);
        check(image.context(3*image.block).ranges.empty()); // init/bitmap failure
        image.pointer(3,0);
        check(image.context().ranges.size() == 1 && image.context().ranges[0].length == 3*image.block);
    }
    ExtImage image(2,4);
    put(image.data,5*image.block+0x20,0x80000);
    const auto inode = 5*image.block+40;
    put(image.data,inode,0xf30a,2); put(image.data,inode+2,1,2); put(image.data,inode+6,1,2);
    put(image.data,inode+16,20); // extent index to block 20
    put(image.data,20*image.block,0xf30a,2); put(image.data,20*image.block+2,2,2);
    put(image.data,20*image.block+16,2,2); put(image.data,20*image.block+20,400);
    put(image.data,20*image.block+28,0x8001,2); put(image.data,20*image.block+32,500);
    const auto extents = image.context();
    check(extents.ranges.size() == 2 && extents.ranges[0].offset == 400*image.block &&
          extents.ranges[0].length == 2*image.block && extents.ranges[1].length == image.block);
    for (const auto kept : {std::size_t{0},image.block-1})
        check(image.short_context(20*image.block,image.block,kept).ranges.empty());
    put(image.data,5*image.block+0x20,0x10000000);
    check(image.context().ranges.empty());
    Bytes xfs(2048); xfs[0]='X'; xfs[1]='F'; xfs[2]='S'; xfs[3]='B';
    unsigned reads = 0;
    check(snapshot_bad_cluster_context("xfs",xfs.size(),[&](auto at,auto count) {
        ++reads; return Bytes(xfs.begin()+at,xfs.begin()+at+count);
    }).ranges.empty() && reads == 2);
}
void wire() {
    for (const auto compression : {TransferCompression::none,TransferCompression::lz4})
        for (const bool cbt : {false,true}) for (const auto mode : {0U,1U,2U}) {
            if (!cbt && mode == 2) continue;
            std::vector<std::pair<std::uint64_t,std::size_t>> reads;
            constexpr std::uint64_t mib = 1024*1024;
            auto volume = std::make_shared<ImageSource>(mib,[&](auto at,auto count,auto*) {
                check(at+count <= 6144 || at >= 9216);
                reads.emplace_back(at,count); return Bytes(count,42);
            },[] {});
            volume->set_bad_clusters({{{6144,3072}},"/scratch"});
            auto header = std::make_shared<ImageSource>(Bytes(mib));
            ImageSource disk(3*mib,std::vector<ImageExtent>{{0,mib,0,header},{mib,mib,0,volume},{2*mib,mib,0,header}});
            DeltaPlan delta{3*mib,3*mib,{{0,3*mib,true}}}; delta.filesystem_allocation = true;
            std::vector<ChangedExtent> unused;
            if (mode == 1) unused = {{mib,16384}};
            if (mode == 2) {
                delta.ranges = {{0,mib,true},{mib,16384,false},{mib+16384,2*mib-16384,true}};
                delta.transfer_bytes -= 16384;
            }
            unsigned skipped = 0, reports = 0;
            std::uint64_t next = 0;
            stream_image(disk,"bad.img",8192,[&](const Value& record) {
                const auto& fields = std::get<Value::Object>(record.data);
                check(number(record,"offset") == next);
                next += number(record,"length");
                if (number(record,"used") && number(record,"changed") && !fields.contains("buffer")) {
                    check(mode == 0 && number(record,"changed_length") == 0 &&
                          number(record,"is_interval_cbt") == static_cast<unsigned>(cbt) && !fields.contains("compressed"));
                    check((number(record,"offset") == mib+6144 && number(record,"length") == 2048) ||
                          (number(record,"offset") == mib+8192 && number(record,"length") == 1024));
                    ++skipped;
                }
            },{},0,compression,cbt ? &delta : nullptr,unused,{},{},[&](auto type,auto parameters) {
                check(type == 7044 && std::get<std::string>(parameters.at("volume_name").data) == "/scratch");
                check(std::get<std::string>(parameters.at("interval_start").data) == (reports ? "0x2000" : "0x1800"));
                check(std::get<std::string>(parameters.at("interval_end").data) == (reports ? "0x23ff" : "0x1fff"));
                ++reports;
            });
            check(next == disk.size() && skipped == (mode ? 0U : 2U) && reports == skipped);
        }
}
void metadata_routing() {
    constexpr std::uint64_t mib = 1024*1024;
    ExtImage image(2,2);
    put(image.data,1024+0x3a,1,2);
    put(image.data,1024+0x68,1,1);
    std::vector<std::pair<std::uint64_t,std::size_t>> metadata;
    unsigned payload = 0;
    auto volume = std::make_shared<ImageSource>(image.data.size(),
        [&](auto,auto length,auto*) { ++payload; return Bytes(length,42); },[] {},
        [&](auto at,auto length) {
            metadata.emplace_back(at,length);
            return Bytes(image.data.begin()+static_cast<std::ptrdiff_t>(at),
                         image.data.begin()+static_cast<std::ptrdiff_t>(at+length));
        });
    Bytes mbr(mib);
    mbr[510] = 0x55; mbr[511] = 0xaa;
    put(mbr,450,0x83,1);
    put(mbr,454,mib/512);
    put(mbr,458,image.data.size()/512);
    auto header = std::make_shared<ImageSource>(mbr);
    // Nested composites also model logical-volume wrappers.
    auto wrapped = std::make_shared<ImageSource>(volume->size(),
        std::vector<ImageExtent>{{0,volume->size(),0,volume}});
    ImageSource disk(volume->size()+2*mib,std::vector<ImageExtent>{
        {0,mib,0,header},{mib,volume->size(),0,wrapped},{mib+volume->size(),mib,0,header}});
    check(!fixed_image_metadata(disk,512,"routing.img",123).empty() && payload == 0);
    check(metadata == std::vector<std::pair<std::uint64_t,std::size_t>>{{0,512},{1024,1024}});
    const Value logical{Value::Object{
        {"length",Value{static_cast<std::uint64_t>(volume->size())}},
        {"image_name",Value{"logical.img"}},{"filesystem",Value{"ext2"}},
        {"filesystem_uuid",Value{"01000000-0000-0000-0000-000000000000"}},
        {"mount_path",Value{"/data"}},{"lv_uuid",Value{"lv"}},{"vg_uuid",Value{"vg"}},
        {"logical_path",Value{"/dev/fixture/lv"}}}};
    check(!fixed_image_metadata(*wrapped,512,"logical.img",123,nullptr,&logical).empty() && payload == 0);
    check(metadata == std::vector<std::pair<std::uint64_t,std::size_t>>{
        {0,512},{1024,1024},{0,512},{1024,1024}});
    check(disk.read(mib+4096,4096) == Bytes(4096,42) && payload == 1);
}
#ifdef __linux__
void direct_reader() {
    char path[] = "/tmp/opensabba-direct-XXXXXX";
    const auto fd = mkstemp(path);
    check(fd >= 0); unlink(path);
    try {
        const Bytes expected(3*1024*1024,0x5a);
        check(write(fd,expected.data(),expected.size()) == static_cast<ssize_t>(expected.size()));
        check(!(fcntl(fd,F_GETFL,0) & O_DIRECT));
        check(read_source_at(fd,512,512,path,"/scratch",512) == Bytes(512,0x5a));
        enable_source_direct(fd);
        check((fcntl(fd,F_GETFL,0) & O_DIRECT) != 0);
        for (const auto sector : {512U,4096U}) {
            check(read_source_at(fd,sector,sector,path,"/scratch",sector) == Bytes(sector,0x5a));
            failing_descriptor = fd;
            failing_sector = sector;
            ImageSource source(expected.size(),[&](auto at,auto length,auto*) {
                return read_source_at(fd,at,length,path,"/scratch",sector);
            },[] {});
            unsigned skipped = 0, reports = 0;
            stream_image(source,"direct.img",8192,[&](const Value& record) {
                if (!std::get<Value::Object>(record.data).contains("buffer")) {
                    check(number(record,"offset") == sector && number(record,"length") == sector);
                    ++skipped;
                }
            },{},0,TransferCompression::none,nullptr,{},{},{},[&](auto type,auto) {
                check(type == 7044); ++reports;
            });
            check(skipped == 1 && reports == 1);
            failing_descriptor = -1;
        }
    } catch (...) { failing_descriptor = -1; close(fd); throw; }
    close(fd);
}
#endif
}
int main() {
    try {
        parsing(); wire(); metadata_routing();
#ifdef __linux__
        direct_reader();
#endif
        std::cout << "bad-block inode, interval records and aligned reader passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
