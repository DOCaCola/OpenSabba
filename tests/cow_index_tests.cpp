#include "image_delta_fixture.hpp"
#include "opensabba/cow_index.hpp"
#include "opensabba/delta_plan.hpp"
#include <iostream>

using opensabba::pstream::Bytes;
using opensabba::pstream::Error;
void put(Bytes& bytes, std::size_t at, std::uint64_t value, std::size_t width = 8) {
    for (std::size_t n = 0; n < width; ++n) bytes[at+n] = static_cast<std::uint8_t>(value >> (8*n));
}
void check(bool okay) { if (!okay) throw Error("COW index test failed"); }
void compact_partial_bytes() {
    constexpr std::uint64_t batch = 131072;
    for (const std::uint64_t blocks : {1ULL,15ULL,16ULL,112ULL,113ULL,127ULL,128ULL,129ULL,
                                      4095ULL,4096ULL,4097ULL,131185ULL})
        for (const bool changed : {false,true}) {
            const auto entries = (blocks+4095)/4096*4096;
            Bytes cow(static_cast<std::size_t>(4096+entries*8),0);
            // Nonzero driver section padding must never enter the request.
            for (auto n = blocks; n < entries; ++n) put(cow,static_cast<std::size_t>(4096+n*8),1);
            if (changed) put(cow,static_cast<std::size_t>(4096+(blocks-1)*8),UINT64_MAX);
            std::vector<std::pair<std::uint64_t,std::size_t>> reads;
            const auto bitmap = opensabba::compact_cow_index([&](auto at,auto count) {
                reads.emplace_back(at,count);
                return Bytes(cow.begin()+static_cast<std::ptrdiff_t>(at),cow.begin()+static_cast<std::ptrdiff_t>(at+count));
            },cow.size(),(blocks-1)*4096+512); // ceil to a driver block, not a section.
            const auto remainder = blocks%128;
            const auto emits_partial = changed && remainder >= 113;
            check(bitmap.size() == blocks/128+static_cast<unsigned>(emits_partial));
            const auto sets_last = changed && (!remainder || emits_partial);
            for (std::size_t byte = 0; byte < bitmap.size(); ++byte)
                check(bitmap[byte] == (sets_last && byte+1 == bitmap.size() ? 128U : 0U));
            check(reads.size() == (blocks+batch-1)/batch && reads.front().first == 4096);
            check(reads.back().second == (blocks%batch ? blocks%batch : batch)*8);
        }
}
int main() {
    try {
        compact_partial_bytes();
        const std::string uuid(32, 'a');
        Bytes good(4096+8192*8);
        put(good, 0, 4776, 4); put(good, 4, 3, 4);
        put(good, 8, 100); put(good, 16, 1048576); put(good, 24, 7);
        std::fill(good.begin()+32, good.begin()+48, 0xaa);
        put(good, 48, 1); put(good, 56, 4);
        for (auto block : {0, 4095, 4096, 4099})
            put(good, 4096+static_cast<std::size_t>(block)*8, block == 0 ? 19 : 1);
        auto parse = [&](const Bytes& bytes, std::uint64_t size = 4100*4096ULL,
                         std::string_view id = {}, std::uint64_t sequence = 7, std::uint64_t block = 4096) {
            return opensabba::read_cow_index([&](std::uint64_t at, std::size_t count) {
                if (at > bytes.size() || count > bytes.size()-at) throw Error("fixture read out of bounds");
                return Bytes(bytes.begin()+static_cast<std::ptrdiff_t>(at),
                             bytes.begin()+static_cast<std::ptrdiff_t>(at+count));
            }, bytes.size(), size, id.empty() ? uuid : id, sequence, block);
        };
        auto result = parse(good);
        check(result.changed_blocks == 4 && result.extents.size() == 3);
        check(result.extents[1].offset == 4095*4096ULL && result.extents[1].length == 8192);
        // the official agent treats mapping values only as booleans.
        // A mapping never becomes a source offset or a COW payload address.
        auto arbitrary = good;
        put(arbitrary,4096,UINT64_MAX); put(arbitrary,56,UINT64_MAX);
        const auto one = parse(arbitrary,4096);
        check(one.changed_blocks == 1 && one.extents.size() == 1 &&
              one.extents[0].offset == 0 && one.extents[0].length == 4096);
        check(opensabba::union_changed_extents(4096,one.extents).size() == 1);
        check(opensabba::snapshot_delta_plan(4096,one.extents).image_size == 2*1024*1024+4096);
        auto empty = good;
        std::fill(empty.begin()+4096, empty.end(), 0);
        put(empty, 56, 0);
        check(parse(empty).extents.empty());
        auto vmalloc = good;
        put(vmalloc, 4, 7, 4);
        check(parse(vmalloc).changed_blocks == 4);
        unsigned int failures = 0;
        auto reject = [&](const auto& operation) {
            bool rejected = false;
            try { operation(); } catch (const Error&) { rejected = true; }
            check(rejected); ++failures;
        };
        for (const auto [offset, value] : std::vector<std::pair<std::size_t, std::uint64_t>>{
                {0, 4777}, {4, 0}, {4, 2}, {4, 1}, {4, 11}, {8, 0}, {8, 1000},
                {16, 1}, {24, 8}, {32, 0}, {48, 0}, {48, 2},
                {64, 1}}) {
            auto bad = good;
            put(bad, offset, value, offset < 8 ? 4 : 8);
            reject([&] { parse(bad); });
        }
        auto short_file = good; short_file.pop_back();
        check(parse(short_file).changed_blocks == 4);
        // Clean shutdown initializes an extra write-ahead window for dormant
        // direct COW I/O. the official agent Previous-generation index retention reads only the index.
        auto boot_closed = good;
        boot_closed.resize(good.size()+4*4096,0);
        check(parse(boot_closed).changed_blocks == result.changed_blocks);
        put(boot_closed,16,good.size());
        reject([&] { parse(boot_closed); });
        reject([&] { parse(good, 0); });
        reject([&] { parse(good, 4100*4096ULL+512); });
        reject([&] { parse(good, 4100*4096ULL, uuid, 7, 16384); });
        reject([&] { parse(good, 4100*4096ULL, uuid, 0); });
        reject([&] { parse(good, 4100*4096ULL, "bad-uuid"); });
        reject([&] {
            opensabba::read_cow_index([](auto, auto) { return Bytes{}; },
                                     good.size(), 4100*4096ULL, uuid, 7, 4096);
        });
        std::cout << "COW index: 4 valid fixtures and " << failures << " rejection cases passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
