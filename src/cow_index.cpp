#include "opensabba/cow_index.hpp"
#include <algorithm>
#include <charconv>

namespace opensabba {
namespace {
using pstream::Error;
std::uint64_t le(std::span<const std::uint8_t> bytes, std::size_t at, std::size_t width = 8) {
    std::uint64_t value = 0;
    for (std::size_t n = 0; n < width; ++n) value |= std::uint64_t{bytes[at+n]} << (8*n);
    return value;
}
CowIndex read_entries(const ReadCow& read, std::uint64_t file_size, std::uint64_t source_size,
                      std::uint64_t block_size) {
    constexpr std::uint64_t header_size = 4096;
    const auto blocks = source_size/block_size+(source_size%block_size != 0);
    CowIndex result;
    // Previous-generation index retention requests the CURRENT origin's index in
    // 1 MiB fread chunks. A short chunk is discarded in its entirety; the
    // compact prefix already accumulated is still a successful CBT result.
    constexpr std::uint64_t batch_entries = 1024*1024/8;
    for (std::uint64_t base = 0; base < blocks;) {
        const auto count = std::min(batch_entries,blocks-base);
        const auto at = header_size+base*8;
        if (at > file_size || count*8 > file_size-at) break;
        const auto bytes = read(at,static_cast<std::size_t>(count*8));
        if (bytes.size() != count*8) break;
        for (std::size_t n = 0; n < count; ++n) {
            if (!le(bytes,n*8)) continue;
            ++result.changed_blocks;
            const auto offset = (base+n)*block_size;
            if (!result.extents.empty() && result.extents.back().offset+result.extents.back().length == offset)
                result.extents.back().length += block_size;
            else result.extents.push_back({offset,block_size});
        }
        // – emits only at 128-entry boundaries, including
        // a changed mapping's skip to the end of its 16-entry group. the official agent
        // does not flush a remaining partial byte after the loop.
        std::uint8_t compact = 0;
        for (std::uint64_t n = 0; n < count;) {
            auto next = n+1;
            if (le(bytes,static_cast<std::size_t>(n*8))) {
                compact |= std::uint8_t{1} << ((n/16)%8);
                next = (n/16+1)*16;
            }
            if ((n+1)%128 == 0 || next%128 == 0) {
                result.compact_bitmap.push_back(compact);
                compact = 0;
            }
            n = next;
        }
        base += count;
    }
    return result;
}

}
CowIndex read_cow_index(const ReadCow& read, std::uint64_t file_size, std::uint64_t source_size,
                        std::string_view uuid, std::uint64_t sequence, std::uint64_t block_size) {
    constexpr std::uint64_t header_size = 4096;
    if (block_size != 4096 || !source_size || source_size % block_size)
        throw Error("COW index reader requires a 4 KiB driver and block-aligned source");
    if (!sequence || uuid.size() != 32) throw Error("invalid expected COW generation");
    auto exact = [&](std::uint64_t at, std::size_t length) {
        auto bytes = read(at, length);
        if (bytes.size() != length) throw Error("truncated COW index read");
        return bytes;
    };
    const auto header = exact(0, header_size);
    const auto flags = le(header, 4, 4);
    if (le(header, 0, 4) != 4776 || le(header, 48) != 1)
        throw Error("unsupported COW index magic or version");
    if ((flags & 3) != 3 || (flags & ~std::uint64_t{7}))
        throw Error("COW index must be clean, closed and index-only");
    if (le(header, 24) != sequence) throw Error("COW index sequence differs from the retained generation");
    for (std::size_t n = 0; n < 16; ++n) {
        unsigned int byte{};
        const auto [end, error] = std::from_chars(uuid.data()+2*n, uuid.data()+2*n+2, byte, 16);
        if (error != std::errc{} || end != uuid.data()+2*n+2 || header[32+n] != byte)
            throw Error("COW index UUID differs from the retained generation");
    }
    if (std::any_of(header.begin()+64, header.end(), [](auto byte) { return byte != 0; }))
        throw Error("unsupported COW header extension");
    const auto position = le(header, 8), allocation = le(header, 16);
    if (position < header_size/block_size || allocation < header_size || file_size > allocation ||
        position > allocation/block_size)
        throw Error("invalid COW index header geometry");
    return read_entries(read,file_size,source_size,block_size);
}
pstream::Bytes compact_cow_index(const ReadCow& read, std::uint64_t file_size, std::uint64_t source_size) {
    // Index retention compacts bytes without interpreting its header,
    // UUID, sequence, mapping addresses or changed-block count.
    return read_entries(read,file_size,source_size,4096).compact_bitmap;
}

}
