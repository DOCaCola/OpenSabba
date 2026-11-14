#include "opensabba/bad_cluster.hpp"
#include "opensabba/filesystem.hpp"
#include <iostream>

namespace opensabba {
namespace {
using pstream::Bytes;
using pstream::Error;
using Reader = std::function<Bytes(std::uint64_t,std::size_t)>;
std::uint16_t le16(const Bytes& bytes, std::size_t at) {
    return static_cast<std::uint16_t>(bytes.at(at) | std::uint16_t(bytes.at(at+1)) << 8);
}
std::uint32_t le32(const Bytes& bytes, std::size_t at) {
    return std::uint32_t(le16(bytes,at)) | std::uint32_t(le16(bytes,at+2)) << 16;
}
std::uint32_t crc32c(std::span<const std::uint8_t> bytes) {
    std::uint32_t crc = 0xffffffffU;
    for (const auto byte : bytes) {
        crc ^= byte;
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ ((crc & 1) ? 0x82f63b78U : 0);
    }
    return crc;
}
void validate_ext(const Bytes& sb, std::uint64_t block) {
    // Filesystem initialization and validation. A bad-block
    // context has the same initialization contract as an allocation context.
    const auto revision = le32(sb,0x4c), incompat = le32(sb,0x60), ro = le32(sb,0x64);
    const auto block_log = le32(sb,0x18), cluster_log = le32(sb,0x1c);
    const auto per_group = le32(sb,0x20), inodes = le32(sb,0x28);
    const auto inode_size = revision ? le16(sb,0x58) : 128U;
    const auto blocks = std::uint64_t(le32(sb,4)) |
        ((incompat & 0x80U) ? std::uint64_t(le32(sb,0x150)) << 32 : 0);
    const auto first = le32(sb,0x14);
    if (revision > 1 || cluster_log < block_log || cluster_log-block_log > 16 ||
        (!(ro & 0x200U) && cluster_log != block_log) ||
        ((incompat & 0x80U) && le16(sb,0xfe) < 64) || (incompat & 8U) ||
        blocks <= first || !per_group ||
        per_group > (std::uint64_t{65528} << (cluster_log-block_log)) || !inodes ||
        inode_size < 128 || inode_size > block || (inode_size & (inode_size-1)))
        throw Error("invalid ext bad-block filesystem geometry");
    const auto groups = (blocks-first+per_group-1)/per_group;
    const auto table_blocks = (std::uint64_t(inodes)*inode_size+block-1)/block;
    if (groups > UINT32_MAX || groups*inodes != le32(sb,0) ||
        table_blocks > 65536-block/inode_size)
        throw Error("invalid ext bad-block inode geometry");
}
struct ExtBadBlocks {
    std::uint64_t length, block;
    const Reader& read;
    std::vector<std::uint64_t> numbers;
    Bytes bytes(std::uint64_t at, std::size_t count) const {
        if (at > length || count > length-at) throw Error("ext bad-block metadata exceeds volume");
        auto result = read(at,count);
        if (result.size() != count) throw Error("short ext bad-block metadata read");
        return result;
    }
    void indirect(std::uint64_t number, unsigned depth) {
        // Indirect-block reads reports failure locally; its callers
        // continue walking, preserving any earlier entries.
        try {
            const auto data = bytes(number*block,static_cast<std::size_t>(block));
            for (std::size_t at = 0; at < data.size(); at += 4) {
                const auto child = le32(data,at);
                if (!child) break;
                if (depth == 1) numbers.push_back(child);
                else indirect(child,depth-1);
            }
        } catch (const Error& error) {
            std::cerr << "Failed to read ext bad-block indirect block: " << error.what() << '\n';
        }
    }
    void extents(const Bytes& data, std::size_t first) {
        const auto entries = le16(data,first+2), depth = le16(data,first+6);
        if (entries > (data.size()-first-12)/12 || depth > 5)
            throw Error("invalid ext bad-block extent tree");
        for (std::size_t n = 0; n < entries; ++n) {
            const auto at = first+12+n*12;
            if (depth) {
                const auto child = std::uint64_t(le32(data,at+4)) | std::uint64_t(le16(data,at+8)) << 32;
                try { extents(bytes(child*block,static_cast<std::size_t>(block)),0); }
                catch (const Error& error) {
                    std::cerr << "Failed to read ext bad-block extent block: " << error.what() << '\n';
                }
            } else {
                const auto encoded = le16(data,at+4);
                const auto count = encoded > 0x8000U ? encoded-0x8000U : encoded;
                const auto start = std::uint64_t(le32(data,at+8)) | std::uint64_t(le16(data,at+6)) << 32;
                for (std::uint64_t i = 0; i < count; ++i) numbers.push_back(start+i);
            }
        }
    }
    void inode(std::uint64_t table_offset) {
        // Inode 1 is the first inode in group 0, independent of inode size.
        const auto data = bytes(table_offset,128);
        const auto flags = le32(data,0x20);
        if (flags & 0x10000000U) return; // official agent skips inline-data inodes
        if (flags & 0x80000U) { extents(data,40); return; }
        for (unsigned i = 0; i < 15; ++i) {
            const auto number = le32(data,40+4*i);
            if (!number) break;
            if (i < 12) numbers.push_back(number);
            else indirect(number,i-11);
        }
    }
};
}
BadClusterContext snapshot_bad_cluster_context(std::string_view volume, std::uint64_t length,
                                               const Reader& read) {
    BadClusterContext result{{},std::string(volume)};
    try {
        const auto first = read(0,512);
        if (first.size() != 512) throw Error("short filesystem header");
        if (first[0] == 'X' && first[1] == 'F' && first[2] == 'S' && first[3] == 'B') {
            // XFS initialization can fail, but bad-block lookup itself
            // always returns an empty vector.
            (void)filesystem_unused_extents(length,read);
            return result;
        }
        const auto sb = read(1024,1024);
        if (sb.size() != 1024 || le16(sb,0x38) != 0xef53 || le32(sb,0x18) > 6)
            throw Error("unsupported filesystem or invalid ext superblock");
        if (le32(sb,0x64) & 0x400U)
            if (sb[0x175] != 1 || crc32c(std::span(sb).first(0x3fc)) != le32(sb,0x3fc))
                throw Error("ext bad-block superblock checksum mismatch or unsupported checksum type");
        validate_ext(sb,std::uint64_t{1024} << le32(sb,0x18));
        // Filesystem initialization reads the group descriptors and
        // allocation bitmap before the inode walker is available. A failure
        // here discards the context, independently of the worker's used map.
        const auto allocation = ext_allocation_context(length,sb,read);
        ExtBadBlocks ext{length,std::uint64_t{1024} << le32(sb,0x18),read,{}};
        try { ext.inode(allocation.inode_table_offset); }
        catch (const Error& error) {
            // Inode block lookup returns its empty vector when
            // inode lookup fails; it does not fail Bad-block discovery.
            std::cerr << "Failed to read ext bad-blocks inode: " << error.what() << '\n';
        }
        // Bad-block discovery coalesces in traversal order.
        // It does not sort or add the indirect blocks themselves to this list.
        for (const auto number : ext.numbers) {
            if (!number) continue;
            const auto at = number*ext.block;
            if (!result.ranges.empty() && result.ranges.back().offset+result.ranges.back().length == at)
                result.ranges.back().length += ext.block;
            else result.ranges.push_back({at,ext.block});
        }
    } catch (const Error& error) {
        std::cerr << "Failed to initialize bad cluster context on '" << volume << "': " << error.what() << '\n';
    }
    return result;
}
}
