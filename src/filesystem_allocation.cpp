#include "opensabba/filesystem.hpp"
#include <algorithm>
#include <bit>
#include <iostream>
#include <set>
#include <stdexcept>

namespace opensabba {
namespace {
using pstream::Bytes;
using Reader = std::function<Bytes(std::uint64_t,std::size_t)>;
std::uint16_t le16(const Bytes& b, std::size_t p) {
    return static_cast<std::uint16_t>(b.at(p) | std::uint16_t(b.at(p+1)) << 8);
}
std::uint32_t le32(const Bytes& b, std::size_t p) {
    return std::uint32_t(le16(b,p)) | std::uint32_t(le16(b,p+2)) << 16;
}
std::uint16_t be16(const Bytes& b, std::size_t p) {
    return static_cast<std::uint16_t>(std::uint16_t(b.at(p)) << 8 | b.at(p+1));
}
std::uint32_t be32(const Bytes& b, std::size_t p) {
    return std::uint32_t(be16(b,p)) << 16 | be16(b,p+2);
}
std::uint64_t be64(const Bytes& b, std::size_t p) {
    return std::uint64_t(be32(b,p)) << 32 | be32(b,p+4);
}
std::uint32_t crc32c(std::uint32_t crc, std::span<const std::uint8_t> b) {
    for (auto byte : b) {
        crc ^= byte;
        for (unsigned i = 0; i < 8; ++i) crc = (crc >> 1) ^ ((crc & 1) ? 0x82f63b78U : 0);
    }
    return crc;
}
std::uint16_t crc16(std::uint16_t crc, std::span<const std::uint8_t> b) {
    for (auto byte : b) {
        crc ^= byte;
        for (unsigned i = 0; i < 8; ++i)
            crc = static_cast<std::uint16_t>((crc >> 1) ^ ((crc & 1) ? 0xa001U : 0));
    }
    return crc;
}
struct Allocation {
    std::uint64_t length, block_size, blocks;
    Reader read;
    Bytes bitmap;
    Allocation(std::uint64_t length_, std::uint64_t block, std::uint64_t count, Reader read_)
        : length(length_), block_size(block), blocks(count), read(std::move(read_)) {
        if (!block || !count || count > length/block) throw FilesystemAllocationError("filesystem allocation geometry exceeds source");
        bitmap.assign(static_cast<std::size_t>((count+7)/8),255);
    }
    Bytes bytes(std::uint64_t offset, std::size_t size) const {
        if (offset > length || size > length-offset) throw FilesystemAllocationError("filesystem allocation read exceeds source");
        auto result = read(offset,size);
        if (result.size() != size) throw FilesystemAllocationError("short filesystem allocation metadata read");
        return result;
    }
    void set(std::uint64_t start, std::uint64_t count, bool used) {
        if (start > blocks || count > blocks-start) throw FilesystemAllocationError("filesystem allocation extent exceeds source");
        for (auto n = start; n < start+count; ++n) {
            auto& byte = bitmap.at(static_cast<std::size_t>(n/8));
            const auto bit = static_cast<std::uint8_t>(1U << (n%8));
            byte = used ? static_cast<std::uint8_t>(byte | bit) : static_cast<std::uint8_t>(byte & ~bit);
        }
    }
    std::vector<ChangedExtent> unused() const {
        std::vector<ChangedExtent> result;
        for (std::uint64_t n = 0; n < blocks; ++n) {
            if (bitmap[static_cast<std::size_t>(n/8)] & (1U << (n%8))) continue;
            const auto at = n*block_size;
            if (!result.empty() && result.back().offset+result.back().length == at) result.back().length += block_size;
            else result.push_back({at,block_size});
        }
        return result;
    }
};
bool power_of(std::uint64_t n, std::uint64_t base) {
    while (n > 1 && n%base == 0) n /= base;
    return n == 1;
}
ExtAllocationContext ext_unused(std::uint64_t length, const Reader& read, const Bytes& sb) {
    const auto incompat = le32(sb,0x60), ro = le32(sb,0x64), compat = le32(sb,0x5c);
    const auto log_block = le32(sb,0x18), log_cluster = le32(sb,0x1c);
    if (log_block > 6 || log_cluster < log_block || log_cluster-log_block > 16)
        throw FilesystemAllocationError("invalid ext allocation block/cluster size");
    const std::uint64_t block = std::uint64_t{1024} << log_block;
    const std::uint64_t cluster = std::uint64_t{1} << (log_cluster-log_block);
    const std::uint64_t blocks = le32(sb,4) | ((incompat & 0x80) ? std::uint64_t(le32(sb,0x150)) << 32 : 0);
    const auto first = le32(sb,0x14), per_group = le32(sb,0x20), clusters = le32(sb,0x24);
    const std::uint64_t desc_size = (incompat & 0x80) ? le16(sb,0xfe) : 32;
    if (!per_group || !clusters || clusters > block*8 || std::uint64_t(clusters)*cluster != per_group ||
        blocks <= first || desc_size < 32 || desc_size > block || block%desc_size)
        throw FilesystemAllocationError("invalid ext allocation group geometry");
    Allocation map(length,block,blocks,read);
    const auto groups = (blocks-first+per_group-1)/per_group;
    const auto desc_per_block = block/desc_size, desc_blocks = (groups+desc_per_block-1)/desc_per_block;
    const auto first_meta = le32(sb,0x104);
    const auto has_super = [&](std::uint64_t group) {
        if (!group) return true;
        if (compat & 0x200) return group == le32(sb,0x24c) || group == le32(sb,0x250);
        return !(ro & 1) || group == 1 || power_of(group,3) || power_of(group,5) || power_of(group,7);
    };
    const auto group_start = [&](std::uint64_t group) { return first+group*per_group; };
    const auto descriptor_block = [&](std::uint64_t n) {
        if ((incompat & 0x10) && n >= first_meta) {
            const auto group = n*desc_per_block;
            return group_start(group)+(has_super(group) ? 1U : 0U);
        }
        return std::uint64_t(first)+1+n;
    };
    std::vector<Bytes> descriptors;
    descriptors.reserve(static_cast<std::size_t>(groups));
    Bytes descriptor_page;
    for (std::uint64_t group = 0; group < groups; ++group) {
        if (group%desc_per_block == 0)
            descriptor_page = map.bytes(descriptor_block(group/desc_per_block)*block,static_cast<std::size_t>(block));
        const auto at = static_cast<std::size_t>((group%desc_per_block)*desc_size);
        descriptors.emplace_back(descriptor_page.begin()+static_cast<std::ptrdiff_t>(at),
            descriptor_page.begin()+static_cast<std::ptrdiff_t>(at+desc_size));
        const auto& gd = descriptors.back();
        const bool uninit = (ro & 0x410) && (le16(gd,18) & 2);
        if (uninit) {
            Bytes group_bytes(4);
            for (unsigned i = 0; i < 4; ++i) group_bytes[i] = static_cast<std::uint8_t>(group >> (8*i));
            const auto stored = le16(gd,30);
            bool valid;
            if (ro & 0x400) {
                const auto seed = (incompat & 0x2000) ? le32(sb,0x270) :
                    crc32c(0xffffffffU,std::span(sb).subspan(0x68,16));
                auto copy = gd; copy[30] = copy[31] = 0;
                valid = static_cast<std::uint16_t>(crc32c(crc32c(seed,group_bytes),copy)) == stored;
            } else {
                auto crc = crc16(crc16(0xffff,std::span(sb).subspan(0x68,16)),group_bytes);
                crc = crc16(crc,std::span(gd).first(30));
                if (gd.size() > 32) crc = crc16(crc,std::span(gd).subspan(32));
                valid = crc == stored;
            }
            if (!valid) throw FilesystemAllocationError("ext uninitialized allocation descriptor checksum mismatch");
        }
        const auto start = group_start(group);
        const auto count = std::min<std::uint64_t>(per_group,blocks-start);
        if (uninit) map.set(start,count,false);
        else {
            const auto location = le32(gd,0) | ((incompat & 0x80) ? std::uint64_t(le32(gd,32)) << 32 : 0);
            if (!location) throw FilesystemAllocationError("ext block bitmap is at block zero");
            const auto bitmap = map.bytes(location*block,static_cast<std::size_t>((clusters+7)/8));
            for (std::uint64_t n = 0; n < count; n += cluster)
                map.set(start+n,std::min(cluster,count-n),
                    (bitmap.at(static_cast<std::size_t>(n/cluster/8)) & (1U << (n/cluster%8))) != 0);
        }
    }
    // Lazy groups have no valid block bitmap. Reconstruct exactly their
    // superblock/GDT reservations and metadata allocations, including flex_bg.
    for (std::uint64_t group = 0; group < groups; ++group) {
        const auto& gd = descriptors[static_cast<std::size_t>(group)];
        if (!(le16(gd,18) & 2)) continue;
        const auto reserve = [&](std::uint64_t at, std::uint64_t count) {
            if (!count) return;
            if (at < first || at >= blocks || count > blocks-at)
                throw FilesystemAllocationError("ext metadata reservation exceeds filesystem");
            const auto begin = first+((at-first)/cluster)*cluster;
            const auto end = std::min(blocks,first+((at-first+count+cluster-1)/cluster)*cluster);
            map.set(begin,end-begin,true);
        };
        auto start = group_start(group);
        if (has_super(group)) reserve(start,1);
        if (!(incompat & 0x10)) {
            if (has_super(group)) reserve(start+1,desc_blocks+le16(sb,0xce));
        } else if (group < std::uint64_t(first_meta)*desc_per_block) {
            if (has_super(group)) reserve(start+1,first_meta);
        } else if (group%desc_per_block <= 1 || group%desc_per_block == desc_per_block-1)
            reserve(start+(has_super(group) ? 1U : 0U),1);
        for (const auto position : {0U,4U,8U}) {
            const auto at = le32(gd,position) |
                ((incompat & 0x80) ? std::uint64_t(le32(gd,position+32)) << 32 : 0);
            const std::uint64_t inode_size = le32(sb,0x4c) ? le16(sb,0x58) : 128;
            const auto count = position == 8 ?
                (std::uint64_t(le32(sb,0x28))*inode_size+block-1)/block : 1;
            if (at) reserve(at,count);
        }
    }
    const auto& first_descriptor = descriptors.front();
    const auto inode_table = std::uint64_t(le32(first_descriptor,8)) |
        ((incompat & 0x80) ? std::uint64_t(le32(first_descriptor,40)) << 32 : 0);
    return {map.unused(),inode_table*block};
}
std::vector<ChangedExtent> xfs_unused(std::uint64_t length, const Reader& read, const Bytes& sb) {
    const auto block = be32(sb,4), ag_blocks = be32(sb,84), ag_count = be32(sb,88);
    const auto sector = be16(sb,102);
    Allocation map(length,block,be64(sb,8),read);
    if (!ag_blocks || !ag_count || !sector || sector > block ||
        ag_count != (map.blocks+ag_blocks-1)/ag_blocks) throw FilesystemAllocationError("invalid XFS allocation geometry");
    for (std::uint64_t ag = 0; ag < ag_count; ++ag) {
        const auto start = ag*ag_blocks, count = std::min<std::uint64_t>(ag_blocks,map.blocks-start);
        const auto agf = map.bytes(start*block+sector,224);
        if (be32(agf,0) != 0x58414746 || be32(agf,12) != count)
            throw FilesystemAllocationError("invalid XFS allocation group header");
        const auto free_extent = [&](std::uint64_t at, std::uint64_t n) {
            if (!n || at >= count || n > count-at) throw FilesystemAllocationError("invalid XFS free extent");
            map.set(start+at,n,false);
        };
        const auto node = [&](std::uint32_t n) {
            if (n >= count) throw FilesystemAllocationError("XFS free-space tree exceeds allocation group");
            return map.bytes((start+n)*block,block);
        };
        auto next = be32(agf,16);
        std::set<std::uint32_t> visited;
        Bytes tree;
        std::size_t header = 0;
        while (true) {
            if (!visited.insert(next).second) throw FilesystemAllocationError("cyclic XFS free-space tree");
            tree = node(next);
            const auto magic = be32(tree,0);
            if (magic != 0x41425442 && magic != 0x41423342) throw FilesystemAllocationError("invalid XFS free-space tree magic");
            header = magic == 0x41425442 ? 16U : 56U;
            if (!be16(tree,4)) break;
            if (!be16(tree,6)) throw FilesystemAllocationError("empty XFS internal free-space tree");
            const auto capacity = (block-header)/12;
            next = be32(tree,header+capacity*8);
        }
        while (true) {
            if (be16(tree,4) || be16(tree,6) > (block-header)/8)
                throw FilesystemAllocationError("invalid XFS free-space leaf");
            for (unsigned i = 0; i < be16(tree,6); ++i)
                free_extent(be32(tree,header+i*8),be32(tree,header+i*8+4));
            next = be32(tree,12);
            if (next == UINT32_MAX) break;
            if (!visited.insert(next).second) throw FilesystemAllocationError("cyclic XFS free-space leaf chain");
            tree = node(next);
            if (be32(tree,0) != (header == 16 ? 0x41425442U : 0x41423342U))
                throw FilesystemAllocationError("invalid XFS free-space leaf magic");
        }
        if (be32(agf,48)) {
            const auto agfl = map.bytes(start*block+3*sector,sector);
            const auto begin = be32(agf,40), end = be32(agf,44);
            const auto offset = be32(agfl,0) == 0x5841464c ? 36U : 0U;
            const auto capacity = (sector-offset)/4;
            if (begin >= capacity || end >= capacity) throw FilesystemAllocationError("invalid XFS allocation free-list cursor");
            auto i = begin;
            do {
                const auto n = be32(agfl,offset+i*4);
                if (n) free_extent(n,1);
                if (i == end) break;
                i = (i+1)%capacity;
            } while (true);
        }
    }
    return map.unused();
}
}
ExtAllocationContext ext_allocation_context(std::uint64_t length, const Bytes& sb, const Reader& read) {
    try { return ext_unused(length,read,sb); }
    catch (const std::out_of_range&) {
        throw FilesystemAllocationError("truncated ext allocation metadata");
    }
}
std::vector<ChangedExtent> filesystem_unused_extents(std::uint64_t length, const Reader& read) {
    try {
        const auto first = read(0,512);
        if (first.size() != 512) throw FilesystemAllocationError("short filesystem allocation superblock read");
        if (be32(first,0) == 0x58465342) return xfs_unused(length,read,first);
        const auto sb = read(1024,1024);
        if (sb.size() != 1024 || le16(sb,0x38) != 0xef53) throw FilesystemAllocationError("unsupported allocation filesystem");
        return ext_allocation_context(length,sb,read).unused;
    }
    catch (const std::out_of_range&) {
        throw FilesystemAllocationError("truncated filesystem allocation metadata");
    }
}
std::vector<ChangedExtent> snapshot_used_context(std::string_view device, std::uint64_t length,
                                                 const Reader& read) {
    try { return filesystem_unused_extents(length,read); }
    catch (const FilesystemAllocationError& error) {
        std::cerr << "Failed to initialize used context on '" << device << "': " << error.what() << '\n';
        return {};
    }
}
}
