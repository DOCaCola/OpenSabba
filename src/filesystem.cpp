#include "opensabba/filesystem.hpp"
#include <algorithm>
#include <array>
#include <bit>

namespace opensabba {
namespace {
using pstream::Bytes;
using pstream::Error;
std::uint16_t le16(const Bytes& b, std::size_t p) {
    return static_cast<std::uint16_t>(std::uint16_t(b[p]) | std::uint16_t(b[p+1]) << 8);
}
std::uint32_t le32(const Bytes& b, std::size_t p) {
    return std::uint32_t(b[p]) | std::uint32_t(b[p+1]) << 8 |
           std::uint32_t(b[p+2]) << 16 | std::uint32_t(b[p+3]) << 24;
}
std::uint16_t be16(const Bytes& b, std::size_t p) {
    return static_cast<std::uint16_t>(std::uint16_t(b[p]) << 8 | b[p+1]);
}
std::uint32_t be32(const Bytes& b, std::size_t p) {
    return std::uint32_t(b[p]) << 24 | std::uint32_t(b[p+1]) << 16 |
           std::uint32_t(b[p+2]) << 8 | b[p+3];
}
std::uint64_t be64(const Bytes& b, std::size_t p) {
    return std::uint64_t(be32(b,p)) << 32 | be32(b,p+4);
}
std::uint32_t crc32c(std::span<const std::uint8_t> b, bool complement) {
    std::uint32_t crc = 0xffffffff;
    for (auto byte : b) {
        crc ^= byte;
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ ((crc & 1) ? 0x82f63b78 : 0);
    }
    return complement ? ~crc : crc;
}
std::string uuid(const Bytes& b, std::size_t at) {
    if (std::all_of(b.begin()+static_cast<std::ptrdiff_t>(at),
                    b.begin()+static_cast<std::ptrdiff_t>(at+16),
                    [](auto c) { return c == 0; }))
        throw Error("Linux filesystem has no UUID");
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (std::size_t i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) result += '-';
        result += hex[b[at+i] >> 4];
        result += hex[b[at+i] & 15];
    }
    return result;
}
LinuxFilesystem ext(const Bytes& b, std::uint64_t length, bool require_clean) {
    const auto revision = le32(b,0x4c);
    if (revision > 1) throw Error("unsupported ext superblock revision");
    // Revision 0 has no feature words or journal metadata. Interpret those
    // fields only for dynamic revision 1, even if old mkfs filled their bytes.
    const auto compat = revision ? le32(b,0x5c) : 0;
    const auto incompat = revision ? le32(b,0x60) : 0;
    const auto ro = revision ? le32(b,0x64) : 0;
    const auto state = le16(b,0x3a);
    if ((require_clean ? state != 1 : (state & ~1U) != 0) ||
        (incompat & (require_clean ? 0x0cU : 0x08U)) ||
        (ro & 0x10000) ||
        (revision && (le32(b,0xe4) ||
          ((compat & 0x4U) ? le32(b,0xe0) == 0 : le32(b,0xe0) != 0) ||
          std::any_of(b.begin()+0xd0,b.begin()+0xe0,[](auto c) { return c != 0; }))))
        throw Error("ext filesystem requires recovery, an external journal, or is not clean");
    // A journal is the distinguishing on-disk ext3 feature; ext4-only
    // features take precedence. Compatible ext4 formats with no such feature
    // are indistinguishable from ext2/ext3 and use that on-disk designation.
    const bool ext4 = (incompat & (0x40U|0x80U|0x200U|0x1000U|0x2000U|
                                  0x4000U|0x8000U|0x10000U|0x20000U|0x40000U)) ||
                      (ro & (0x8U|0x10U|0x20U|0x40U|0x80U|0x100U|
                             0x200U|0x400U|0x1000U));
    if (ro & 0x400) {
        if (b[0x175] != 1 || crc32c(std::span(b).first(0x3fc),false) != le32(b,0x3fc))
            throw Error("ext superblock checksum mismatch or unsupported checksum type");
    }
    const auto log_block = le32(b,0x18);
    if (log_block > 6) throw Error("invalid ext block size");
    const std::uint64_t block_size = std::uint64_t{1024} << log_block;
    std::uint64_t blocks = le32(b,4);
    if (incompat & 0x80) blocks |= std::uint64_t(le32(b,0x150)) << 32;
    if (!blocks || blocks > length/block_size ||
        le32(b,0x14) != (block_size == 1024 ? 1U : 0U))
        throw Error("ext filesystem geometry exceeds its partition or is invalid");
    return {ext4 ? "ext4" : (compat & 0x4 ? "ext3" : "ext2"),uuid(b,0x68)};
}
LinuxFilesystem xfs(const Bytes& first, std::uint64_t length,
                    const std::function<Bytes(std::uint64_t,std::size_t)>& read) {
    const auto block = be32(first,4);
    const auto blocks = be64(first,8);
    const auto log_start = be64(first,48);
    const auto log_blocks = be32(first,96);
    const auto ag_blocks = be32(first,84), ag_count = be32(first,88);
    const auto sector = be16(first,102);
    const auto version = be16(first,100) & 15;
    const auto inode = be16(first,104), inodes_per_block = be16(first,106);
    const auto ag_log = first[124];
    if ((version != 4 && version != 5) || (block != 512 && block != 1024 &&
         block != 2048 && block != 4096 && block != 8192 && block != 16384 &&
         block != 32768 && block != 65536) ||
        (sector != 512 && sector != 1024 && sector != 2048 && sector != 4096) ||
        sector > block || !blocks || blocks > length/block ||
        inode < 256 || inode > block || (inode & (inode-1)) ||
        inodes_per_block != block/inode ||
        first[120] > 16 || (1U << first[120]) != block ||
        first[121] > 12 || (1U << first[121]) != sector ||
        first[122] > 16 || (1U << first[122]) != inode ||
        first[123] > 8 || (1U << first[123]) != inodes_per_block ||
        !be64(first,56) ||
        !ag_blocks || !ag_count || ag_count != 1+(blocks-1)/ag_blocks ||
        std::uint64_t(ag_count-1)*ag_blocks >= blocks ||
        ag_log != std::bit_width(ag_blocks-1) ||
        !log_start || !log_blocks || be64(first,16) || be64(first,24) ||
        first[126] || (be32(first,216) & ~0x3efU) || be32(first,220))
        throw Error("XFS has invalid geometry, external log/realtime device, or needs repair");
    // sb_logstart is an encoded fsblock (AG number in the high bits,
    // block-within-AG in the low bits), not a linear dblocks offset.
    const auto log_ag = log_start >> ag_log;
    const auto log_ag_block = log_start & ((std::uint64_t{1} << ag_log)-1);
    if (log_ag >= ag_count)
        throw Error("XFS internal log geometry exceeds its allocation group");
    const auto ag_length = log_ag == ag_count-1 ? blocks-log_ag*ag_blocks : ag_blocks;
    if (log_ag_block >= ag_length || log_blocks > ag_length-log_ag_block)
        throw Error("XFS internal log geometry exceeds its allocation group");
    if (version == 5) {
        auto sb = sector == 512 ? first : read(0,sector);
        if (sb.size() != sector) throw Error("short XFS superblock read");
        const auto stored_le = le32(sb,224);
        std::fill(sb.begin()+224,sb.begin()+228,0);
        if (crc32c(sb,true) != stored_le)
            throw Error("XFS superblock checksum mismatch");
    }
    return {"xfs",uuid(first,32)};
}
}
bool supported_linux_filesystem(std::string_view type) {
    return type == "ext2" || type == "ext3" || type == "ext4" || type == "xfs";
}
LinuxFilesystem inspect_linux_filesystem(
    std::uint64_t length, const std::function<Bytes(std::uint64_t,std::size_t)>& read,
    bool require_clean) {
    if (length < 2048) throw Error("Linux partition is too small for a filesystem superblock");
    const auto first = read(0,512);
    if (first.size() != 512) throw Error("short Linux filesystem superblock read");
    if (first[0] == 'X' && first[1] == 'F' && first[2] == 'S' && first[3] == 'B')
        return xfs(first,length,read);
    const auto sb = read(1024,1024);
    if (sb.size() != 1024) throw Error("short ext superblock read");
    if (le16(sb,0x38) != 0xef53)
        throw Error("unsupported Linux partition filesystem");
    return ext(sb,length,require_clean);
}
}
