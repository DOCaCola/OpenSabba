#include "opensabba/layout.hpp"
#include <algorithm>
#include <array>
#include <set>

namespace opensabba {
namespace {
using pstream::Bytes;
using pstream::Error;
using pstream::Value;
using Span = std::span<const std::uint8_t>;

std::uint64_t le(Span bytes, std::size_t pos, std::size_t width) {
    std::uint64_t result = 0;
    for (std::size_t i = 0; i < width; ++i)
        result |= std::uint64_t{bytes[pos + i]} << (8 * i);
    return result;
}
bool zero(Span bytes) {
    return std::all_of(bytes.begin(), bytes.end(), [](auto b) { return b == 0; });
}
std::string hex(Span bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (auto b : bytes) { result += digits[b >> 4]; result += digits[b & 15]; }
    return result;
}
std::string guid(Span bytes) {
    constexpr std::array<std::size_t, 16> order{3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
    Bytes ordered;
    for (auto i : order) ordered.push_back(bytes[i]);
    auto value = hex(ordered);
    return value.substr(0,8) + "-" + value.substr(8,4) + "-" + value.substr(12,4) +
           "-" + value.substr(16,4) + "-" + value.substr(20);
}
std::uint32_t crc32(Span bytes) {
    std::uint32_t crc = 0xffffffffU;
    for (auto b : bytes) {
        crc ^= b;
        for (int i = 0; i < 8; ++i)
            crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320U : 0U);
    }
    return ~crc;
}
void check_partitions(const ImageLayout& layout) {
    auto sorted = layout.partitions;
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.offset < b.offset; });
    std::uint64_t end = 0;
    for (const auto& p : sorted) {
        if (!p.length || p.offset < layout.sector_size || p.offset > layout.length ||
            p.length > layout.length - p.offset || p.offset < end)
            throw Error("image partitions overlap or exceed the image extent");
        end = p.offset + p.length;
    }
}
struct Header {
    std::uint64_t current, alternate, first, last, table;
    std::uint32_t count, entry_size;
    std::string disk_id;
    Bytes entries;
};
struct LayoutSource {
    std::uint64_t length;
    const LayoutRead& reader;
    std::uint64_t size() const { return length; }
    Bytes read(std::uint64_t offset, std::size_t count) const {
        if (offset > length || count > length-offset) throw Error("layout read exceeds disk extent");
        auto bytes = reader(offset, count);
        if (bytes.size() != count) throw Error("short disk layout read");
        return bytes;
    }
};
Header read_header(const LayoutSource& source, std::uint32_t sector, std::uint64_t lba) {
    const auto sectors = source.size() / sector;
    auto bytes = source.read(lba * sector, sector);
    if (std::string(bytes.begin(), bytes.begin() + 8) != "EFI PART" ||
        le(bytes, 8, 4) != 0x10000 || le(bytes, 20, 4) != 0)
        throw Error("invalid or unsupported GPT header");
    const auto size = le(bytes, 12, 4);
    if (size < 92 || size > sector) throw Error("invalid GPT header size");
    const auto checksum = le(bytes, 16, 4);
    std::fill(bytes.begin() + 16, bytes.begin() + 20, 0);
    if (crc32(Span(bytes).first(static_cast<std::size_t>(size))) != checksum)
        throw Error("GPT header checksum mismatch");
    Header h{le(bytes,24,8), le(bytes,32,8), le(bytes,40,8), le(bytes,48,8),
             le(bytes,72,8), static_cast<std::uint32_t>(le(bytes,80,4)),
             static_cast<std::uint32_t>(le(bytes,84,4)), guid(Span(bytes).subspan(56,16)), {}};
    if (zero(Span(bytes).subspan(56,16)) || h.current != lba ||
        h.alternate >= sectors || h.alternate == lba || h.first > h.last || h.last >= sectors - 1 ||
        h.first < 2 || h.table < 2 || h.table >= sectors - 1 ||
        !h.count || h.entry_size < 128 || h.entry_size % 128 ||
        (h.entry_size & (h.entry_size - 1)) != 0)
        throw Error("invalid GPT header geometry");
    const auto table_bytes = std::uint64_t{h.count} * h.entry_size;
    if (table_bytes < 16384 || table_bytes > 16 * 1024 * 1024 ||
        table_bytes > source.size() - h.table * sector)
        throw Error("unsupported GPT partition table size");
    const auto table_end = h.table + (table_bytes + sector - 1) / sector;
    if (lba == 1 ? table_end > h.first : (h.table <= h.last || table_end > lba))
        throw Error("GPT partition table overlaps usable space or its header");
    h.entries = source.read(h.table * sector, static_cast<std::size_t>(table_bytes));
    if (crc32(h.entries) != le(bytes,88,4)) throw Error("GPT partition table checksum mismatch");
    return h;
}
}

ImageLayout inspect_image_layout(ImageSource& source, std::uint32_t sector) {
    auto result = inspect_disk_layout(source.size(), sector,
        [&](auto offset, auto count) { return source.read_metadata(offset, count); });
    source.verify_unchanged();
    return result;
}

ImageLayout inspect_disk_layout(std::uint64_t length, std::uint32_t sector, const LayoutRead& reader) {
    const LayoutSource source{length, reader};
    if ((sector != 512 && sector != 4096) || source.size() % sector)
        throw Error("image sector size must be 512 or 4096 and divide the file size");
    const auto sectors = source.size() / sector;
    auto mbr = source.read(0, 512);
    if (mbr[510] != 0x55 || mbr[511] != 0xaa)
        throw Error("image has no valid MBR signature; unpartitioned filesystems are not supported");
    ImageLayout layout{ImageLayout::Scheme::mbr, sector, source.size(),
                       hex(Span(mbr).subspan(440,4)), {}};
    unsigned protective = 0, occupied = 0;
    for (std::uint32_t i = 0; i < 4; ++i) {
        auto entry = Span(mbr).subspan(446 + 16 * i, 16);
        const auto type = entry[4];
        if (type == 0) {
            if (!zero(entry)) throw Error("nonempty unused MBR partition entry");
            continue;
        }
        ++occupied;
        if (entry[0] != 0 && entry[0] != 0x80) throw Error("invalid MBR boot indicator");
        const auto start = le(entry,8,4), count = le(entry,12,4);
        if (type == 0xee) {
            ++protective;
            if (entry[0] || start != 1 || count != std::min<std::uint64_t>(sectors - 1, 0xffffffffU))
                throw Error("invalid protective MBR extent");
            continue;
        }
        if (type == 0x05 || type == 0x0f || type == 0x85)
            throw Error("extended MBR partitions require EBR support");
        layout.partitions.push_back({i + 1, start * sector, count * sector, 0, type, entry[0] == 0x80, {}, {}});
    }
    if (protective) {
        if (protective != 1 || occupied != 1) throw Error("hybrid MBR/GPT layouts are not supported");
        if (sectors < 6) throw Error("image is too small for GPT");
        const auto primary = read_header(source, sector, 1);
        const auto backup = read_header(source, sector, sectors - 1);
        if (primary.alternate != sectors - 1 || backup.alternate != 1 ||
            primary.first != backup.first || primary.last != backup.last ||
            primary.disk_id != backup.disk_id || primary.count != backup.count ||
            primary.entry_size != backup.entry_size || primary.entries != backup.entries)
            throw Error("primary and backup GPT disagree");
        layout.scheme = ImageLayout::Scheme::gpt;
        layout.disk_id = primary.disk_id;
        std::set<std::string> ids;
        for (std::uint32_t i = 0; i < primary.count; ++i) {
            auto entry = Span(primary.entries).subspan(std::size_t{i} * primary.entry_size, primary.entry_size);
            if (zero(entry.first(16))) continue;
            const auto start = le(entry,32,8), last = le(entry,40,8);
            const auto id = guid(entry.subspan(16,16));
            if (zero(entry.subspan(16,16)) || !ids.insert(id).second ||
                start < primary.first || last > primary.last || last < start)
                throw Error("invalid GPT partition identity or extent");
            layout.partitions.push_back({i + 1, start * sector, (last - start + 1) * sector,
                                         le(entry,48,8), 0, false, guid(entry.first(16)), id});
        }
    }
    check_partitions(layout);
    return layout;
}

pstream::Value layout_value(const ImageLayout& layout) {
    Value::Array parts;
    for (const auto& p : layout.partitions) {
        parts.push_back(Value{Value::Object{
            {"number", Value{std::uint64_t{p.number}}}, {"offset", Value{p.offset}},
            {"length", Value{p.length}}, {"attributes", Value{p.attributes}},
            {"mbr_type", Value{std::uint64_t{p.mbr_type}}}, {"bootable", Value{std::uint64_t{p.bootable}}},
            {"type_guid", Value{p.type_guid}}, {"uuid", Value{p.uuid}}}});
    }
    return Value{Value::Object{
        {"scheme", Value{std::string(layout.scheme == ImageLayout::Scheme::mbr ? "MBR" : "GPT")}},
        {"sector_size", Value{std::uint64_t{layout.sector_size}}}, {"length", Value{layout.length}},
        {"disk_id", Value{layout.disk_id}}, {"partitions", Value{std::move(parts)}}}};
}
}
