#pragma once
#include "opensabba/pstream.hpp"

namespace opensabba {
struct ChangedExtent { std::uint64_t offset, length; };
struct CowIndex {
    std::uint64_t changed_blocks = 0;
    // the official agent 64 KiB bitmap; its length can be shorter than the current origin.
    pstream::Bytes compact_bitmap;
    std::vector<ChangedExtent> extents;
};
using ReadCow = std::function<pstream::Bytes(std::uint64_t, std::size_t)>;
// libsynosnap Previous-generation index retention: short fread discards that chunk, succeeds
// with the stored prefix. Bitmap queries past this prefix mean changed.
pstream::Bytes compact_cow_index(const ReadCow&, std::uint64_t file_size, std::uint64_t source_size);
// Closed v1 index-only files from the verified 4 KiB driver configuration,
// including the initialized write-ahead window retained after clean boot.
// Source coordinates are bytes, not virtual disk-image coordinates.
CowIndex read_cow_index(const ReadCow&, std::uint64_t file_size, std::uint64_t source_size,
                        std::string_view uuid, std::uint64_t sequence, std::uint64_t block_size);
}
