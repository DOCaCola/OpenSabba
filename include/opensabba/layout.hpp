#pragma once
#include "opensabba/image.hpp"

namespace opensabba {
struct ImagePartition {
    std::uint32_t number;
    std::uint64_t offset, length, attributes = 0;
    std::uint8_t mbr_type = 0;
    bool bootable = false;
    std::string type_guid, uuid;
};
struct ImageLayout {
    enum class Scheme { mbr, gpt };
    Scheme scheme;
    std::uint32_t sector_size;
    std::uint64_t length;
    std::string disk_id;
    std::vector<ImagePartition> partitions;
};
// Explicit immutable image source. No guessing sector size, repairing GPT copies,
// probing host devices or claiming filesystem/snapshot support.
ImageLayout inspect_image_layout(ImageSource&, std::uint32_t sector_size);
// Read-only layout inspection also accepts a pinned disk reader. This does not
// turn a live block device into a consistent backup ImageSource.
using LayoutRead = std::function<pstream::Bytes(std::uint64_t, std::size_t)>;
ImageLayout inspect_disk_layout(std::uint64_t length, std::uint32_t sector_size,
                                const LayoutRead&);
pstream::Value layout_value(const ImageLayout&);
}
