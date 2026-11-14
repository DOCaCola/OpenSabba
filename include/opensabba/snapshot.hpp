#pragma once
#include "opensabba/layout.hpp"

namespace opensabba {
// Metadata for one immutable disk image. Ordinary images require every
// partition to contain ext2/ext3/ext4/XFS or FAT16/FAT32. A pinned machine plan also
// permits explicitly excluded, all-zero partition ranges. Delta metadata
// accounts for changed bytes; no filesystem allocation bitmap is provided.
// Names in the descriptor are logical source names, not host device paths.
pstream::Bytes fixed_image_metadata(ImageSource&, std::uint32_t sector_size,
                                    std::string_view image_name,
                                    std::uint64_t snapshot_time,
                                    const DeltaPlan* delta = nullptr,
                                    const pstream::Value* machine_plan = nullptr);
struct MetadataDisk {
    ImageSource* source;
    std::uint32_t sector_size;
    std::string image_name;
    const pstream::Value* machine_plan;
    const DeltaPlan* delta = nullptr;
    std::vector<ChangedExtent> additional_unused = {};
    // Exact selected volume ranges with a confirmed acquisition failure.
    std::vector<ChangedExtent> omitted_snapshots = {};
    // Complete discovery/selection inventory, independently of this image.
    const pstream::Value* machine_inventory = nullptr;
};
// One official agent snapshot metadata with a named image and disk layout for each disk.
pstream::Bytes fixed_machine_metadata(std::span<const MetadataDisk>, std::uint64_t snapshot_time);
}
