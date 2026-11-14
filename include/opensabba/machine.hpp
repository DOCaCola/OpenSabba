#pragma once
#include "opensabba/layout.hpp"

namespace opensabba {
struct MachineDevice {
    std::uint32_t major = 0, minor = 0;
    bool operator==(const MachineDevice&) const = default;
};
struct MachineMount {
    std::uint64_t id = 0;
    MachineDevice device;
    std::string root, path, filesystem, options, super_options;
    std::uint64_t parent_id = 0;
    std::string source{};
    std::vector<std::string> optional_fields{};
    bool operator==(const MachineMount&) const = default;
};
struct MachinePartition {
    std::uint32_t number = 0;
    MachineDevice device;
    std::string path;
    std::uint64_t offset = 0, length = 0;
};
struct MachinePlan {
    MachinePartition boot, root;
    MachineMount boot_mount, root_mount;
    // Other direct partitions await task selection or raw/unused classification.
    std::vector<MachinePartition> excluded;
};
struct MachineLvmBoot {
    MachinePartition partition;
    MachineMount mount;
};
MachineLvmBoot plan_lvm_machine_boot(const ImageLayout&,
    const std::vector<MachinePartition>&, const std::vector<MachineMount>&,
    std::uint32_t pv_partition, MachineDevice root_lv_device);
struct MachineStorage {
    MachineDevice device;
    // A partition has its containing disk as a backing device. A stacked
    // device has its sysfs slaves. Only physical leaves prove independence.
    std::vector<MachineDevice> backing;
    bool physical_leaf = false;
    bool operator==(const MachineStorage&) const = default;
};
struct MachineCopyRegion {
    std::uint64_t offset, length;
    bool read_source;
};
struct MachineVolumeRegion {
    std::uint64_t offset, length;
    unsigned type; // 2 raw, 3 immutable capture, 5 unused.
    std::string label;
    bool system;
};
// Only a bounded raw-cache copy I/O error permits type-3 reclassification.
// Cancellation, identity, lease and persistence errors remain capture failures.
class MachineRawCacheCopyError : public pstream::Error {
public: using Error::Error;
};
// Snapshot ownership is independent of whether any physical disk is uploaded.
// Uploaded physical images precede logical images.
std::vector<const pstream::Value*> machine_image_plans(const pstream::Value& plan);
std::size_t machine_physical_image_count(const pstream::Value& plan);
bool machine_bare_metal(const pstream::Value& plan);
// Discovery records blkid's actual UUID for a mounted raw FAT partition.
// Unsupported physical filesystems retain the official agent's empty volume name;
// mounted ext/XFS identities are already recorded by snapshot discovery.
void record_machine_raw_volume_uuid(pstream::Value& volume,
    const std::function<std::string()>& probe_uuid);
std::vector<MachineVolumeRegion> machine_cached_regions(const pstream::Value& disk);
void validate_machine_raw_cache_failures(const pstream::Value& disk);
void machine_cache_raw_regions(pstream::Value& disk,
    const std::function<void(const MachineVolumeRegion&)>& copy,
    const std::function<void()>& verify,
    const std::function<void()>& persist);
// Classify an ordinary partition outside the mounted filesystem snapshots.
std::vector<MachineVolumeRegion> machine_partition_regions(
    const pstream::Value& disk, const pstream::Value& partition);
std::vector<MachineVolumeRegion> machine_layout_regions(const pstream::Value& disk);
std::vector<ChangedExtent> machine_unused_extents(const pstream::Value& disk);
bool machine_disk_need_upload(const pstream::Value& disk);
// Retained raw/layout ranges, 4 KiB-rounded: always reread without CBT context.
std::vector<ChangedExtent> machine_reread_ranges(const pstream::Value& disk,
                                                 std::uint64_t image_size);
void machine_force_raw_changes(DeltaPlan&, const pstream::Value& disk);
// Static-copy schedule: retained boot/raw/layout bytes are read, unused
// regions are zero-filled, and filesystem snapshots are copied separately.
std::vector<MachineCopyRegion> machine_static_regions(const pstream::Value& plan);
// Static regions for a selected additional disk with no root/boot role.
std::vector<MachineCopyRegion> machine_additional_static_regions(const pstream::Value& disk);
// Pin an explicit set of additional mounted ext2/ext3/ext4/XFS paths.
// The unchanged partition table still describes selected and excluded ranges.
pstream::Value select_machine_extra_volumes(pstream::Value plan,
                                            const std::vector<std::string>& mount_paths,
                                            bool bare_metal = false);
// Pure mountinfo parser and topology validation for fixture-based local tests.
std::vector<MachineMount> parse_machine_mounts(std::string_view mountinfo);
// Compare mount identities independently of mountinfo row order. Unrelated
// tmpfs/ramfs lifecycle is ignored; mounts that can overlay block volumes,
// boot, or COW storage remain part of the observation.
bool machine_relevant_mounts_equal(const std::vector<MachineMount>& before,
                                   const std::vector<MachineMount>& after,
                                   const std::vector<MachineDevice>& block_devices,
                                   std::string_view boot_path,
                                   std::string_view cow_path);
MachinePlan plan_machine_capture(const ImageLayout&, const std::vector<MachinePartition>&,
                                 const std::vector<MachineMount>&);
void validate_machine_cow_storage(MachineDevice source, MachineDevice cow,
                                  const std::vector<MachineStorage>&);
// Read-only Linux discovery. No driver calls, mounts, filesystem freezes,
// directory/file creation, NAS requests or durable configuration changes.
pstream::Value inspect_machine(const std::string& disk, const std::string& cow_directory);
// Rediscover the physical disk containing the current mounted root.
pstream::Value inspect_running_machine(const std::string& cow_directory);
// Discovery has no NAS selection or distinguished root/boot disk. The selected
// plan owns a real primary snapshot origin and an optional retained FAT mount.
pstream::Value discover_machine_inventory(const std::string& working_directory);
pstream::Value select_machine_inventory(pstream::Value inventory,
                                        const pstream::Value& task);
pstream::Value rediscover_machine_plan(const pstream::Value&);
std::string machine_disk_image_name(const std::string& disk);
// Resolve a mounted block filesystem's persistent UUID from its current device.
std::string machine_filesystem_uuid(MachineDevice);
}
