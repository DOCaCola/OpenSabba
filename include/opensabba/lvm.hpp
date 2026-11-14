#pragma once
#include "opensabba/pstream.hpp"
#include <string_view>

namespace opensabba {
struct LvmDevice {
    std::uint32_t major = 0, minor = 0;
    bool operator==(const LvmDevice&) const = default;
};
struct LvmSegment {
    std::uint64_t logical_offset = 0, length = 0, pv_offset = 0;
    std::string pv_uuid;
    // Nonlinear layouts retain the LVM segment report as topology identity.
    std::string type = "linear", mapping;
    bool operator==(const LvmSegment&) const = default;
};
struct LvmPv {
    std::string name, uuid, vg_uuid;
    // size is the usable PE extent size; device_size is the complete PV device.
    std::uint64_t size = 0, device_size = 0, pe_start = 0, mda_size = 0;
    std::uint64_t extent_count = 0, mda_count = 0;
    LvmDevice device, parent_device;
    std::string parent_disk;
    std::uint32_t partition_number = 0;
    std::uint64_t partition_offset = 0, partition_length = 0, disk_sequence = 0;
    bool operator==(const LvmPv&) const = default;
};
struct LvmVg {
    std::string name, uuid;
    std::uint64_t extent_size = 0, mda_size = 0, total_size = 0, sequence = 0;
    std::uint64_t pv_count = 0, lv_count = 0;
    bool operator==(const LvmVg&) const = default;
};
struct LvmLv {
    std::string name, uuid, vg_uuid, path, dm_path;
    LvmDevice device;
    std::uint64_t size = 0;
    std::vector<LvmSegment> segments;
    std::string attributes, kernel_table;
    bool public_device = true, visible = true;
    bool operator==(const LvmLv&) const = default;
};
struct LvmInventory {
    std::vector<LvmVg> volume_groups;
    std::vector<LvmPv> physical_volumes;
    std::vector<LvmLv> logical_volumes;
    struct KernelNode {
        LvmDevice device;
        std::string name, uuid, table;
        std::vector<LvmDevice> dependencies;
        bool operator==(const KernelNode&) const = default;
    };
    std::vector<KernelNode> kernel_nodes;
    bool operator==(const LvmInventory&) const = default;
};
// The official Linux agent image name for an LV, constrained to a safe local filename.
std::string lvm_image_name(std::string_view vg, std::string_view lv);
struct LvmDmTarget {
    LvmDevice device;
    std::uint64_t logical_offset = 0, length = 0, device_offset = 0;
    std::string type = "linear", parameters;
    bool operator==(const LvmDmTarget&) const = default;
};
struct LvmDmIdentity {
    std::string name, uuid;
    LvmDevice device;
    std::uint64_t segments = 0, events = 0;
    bool operator==(const LvmDmIdentity&) const = default;
};
// Strict, no-heading, "|" separated LVM reports, byte units and no suffix:
// vgs: vg_name,vg_uuid,vg_attr,vg_extent_size,vg_size,vg_mda_size,vg_seqno,
// pv_count,lv_count,vg_missing_pv_count,vg_lock_type,vg_sysid
// pvs: pv_name,pv_uuid,vg_uuid,pv_size,pe_start,pv_mda_size,pv_attr,
// pv_pe_count,pv_mda_count,dev_size
// lvs --segments --all: lv_name,lv_uuid,vg_uuid,lv_path,lv_dm_path,lv_attr,
// lv_size,segtype,seg_start,seg_size,seg_pe_ranges,lv_kernel_major,lv_kernel_minor
LvmInventory parse_lvm_reports(std::string_view vgs, std::string_view pvs,
                               std::string_view lvs);
// Complete local VGs, including internal and inactive LV inventory entries.
// The pure report validator does not assert kernel/PV-header geometry.
void validate_lvm_inventory(const LvmInventory&);
// dmsetup table for one mapper, without a device-name prefix. Input units are
// sectors; parsed ranges are bytes. Nonlinear target parameters stay intact.
std::vector<LvmDmTarget> parse_lvm_dm_table(std::string_view);
// dmsetup info -c: name,uuid,major,minor,segments,events,attr
LvmDmIdentity parse_lvm_dm_identity(std::string_view);
void validate_lvm_mapping(const LvmInventory&, const LvmLv&,
                          const LvmDmIdentity&, const std::vector<LvmDmTarget>&);
// Every active LVM mapper must resolve through the same VG to its observed PVs.
void validate_lvm_kernel_graph(const LvmInventory&);
// Stable topology identity uses PV/LV UUIDs, not boot-specific kernel numbers.
std::string lvm_kernel_topology(const LvmInventory&, std::string_view vg_uuid);
// Check the first four 512-byte PV sectors against the LVM2 label/header,
// including its CRC, PV UUID, data offset, metadata areas and device size.
void validate_lvm_pv_header(const LvmPv&, std::span<const std::uint8_t>);
// Read-only discovery using installed /sbin or /usr/sbin LVM2/dmsetup through
// posix_spawn (no shell, activation, writes, snapshots, mounts or NAS access).
// Also checks the complete live DM dependency graph/UUIDs, partition geometry, physical parents,
// PV labels, block sizes and a repeated inventory. This is an observation,
// not a topology lease; capture must hold/recheck its own inputs.
LvmInventory inspect_lvm();
}
