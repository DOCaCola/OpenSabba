#pragma once
#include "opensabba/pstream.hpp"
#include "opensabba/cow_index.hpp"
#include <functional>

namespace opensabba {
struct LinuxFilesystem {
    std::string type;
    std::string uuid;
};
// Inspect one complete Linux data partition. Reads are relative to its start.
// This is a structural/identity check, not a filesystem consistency checker.
LinuxFilesystem inspect_linux_filesystem(
    std::uint64_t length,
    const std::function<pstream::Bytes(std::uint64_t, std::size_t)>& read,
    bool require_clean = true);
bool supported_linux_filesystem(std::string_view type);
// Raised when a snapshot's allocation metadata cannot form a used context.
// Preparation discards the
// failed context and reads the whole interval.
class FilesystemAllocationError : public pstream::Error {
public:
    using pstream::Error::Error;
};
// The filesystem reader retains its parsed descriptors after initialization. Inode 1
// uses group 0's cached inode-table address instead of reading its GDT again.
struct ExtAllocationContext {
    std::vector<ChangedExtent> unused;
    std::uint64_t inode_table_offset;
};
ExtAllocationContext ext_allocation_context(std::uint64_t length,
    const pstream::Bytes& superblock,
    const std::function<pstream::Bytes(std::uint64_t,std::size_t)>& read);
// Snapshot-relative unused native filesystem blocks. FAT and raw intervals
// do not have a official agent used-bitmap context.
std::vector<ChangedExtent> filesystem_unused_extents(std::uint64_t length,
    const std::function<pstream::Bytes(std::uint64_t,std::size_t)>& read);
// The official agent used context for one snapshot interval: its unused blocks, or none
// after logging when the allocation metadata cannot be interpreted.
std::vector<ChangedExtent> snapshot_used_context(std::string_view device, std::uint64_t length,
    const std::function<pstream::Bytes(std::uint64_t,std::size_t)>& read);
}
