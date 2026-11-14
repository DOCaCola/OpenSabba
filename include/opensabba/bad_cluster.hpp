#pragma once
#include "opensabba/cow_index.hpp"
#include "opensabba/pstream.hpp"
#include <functional>

namespace opensabba {
// Native filesystem bad-block numbers become byte intervals relative to the
// snapshot volume. They do not alter either allocation or CBT bitmaps.
struct BadClusterContext {
    std::vector<ChangedExtent> ranges;
    std::string volume;
};
// The official Linux agent supports ext2/3/4 (bad-blocks inode 1) and XFS (empty list).
// Initialization failures warn and discard the context. Inode/tree read failures
// warn and retain the blocks already discovered, as the official agent inode walker does.
BadClusterContext snapshot_bad_cluster_context(std::string_view volume, std::uint64_t length,
    const std::function<pstream::Bytes(std::uint64_t,std::size_t)>& read);
}
