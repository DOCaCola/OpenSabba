#pragma once
#include "opensabba/cow_index.hpp"

namespace opensabba {
struct DeltaRange { std::uint64_t offset, length; bool changed; };
struct DeltaPlan {
    std::uint64_t image_size, transfer_bytes;
    std::vector<DeltaRange> ranges;
    // With a filesystem allocation context, used and changed are independent
    // flags. A free range can be unchanged; type-5 exclusions remain changed.
    bool filesystem_allocation = false;
};
// Union independently validated generation maps, including overlaps and
// adjacent extents. Every input extent must fit the same source geometry.
std::vector<ChangedExtent> union_changed_extents(std::uint64_t source_size,
                                                std::vector<ChangedExtent> changed);
void validate_delta_plan(const DeltaPlan&, std::uint64_t image_size);
pstream::Value delta_plan_value(const DeltaPlan&);
DeltaPlan delta_plan_from_value(const pstream::Value&, std::uint64_t image_size);
}
