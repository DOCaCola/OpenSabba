#include "image_delta_fixture.hpp"
#include "opensabba/client.hpp"
#include <algorithm>
namespace opensabba {
using pstream::Error;
DeltaPlan snapshot_delta_plan(std::uint64_t size, std::span<const ChangedExtent> changed) {
    constexpr std::uint64_t padding = 1024*1024;
    if (!size || size % 4096 || size/512 > UINT32_MAX-2*padding/512)
        throw pstream::Error("unsupported snapshot delta geometry");
    DeltaPlan plan{size+2*padding, 0, {}};
    std::uint64_t at = 0;
    auto append = [&](std::uint64_t end, bool modified) {
        if (end == at) return;
        if (modified) plan.transfer_bytes += end-at;
        if (!plan.ranges.empty() && plan.ranges.back().changed == modified)
            plan.ranges.back().length += end-at;
        else plan.ranges.push_back({at, end-at, modified});
        at = end;
    };
    append(padding, true);
    for (const auto& range : changed) {
        if (!range.length || range.offset % 4096 || range.length % 4096 ||
            range.offset > size || range.length > size-range.offset || range.offset+padding < at)
            throw pstream::Error("invalid or overlapping snapshot changed ranges");
        append(range.offset+padding, false);
        append(range.offset+padding+range.length, true);
    }
    append(size+padding, false);
    append(plan.image_size, true);
    return plan;
}
DeltaPlan image_delta_plan(ImageSource& base, ImageSource& current,
                           const std::function<bool()>& cancelled) {
    const auto size = current.size();
    constexpr std::uint64_t boundary = 1024*1024;
    if (base.size() != size || size <= 2*boundary || size % 4096 || size/512 > UINT32_MAX)
        throw Error("whole-machine incremental transfer requires equal 4 KiB-aligned images between 2 MiB and 2 TiB");
    std::uint64_t unit = 4096;
    while ((size+unit-1)/unit > 131072) unit *= 2;
    DeltaPlan plan{size,0,{}};
    base.verify_unchanged();
    current.verify_unchanged();
    const auto chunk_size = std::max<std::uint64_t>(1024*1024,unit);
    for (std::uint64_t chunk = 0; chunk < size;) {
        if (cancelled && cancelled()) throw Cancelled();
        const auto count = std::min(chunk_size,size-chunk);
        const auto before = base.read(chunk,static_cast<std::size_t>(count));
        const auto after = current.read(chunk,static_cast<std::size_t>(count));
        for (std::uint64_t local = 0; local < count;) {
            const auto at = chunk+local, length = std::min(unit,count-local);
            const auto first = static_cast<std::ptrdiff_t>(local);
            const auto last = static_cast<std::ptrdiff_t>(local+length);
            const bool changed = at < boundary || at+length > size-boundary ||
                !std::equal(before.begin()+first,before.begin()+last,after.begin()+first);
            if (changed) plan.transfer_bytes += length;
            if (!plan.ranges.empty() && plan.ranges.back().changed == changed)
                plan.ranges.back().length += length;
            else plan.ranges.push_back({at,length,changed});
            local += length;
        }
        chunk += count;
    }
    base.verify_unchanged();
    current.verify_unchanged();
    validate_delta_plan(plan,size);
    return plan;
}
}
