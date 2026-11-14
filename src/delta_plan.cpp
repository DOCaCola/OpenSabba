#include "opensabba/delta_plan.hpp"
#include <algorithm>

namespace opensabba {
std::vector<ChangedExtent> union_changed_extents(std::uint64_t size, std::vector<ChangedExtent> changes) {
    if (!size || size % 4096) throw pstream::Error("invalid generation source geometry");
    for (const auto& range : changes)
        if (!range.length || range.offset % 4096 || range.length % 4096 ||
            range.offset > size || range.length > size-range.offset)
            throw pstream::Error("invalid generation change extent");
    std::sort(changes.begin(), changes.end(), [](const auto& a, const auto& b) { return a.offset < b.offset; });
    std::vector<ChangedExtent> result;
    for (const auto& range : changes) {
        if (!result.empty() && range.offset <= result.back().offset + result.back().length)
            result.back().length = std::max(result.back().offset + result.back().length,
                                            range.offset + range.length) - result.back().offset;
        else result.push_back(range);
    }
    return result;
}
void validate_delta_plan(const DeltaPlan& plan, std::uint64_t size) {
    if (!size || size % 4096 || size/512 > UINT32_MAX ||
        plan.image_size != size || plan.ranges.empty() || plan.ranges.size() > 131075)
        throw pstream::Error("invalid incremental image geometry or range count");
    std::uint64_t at = 0, transferred = 0;
    bool previous = false;
    for (const auto& range : plan.ranges) {
        if (range.offset != at || !range.length || range.length % 4096 ||
            range.length > size-at || (at && previous == range.changed))
            throw pstream::Error("invalid incremental range coverage");
        if (range.changed) transferred += range.length;
        at += range.length;
        previous = range.changed;
    }
    if (at != size || transferred != plan.transfer_bytes)
        throw pstream::Error("incomplete incremental plan or invalid byte count");
}
pstream::Value delta_plan_value(const DeltaPlan& plan) {
    validate_delta_plan(plan, plan.image_size);
    pstream::Value::Array ranges;
    for (const auto& range : plan.ranges)
        ranges.push_back(pstream::Value{pstream::Value::Object{
            {"offset", pstream::Value{range.offset}}, {"length", pstream::Value{range.length}},
            {"changed", pstream::Value{std::uint64_t{range.changed}}}}});
    return pstream::Value{std::move(ranges)};
}
DeltaPlan delta_plan_from_value(const pstream::Value& value, std::uint64_t size) {
    const auto* array = std::get_if<pstream::Value::Array>(&value.data);
    if (!array || array->size() > 131075) throw pstream::Error("invalid incremental range list");
    DeltaPlan plan{size, 0, {}};
    for (const auto& item : *array) {
        const auto* fields = std::get_if<pstream::Value::Object>(&item.data);
        if (!fields || fields->size() != 3) throw pstream::Error("invalid incremental range");
        auto number = [&](const char* name) {
            const auto it = fields->find(name);
            if (it == fields->end() || !std::holds_alternative<std::uint64_t>(it->second.data))
                throw pstream::Error("invalid incremental range field");
            return std::get<std::uint64_t>(it->second.data);
        };
        const auto changed = number("changed"), length = number("length");
        if (changed > 1 || length > size || (changed && plan.transfer_bytes > size-length))
            throw pstream::Error("invalid incremental range counter");
        plan.ranges.push_back({number("offset"), length, changed != 0});
        if (changed) plan.transfer_bytes += length;
    }
    validate_delta_plan(plan, size);
    return plan;
}
}
