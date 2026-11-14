#include "image_delta_fixture.hpp"
#include "opensabba/delta_plan.hpp"
#include <iostream>
#include <limits>

using namespace opensabba;
void check(bool okay) { if (!okay) throw pstream::Error("delta plan test failed"); }
int main() {
    try {
        constexpr std::uint64_t pad = 1024*1024, block = 4096, size = 8*block;
        // Exhaustively compare all eight-block change masks with independent
        // per-block expectations, including container padding and inheritance.
        for (unsigned mask = 0; mask < 256; ++mask) {
            std::vector<ChangedExtent> changes;
            unsigned count = 0;
            for (unsigned bit = 0; bit < 8; ++bit)
                if (mask & (1U << bit)) { changes.push_back({bit*block, block}); ++count; }
            const auto plan = snapshot_delta_plan(size, changes);
            const auto serialized = delta_plan_value(plan);
            check(delta_plan_value(delta_plan_from_value(serialized, plan.image_size)) == serialized);
            check(plan.image_size == size+2*pad && plan.transfer_bytes == 2*pad+count*block);
            std::uint64_t at = 0;
            bool previous = false;
            for (const auto& range : plan.ranges) {
                check(range.offset == at && range.length && range.length % block == 0);
                check(at == 0 || previous != range.changed);
                for (auto offset = at; offset < at+range.length; offset += block) {
                    const bool expected = offset < pad || offset >= pad+size ||
                        (mask & (1U << ((offset-pad)/block)));
                    check(range.changed == expected);
                }
                previous = range.changed;
                at += range.length;
            }
            check(at == plan.image_size);
        }
        // All pairs of generation maps, including duplicate/reverted writes:
        // inherited blocks must be unchanged in BOTH maps.
        for (unsigned older = 0; older < 256; ++older)
            for (unsigned newer = 0; newer < 256; ++newer) {
                std::vector<ChangedExtent> changes;
                for (auto mask : {newer, older})
                    for (unsigned bit = 0; bit < 8; ++bit)
                        if (mask & (1U << bit)) changes.push_back({bit*block, block});
                auto merged = union_changed_extents(size, changes);
                unsigned actual = 0;
                for (const auto& range : merged)
                    for (auto at = range.offset; at < range.offset+range.length; at += block)
                        actual |= 1U << (at/block);
                check(actual == (older | newer));
                validate_delta_plan(snapshot_delta_plan(size, merged), size+2*pad);
            }
        unsigned rejected = 0;
        auto reject = [&](std::uint64_t geometry, std::vector<ChangedExtent> changes) {
            try { snapshot_delta_plan(geometry, changes); }
            catch (const pstream::Error&) { ++rejected; return; }
            throw pstream::Error("invalid delta plan accepted");
        };
        reject(0, {});
        reject(size+1, {});
        reject(std::numeric_limits<std::uint64_t>::max()-4095, {});
        reject(size, {{0, 0}});
        reject(size, {{1, block}});
        reject(size, {{0, block+1}});
        reject(size, {{size, block}});
        reject(size, {{size+block, block}});
        reject(size, {{0, std::numeric_limits<std::uint64_t>::max()-4095}});
        reject(size, {{0, 2*block}, {block, block}});
        reject(size, {{block, block}, {0, block}});
        auto valid = snapshot_delta_plan(size, {});
        auto bad = valid;
        auto reject_plan = [&](const DeltaPlan& plan) {
            try { validate_delta_plan(plan, valid.image_size); }
            catch (const pstream::Error&) { ++rejected; return; }
            throw pstream::Error("invalid saved delta accepted");
        };
        bad.ranges[0].offset = block; reject_plan(bad);
        bad = valid; bad.ranges[1].length += block; reject_plan(bad);
        bad = valid; bad.ranges[0].changed = false; reject_plan(bad);
        bad = valid; bad.ranges.pop_back(); reject_plan(bad);
        bad = valid; ++bad.transfer_bytes; reject_plan(bad);
        bad = valid; ++bad.image_size; reject_plan(bad);
        std::vector<ChangedExtent> fragmented;
        for (std::uint64_t n = 0; n < 65536; ++n) fragmented.push_back({(2*n+1)*block, block});
        const auto largest = snapshot_delta_plan(131073*block, fragmented);
        const pstream::Limits journal_limits{24*1024*1024, 1000000, 20};
        const auto bytes = pstream::encode(delta_plan_value(largest), journal_limits);
        check(delta_plan_from_value(pstream::decode(bytes, journal_limits), largest.image_size).transfer_bytes
              == largest.transfer_bytes);
        std::cout << "Delta plans: 256 change masks and " << rejected << " rejection cases passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
