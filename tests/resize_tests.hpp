#pragma once

// Synthetic model of a 256 -> 384 MiB tracked LV transition. Metadata
// lives in the old capacity (ext4 flex_bg), including the added group's map.
void resized_tracking_volume() {
    constexpr std::uint64_t mib = 1024*1024, old_size = 256*mib, size = 384*mib;
    const auto put = [](Bytes& bytes, std::size_t at, std::uint64_t value, unsigned width = 4) {
        for (unsigned i = 0; i < width; ++i) bytes.at(at+i) = static_cast<std::uint8_t>(value >> (8*i));
    };
    const auto compact = [&](std::uint64_t capacity, std::uint64_t origin) {
        Bytes cow(static_cast<std::size_t>(4096+capacity/4096*8),0);
        put(cow,4096,1,8);
        if (capacity == size) put(cow,static_cast<std::size_t>(4096+old_size/4096*8),1,8);
        return compact_cow_index([&](auto at,auto count) {
            return Bytes(cow.begin()+static_cast<std::ptrdiff_t>(at),cow.begin()+static_cast<std::ptrdiff_t>(at+count));
        },cow.size(),origin);
    };
    check(compact(old_size,size).empty()); // First 768 KiB fread was short.
    auto prefix = compact(768*mib,1536*mib);
    check(prefix.size() == 1024 && prefix.front() == 1); // Keep a full 1 MiB chunk.
    check(compact(size,old_size).size() == 512); // Shrink reads only current index.
    for (const unsigned variant : {0U,1U,2U}) {
        const bool grow_filesystem = variant != 0, metadata_reachable = variant != 2;
        auto base = ready(), current = ready();
        base.id = std::string(32,'a'); current.id = std::string(32,'b');
        Value volume{Value::Object{{"offset",n(0)},{"length",n(old_size)},
            {"filesystem_uuid",Value{std::string("resize-fs")}},{"lv_uuid",Value{std::string("resize-lv")}}}};
        base.plan = Value{Value::Object{{"layout",Value{Value::Object{{"length",n(16*mib)}}}},{"root",volume}}};
        current.plan = base.plan;
        set(std::get<Value::Object>(current.plan.data).at("root"),"length",n(size));
        base.snapshot = Value{Value::Object{{"uuid",Value{std::string(32,'c')}},{"sequence",n(7)}}};
        current.snapshot = base.snapshot; set(current.snapshot,"sequence",n(8));
        current.reservation = Value{Value::Object{{"previous_capture_id",Value{base.id}},
            {"prior",Value{Value::Object{{"snapshot",base.snapshot}}}},
            {"changes",Value{compact(old_size,size)}},{"filesystem_unused",Value{Value::Array{}}}}};
        Bytes metadata(8*4096,0);
        put(metadata,1024+4,(grow_filesystem ? size : old_size)/4096);
        put(metadata,1024+0x18,2); put(metadata,1024+0x1c,2);
        put(metadata,1024+0x20,32768); put(metadata,1024+0x24,32768);
        put(metadata,1024+0x38,0xef53,2);
        for (unsigned group = 0; group < (grow_filesystem ? 3U : 2U); ++group) {
            put(metadata,4096+group*32,group == 2 && !metadata_reachable ? old_size/4096 : 4+group);
            std::fill_n(metadata.begin()+(4+group)*4096,2,255); // 64 KiB used per group.
        }
        for (const bool next_backup : {false,true}) {
            const auto capacity = next_backup ? size : old_size;
            const auto read = [&](std::uint64_t at,std::size_t count,auto*) {
                if (at >= capacity) return Bytes{};
                count = static_cast<std::size_t>(std::min<std::uint64_t>(count,capacity-at));
                Bytes bytes(count,42);
                if (at < metadata.size()) {
                    const auto length = std::min(count,metadata.size()-static_cast<std::size_t>(at));
                    std::copy_n(metadata.begin()+static_cast<std::ptrdiff_t>(at),length,bytes.begin());
                }
                if (grow_filesystem && !metadata_reachable) {
                    const auto first = std::max(at,old_size), last = std::min(at+count,old_size+4096);
                    if (first < last) {
                        std::fill(bytes.begin()+static_cast<std::ptrdiff_t>(first-at),
                            bytes.begin()+static_cast<std::ptrdiff_t>(last-at),0);
                        for (auto n = first; n < std::min(last,old_size+2); ++n)
                            bytes.at(static_cast<std::size_t>(n-at)) = 255;
                    }
                }
                return bytes;
            };
            const auto free = snapshot_used_context("/dev/synosnap3",size,[&](auto at,auto count) {
                return read(at,count,static_cast<std::uint64_t*>(nullptr));
            });
            // The filesystem reader reads the snapshot, not the enlarged
            // origin. A new bitmap beyond its old capacity clears allocation context;
            // flex_bg metadata still inside the snapshot remains readable.
            check(free.empty() == (!next_backup && !metadata_reachable));
            Value::Array unused;
            for (const auto& range : free) unused.push_back(Value{Value::Object{
                {"offset",n(range.offset)},{"length",n(range.length)}}});
            set(current.reservation,"filesystem_unused",Value{unused});
            if (next_backup) {
                base = current;
                current.id = std::string(32,'d');
                set(current.snapshot,"sequence",n(9));
                set(current.reservation,"previous_capture_id",Value{base.id});
                set(current.reservation,"prior",Value{Value::Object{{"snapshot",base.snapshot}}});
                set(current.reservation,"changes",Value{compact(size,size)});
            }
            Value policy;
            std::vector<ChangedExtent> reread;
            auto delta = fixture_tracking_delta(current,base,1,&reread,false,&policy);
            check(delta.image_size == size);
            check(std::get<std::uint64_t>(std::get<Value::Object>(policy.data).at("is_cbt").data) == static_cast<std::uint64_t>(next_backup));
            const auto ranges = machine_tracking_unused(current,1,true,reread);
            auto source = std::make_shared<ImageSource>(size,read,[] {});
            // Add another image interval to prove EOF cannot swallow it.
            auto sibling = std::make_shared<ImageSource>(Bytes(1024*1024,11));
            ImageSource image(size+mib,std::vector<ImageExtent>{{0,size,0,source},{size,mib,0,sibling}});
            DeltaPlan composite = delta;
            composite.image_size += mib; composite.transfer_bytes += mib;
            if (composite.ranges.back().changed) composite.ranges.back().length += mib;
            else composite.ranges.push_back({size,mib,true});
            unsigned fills = 0, tail_payloads = 0, sibling_records = 0;
            std::uint64_t next = 0;
            stream_image(image,"resize.img",1024*1024,[&](const Value& value) {
                const auto& block = std::get<Value::Object>(value.data);
                const auto at = std::get<std::uint64_t>(block.at("offset").data);
                const auto length = std::get<std::uint64_t>(block.at("length").data);
                check(at == next); next += length;
                if (at == old_size && !next_backup) {
                    check(length == size-old_size);
                    check(std::get<std::uint64_t>(block.at("used").data) == 1);
                    check(std::get<std::uint64_t>(block.at("changed").data) == 0);
                    check(std::get<std::uint64_t>(block.at("is_interval_cbt").data) == 0);
                    check(std::get<std::uint64_t>(block.at("changed_length").data) == 0);
                    check(!block.contains("buffer") && !block.contains("compressed"));
                    ++fills;
                }
                if (at == old_size && next_backup) {
                    check(length == 65536 && block.contains("buffer"));
                    ++tail_payloads;
                }
                if (at == size) { check(block.contains("buffer")); ++sibling_records; }
            },{},0,TransferCompression::lz4,&composite,ranges,reread);
            check(next == size+mib && sibling_records == 1);
            check(fills == (next_backup ? 0U : 1U) && tail_payloads == (next_backup ? 1U : 0U));
        }
    }
}
