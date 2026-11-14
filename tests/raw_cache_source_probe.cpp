#include "opensabba/machine_capture.hpp"
#include "opensabba/machine.hpp"
#include "opensabba/client.hpp"
#include <lz4.h>
#include <algorithm>
#include <fstream>
#include <cstdlib>
#include <iostream>
#include <iterator>

using namespace opensabba;
using namespace opensabba::pstream;
namespace {
const Value& field(const Value& value,const char* key) {
    return std::get<Value::Object>(value.data).at(key);
}
std::uint64_t number(const Value& value,const char* key) {
    return std::get<std::uint64_t>(field(value,key).data);
}
void check(bool okay) { if (!okay) throw Error("raw cache source probe failed"); }
}
int main(int argc,char** argv) {
    try {
        if (argc < 3) throw Error("usage: raw_cache_source_probe CAPTURE EXPECTED_IMAGE...");
        ReadyMachineCapture capture(argv[1]);
        check(capture.disk_count() == static_cast<std::size_t>(argc-2));
        for (std::size_t index = 0; index < capture.disk_count(); ++index) {
            const auto& plan = index ? std::get<Value::Array>(
                field(capture.journal().plan,"additional_disks").data).at(index-1) : capture.journal().plan;
            auto& source = capture.source(index);
            std::ifstream input(argv[index+2],std::ios::binary);
            Bytes expected{std::istreambuf_iterator<char>(input),std::istreambuf_iterator<char>()};
            check(expected.size() == source.size());
            const auto unused = machine_unused_extents(plan);
            const auto reread = machine_reread_ranges(plan,source.size());
            const auto swap = machine_partition_regions(plan,std::get<Value::Array>(field(plan,"excluded").data).front());
            check(swap[0].type == 2 && swap[1].type == 5);
            DeltaPlan delta{source.size(),0,{{0,source.size(),false}}};
            delta.filesystem_allocation = true;
            machine_force_raw_changes(delta,plan);
            for (bool incremental : {false,true})
                for (auto compression : {TransferCompression::none,TransferCompression::lz4})
                    for (const auto start : {std::uint64_t{0},std::uint64_t{512},
                            swap[1].offset+512,std::uint64_t{3*1024*1024+512}}) {
                        auto rebuilt = expected;
                        std::uint64_t next = start;
                        unsigned eof_records = 0;
                        const bool injected_eof = std::getenv("OPENSABBA_RAW_EOF") && index == 0;
                        stream_image(source,"disk",1024*1024,[&](const Value& value) {
                            const auto at = number(value,"offset"), length = number(value,"length");
                            check(at == next && at+length <= expected.size());
                            const bool omitted = !number(value,"used"), changed = number(value,"changed");
                            const bool raw = std::any_of(reread.begin(),reread.end(),[&](const auto& range) {
                                return at >= range.offset && at+length <= range.offset+range.length;
                            });
                            check(number(value,"is_interval_cbt") == (incremental && !raw ? 1U : 0U));
                            if (omitted) {
                                check(changed && at >= swap[1].offset && at+length <= swap[1].offset+swap[1].length);
                                check(!std::get<Value::Object>(value.data).contains("buffer"));
                                std::fill_n(rebuilt.begin()+static_cast<std::ptrdiff_t>(at),
                                    static_cast<std::size_t>(length),0);
                            } else if (changed) {
                                auto bytes = std::get<Bytes>(field(value,"buffer").data);
                                if (compression == TransferCompression::lz4) {
                                    Bytes plain(length);
                                    check(LZ4_decompress_safe(reinterpret_cast<const char*>(bytes.data()),
                                        reinterpret_cast<char*>(plain.data()),static_cast<int>(bytes.size()),
                                        static_cast<int>(length)) == static_cast<int>(length));
                                    bytes = std::move(plain);
                                }
                                check(bytes.size() == length);
                                std::copy(bytes.begin(),bytes.end(),rebuilt.begin()+static_cast<std::ptrdiff_t>(at));
                            } else {
                                const bool eof = injected_eof && at == 512;
                                check((!raw && incremental) || eof);
                                if (eof) {
                                    check(length == 1024*1024-512 && number(value,"used") == 1 &&
                                          number(value,"is_interval_cbt") == 0 && number(value,"changed_length") == 0);
                                    const auto& fields = std::get<Value::Object>(value.data);
                                    check(!fields.contains("buffer") && !fields.contains("compressed"));
                                    ++eof_records;
                                }
                            }
                            next += length;
                        },{},start,compression,incremental ? &delta : nullptr,unused,reread);
                        check(next == expected.size() && rebuilt == expected);
                        check(eof_records == (injected_eof && start < 1024*1024 ? 1U : 0U));
                    }
        }
        std::cout << "raw cache direct full/incremental/resume sources passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
