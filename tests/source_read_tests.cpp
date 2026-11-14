#include "opensabba/image.hpp"
#include <algorithm>
#include <chrono>
#ifdef __linux__
#include <cstdio>
#include <unistd.h>
#endif
#include <iostream>
#include <source_location>
#include <stdexcept>
#include <vector>
using namespace opensabba;
using pstream::Value;
namespace {
void check(bool okay, const std::source_location where = std::source_location::current()) {
    if (!okay) throw std::runtime_error("source read policy invariant failed at line " +
                                       std::to_string(where.line()));
}
std::uint64_t number(const Value& value, const char* key) {
    return std::get<std::uint64_t>(std::get<Value::Object>(value.data).at(key).data);
}
void mapping() {
    for (int error = -1; error <= 140; ++error) {
        SourceReadError failure(error,"/dev/synosnap7","/dev/source",0,512);
        check(failure.error == error && failure.source == "/dev/synosnap7");
        const auto type = error == 2 ? 7040U : error == 13 ? 7038U : error == 16 ? 7043U : 7020U;
        check(failure.log_type() == type);
        const auto params = failure.parameters();
        check(params.size() == (type == 7020 ? 1U : 2U));
        check(std::get<std::string>(params.at("error_code").data) == std::to_string(error));
        if (type != 7020) check(std::get<std::string>(params.at("volume_name").data) == "/dev/synosnap7");
    }
}
void fallback() {
    for (const auto sector : {512U,4096U})
        for (const bool cbt : {false,true})
            for (const auto compression : {TransferCompression::none,TransferCompression::lz4}) {
                std::vector<std::pair<std::uint64_t,std::size_t>> reads;
                unsigned reports = 0, skipped = 0;
                constexpr std::uint64_t size = 3*1024*1024;
                ImageSource source(size,[&](auto at,auto length,auto*) -> pstream::Bytes {
                    reads.emplace_back(at,length);
                    if (at < 2*sector && sector < at+length)
                        throw SourceReadError(5,"/dev/synosnap7","/dev/source",at,sector);
                    return pstream::Bytes(length,42);
                },[] {});
                DeltaPlan delta{size,size,{{0,size,true}}};
                delta.filesystem_allocation = true;
                stream_image(source,"test-image",8192,[&](const Value& block) {
                    const auto& fields = std::get<Value::Object>(block.data);
                    check(number(block,"used") == 1 && number(block,"changed") == 1);
                    check(number(block,"is_interval_cbt") == static_cast<std::uint64_t>(cbt));
                    if (!fields.contains("buffer")) {
                        check(number(block,"offset") == sector && number(block,"length") == sector);
                        check(number(block,"changed_length") == 0 && !fields.contains("compressed"));
                        ++skipped;
                    }
                },{},0,compression,cbt ? &delta : nullptr,{},{},{},[&](auto type,auto params) {
                    check(type == 7044 && params.size() == 3);
                    check(std::get<std::string>(params.at("volume_name").data) == "/dev/source");
                    check(std::get<std::string>(params.at("interval_start").data) == (sector == 512 ? "0x200" : "0x1000"));
                    check(std::get<std::string>(params.at("interval_end").data) == (sector == 512 ? "0x3ff" : "0x1fff"));
                    ++reports;
                },[](auto) { check(false); });
                check(skipped == 1 && reports == 1);
                check(reads.front().first == 0 && reads.front().second == 8192);
                check(reads.back().first == size-8192 && reads.back().second == 8192);
                check(reads.size() == size/8192+8192/sector);
            }
}
void eof_fill() {
#ifdef __linux__
    // Exercise the production pread adapter as well as the portable wire model.
    FILE* file = std::tmpfile();
    check(file != nullptr);
    const pstream::Bytes data(4096,42);
    check(std::fwrite(data.data(),1,data.size(),file) == data.size() && std::fflush(file) == 0);
    check(read_source_at(fileno(file),2048,4096,"fixture","fixture",512).size() == 2048);
    check(read_source_at(fileno(file),4096,4096,"fixture","fixture",512).empty());
    std::fclose(file);
#endif
    constexpr std::uint64_t size = 4*1024*1024, capacity = 1024*1024+512;
    for (const bool cbt : {false,true})
        for (const auto compression : {TransferCompression::none,TransferCompression::lz4}) {
            ImageSource source(size,[&](auto at,auto length,auto*) {
                return pstream::Bytes(static_cast<std::size_t>(at < capacity ?
                    std::min<std::uint64_t>(length,capacity-at) : 0),42);
            },[] {});
            DeltaPlan delta{size,size,{{0,size,true}}};
            delta.filesystem_allocation = true;
            unsigned fills = 0, partials = 0;
            std::uint64_t next = 0, measured = 0;
            stream_image(source,"eof.img",65536,[&](const Value& block) {
                const auto& fields = std::get<Value::Object>(block.data);
                check(number(block,"offset") == next);
                next += number(block,"length");
                if (number(block,"offset") == capacity) {
                    check(number(block,"length") == size-capacity && number(block,"used") == 1);
                    check(number(block,"changed") == 0 && number(block,"changed_length") == 0);
                    check(number(block,"is_interval_cbt") == static_cast<std::uint64_t>(cbt));
                    check(!fields.contains("buffer") && !fields.contains("compressed"));
                    ++fills;
                } else if (number(block,"offset") == 1024*1024) {
                    check(number(block,"length") == 512 && fields.contains("buffer"));
                    ++partials;
                }
            },{},0,compression,cbt ? &delta : nullptr,{},{},[&](auto,auto length) { measured += length; });
            check(next == size && measured == capacity && fills == 1 && partials == 1);
        }
}
void retry_and_fatal() {
    using namespace std::chrono_literals;
    unsigned reads = 0, waits = 0, blocks = 0;
    std::chrono::milliseconds waited{0};
    ImageSource source(1024,[&](auto at,auto length,auto*) -> pstream::Bytes {
        check(at == blocks*512 && length == 512);
        // Each of two blocks consumes the entire retry budget. Success must
        // reset it, and every failed read must wait before the next attempt.
        check(waits == reads-blocks);
        ++reads;
        if (reads % 31) throw SourceReadError(61,"/dev/source","/dev/source",at,512);
        return pstream::Bytes(length,42);
    },[] {});
    const auto wait = [&](auto duration) {
        check(duration == 1000ms && waits+blocks+1 == reads);
        ++waits;
        waited += duration;
    };
    stream_image(source,"test-image",512,[&](const Value& block) {
        check(number(block,"offset") == blocks*512 && reads == (blocks+1)*31);
        ++blocks;
    },{},0,TransferCompression::none,nullptr,{},{},{},{},wait);
    check(reads == 62 && blocks == 2 && waits == 60 && waited == 60s);

    // Thirty waits permit exactly 31 failed reads; the final failure is
    // propagated unchanged, without an extra wait or a data block.
    reads = waits = blocks = 0;
    waited = 0ms;
    ImageSource exhausted(512,[&](auto at,auto,auto*) -> pstream::Bytes {
        check(at == 0 && waits == reads);
        ++reads;
        throw SourceReadError(61,"/dev/source","/dev/source",at,512);
    },[] {});
    bool exhausted_error = false;
    try {
        stream_image(exhausted,"test-image",512,[](const Value&) { check(false); },
            {},0,TransferCompression::none,nullptr,{},{},{},{},wait);
    } catch (const SourceReadError& error) {
        exhausted_error = error.error == 61 && error.offset == 0 && error.sector_size == 512;
    }
    check(exhausted_error && reads == 31 && waits == 30 && waited == 30s);

    for (const auto snapshot_error : {-5,-27}) {
        unsigned failures = 0;
        ImageSource fatal(4096,[&](auto at,auto,auto*) -> pstream::Bytes {
            ++failures;
            throw SourceReadError(5,"/dev/synosnap7","/dev/source",at,512,snapshot_error);
        },[] {});
        bool failed = false;
        try {
            stream_image(fatal,"test-image",4096,[](const Value&) { check(false); },
                {},0,TransferCompression::none,nullptr,{},{},{},{},[](auto) { check(false); });
        }
        catch (const SourceReadError& error) {
            failed = error.error == 5 && error.snapshot_error == snapshot_error;
        }
        check(failed && failures == 1);
    }

    bool cancelled = false, cancellation_observed = false;
    reads = waits = 0;
    ImageSource interrupted(512,[&](auto at,auto,auto*) -> pstream::Bytes {
        ++reads;
        throw SourceReadError(61,"/dev/source","/dev/source",at,512);
    },[] {});
    try {
        stream_image(interrupted,"test-image",512,[](const Value&) { check(false); },
            [&] { return cancelled; },0,TransferCompression::none,nullptr,{},{},{},{},[&](auto duration) {
                check(duration == 1000ms && reads == 1);
                ++waits;
                cancelled = true;
            });
    } catch (const pstream::Error& error) {
        cancellation_observed = std::string_view(error.what()) == "image transfer cancelled";
    }
    check(cancellation_observed && reads == 1 && waits == 1);
}
}
int main() {
    try { mapping(); fallback(); eof_fill(); retry_and_fatal(); std::cout << "source read mapping, fallback, retry reset and fatal state passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
