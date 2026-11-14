#pragma once
#include "opensabba/pstream.hpp"
#include <chrono>
#include <functional>

namespace opensabba {
// OS read failures retain the actual source, independently of their diagnostic
// text. Snapshot status is sampled after the failed read, before retry/skip.
class SourceReadError : public pstream::Error {
public:
    int error;
    std::string source, volume;
    std::uint64_t offset;
    std::size_t sector_size;
    int snapshot_error;
    SourceReadError(int code, std::string path, std::string volume_name,
                    std::uint64_t at, std::size_t sector, int snapshot_code = 0);
    std::uint64_t log_type() const;
    pstream::Value::Object parameters() const;
};
using SourceReadActivity = std::function<void(std::uint64_t, pstream::Value::Object)>;
// An injectable wait keeps retry-budget/order tests independent of host timers.
// Production requests the official agent 1000 ms delay through std::this_thread::sleep_for.
using SourceReadRetryWait = std::function<void(std::chrono::milliseconds)>;
#ifdef __linux__
// the official agent warns if F_SETFL fails and continues using the opened descriptor.
void enable_source_direct(int descriptor);
pstream::Bytes read_source_at(int descriptor, std::uint64_t offset, std::size_t size,
                             const std::string& source, const std::string& volume,
                             std::size_t sector_size, std::uint64_t* read_nanoseconds = nullptr);
#endif
}
