#include "opensabba/source_read.hpp"
#include <chrono>
#ifdef __linux__
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <unistd.h>
#endif

namespace opensabba {
SourceReadError::SourceReadError(int code, std::string path, std::string volume_name,
                               std::uint64_t at, std::size_t sector, int snapshot_code)
    : Error("source read failed: " + path + " (errno " + std::to_string(code) + ")"),
      error(code), source(std::move(path)), volume(std::move(volume_name)), offset(at),
      sector_size(sector), snapshot_error(snapshot_code) {}
std::uint64_t SourceReadError::log_type() const {
    // ABB Linux Source-error mapping, followed by
    // Interval preparation's generic read remap.
    switch (error) {
    case 2: return 7040;
    case 13: return 7038;
    case 16: return 7043;
    default: return 7020;
    }
}
pstream::Value::Object SourceReadError::parameters() const {
    pstream::Value::Object result{{"error_code",pstream::Value{std::to_string(error)}}};
    if (log_type() != 7020) result.emplace("volume_name",pstream::Value{source});
    return result;
}
#ifdef __linux__
void enable_source_direct(int descriptor) {
    const auto flags = fcntl(descriptor,F_GETFL,0);
    if (fcntl(descriptor,F_SETFL,flags | O_DIRECT) < 0)
        std::cerr << "DiskImageFile open fcntl SETFL failed (errno " << errno << ")\n";
}
pstream::Bytes read_source_at(int descriptor, std::uint64_t offset, std::size_t size,
                             const std::string& source, const std::string& volume,
                             std::size_t sector_size, std::uint64_t* read_nanoseconds) {
    // Source reads uses memalign(4096,size), including sector-sized
    // retries. Alignment is independent of the logical sector read length.
    void* allocation = nullptr;
    const auto error = posix_memalign(&allocation,4096,size);
    if (error) throw pstream::Error("cannot allocate aligned source read buffer");
    std::unique_ptr<void,decltype(&std::free)> buffer(allocation,&std::free);
    auto* data = static_cast<std::uint8_t*>(allocation);
    std::size_t done = 0;
    const auto started = std::chrono::system_clock::now();
    while (done < size) {
        const auto count = pread(descriptor,data+done,size-done,static_cast<off_t>(offset+done));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) throw SourceReadError(errno,source,volume,offset,sector_size);
        if (!count) break;
        done += static_cast<std::size_t>(count);
    }
    if (read_nanoseconds) *read_nanoseconds = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now()-started).count());
    return pstream::Bytes(data,data+done);
}
#endif
}
