#include "opensabba/image.hpp"
#include "opensabba/filesystem.hpp"
#include <algorithm>
#include <charconv>
#include <chrono>
#include <iostream>
#include <limits>
#include <sstream>
#include <thread>
#include <lz4.h>
#ifndef _WIN32
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#ifdef __linux__
#include <poll.h>
#include <sys/inotify.h>
#endif

namespace opensabba {
using pstream::Value;
using pstream::Error;
#ifndef _WIN32
struct ImageSource::Impl {
    int fd = -1;
    std::string source;
#ifdef __linux__
    int changes = -1;
#endif
    struct stat initial{};
    Impl(int descriptor, std::string path) : fd(descriptor), source(std::move(path)) {
        if (fd < 0) throw Error("cannot open offline image");
        try {
#ifdef __linux__
            // Watch the opened inode before taking its baseline. Timestamp precision
            // alone cannot distinguish multiple writes in the same clock tick.
            changes = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
            if (changes < 0 || inotify_add_watch(changes,
                ("/proc/self/fd/"+std::to_string(fd)).c_str(),
                IN_MODIFY | IN_ATTRIB | IN_MOVE_SELF | IN_DELETE_SELF) < 0)
                throw Error("cannot monitor offline image changes");
#endif
            if (fstat(fd, &initial) != 0 || !S_ISREG(initial.st_mode) ||
                initial.st_size <= 0 || initial.st_size % 512 != 0) {
                throw Error("offline image must be a nonempty regular file with a size divisible by 512");
            }
        } catch (...) {
#ifdef __linux__
            if (changes >= 0) close(changes);
#endif
            close(fd);
            throw;
        }
    }
    explicit Impl(const std::filesystem::path& path)
        : Impl(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK),path.string()) {}
    ~Impl() {
#ifdef __linux__
        if (changes >= 0) close(changes);
#endif
        if (fd >= 0) close(fd);
    }
};
ImageSource::ImageSource(const std::filesystem::path& path) : impl_(std::make_unique<Impl>(path)) {}
ImageSource::ImageSource(int descriptor, std::string source)
    : impl_(std::make_unique<Impl>(fcntl(descriptor, F_DUPFD_CLOEXEC, 0),std::move(source))) {}
ImageSource::~ImageSource() = default;
std::uint64_t ImageSource::size() const {
    if (interval_length_) return interval_length_;
    if (composite_length_) return composite_length_;
    if (memory_) return memory_->size();
    return static_cast<std::uint64_t>(impl_->initial.st_size);
}
void ImageSource::verify_unchanged() const {
    if (interval_verify_) { interval_verify_(); return; }
    if (composite_length_) { verify_composite(); return; }
    if (memory_) return;
#ifdef __linux__
    // Never drain this private queue: any mutation, lost watch or overflow
    // permanently invalidates the source, including subsequent retries.
    pollfd notification{impl_->changes, POLLIN, 0};
    int result;
    do { result = poll(&notification, 1, 0); } while (result < 0 && errno == EINTR);
    if (result < 0) throw Error("cannot inspect offline image change monitor");
    if (result > 0) throw Error("offline image changed during transfer");
#endif
    struct stat current{};
    if (fstat(impl_->fd, &current) != 0) throw Error("cannot inspect offline image");
    const auto& before = impl_->initial;
    if (current.st_size != before.st_size ||
        current.st_mtim.tv_sec != before.st_mtim.tv_sec || current.st_mtim.tv_nsec != before.st_mtim.tv_nsec ||
        current.st_ctim.tv_sec != before.st_ctim.tv_sec || current.st_ctim.tv_nsec != before.st_ctim.tv_nsec)
        throw Error("offline image changed during transfer");
}
pstream::Bytes ImageSource::read_from(bool metadata, std::uint64_t offset, std::size_t length,
                                     std::uint64_t* read_nanoseconds) {
    if (prepared_stream_) throw Error("cached image payload is available only as prepared interval records");
    if (offset > size() || length > size() - offset) throw Error("image read exceeds source extent");
    if (read_nanoseconds) *read_nanoseconds = 0;
    if (interval_read_) {
        verify_unchanged();
        auto bytes = metadata && metadata_read_ ? metadata_read_(offset,length) :
                                                 interval_read_(offset,length,read_nanoseconds);
        verify_unchanged();
        return bytes;
    }
    if (composite_length_) return read_composite(offset, length,read_nanoseconds,metadata);
    if (memory_) {
        pstream::Bytes result(length);
        const auto started = std::chrono::system_clock::now();
        std::copy_n(memory_->begin()+static_cast<std::ptrdiff_t>(offset),length,result.begin());
        if (read_nanoseconds) *read_nanoseconds = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::system_clock::now()-started).count());
        return result;
    }
    verify_unchanged();
    pstream::Bytes result(length);
    std::size_t done = 0;
    const auto started = std::chrono::system_clock::now();
    while (done < length) {
        const auto count = pread(impl_->fd, result.data() + done, length - done,
                                 static_cast<off_t>(offset + done));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) throw SourceReadError(errno,impl_->source,impl_->source,offset,512);
        if (!count) throw Error("offline image source was truncated");
        done += static_cast<std::size_t>(count);
    }
    if (read_nanoseconds) *read_nanoseconds = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now()-started).count());
    verify_unchanged();
    return result;
}
#else
struct ImageSource::Impl {};
ImageSource::ImageSource(const std::filesystem::path&) { throw Error("offline image source currently requires Linux"); }
ImageSource::ImageSource(int, std::string) { throw Error("offline image source currently requires Linux"); }
ImageSource::~ImageSource() = default;
std::uint64_t ImageSource::size() const {
    if (interval_length_) return interval_length_;
    if (composite_length_) return composite_length_;
    if (memory_) return memory_->size();
    throw Error("offline image source currently requires Linux");
}
void ImageSource::verify_unchanged() const {
    if (interval_verify_) { interval_verify_(); return; }
    if (composite_length_) { verify_composite(); return; }
    if (!memory_) throw Error("offline image source currently requires Linux");
}
pstream::Bytes ImageSource::read_from(bool metadata, std::uint64_t offset, std::size_t length,
                                     std::uint64_t* read_nanoseconds) {
    if (prepared_stream_) throw Error("cached image payload is available only as prepared interval records");
    if (offset > size() || length > size() - offset) throw Error("image read exceeds source extent");
    if (read_nanoseconds) *read_nanoseconds = 0;
    if (interval_read_) {
        verify_unchanged();
        auto bytes = metadata && metadata_read_ ? metadata_read_(offset,length) :
                                                 interval_read_(offset,length,read_nanoseconds);
        verify_unchanged();
        return bytes;
    }
    if (composite_length_) return read_composite(offset, length,read_nanoseconds,metadata);
    pstream::Bytes result(length);
    const auto started = std::chrono::system_clock::now();
    std::copy_n(memory_->begin()+static_cast<std::ptrdiff_t>(offset),length,result.begin());
    if (read_nanoseconds) *read_nanoseconds = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now()-started).count());
    return result;
}
#endif
pstream::Bytes ImageSource::read(std::uint64_t offset, std::size_t length, std::uint64_t* elapsed) {
    return read_from(false,offset,length,elapsed);
}
pstream::Bytes ImageSource::read_metadata(std::uint64_t offset, std::size_t length) {
    return read_from(true,offset,length,nullptr);
}

ImageSource::ImageSource(std::uint64_t length,
    std::function<pstream::Bytes(std::uint64_t,std::size_t,std::uint64_t*)> read,
    std::function<void()> verify, MetadataRead metadata)
    : interval_length_(length), interval_read_(std::move(read)), interval_verify_(std::move(verify)),
      metadata_read_(std::move(metadata)) {
    if (!length || length%512 || !interval_read_ || !interval_verify_)
        throw Error("invalid machine interval source");
    verify_unchanged();
}
std::uint64_t ImageSource::read_interval_end(std::uint64_t offset) const {
    for (const auto& extent : extents_) {
        if (offset < extent.offset || offset >= extent.offset+extent.length) continue;
        const auto source_end = extent.source->read_interval_end(extent.source_offset+offset-extent.offset);
        return extent.offset+std::min(extent.length,source_end-extent.source_offset);
    }
    return size();
}
bool ImageSource::direct_intervals() const {
    return interval_length_ || std::any_of(extents_.begin(),extents_.end(),
        [](const auto& extent) { return extent.source->direct_intervals(); });
}
void ImageSource::set_bad_clusters(const BadClusterContext& context, std::uint64_t image_offset) {
    bad_clusters_.clear();
    for (const auto& range : context.ranges)
        bad_clusters_.push_back({image_offset+range.offset,range.length,range.offset,context.volume});
}
std::vector<ImageBadCluster> ImageSource::bad_clusters() const {
    auto result = bad_clusters_;
    for (const auto& extent : extents_) {
        for (const auto& bad : extent.source->bad_clusters()) {
            const auto first = std::max(extent.source_offset,bad.offset);
            const auto last = std::min(extent.source_offset+extent.length,bad.offset+bad.length);
            if (first < last) result.push_back({extent.offset+first-extent.source_offset,
                last-first,bad.volume_offset+first-bad.offset,bad.volume});
        }
    }
    std::sort(result.begin(),result.end(),[](const auto& a,const auto& b) { return a.offset < b.offset; });
    return result;
}
ImageSource::ImageSource(std::uint64_t length, PreparedStream stream, std::function<void()> verify)
    : interval_length_(length), interval_verify_(std::move(verify)), prepared_stream_(std::move(stream)) {
    if (!length || length%512 || !prepared_stream_ || !interval_verify_)
        throw Error("invalid cached interval source");
    verify_unchanged();
}
bool ImageSource::stream_prepared(std::string_view name, std::uint64_t offset,
    const std::function<void(const Value&)>& send, const std::function<bool()>& cancelled) {
    if (!prepared_stream_) return false;
    verify_unchanged();
    prepared_stream_(name,offset,send,cancelled);
    verify_unchanged();
    return true;
}

ImageSource::ImageSource(pstream::Bytes image) : memory_(std::move(image)) {
    if (memory_->empty() || memory_->size() % 512)
        throw Error("immutable image must be nonempty with a size divisible by 512");
}

ImageSource::ImageSource(std::uint64_t length, std::vector<ImageExtent> extents)
    : extents_(std::move(extents)), composite_length_(length) {
    if (!length || length % 512 || extents_.empty())
        throw Error("composite image must have a nonempty sector-aligned extent");
    std::uint64_t at = 0;
    for (const auto& extent : extents_) {
        if (!extent.source || extent.offset != at || !extent.length ||
            extent.length % 512 || extent.source_offset % 512 || extent.length > length-at)
            throw Error("composite image extents must cover the image exactly without gaps or overlaps");
        if (extent.source_offset > extent.source->size() ||
            extent.length > extent.source->size()-extent.source_offset)
            throw Error("composite image extent exceeds its source");
        at += extent.length;
    }
    if (at != length) throw Error("composite image has incomplete coverage");
    verify_composite();
}
void ImageSource::verify_composite() const {
    for (std::size_t i = 0; i < extents_.size(); ++i) {
        const auto* source = extents_[i].source.get();
        const bool seen = std::any_of(extents_.begin(), extents_.begin()+static_cast<std::ptrdiff_t>(i),
            [&](const auto& earlier) { return earlier.source.get() == source; });
        if (!seen) source->verify_unchanged();
    }
}
pstream::Bytes ImageSource::read_composite(std::uint64_t offset, std::size_t length,
                                          std::uint64_t* read_nanoseconds, bool metadata) {
    verify_composite();
    pstream::Bytes result;
    result.reserve(length);
    const auto end = offset+length;
    for (const auto& extent : extents_) {
        const auto first = std::max(offset, extent.offset);
        const auto last = std::min(end, extent.offset+extent.length);
        if (first >= last) continue;
        std::uint64_t elapsed = 0;
        const auto at = extent.source_offset+first-extent.offset;
        const auto count = static_cast<std::size_t>(last-first);
        auto bytes = metadata ? extent.source->read_metadata(at,count) :
            extent.source->read(at,count,read_nanoseconds ? &elapsed : nullptr);
        if (read_nanoseconds) *read_nanoseconds += elapsed;
        result.insert(result.end(), bytes.begin(), bytes.end());
        if (bytes.size() < last-first) break;
    }
    verify_composite();
    return result;
}

void validate_image_options(std::string_view name, std::size_t block_size) {
    if (name.empty() || name.size() > 128 || name == "." || name == ".." ||
        name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-=+") != name.npos)
        throw Error("image name must be a simple ASCII name, not a path");
    if (block_size < 512 || block_size > 4 * 1024 * 1024 || block_size % 512 != 0)
        throw Error("image block size must be a multiple of 512 between 512 and 4194304");
}
void validate_unused_ranges(std::span<const ChangedExtent> ranges, std::uint64_t image_size) {
    std::uint64_t end = 0;
    for (const auto& range : ranges) {
        if (!range.length || range.offset % 512 || range.length % 512 ||
            range.offset < end || range.offset > image_size ||
            range.length > image_size-range.offset)
            throw Error("invalid unused image interval");
        end = range.offset+range.length;
    }
}
std::vector<ChangedExtent> union_unused_ranges(std::uint64_t size, std::vector<ChangedExtent> ranges) {
    for (const auto& range : ranges) validate_unused_ranges(std::span(&range,1),size);
    std::sort(ranges.begin(),ranges.end(),[](const auto& a,const auto& b) { return a.offset < b.offset; });
    std::vector<ChangedExtent> result;
    for (const auto& range : ranges) {
        if (!result.empty() && range.offset <= result.back().offset+result.back().length)
            result.back().length = std::max(result.back().offset+result.back().length,
                range.offset+range.length)-result.back().offset;
        else result.push_back(range);
    }
    return result;
}
void validate_reread_ranges(std::span<const ChangedExtent> ranges, const DeltaPlan& delta) {
    std::size_t index = 0;
    std::uint64_t end = 0;
    for (const auto& range : ranges) {
        if (!range.length || range.offset % 4096 || range.length % 4096 || range.offset < end ||
            range.offset > delta.image_size || range.length > delta.image_size-range.offset)
            throw Error("invalid reread image interval");
        while (delta.ranges[index].offset+delta.ranges[index].length <= range.offset) ++index;
        const auto& covering = delta.ranges[index];
        if (!covering.changed || range.offset+range.length > covering.offset+covering.length)
            throw Error("reread image interval is not changed in the incremental plan");
        end = range.offset+range.length;
    }
}
void verify_unused_source(ImageSource& source, std::span<const ChangedExtent> ranges) {
    validate_unused_ranges(ranges,source.size());
    if (source.direct_intervals()) { source.verify_unchanged(); return; }
    for (const auto& range : ranges)
        for (std::uint64_t at = range.offset; at < range.offset+range.length;) {
            auto bytes = source.read(at,static_cast<std::size_t>(
                std::min<std::uint64_t>(1024*1024,range.offset+range.length-at)));
            if (std::any_of(bytes.begin(),bytes.end(),[](auto byte) { return byte != 0; }))
                throw Error("unused image interval contains source data");
            at += bytes.size();
        }
    source.verify_unchanged();
}
void stream_image(ImageSource& source, std::string_view name, std::size_t block_size,
                  const SendBlock& send, const std::function<bool()>& cancelled, std::uint64_t start_offset,
                  TransferCompression compression, const DeltaPlan* delta,
                  std::span<const ChangedExtent> unused, std::span<const ChangedExtent> reread,
                  const ReadPerformance& read_performance, const SourceReadActivity& read_activity,
                  const SourceReadRetryWait& retry_wait) {
    validate_image_options(name, block_size);
    if (compression != TransferCompression::none && compression != TransferCompression::lz4)
        throw Error("unsupported transfer compression");
    if (start_offset > source.size() || start_offset % 512) throw Error("invalid image resume offset");
    if (delta) {
        validate_delta_plan(*delta, source.size());
        validate_reread_ranges(reread, *delta);
    }
    validate_unused_ranges(unused,source.size());
    if (source.stream_prepared(name,start_offset,send,cancelled)) return;
    std::size_t range_index = 0;
    std::size_t unused_index = 0;
    std::size_t reread_index = 0;
    std::uint64_t fallback_end = 0;
    std::size_t fallback_size = 0;
    unsigned read_retries = 0;
    const auto bad_clusters = source.bad_clusters();
    std::size_t bad_index = 0;
    std::uint64_t bad_split_end = 0;
    for (std::uint64_t offset = start_offset; offset < source.size();) {
        if (cancelled && cancelled()) throw Error("image transfer cancelled");
        bool changed = true;
        auto end = source.size();
        if (delta) {
            while (delta->ranges[range_index].offset + delta->ranges[range_index].length <= offset)
                ++range_index;
            const auto& range = delta->ranges[range_index];
            changed = range.changed;
            end = range.offset + range.length;
        }
        while (unused_index < unused.size() &&
               unused[unused_index].offset+unused[unused_index].length <= offset)
            ++unused_index;
        bool used = true;
        if (unused_index < unused.size()) {
            const auto& range = unused[unused_index];
            if (offset < range.offset) end = std::min(end,range.offset);
            else {
                used = false;
                if (!delta || !delta->filesystem_allocation) changed = true;
                end = std::min(end,range.offset+range.length);
            }
        }
        // the official agent raw interval workers have no CBT context, even in an incremental.
        bool cbt = delta != nullptr;
        if (delta) {
            while (reread_index < reread.size() &&
                   reread[reread_index].offset+reread[reread_index].length <= offset)
                ++reread_index;
            if (reread_index < reread.size()) {
                const auto& range = reread[reread_index];
                if (offset < range.offset) end = std::min(end,range.offset);
                else {
                    end = std::min(end,range.offset+range.length);
                    cbt = delta->filesystem_allocation ? false : !used;
                }
            }
        }
        const auto interval_end = source.read_interval_end(offset);
        end = std::min(end,interval_end);
        const auto query_size = delta && delta->filesystem_allocation && cbt ?
            std::min<std::size_t>(block_size,65536) : block_size;
        if (offset < bad_split_end) end = std::min(end,bad_split_end);
        auto length = static_cast<std::size_t>(
            std::min<std::uint64_t>(offset < fallback_end ? fallback_size : query_size,
                std::min(end,offset < fallback_end ? fallback_end : end) - offset));
        bool bad_block = false;
        if (used && changed) {
            while (bad_index < bad_clusters.size() &&
                   bad_clusters[bad_index].offset+bad_clusters[bad_index].length <= offset) ++bad_index;
            if (bad_index < bad_clusters.size()) {
                const auto& bad = bad_clusters[bad_index];
                const auto next = offset < bad.offset ? bad.offset : bad.offset+bad.length;
                bad_block = offset >= bad.offset;
                if (next < offset+length) {
                    bad_split_end = offset+length;
                    length = static_cast<std::size_t>(next-offset);
                }
            }
        }
        const auto report_bad = [&](const std::string& volume,std::uint64_t at) {
            if (!read_activity) return;
            const auto hex = [](std::uint64_t value) {
                std::ostringstream out; out << "0x" << std::hex << value; return out.str();
            };
            read_activity(7044,{{"volume_name",Value{volume}},
                {"interval_start",Value{hex(at)}},{"interval_end",Value{hex(at+length-1)}}});
        };
        if (bad_block) {
            const auto& bad = bad_clusters[bad_index];
            report_bad(bad.volume,bad.volume_offset+offset-bad.offset);
        }
        pstream::Bytes bytes;
        if (used && changed && !bad_block) {
            std::uint64_t elapsed = 0;
            try {
                bytes = source.read(offset, length,read_performance ? &elapsed : nullptr);
                read_retries = 0;
            } catch (const SourceReadError& error) {
                if (error.snapshot_error) throw;
                if (error.error == 5) {
                    if (length != error.sector_size) {
                        fallback_end = offset+length;
                        fallback_size = error.sector_size;
                        continue;
                    }
                    bad_block = true;
                    report_bad(error.volume,error.offset);
                } else {
                    if (read_retries == 30) throw;
                    // The source reader's constructor selects 1000 ms; its counter
                    // permits 30 sleeps and a final (31st) unsuccessful read.
                    const auto delay = std::chrono::milliseconds{1000};
                    if (retry_wait) retry_wait(delay);
                    else std::this_thread::sleep_for(delay);
                    ++read_retries;
                    continue;
                }
            }
            if (!bad_block) {
                if (bytes.empty()) {
                    // Source reads: EOF is one unchanged,
                    // used record for the whole remaining interval, even
                    // when later bitmap queries would have different flags.
                    length = static_cast<std::size_t>(interval_end-offset);
                    used = true;
                    changed = false;
                } else {
                    length = bytes.size();
                    if (read_performance) read_performance(elapsed,length);
                }
            }
        }
        if (used && changed && !bad_block && compression == TransferCompression::lz4) {
            const auto capacity = LZ4_compressBound(static_cast<int>(length));
            pstream::Bytes compressed(static_cast<std::size_t>(capacity));
            const auto count = LZ4_compress_default(reinterpret_cast<const char*>(bytes.data()),
                reinterpret_cast<char*>(compressed.data()), static_cast<int>(length), capacity);
            if (count <= 0) throw Error("LZ4 block compression failed");
            compressed.resize(static_cast<std::size_t>(count));
            bytes = std::move(compressed);
        }
        Value::Object block{
            {"image_name", Value{std::string(name)}}, {"offset", Value{offset}},
            {"length", Value{static_cast<std::uint64_t>(length)}},
            {"used", Value{std::uint64_t{used}}}, {"changed", Value{std::uint64_t{changed}}},
            {"is_interval_cbt", Value{std::uint64_t{cbt}}}};
        if (used && changed && !bad_block) block["buffer"] = Value{std::move(bytes)};
        else block["changed_length"] = Value{std::uint64_t{0}};
        if (used && changed && !bad_block && compression == TransferCompression::lz4) block["compressed"] = Value{std::uint64_t{1}};
        send(Value{std::move(block)});
        offset += length;
    }
    source.verify_unchanged();
}


}
