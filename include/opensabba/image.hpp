#pragma once
#include "opensabba/source_read.hpp"
#include "opensabba/bad_cluster.hpp"
#include "opensabba/pstream.hpp"
#include "opensabba/delta_plan.hpp"
#include <filesystem>
#include <memory>
#include <optional>

namespace opensabba {
enum class TransferCompression { none, lz4 };
// the official agent performance records contain elapsed system-clock nanoseconds and
// uncompressed logical byte counts. Only successful payload reads count.
using ReadPerformance = std::function<void(std::uint64_t nanoseconds, std::uint64_t bytes)>;
class ImageSource;
struct ImageExtent {
    std::uint64_t offset, length, source_offset;
    std::shared_ptr<ImageSource> source;
};
struct ImageBadCluster {
    std::uint64_t offset, length, volume_offset;
    std::string volume;
};
// Explicit sources: a regular offline disk image, or an owned snapshot volume
// wrapped in a deterministic nonbootable MBR disk. No arbitrary block devices.
class ImageSource {
public:
    using MetadataRead = std::function<pstream::Bytes(std::uint64_t,std::size_t)>;
    using PreparedStream = std::function<void(std::string_view, std::uint64_t,
        const std::function<void(const pstream::Value&)>&, const std::function<bool()>&)>;
    explicit ImageSource(const std::filesystem::path&);
    // Duplicate a pinned regular-file descriptor; ownership stays with caller.
    ImageSource(int descriptor, std::string source);
    // Own an immutable complete disk image (also usable by offline tooling).
    explicit ImageSource(pstream::Bytes image);
    // Exact contiguous coverage assembled from owned immutable/snapshot
    // sources. There is no fallback to the live disk for missing extents.
    ImageSource(std::uint64_t length, std::vector<ImageExtent> extents);
    // Machine intervals retain their snapshot/raw source and verify its ownership.
    ImageSource(std::uint64_t length,
        std::function<pstream::Bytes(std::uint64_t,std::size_t,std::uint64_t*)> read,
        std::function<void()> verify, MetadataRead metadata = {});
    ImageSource(std::uint64_t length, PreparedStream, std::function<void()> verify);
    bool stream_prepared(std::string_view name, std::uint64_t offset,
        const std::function<void(const pstream::Value&)>&, const std::function<bool()>&);
    bool direct_intervals() const;
    void set_bad_clusters(const BadClusterContext&, std::uint64_t image_offset = 0);
    std::vector<ImageBadCluster> bad_clusters() const;
    ~ImageSource();
    ImageSource(const ImageSource&) = delete;
    ImageSource& operator=(const ImageSource&) = delete;
    std::uint64_t size() const;
    // The source reader EOF fills the remainder of this source interval.
    std::uint64_t read_interval_end(std::uint64_t offset) const;
    pstream::Bytes read(std::uint64_t offset, std::size_t length,
                        std::uint64_t* read_nanoseconds = nullptr);
    // Layout and filesystem parsers use the buffered descriptor of snapshot
    // sources. Ordinary immutable/raw sources use their normal reader.
    pstream::Bytes read_metadata(std::uint64_t offset, std::size_t length);
    void verify_unchanged() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::optional<pstream::Bytes> memory_;
    std::vector<ImageExtent> extents_;
    std::uint64_t composite_length_ = 0;
    std::uint64_t interval_length_ = 0;
    std::function<pstream::Bytes(std::uint64_t,std::size_t,std::uint64_t*)> interval_read_;
    std::function<void()> interval_verify_;
    MetadataRead metadata_read_;
    PreparedStream prepared_stream_;
    std::vector<ImageBadCluster> bad_clusters_;
    pstream::Bytes read_from(bool, std::uint64_t, std::size_t, std::uint64_t*);
    pstream::Bytes read_composite(std::uint64_t, std::size_t, std::uint64_t*, bool metadata);
    void verify_composite() const;
};

using SendBlock = std::function<void(const pstream::Value&)>;
void validate_image_options(std::string_view image_name, std::size_t block_size);
// Complete logical image coverage. CBT unchanged ranges inherit a base image;
// unused ranges send no payload and are omitted from the restore used-interval
// table. Sealed unused ranges must be zero; owned snapshot ranges are verified
// against filesystem allocation. Allocation-aware CBT keeps both flags independent.
// Reread ranges are raw intervals without CBT context: during an incremental
// transfer they lie inside changed coverage and are sent with is_interval_cbt=0.
void stream_image(ImageSource&, std::string_view image_name, std::size_t block_size,
                  const SendBlock&, const std::function<bool()>& cancelled = {},
                  std::uint64_t start_offset = 0,
                  TransferCompression compression = TransferCompression::none,
                  const DeltaPlan* delta = nullptr,
                  std::span<const ChangedExtent> unused = {},
                  std::span<const ChangedExtent> reread = {},
                  const ReadPerformance& read_performance = {},
                  const SourceReadActivity& read_activity = {},
                  const SourceReadRetryWait& retry_wait = {});
void validate_unused_ranges(std::span<const ChangedExtent>, std::uint64_t image_size);
// Allocation and FIEMAP use filesystem-native units, which can be smaller
// than the driver's 4 KiB CBT units.
std::vector<ChangedExtent> union_unused_ranges(std::uint64_t image_size,
    std::vector<ChangedExtent>);
// Sorted, disjoint 4 KiB ranges, each inside one changed range of the delta.
void validate_reread_ranges(std::span<const ChangedExtent>, const DeltaPlan&);
void verify_unused_source(ImageSource&, std::span<const ChangedExtent>);
}
