#include "opensabba/backup_cache.hpp"
#include "opensabba/capture.hpp"
#include <lz4.h>
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <iostream>

namespace {
using namespace opensabba;
using pstream::Bytes;
using pstream::Error;
using pstream::Value;
constexpr std::uint64_t mib = 1024 * 1024;
constexpr std::uint64_t gib = mib * 1024;
constexpr std::uint64_t image_size = 6 * mib;
void check(bool okay, std::string_view detail) {
    if (!okay) throw Error("backup cache regression: " + std::string(detail));
}
template<class F> void rejects(F action, std::string_view message) {
    try { action(); }
    catch (const Error& error) {
        check(std::string_view(error.what()).find(message) != std::string_view::npos,
              std::string("expected '") + std::string(message) + "', got '" + error.what() + "'");
        return;
    }
    throw Error("backup cache operation unexpectedly accepted: " + std::string(message));
}
Value n(std::uint64_t value) { return Value{value}; }
Value s(std::string value) { return Value{std::move(value)}; }
const Value::Object& object(const Value& value) { return std::get<Value::Object>(value.data); }
std::uint64_t number(const Value& value, const char* key) {
    return std::get<std::uint64_t>(object(value).at(key).data);
}
std::string text(const Value& value, const char* key) {
    return std::get<std::string>(object(value).at(key).data);
}
struct Directory {
    std::filesystem::path path;
    Directory() {
        const auto seed = std::chrono::steady_clock::now().time_since_epoch().count();
        for (unsigned attempt = 0; attempt < 100; ++attempt) {
            path = std::filesystem::temp_directory_path() /
                ("opensabba-cache-test-" + std::to_string(seed) + "-" + std::to_string(attempt));
            if (std::filesystem::create_directory(path)) return;
        }
        throw Error("cannot allocate cache test directory");
    }
    ~Directory() { std::error_code ignored; std::filesystem::remove_all(path, ignored); }
};
Bytes read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw Error("cannot read cache test fixture");
    return Bytes(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}
void write_file(const std::filesystem::path& path, const Bytes& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!output) throw Error("cannot write cache test fixture");
}
std::string md5(const Bytes& bytes) {
    std::array<unsigned char, 16> digest{};
    std::size_t size = digest.size();
    check(EVP_Q_digest(nullptr, "MD5", nullptr, bytes.data(), bytes.size(), digest.data(), &size) == 1 &&
          size == digest.size(), "fixture MD5");
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (const auto byte : digest) { result += hex[byte >> 4]; result += hex[byte & 15]; }
    return result;
}
std::uint64_t little(const Bytes& bytes, std::size_t offset) {
    std::uint64_t value = 0;
    for (unsigned byte = 0; byte < 8; ++byte)
        value |= std::uint64_t{bytes.at(offset + byte)} << (8 * byte);
    return value;
}
void put(Bytes& bytes, std::size_t offset, std::uint64_t value) {
    for (unsigned byte = 0; byte < 8; ++byte)
        bytes.at(offset + byte) = static_cast<std::uint8_t>(value >> (8 * byte));
}
std::uint8_t payload_byte(std::uint64_t at) {
    return static_cast<std::uint8_t>((at / 4096) % 251 + 1);
}
struct Fixture {
    std::uint64_t read_bytes = 0, reads = 0;
    ImageSource source;
    IncrementalBackup incremental;
    BackupImage image;
    Fixture() : source(image_size, [this](std::uint64_t at, std::size_t length, auto) {
        check((at < mib && length <= mib - at) ||
              (at >= 4 * mib && length <= image_size - at), "source read unused or inherited payload");
        read_bytes += length;
        ++reads;
        Bytes bytes(length);
        for (std::size_t i = 0; i < length; ++i) bytes[i] = payload_byte(at + i);
        return bytes;
    }, [] {}),
        incremental{19, 20, 21, std::string(32, 'a'), std::string(64, 'b'),
            DeltaPlan{image_size, 4 * mib, {
                {0, mib, true}, {mib, mib, false}, {2 * mib, mib, true},
                {3 * mib, mib, false}, {4 * mib, 2 * mib, true}}, true}},
        image{&source, "disk.img", {{mib, 2 * mib}}, {{4 * mib, 4096}}} {}
};
void policy_tests() {
    const auto empty = backup_cache_policy(Value{Value::Object{}});
    check(!empty.enabled && !empty.paused && empty.volume_uuid.empty() &&
          empty.mount_path.empty() && !empty.floor_unit && !empty.floor_value, "default cache policy");
    // Disabled NAS policies clear stale settings, including malformed values.
    const auto disabled = backup_cache_policy(Value{Value::Object{
        {"cached_enabled", n(0)}, {"is_paused", n(9)},
        {"cached_volume_name", n(44)}, {"cached_mount_path", n(8)},
        {"cached_volume_space_lower_bound_unit", n(9)},
        {"cached_volume_space_lower_bound_value", n(UINT64_MAX)}}});
    check(!disabled.enabled && !disabled.paused && disabled.volume_uuid.empty() &&
          disabled.mount_path.empty() && !disabled.floor_unit && !disabled.floor_value,
          "disabled policy clears settings");
    Value enabled{Value::Object{{"cached_enabled", n(1)}, {"is_paused", n(1)},
        {"cached_volume_name", s("volume-uuid")}, {"cached_mount_path", s("/cache")},
        {"cached_volume_space_lower_bound_unit", n(0)},
        {"cached_volume_space_lower_bound_value", n(25)}}};
    const auto policy = backup_cache_policy(enabled);
    auto template_task = enabled;
    std::get<Value::Object>(template_task.data)["cached_volume_name"] = s("{DataVolume}");
    const Value::Array volumes{
        Value{Value::Object{{"is_system_drive",n(1)},{"free_size",n(900)},
            {"path",s("/")},{"volume_name",s("root-uuid")}}},
        Value{Value::Object{{"is_system_drive",n(0)},{"free_size",n(40)},
            {"path",s("/small")},{"volume_name",s("small-uuid")}}},
        Value{Value::Object{{"is_system_drive",n(0)},{"free_size",n(80)},
            {"path",s("/large")},{"volume_name",s("large-uuid")}}}};
    check(backup_cache_policy(translate_backup_cache_task(template_task,volumes)).volume_uuid == "large-uuid",
        "data template chooses the largest free mounted data volume");
    std::get<Value::Object>(template_task.data)["cached_volume_name"] = s("{SystemVolume}");
    check(backup_cache_policy(translate_backup_cache_task(template_task,volumes)).volume_uuid == "root-uuid",
        "system template uses the system volume");
    check(!backup_cache_policy(translate_backup_cache_task(template_task,{})).enabled,
        "missing template candidate disables cache policy");
    check(policy.enabled && policy.paused && policy.volume_uuid == "volume-uuid" &&
          policy.mount_path == "/cache" && policy.floor_unit == 0 && policy.floor_value == 25,
          "enabled cache policy");
    for (const auto& [key, value] : Value::Object{
        {"cached_enabled", n(2)}, {"is_paused", n(2)}, {"cached_volume_name", s("")},
        {"cached_mount_path", n(2)}, {"cached_volume_space_lower_bound_unit", n(2)},
        {"cached_volume_space_lower_bound_value", n(101)}}) {
        auto bad = enabled;
        std::get<Value::Object>(bad.data)[key] = value;
        rejects([&] { (void)backup_cache_policy(bad); }, "invalid");
    }
    auto bad = enabled;
    std::get<Value::Object>(bad.data).erase("cached_volume_name");
    rejects([&] { (void)backup_cache_policy(bad); }, "missing");
    BackupCachePolicy floor;
    floor.floor_value = 25;
    check(!backup_cache_space_enough(floor, 1000, 250) &&
          backup_cache_space_enough(floor, 1000, 251), "percent floor is strictly greater");
    floor.floor_value = 1;
    check(!backup_cache_space_enough(floor, 199, 1) &&
          backup_cache_space_enough(floor, 199, 2), "percent floor truncates");
    floor.floor_value = 99;
    const auto max_floor = UINT64_MAX - (UINT64_MAX / 100 + 1);
    check(!backup_cache_space_enough(floor, UINT64_MAX, max_floor) &&
          backup_cache_space_enough(floor, UINT64_MAX, max_floor + 1), "percent multiplication does not overflow");
    floor.floor_value = 100;
    check(!backup_cache_space_enough(floor, UINT64_MAX, UINT64_MAX), "100 percent never admitted");
    floor.floor_value = 0;
    check(!backup_cache_space_enough(floor, 0, 0) &&
          backup_cache_space_enough(floor, 1, 1), "zero floor still requires free bytes");
    floor.floor_unit = 1; floor.floor_value = 2;
    check(!backup_cache_space_enough(floor, 3 * gib, 2 * gib) &&
          backup_cache_space_enough(floor, 3 * gib, 2 * gib + 1), "GiB floor is strictly greater");
    floor.floor_value = UINT64_MAX / gib;
    check(!backup_cache_space_enough(floor, UINT64_MAX, floor.floor_value * gib) &&
          backup_cache_space_enough(floor, UINT64_MAX, floor.floor_value * gib + 1), "largest representable GiB floor");
    ++floor.floor_value;
    check(!backup_cache_space_enough(floor, UINT64_MAX, UINT64_MAX), "GiB floor overflow rejects admission");
    rejects([&] { (void)backup_cache_space_enough(floor, 1, 2); }, "measurement");
    floor.floor_unit = 2;
    rejects([&] { (void)backup_cache_space_enough(floor, 1, 1); }, "floor");
    floor.floor_unit = 0; floor.floor_value = 101;
    rejects([&] { (void)backup_cache_space_enough(floor, 1, 1); }, "floor");
}
void replay_tests(const std::filesystem::path& directory, TransferCompression compression) {
    Fixture fixture;
    const std::string name = compression == TransferCompression::lz4 ? "compressed" : "raw";
    const auto manifest = write_backup_cache_image(directory, name, fixture.image, fixture.incremental, compression);
    check(fixture.read_bytes == 3 * mib && fixture.reads > 0, "capture reads only used changed ranges");
    const auto captured_reads = fixture.read_bytes;
    check(number(manifest, "size") == image_size && number(manifest, "format") == 1, "manifest geometry");
    const auto header = read_file(directory / text(manifest, "header"));
    const auto data = read_file(directory / text(manifest, "data"));
    check(header.size() == 40 * number(manifest, "records") &&
          md5(header) == text(manifest, "header_md5") &&
          md5(data) == text(manifest, "data_md5"), "manifest binds immutable file pair");
    if (compression == TransferCompression::lz4) check(data.size() < 3 * mib, "compressed file payload");
    else check(data.size() == 3 * mib, "raw file payload");
    std::vector<Value> records;
    {
        CachedBackupImage cached(directory, manifest);
        check(cached.source().size() == image_size, "replay source size");
        // Caller upload block size and compression cannot split or re-encode
        // the immutable records already selected during offline capture.
        stream_image(cached.source(), "disk.img", 4096,
            [&](const Value& block) { records.push_back(block); }, {}, 0,
            compression == TransferCompression::lz4 ? TransferCompression::none : TransferCompression::lz4);
        check(records.size() == number(manifest, "records"), "replay record count");
        std::uint64_t position = 0, payload = 0;
        std::array<std::uint64_t, 5> classes{};
        for (std::size_t i = 0; i < records.size(); ++i) {
            const auto& block = records[i];
            const auto offset = number(block, "offset"), length = number(block, "length");
            check(offset == position && length && offset + length <= image_size, "replay contiguous coverage");
            const bool used = offset < mib || offset >= 3 * mib;
            const bool changed = offset < mib || (offset >= 2 * mib && offset < 3 * mib) || offset >= 4 * mib;
            const bool cbt = offset < 4 * mib || offset >= 4 * mib + 4096;
            check(number(block, "used") == used && number(block, "changed") == changed &&
                  number(block, "is_interval_cbt") == cbt, "allocation/changed/CBT flags remain independent");
            const auto flags = std::uint64_t{used} | (std::uint64_t{changed} << 1) |
                (std::uint64_t{used && changed && compression == TransferCompression::lz4} << 2) |
                (std::uint64_t{cbt} << 3);
            check(little(header, i * 40) == offset && little(header, i * 40 + 8) == length &&
                  little(header, i * 40 + 16) == payload && little(header, i * 40 + 32) == flags,
                  "portable 40-byte little-endian record");
            if (used && changed) {
                const auto& bytes = std::get<Bytes>(object(block).at("buffer").data);
                check(little(header, i * 40 + 24) == bytes.size() &&
                      std::equal(bytes.begin(), bytes.end(), data.begin() + static_cast<std::ptrdiff_t>(payload)),
                      "replay retains exact cached bytes");
                Bytes decoded(static_cast<std::size_t>(length));
                if (compression == TransferCompression::lz4) {
                    check(number(block, "compressed") == 1 &&
                        LZ4_decompress_safe(reinterpret_cast<const char*>(bytes.data()),
                            reinterpret_cast<char*>(decoded.data()), static_cast<int>(bytes.size()),
                            static_cast<int>(length)) == static_cast<int>(length), "LZ4 replay is decodable");
                } else {
                    check(!object(block).contains("compressed") && bytes.size() == length, "raw replay encoding");
                    decoded = bytes;
                }
                for (std::size_t byte = 0; byte < decoded.size(); ++byte)
                    check(decoded[byte] == payload_byte(offset + byte), "replayed payload matches capture");
                payload += bytes.size();
                classes[cbt ? 0 : 4] += length;
            } else {
                check(!object(block).contains("buffer") && !object(block).contains("compressed") &&
                      number(block, "changed_length") == 0 && little(header, i * 40 + 24) == 0,
                      "unused and inherited records have no payload");
                classes[used ? 3 : changed ? 2 : 1] += length;
            }
            position += length;
        }
        check(position == image_size && payload == data.size() &&
              classes == std::array<std::uint64_t, 5>{3 * mib - 4096, mib, mib, mib, 4096},
              "all independent interval classes covered");
        const auto checkpoint = number(records.at(3), "offset");
        std::size_t resumed = 3;
        stream_image(cached.source(), "disk.img", 512, [&](const Value& block) {
            check(block == records.at(resumed++), "exact checkpoint replays original suffix");
        }, {}, checkpoint);
        check(resumed == records.size(), "checkpoint completes suffix");
        bool sent = false;
        stream_image(cached.source(), "disk.img", 512, [&](const Value&) { sent = true; }, {}, image_size);
        check(!sent, "completed image checkpoint sends nothing");
        rejects([&] { stream_image(cached.source(), "disk.img", 512, [](const Value&) {}, {}, 512); }, "exact cached record boundary");
        rejects([&] { stream_image(cached.source(), "other.img", 512, [](const Value&) {}); }, "name differs");
        bool cancelled = false;
        try { stream_image(cached.source(), "disk.img", 512, [](const Value&) {}, [] { return true; }); }
        catch (const Cancelled&) { cancelled = true; }
        check(cancelled, "replay cancellation propagates");
    }
    check(fixture.read_bytes == captured_reads, "replay never rereads captured source");
    const auto unrelated = directory / (name + ".unrelated");
    write_file(unrelated, Bytes{1, 2, 3});
    remove_backup_cache_image(directory, manifest);
    remove_backup_cache_image(directory, manifest);
    check(!std::filesystem::exists(directory / text(manifest, "header")) &&
          !std::filesystem::exists(directory / text(manifest, "data")) &&
          read_file(unrelated) == Bytes({1, 2, 3}), "cleanup removes exact manifest files only");
}
void corruption_tests(const std::filesystem::path& directory) {
    Fixture fixture;
    const auto manifest = write_backup_cache_image(directory, "integrity", fixture.image,
        fixture.incremental, TransferCompression::none);
    const auto header_path = directory / text(manifest, "header");
    const auto data_path = directory / text(manifest, "data");
    const auto original_header = read_file(header_path), original_data = read_file(data_path);
    for (const bool header : {false, true}) {
        auto bytes = header ? original_header : original_data;
        bytes[0] ^= 0x80;
        const auto path = header ? header_path : data_path;
        write_file(path, bytes);
        rejects([&] { CachedBackupImage cached(directory, manifest); }, "integrity");
        // Corruption must not authorize deletion using stale manifest identity.
        if (header) rejects([&] { remove_backup_cache_image(directory, manifest); }, "refusing to delete changed");
        write_file(path, header ? original_header : original_data);
    }
    // Even a matching digest cannot authorize malformed interval metadata.
    for (const auto& [at, value] : std::array<std::pair<std::size_t, std::uint64_t>, 6>{
        std::pair<std::size_t, std::uint64_t>{0, 512}, {8, 0}, {8, 513},
        {16, 1}, {24, image_size}, {32, 16}}) {
        auto bytes = original_header;
        put(bytes, at, value);
        write_file(header_path, bytes);
        auto updated = manifest;
        std::get<Value::Object>(updated.data)["header_md5"] = s(md5(bytes));
        rejects([&] { CachedBackupImage cached(directory, updated); }, "record coverage");
    }
    write_file(header_path, original_header);
    auto truncated = original_data;
    truncated.pop_back();
    write_file(data_path, truncated);
    auto updated = manifest;
    std::get<Value::Object>(updated.data)["data_md5"] = s(md5(truncated));
    rejects([&] { CachedBackupImage cached(directory, updated); }, "record coverage");
    truncated = original_data;
    truncated.push_back(0);
    write_file(data_path, truncated);
    std::get<Value::Object>(updated.data)["data_md5"] = s(md5(truncated));
    rejects([&] { CachedBackupImage cached(directory, updated); }, "incomplete");
    write_file(data_path, original_data);
    auto unsafe = manifest;
    std::get<Value::Object>(unsafe.data)["header"] = s("../outside.header");
    rejects([&] { CachedBackupImage cached(directory, unsafe); }, "filename");
    remove_backup_cache_image(directory, manifest);
}
void failure_tests(const std::filesystem::path& directory) {
    Fixture fixture;
    const auto absent = [&](std::string_view name) {
        check(!std::filesystem::exists(directory / (std::string(name) + ".header")) &&
              !std::filesystem::exists(directory / (std::string(name) + ".data")), "failed attempt cleaned both files");
    };
    rejects([&] { (void)write_backup_cache_image(directory, "cancelled", fixture.image,
        fixture.incremental, TransferCompression::none, [&] { return fixture.read_bytes >= 65536; }); }, "cancelled");
    check(fixture.read_bytes == 65536, "cancellation occurred after a partial payload write");
    absent("cancelled");
    std::uint64_t reads = 0;
    ImageSource failure(image_size, [&](auto, auto length, auto) {
        if (reads++) throw Error("injected source read failure");
        return Bytes(length, 0x42);
    }, [] {});
    const BackupImage image{&failure, "disk.img", {}, {}};
    rejects([&] { (void)write_backup_cache_image(directory, "read-failure", image,
        fixture.incremental, TransferCompression::none); }, "injected source read failure");
    check(reads == 2, "source failure occurred after one successful record");
    absent("read-failure");
    // When the second create fails, cleanup owns only the newly created header.
    const auto occupied = directory / "occupied.data";
    const Bytes sentinel{0x55, 0x66};
    write_file(occupied, sentinel);
    rejects([&] { (void)write_backup_cache_image(directory, "occupied", fixture.image,
        fixture.incremental, TransferCompression::none); }, "cannot create");
    check(!std::filesystem::exists(directory / "occupied.header") &&
          read_file(occupied) == sentinel, "failed create preserves pre-existing pair member");
    rejects([&] { (void)write_backup_cache_image(directory, "../escape", fixture.image,
        fixture.incremental, TransferCompression::none); }, "filename");
    const auto attempt = write_backup_cache_image(directory, "abandoned", fixture.image,
        fixture.incremental, TransferCompression::lz4);
    const auto neighbor = directory / "abandoned-neighbor.data";
    write_file(neighbor, sentinel);
    remove_backup_cache_attempt(directory, "abandoned");
    remove_backup_cache_attempt(directory, "abandoned");
    absent("abandoned");
    check(std::filesystem::exists(neighbor) && number(attempt, "records") > 0, "attempt cleanup uses exact names");
}
void event_and_partial_tests() {
    Value task{Value::Object{{"id",n(2)},{"task_uuid",s("task-fixture")},
        {"cached_enabled",n(1)},{"cached_volume_name",s("volume-fixture")},
        {"cached_mount_path",s("/display-only")},{"cached_volume_space_lower_bound_unit",n(0)},
        {"cached_volume_space_lower_bound_value",n(10)},{"is_paused",n(1)}}};
    const Value config{Value::Object{{"task_id",n(2)},{"ds_id",s("nas-fixture")}}};
    Value policy{Value::Object{{"task_owner",config},{"task",task},{"assigned",n(1)}}};
    Value request{Value::Object{{"task_id",n(2)},{"task_uuid",s("task-fixture")},
        {"event_type",s("cache_write")}}};
    const auto event = backup_cache_write_event(request,config,policy,"event-fixture",1234);
    check(object(event).at("task_owner") == config && text(event,"event_id") == "event-fixture" &&
        number(event,"trigger_type") == 2 && number(event,"due") == 1234,
        "manual cache event preserves owner and official trigger despite replay pause");
    check(pstream::decode(pstream::encode(event)) == event,"queued cache event survives journal serialization");
    auto wrong = request;
    std::get<Value::Object>(wrong.data)["task_uuid"] = s("another-task");
    rejects([&] { (void)backup_cache_write_event(wrong,config,policy,"event",1234); },"another assigned");
    wrong = config;
    std::get<Value::Object>(wrong.data)["ds_id"] = s("another-nas");
    rejects([&] { (void)backup_cache_write_event(request,wrong,policy,"event",1234); },"another assigned");
    std::get<Value::Object>(policy.data)["assigned"] = n(0);
    rejects([&] { (void)backup_cache_write_event(request,config,policy,"event",1234); },"another assigned");
    std::get<Value::Object>(policy.data)["assigned"] = n(1);
    std::get<Value::Object>(task.data)["cached_enabled"] = n(0);
    std::get<Value::Object>(policy.data)["task"] = task;
    rejects([&] { (void)backup_cache_write_event(request,config,policy,"event",1234); },"disabled");
    std::get<Value::Object>(task.data)["cached_enabled"] = n(1);
    std::get<Value::Object>(policy.data)["task"] = task;
    std::get<Value::Object>(request.data)["event_type"] = s("invented-event");
    rejects([&] { (void)backup_cache_write_event(request,config,policy,"event",1234); },"unsupported");
    CaptureJournal capture;
    capture.snapshot = Value{Value::Object{}};
    capture.reservation = Value{Value::Object{{"extras",Value{Value::Array{}}}}};
    check(!backup_cache_capture_partial(capture),"complete cache is eligible as a clean base");
    const Value omitted{Value::Object{{"acquisition_error",n(5)}}};
    std::get<Value::Object>(capture.reservation.data)["extras"] =
        Value{Value::Array{Value{Value::Object{{"snapshot",omitted}}}}};
    check(backup_cache_capture_partial(capture),"extra acquisition omission publishes partial cache");
    capture.snapshot = omitted;
    std::get<Value::Object>(capture.reservation.data)["extras"] = Value{Value::Array{}};
    check(backup_cache_capture_partial(capture),"root acquisition omission publishes partial cache");
    capture.snapshot = Value{Value::Object{{"acquisition_error",n(0)}}};
    rejects([&] { (void)backup_cache_capture_partial(capture); },"invalid omitted");
}
void base_eligibility_tests(const std::filesystem::path& parent) {
    const auto volume = [&](std::string mount, std::uint64_t offset) {
        return Value{Value::Object{{"partition",n(1)},{"offset",n(offset)},{"length",n(4*mib)},
            {"mount_path",s(std::move(mount))},{"filesystem",s("ext4")},{"filesystem_uuid",s("volume")}}};
    };
    Value target{Value::Object{{"layout",Value{Value::Object{{"length",n(16*mib)},{"disk_id",s("disk")}}}},
        {"boot",volume("/boot",mib)},{"root",volume("/",6*mib)},{"cow_directory",s(parent.string())}}};
    CaptureJournal capture;
    capture.id = std::string(32,'a');
    capture.phase = CapturePhase::ready;
    capture.snapshot = Value{Value::Object{}};
    const auto directory = parent/("capture-"+capture.id);
    std::filesystem::create_directory(directory);
    capture.plan = target;
    std::get<Value::Object>(capture.plan.data)["cow_directory"] = s(directory.string());
    capture.reservation = Value{Value::Object{{"directory",s(directory.string())},{"extras",Value{Value::Array{}}}}};
    check(backup_cache_base_eligible(capture,target),"clean configured retained cache base accepted");
    auto other = target;
    std::get<Value::Object>(std::get<Value::Object>(other.data).at("layout").data)["disk_id"] = s("old-target");
    check(!backup_cache_base_eligible(capture,other),"old target archive is ineligible");
    other = target;
    std::get<Value::Object>(other.data)["cow_directory"] = s((parent/"other-storage").string());
    check(!backup_cache_base_eligible(capture,other),"archive from another independent storage is ineligible");
    other = target;
    std::get<Value::Object>(other.data)["cow_filesystem_uuid"] = s("replacement-storage");
    check(!backup_cache_base_eligible(capture,other),"storage UUID changes cannot adopt old archives");
    capture.snapshot = Value{Value::Object{{"acquisition_error",n(28)}}};
    check(!backup_cache_base_eligible(capture,target),"partial captures cannot be local cache bases");
    capture.snapshot = Value{Value::Object{}};
    const auto marker = directory/"retention.pstream";
    const auto save_marker = [&](std::string id, std::string state) {
        write_file(marker,pstream::encode(Value{Value::Object{{"format",n(1)},{"capture_id",s(std::move(id))},
            {"state",s(std::move(state))}}}));
        std::filesystem::permissions(marker,std::filesystem::perms::owner_read|std::filesystem::perms::owner_write);
    };
    save_marker(capture.id,"delete-pending");
    check(!backup_cache_base_eligible(capture,target),"pending pruning excludes an archived base");
    save_marker(capture.id,"deleted");
    check(!backup_cache_base_eligible(capture,target),"pruned archived base cannot be selected");
    save_marker(std::string(32,'b'),"deleted");
    rejects([&] { (void)backup_cache_base_eligible(capture,target); },"retention marker differs");
    std::filesystem::remove_all(directory);
    check(!backup_cache_base_eligible(capture,target),"missing archive capture directory is ineligible");
}
}
int main() {
    try {
        Directory directory;
        policy_tests();
        event_and_partial_tests();
        base_eligibility_tests(directory.path);
        replay_tests(directory.path, TransferCompression::none);
        replay_tests(directory.path, TransferCompression::lz4);
        corruption_tests(directory.path);
        failure_tests(directory.path);
        std::cout << "backup cache tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
