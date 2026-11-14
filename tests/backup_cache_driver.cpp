#include "opensabba/backup_cache.hpp"
#include <algorithm>
#include <csignal>
#include <fstream>
#include <iostream>

// Loopback-only client. All identities, sources and NAS credentials are fixtures.
int main(int argc, char** argv) {
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif
    using namespace opensabba;
    using pstream::Value;
    try {
        if (argc != 5) throw pstream::Error("invalid cache driver arguments");
        Endpoint endpoint;
        endpoint.host = "127.0.0.1";
        endpoint.port = static_cast<std::uint16_t>(std::stoul(argv[1]));
        endpoint.ca_file = argv[2];
        endpoint.timeout = std::chrono::seconds{3};
        endpoint.cached_backup = true;
        endpoint.backup_trigger_type = 0;
        const std::string mode = argv[3];
        const bool multi = mode.starts_with("multi-");
        const bool restart = mode.ends_with("-resume");
        const bool partial = mode.find("-partial") != std::string::npos;
        const auto expected_outcome = partial ? BackupOutcome::partial : BackupOutcome::complete;
        const auto compression = mode.find("-lz4") != std::string::npos ?
            TransferCompression::lz4 : TransferCompression::none;
        const auto count = multi ? std::size_t{2} : std::size_t{1};
        const std::filesystem::path directory = argv[4];
        const SavedAuth auth{"test-user", "test-device", "test-token", "test-nas"};
        constexpr std::uint64_t mib = 1024 * 1024, size = 5 * mib, checkpoint = 65536;
        const std::vector<ChangedExtent> unused{{mib, 2 * mib}}, reread{{4 * mib, 4096}};
        const pstream::Bytes metadata{'{', '}'};
        std::vector<Value> manifests;
        std::vector<IncrementalBackup> incremental;
        for (std::size_t i = 0; i < count; ++i) {
            pstream::Bytes bytes(static_cast<std::size_t>(size), i ? 0x5a : 0xa5);
            std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(mib),
                      bytes.begin() + static_cast<std::ptrdiff_t>(3 * mib), 0);
            ImageSource source(std::move(bytes));
            incremental.push_back({8, 13, 26, std::string(32, 'a'), std::string(64, 'b'),
                DeltaPlan{size, 2 * mib, {{0, mib, true}, {mib, 3 * mib, false},
                    {4 * mib, mib, true}}, true}});
            const BackupImage image{&source, "disk-" + std::to_string(i), unused, reread};
            manifests.push_back(write_backup_cache_image(directory, "cache-" + std::to_string(i),
                image, incremental.back(), compression));
        } // Original memory sources are destroyed before any network operation.
        std::vector<std::unique_ptr<CachedBackupImage>> readers;
        std::vector<BackupImage> images;
        const auto reopen = [&] {
            images.clear();
            readers.clear();
            for (std::size_t i = 0; i < count; ++i) {
                readers.push_back(std::make_unique<CachedBackupImage>(directory, manifests[i]));
                images.push_back({&readers.back()->source(), "disk-" + std::to_string(i), unused, reread});
            }
        };
        reopen();
        Value saved;
        const auto persist = [&](const Value& record) {
            saved = pstream::decode(pstream::encode(record));
            // The service binds its assigned task identity to each durable phase.
            std::get<Value::Object>(saved.data)["task_id"] = Value{std::uint64_t{2}};
            (void)backup_job_status(saved, auth);
            const auto encoded = pstream::encode(saved);
            std::ofstream journal(directory / "job.pstream", std::ios::binary | std::ios::trunc);
            journal.write(reinterpret_cast<const char*>(encoded.data()),
                          static_cast<std::streamsize>(encoded.size()));
            if (!journal) throw pstream::Error("cannot save cache fixture journal");
        };
        bool interrupted = false;
        try {
            if (create_cached_images_job(endpoint, auth, 2, images, incremental, metadata,
                persist, compression, expected_outcome) != expected_outcome)
                throw pstream::Error("cached backup did not complete");
        } catch (const TransportError&) {
            if (!restart) throw;
            interrupted = true;
        }
        if (restart) {
            if (!interrupted ||
                std::get<std::string>(std::get<Value::Object>(saved.data).at("phase").data) != "upload")
                throw pstream::Error("interrupted cache upload lost its journal");
            reopen(); // No open readers survive transport interruption.
            {
                std::ifstream journal(directory / "job.pstream", std::ios::binary);
                const pstream::Bytes bytes{std::istreambuf_iterator<char>(journal), {}};
                saved = pstream::decode(bytes);
            }
            const auto outcome = multi ? resume_images_job(endpoint, auth, images, saved, persist) :
                resume_image_job(endpoint, auth, *images.front().source, saved, persist, unused, reread);
            if (outcome != expected_outcome)
                throw pstream::Error("reopened cache resume did not complete");
            const auto& fields = std::get<Value::Object>(saved.data);
            if (multi) {
                const auto& entries = std::get<Value::Array>(fields.at("images").data);
                if (std::get<std::uint64_t>(std::get<Value::Object>(entries[0].data).at("resume_offset").data) != size ||
                    std::get<std::uint64_t>(std::get<Value::Object>(entries[1].data).at("resume_offset").data) != checkpoint)
                    throw pstream::Error("multi-cache resume used different NAS checkpoints");
            } else if (std::get<std::uint64_t>(fields.at("resume_offset").data) != checkpoint)
                throw pstream::Error("single-cache resume used a different NAS checkpoint");
        }
        const auto& final = std::get<Value::Object>(saved.data);
        if (std::get<std::string>(final.at("phase").data) != (partial ? "partial" : "complete") ||
            std::get<std::string>(final.at("requested_outcome").data) != (partial ? "partial" : "complete") ||
            std::get<std::uint64_t>(final.at("is_cache").data) != 1)
            throw pstream::Error("cached completion lost its durable policy");
        images.clear();
        readers.clear();
        for (const auto& manifest : manifests) remove_backup_cache_image(directory, manifest);
        std::cout << "cached " << mode << " complete\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
