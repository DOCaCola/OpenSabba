#include "opensabba/client.hpp"
#include "opensabba/backup_job.hpp"
#include "opensabba/service_backup.hpp"
#include <csignal>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <unistd.h>

// Test-only client. Real session credentials are never accepted.
int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);
    try {
        if (argc != 7) throw std::runtime_error("invalid test arguments");
        opensabba::Endpoint endpoint;
        endpoint.host = "127.0.0.1";
        endpoint.port = static_cast<std::uint16_t>(std::stoul(argv[1]));
        endpoint.ca_file = argv[2];
        endpoint.timeout = std::chrono::seconds{2};
        const std::string mode = argv[3];
        if (mode.starts_with("service-")) endpoint.timeout = std::chrono::seconds{15};
        const opensabba::SavedAuth auth{"test-user", "test-device", "test-token", "test-nas"};
        const opensabba::TaskView task_view{
            [&](const opensabba::Endpoint& connection) { return opensabba::tasks(connection,auth); },
            [&](const opensabba::Endpoint& connection) { return opensabba::running_tasks(connection,auth); }};
        std::ifstream input(argv[4], std::ios::binary);
        if (!input) throw std::runtime_error("cannot open test metadata");
        const std::string json{std::istreambuf_iterator<char>(input), {}};
        const opensabba::pstream::Bytes metadata(json.begin(), json.end());
        auto persist = [&](const opensabba::pstream::Value& record) {
            const auto& fields = std::get<opensabba::pstream::Value::Object>(record.data);
            const auto& stage = std::get<std::string>(fields.at("phase").data);
            if (mode == "persist-" + stage)
                throw std::runtime_error("simulated persistence failure");
            const std::string state_path = std::string(argv[6]) + ".pstream";
            const std::string temporary = state_path + ".tmp";
            const auto encoded = opensabba::pstream::encode(record);
            int state_fd = open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
            if (state_fd < 0) throw std::runtime_error("cannot open test state");
            const bool state_saved = write(state_fd, encoded.data(), encoded.size()) == static_cast<ssize_t>(encoded.size())
                                     && fsync(state_fd) == 0;
            close(state_fd);
            if (!state_saved || rename(temporary.c_str(), state_path.c_str()) != 0)
                throw std::runtime_error("cannot replace test state");
            const auto parent = std::filesystem::path(state_path).parent_path();
            int dir_fd = open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            const bool dir_saved = dir_fd >= 0 && fsync(dir_fd) == 0;
            if (dir_fd >= 0) close(dir_fd);
            if (!dir_saved) throw std::runtime_error("cannot persist test state");
            // Round-trip and identity checking are part of every persisted phase.
            const auto decoded = opensabba::pstream::decode(encoded);
            opensabba::backup_job_status(decoded, auth);
            auto foreign = auth;
            foreign.device_uuid = "other-device";
            bool rejected = false;
            try { opensabba::backup_job_status(decoded, foreign); }
            catch (const opensabba::pstream::Error&) { rejected = true; }
            if (!rejected) throw std::runtime_error("foreign backup journal accepted");
            int fd = open(argv[6], O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
            if (fd < 0) throw std::runtime_error("cannot open test journal");
            const std::string line = std::string(stage) + "\n";
            const bool saved = write(fd, line.data(), line.size()) == static_cast<ssize_t>(line.size())
                               && fsync(fd) == 0;
            close(fd);
            if (!saved) throw std::runtime_error("cannot save test journal");
            if (stage == "prepared" && mode == "mutate-after-prepare") {
                std::fstream modify(argv[5], std::ios::in | std::ios::out | std::ios::binary);
                modify.put('X');
                modify.flush();
            }
            if (stage == "prepared" && mode == "replace-after-prepare") {
                const auto size = std::filesystem::file_size(argv[5]);
                std::filesystem::rename(argv[5], std::string(argv[5]) + ".original");
                std::ofstream replacement(argv[5], std::ios::binary);
                replacement.seekp(static_cast<std::streamoff>(size - 1));
                replacement.put('\0');
                replacement.close();
            }
        };
        opensabba::ImageSource source(argv[5]);
        if (mode.starts_with("service-")) {
            std::optional<opensabba::pstream::Value> saved;
            if (mode == "service-restart") {
                std::ifstream file(std::string(argv[6]) + ".pstream", std::ios::binary);
                const opensabba::pstream::Bytes bytes{std::istreambuf_iterator<char>(file), {}};
                saved = opensabba::pstream::decode(bytes);
            }
            opensabba::run_service_backup(endpoint, auth,task_view,2, saved, persist,
                [&](const opensabba::Endpoint& transfer, const opensabba::SaveBackupJob& save) {
                    if (saved) opensabba::resume_image_job(transfer, auth, source, *saved, save);
                    else if (mode == "service-incremental") {
                        const opensabba::IncrementalBackup incremental{8, 13, 26, std::string(32, 'a'),
                            std::string(64, 'b'), {source.size(), source.size(), {{0, source.size(), true}}}};
                        opensabba::run_incremental_image_job(transfer, auth, 2, 27, source, "test-image",
                                                             metadata, incremental, save, opensabba::TransferCompression::none);
                    }
                    else opensabba::run_full_image_job(transfer, auth, 27, source, "test-image", metadata, save);
                });
            return 0;
        }
        const auto requested = mode == "cancel" ? opensabba::BackupOutcome::cancelled
                             : mode == "report-error" ? opensabba::BackupOutcome::error
                             : opensabba::BackupOutcome::complete;
        auto outcome = opensabba::run_full_image_job(endpoint, auth, 27, source, "test-image",
                                                     metadata, persist, requested);
        // Only a matching terminal result is success for this test invocation.
        if (outcome != requested) throw std::runtime_error("NAS returned a different terminal outcome");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
