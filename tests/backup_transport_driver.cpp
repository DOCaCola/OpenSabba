#include "opensabba/backup_job.hpp"
#include <array>
#include <csignal>
#include <iostream>
using namespace opensabba;
using pstream::Value;
int main(int argc, char** argv) {
#ifdef SIGPIPE
    std::signal(SIGPIPE,SIG_IGN);
#endif
    try {
        if (argc != 4) throw pstream::Error("invalid transport fixture arguments");
        Endpoint endpoint{"127.0.0.1",static_cast<std::uint16_t>(std::stoul(argv[1])),argv[2]};
        const std::string mode(argv[3]);
        endpoint.backup_encryption = mode.find("plain") == mode.npos;
        endpoint.cached_backup = mode.starts_with("cache");
        const bool multi = mode.starts_with("multi"), resume = mode.find("resume") != mode.npos;
        const SavedAuth auth{"test-user","test-device","test-token","test-nas"};
        ImageSource first(pstream::Bytes(16384,0xa5)), second(pstream::Bytes(16384,0x5a));
        const std::array<BackupImage,2> images{{{&first,"disk-0"},{&second,"disk-1"}}};
        const pstream::Bytes metadata{'{','}'};
        Value saved;
        bool interrupted = false;
        const auto save = [&](const Value& record) {
            saved = pstream::decode(pstream::encode(record));
            auto& fields = std::get<Value::Object>(saved.data);
            fields["task_id"] = Value{std::uint64_t{2}};
            if (resume && !interrupted && std::get<std::string>(fields.at("phase").data) == "upload") {
                interrupted = true;
                throw pstream::Error("fixture upload interruption");
            }
        };
        try {
            if (multi) run_full_images_job(endpoint,auth,27,images,metadata,save,TransferCompression::none);
            else run_full_image_job(endpoint,auth,27,first,"disk-0",metadata,save);
        } catch (const pstream::Error&) {
            if (!interrupted) throw;
        }
        if (resume) {
            if (!interrupted) throw pstream::Error("fixture did not reach upload intent");
            if (multi) resume_images_job(endpoint,auth,images,saved,save);
            else resume_image_job(endpoint,auth,first,saved,save);
        }
        if (std::get<std::string>(std::get<Value::Object>(saved.data).at("phase").data) != "complete")
            throw pstream::Error("transport fixture did not complete");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
