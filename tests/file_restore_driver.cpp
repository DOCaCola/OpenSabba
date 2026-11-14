#include "opensabba/file_restore_job.hpp"
#include <cstdio>
#include <cstring>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

// Test-only service entry point; accepts disposable loopback credentials only.
int main(int argc, char** argv) {
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif
    try {
        using namespace opensabba;
        if (argc != 5 && argc != 6) throw pstream::Error("invalid test arguments");
        Endpoint endpoint{"127.0.0.1", static_cast<std::uint16_t>(std::stoul(argv[1])), argv[2],
                          std::chrono::seconds{15}};
        const SavedAuth auth{"test-user", "test-device", "test-token", "test-nas"};
        const opensabba::TaskView task_view{
            [&](const opensabba::Endpoint& connection) { return opensabba::tasks(connection,auth); },
            [&](const opensabba::Endpoint& connection) { return opensabba::running_tasks(connection,auth); }};
        const auto read = [](const std::filesystem::path& path) {
            std::ifstream input(path, std::ios::binary);
            if (!input) throw pstream::Error("cannot open fixture state");
            return pstream::decode(pstream::Bytes{std::istreambuf_iterator<char>(input), {}});
        };
        const auto running = read(argv[3]);
        const std::filesystem::path journal_path(argv[4]);
        std::optional<pstream::Value> journal;
        // A fresh process must never restore its test observation as context.
        const auto save = [&](const pstream::Value& record) {
            journal = record;
            if (argc == 6 && std::string_view(argv[5]) == "--crash-before-finish" &&
                std::get<std::string>(std::get<pstream::Value::Object>(record.data).at("phase").data) == "finish")
                std::_Exit(77);
            const auto bytes = pstream::encode(record);
            const auto temporary = journal_path.string() + ".tmp";
            auto* file = std::fopen(temporary.c_str(), "wb");
            if (!file) throw pstream::Error("cannot create fixture journal");
            bool saved = std::fwrite(bytes.data(), 1, bytes.size(), file) == bytes.size();
            saved = std::fflush(file) == 0 && saved;
#ifdef _WIN32
            saved = _commit(_fileno(file)) == 0 && saved;
#else
            saved = fsync(fileno(file)) == 0 && saved;
#endif
            saved = std::fclose(file) == 0 && saved;
            if (!saved) throw pstream::Error("cannot persist fixture journal");
#ifdef _WIN32
            // The Linux service uses rename(2). Exercise the same replacement
            // semantics with readers of an older generation still open.
            const auto target = std::filesystem::absolute(journal_path).make_preferred().wstring();
            const auto size = offsetof(FILE_RENAME_INFO,FileName)+(target.size()+1)*sizeof(wchar_t);
            std::vector<unsigned char> storage(size);
            auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
            rename->Flags = FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
            rename->FileNameLength = static_cast<DWORD>(target.size()*sizeof(wchar_t));
            std::memcpy(rename->FileName,target.data(),rename->FileNameLength);
            const auto handle = CreateFileW(std::filesystem::path(temporary).c_str(),DELETE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,nullptr);
            if (handle == INVALID_HANDLE_VALUE) throw pstream::Error("cannot open fixture rename handle");
            const bool installed = SetFileInformationByHandle(handle,FileRenameInfoEx,rename,static_cast<DWORD>(size));
            const auto error = GetLastError();
            CloseHandle(handle);
            if (!installed) throw pstream::Error("cannot install fixture journal (Windows error " +
                                                 std::to_string(error) + ")");
#else
            std::filesystem::rename(temporary, journal_path);
            const auto descriptor = open(journal_path.parent_path().c_str(), O_RDONLY | O_DIRECTORY);
            const bool synced = descriptor >= 0 && fsync(descriptor) == 0;
            if (descriptor >= 0) close(descriptor);
            if (!synced) throw pstream::Error("cannot sync fixture journal directory");
#endif
        };
        if (argc == 6 && std::string_view(argv[5]) == "--resident") {
            std::string command;
            while (std::getline(std::cin,command) && command == "run") {
                try {
                    const auto outcome = run_service_file_restore(endpoint,auth,task_view,running,journal,save);
                    std::cout << "OK " << outcome << std::endl;
                } catch (const std::exception& error) {
                    std::cout << "ERROR " << error.what() << std::endl;
                }
            }
        } else {
            std::cout << run_service_file_restore(endpoint, auth,task_view,running, {}, save) << '\n';
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
