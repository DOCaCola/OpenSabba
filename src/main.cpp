#include "opensabba/pstream.hpp"
#include "opensabba/client.hpp"
#include "opensabba/session.hpp"
#include "opensabba/service_process.hpp"
#include "opensabba/snapshot_driver.hpp"
#include "opensabba/cli.hpp"
#include "opensabba/historical_logs.hpp"

#include <charconv>
#include <csignal>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <string_view>

using namespace opensabba::pstream;
int main(int argc, char** argv) {
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN); // Report peer disconnects as transport errors.
#endif
    std::string failed_command;
    bool official_command = false;
    try {
        // Initramfs has no saved session or home directory. Reload must run
        // before CLI/history initialization and before writable origin mounts.
        if (argc == 6 && std::string_view(argv[1]) == "snapshot" &&
            (std::string_view(argv[2]) == "reload-snapshot" ||
             std::string_view(argv[2]) == "reload-incremental")) {
            std::uint32_t minor{};
            const std::string_view input(argv[5]);
            const auto [end,error] = std::from_chars(input.data(),input.data()+input.size(),minor);
            if (error != std::errc{} || end != input.data()+input.size() || minor >= 255)
                throw Error("synosnap minor must be between 0 and 254");
            opensabba::snapshot_driver_reload(minor,
                std::filesystem::canonical(argv[3]).string(),argv[4],
                std::string_view(argv[2]) == "reload-snapshot");
            return 0;
        }
        auto parsed = opensabba::parse_cli(argc, argv);
        official_command = parsed.official;
        std::vector<char*> arguments;
        for (auto& argument : parsed.arguments) arguments.push_back(argument.data());
        argc = static_cast<int>(arguments.size());
        argv = arguments.data();
        class QuietOutput : public std::streambuf {
            int overflow(int ch) override { return traits_type::not_eof(ch); }
        } quiet_buffer;
        struct RestoreOutput {
            std::streambuf* previous;
            ~RestoreOutput() { std::cout.rdbuf(previous); }
        } restore_output{std::cout.rdbuf()};
        if (parsed.quiet && parsed.arguments[1] != "--version") std::cout.rdbuf(&quiet_buffer);
        const std::string_view command = argc > 1 ? argv[1] : "--help";
        failed_command = command;
        if (argc == 3 && command == "service" && std::string_view(argv[2]) == "start")
            if (const auto status = opensabba::daemonize_service()) return *status;
        opensabba::HistoricalLogRun history(command);
        if (command == "--usage") {
            std::cout << "\nUsage:\n  Connect: opensabba -c [options]\n"
                         "  Logout: opensabba -l [options]\n"
                         "  Reload: opensabba -r [options]\n"
                         "  Status: opensabba -s\n\nUse -h, --help for more informations\n";
            return 1;
        }
        if (argc <= 2 && command == "--help") {
            std::cout << "OpenSabba " << OPENSABBA_VERSION << std::endl
                << "  -c, --connect -a HOST -u USER [-p PASSWORD] [-o OTP] [-q]" << std::endl
                << "  -r, --reload [-a HOST] [-u USER] [proxy options] [-q]" << std::endl
                << "  -l, --logout [-u ADMIN -p PASSWORD] [-o OTP] [-q]" << std::endl
                << "  -s, --status [--skip-portal] [-q]" << std::endl
                << "  -e, --export-log [-f FILE] [-q]" << std::endl
                << "  -v, --version; -h, --help" << std::endl
                << "  Proxy: --proxy-address HOST --proxy-port N" << std::endl
                << "         [--proxy-username USER --proxy-password PASSWORD]" << std::endl
                << "  service start|run" << std::endl;
            return 0;
        }
        if (argc == 2 && command == "--version") {
            std::cout << "OpenSabba " << OPENSABBA_VERSION << '\n';
            return 0;
        }
        if (command == "export-log") {
            if (argc != 2 && argc != 4)
                throw Error("usage: opensabba --export-log [--output-file FILE]");
            return opensabba::export_logs_command(argc == 4 ? argv[3] : "", parsed.quiet);
        }
        return opensabba::session_command(argc,argv);
    } catch (const opensabba::CliError& exc) {
        if (!(official_command && failed_command == "status" &&
              (exc.exit_code == 2 || exc.exit_code == 5))) std::cerr << "opensabba: ";
        std::cerr << exc.what() << '\n';
        return official_command ? exc.exit_code : 1;
    } catch (const opensabba::CertificateError& exc) {
        std::cerr << "opensabba: " << exc.what() << '\n';
        return official_command ? (exc.changed ? 12 : 13) : 1;
    } catch (const opensabba::ServerError& exc) {
        std::cerr << "opensabba: " << exc.what() << '\n';
        return failed_command == "connect" || failed_command == "logout" ? 3 : failed_command == "reload" ? 4 : 1;
    } catch (const opensabba::TransportError& exc) {
        std::cerr << "opensabba: " << exc.what() << '\n';
        return failed_command == "connect" || failed_command == "logout" ? 3 : failed_command == "reload" ? 4 : 1;
    } catch (const std::exception& exc) {
        std::cerr << "opensabba: " << exc.what() << '\n';
        return 1;
    }
}
