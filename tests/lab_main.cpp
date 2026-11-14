#include "lab.hpp"
#include "opensabba/pstream.hpp"
#include "opensabba/client.hpp"
#include "opensabba/session.hpp"
#include "opensabba/service_process.hpp"
#include "opensabba/image.hpp"
#include "opensabba/layout.hpp"
#include "opensabba/snapshot.hpp"
#include "opensabba/snapshot_driver.hpp"
#include "opensabba/display.hpp"
#include "opensabba/machine.hpp"
#include "opensabba/machine_capture.hpp"
#include "opensabba/cli.hpp"
#include "opensabba/historical_logs.hpp"

#include <charconv>
#include <csignal>
#include <ctime>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <string_view>

using namespace opensabba::pstream;
namespace {
unsigned parse_number(std::string_view text, unsigned maximum) {
    unsigned value = 0;
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || value == 0 || value > maximum)
        throw Error("invalid numeric option: " + std::string(text));
    return value;
}
void print(const Value& value) {
    opensabba::print_json(std::cout, value);
}
}

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
        auto parsed = opensabba::parse_lab_cli(argc, argv);
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
        if (argc == 3 && command == "service" && std::string_view(argv[2]) == "start" &&
            !opensabba::daemonize_service()) return 0;
        opensabba::HistoricalLogRun history(command);
        if (command == "--usage") {
            std::cout << "\nUsage:\n  Connect: opensabba -c [options]\n"
                         "  Logout: opensabba -l [options]\n"
                         "  Reload: opensabba -r [options]\n"
                         "  Status: opensabba -s\n\nUse -h, --help for more informations\n";
            return 1;
        }
        if (argc <= 2 && command == "--help") {
            std::cout << "OpenSabba " << OPENSABBA_VERSION << " - experimental ABB client\n"
                         "  opensabba -c|--connect -a|--address HOST -u|--username USER [-p|--password PASSWORD]\n"
                         "    [-o|--otp CODE] [-q|--quiet] [--port N] [--ca-file PEM] [--timeout SECONDS]\n"
                         "    [--password-fd N [--otp-fd N]]  Descriptor input disables interactive prompts/retries\n"
                         "    connect/probe: [--proxy-address HOST --proxy-port N]  HTTP CONNECT proxy\n"
                         "    connect: [--proxy-username USER --proxy-password PASSWORD|--proxy-password-fd N]\n"
                         "    connect: [--proxy-auth ntlm --proxy-domain DOMAIN --proxy-workstation NAME]\n"
                         "           [--proxy-ntlm-version 1|2]  NTLMv2 by default; NTLMv1 requires 1\n"
                         "  opensabba -s|--status         Show status from the running service\n"
                         "  opensabba --status --online [--json]  Query NAS tasks and current jobs\n"
                         "  opensabba -e|--export-log [--output-file FILE]  Export diagnostic archive (offline)\n"
                         "  opensabba tasks [--json]     List NAS-assigned backup tasks\n"
                         "  opensabba -l|--logout [-u USER -p PASSWORD]  Authorize NAS admin logout and stop the service\n"
                         "    [--password-fd N [--otp-fd N]] [-o CODE] [-q]  Quiet logout requires admin credentials\n"
                         "  opensabba -v|--version        Show OpenSabba version\n"
                         "  opensabba -h|--help           Show help\n"
                         "  Official agent commands accept -q|--quiet: suppress output/prompts; version remains visible.\n"
                         "  opensabba inspect FILE       Decode one PStream control value\n"
                         "  opensabba query-info FILE    Write a query_server_info request fixture\n"
                         "  opensabba probe HOST [--port N] [--ca-file PEM] [--timeout SECONDS]\n"
                         "  opensabba probe              Use the saved server and CA settings\n"
                         "  opensabba reconnect          Authenticate with the saved token\n"
                         "  opensabba -r|--reload [-a HOST] [-u USER] [proxy options]  Edit the saved connection\n"
                         "  opensabba heartbeat          Send one authenticated heartbeat\n"
                         "  opensabba service start      Start the detached system service (/run/opensabba.pid)\n"
                         "  opensabba service run        Maintain connection and dispatch a bound source in foreground\n"
                         "  opensabba service check      Check local startup state without contacting the NAS\n"
                         "  opensabba service bind-machine DIRECTORY --task ID --image-name NAME (diagnostic full source)\n"
                         "  opensabba service source     Show the saved source and claimed NAS job\n"
                         "  opensabba events [--json]    Show retained event receipts without payloads\n"
                         "  opensabba image-stream IMAGE OUTPUT [--image-name NAME] [--block-size BYTES] [--compression none|lz4]\n"
                         "  opensabba image-layout IMAGE --sector-size 512|4096\n"
                         "  opensabba machine plan DISK --cow-dir DIR  Inspect root/boot capture topology (read-only JSON)\n"
                         "  opensabba machine capture DISK --cow-dir DIR --cow-mib N\n"
                         "  opensabba machine journal|recover DIRECTORY  Inspect or abandon an interrupted capture\n"
                         "  opensabba machine discard-reservation DIRECTORY  Remove an unpublished capture allocation\n"
                         "  opensabba image-spec IMAGE --sector-size 512|4096 --image-name NAME\n"
                         "  opensabba snapshot status [--minor N]  Inspect synosnap control (JSON, read-only)\n"
                         "  opensabba backup status [--json]  Show the private backup journal\n"
                         "  opensabba backup image IMAGE --task ID [--running-task ID] --sector-size 512|4096 --image-name NAME\n"
                         "  opensabba restore image NEW_FILE [--image-name NAME]  Restore a saved backup image\n"
                         "  opensabba restore versions --task ID [--offset N] [--limit 1..50] [--json]  Browse NAS versions\n"
                         "  opensabba restore status [--json]  Show the private restore journal\n"
                         "  opensabba backup reconcile   Read and record the saved job's NAS result\n"
                         "  opensabba backup cancel      Cancel the matching unfinished backup job\n"
                         "  opensabba backup resume IMAGE  Resume the saved backup from NAS progress\n"
                         "  opensabba restore cancel     Cancel the matching unfinished restore job\n"
                         "  opensabba restore reconcile  Read and record the saved restore's NAS result\n"
                         "  opensabba restore resume     Continue the saved image download from its checkpoint\n"
                         "Probe requests server info over verified TLS; no account or driver needed.\n"
                         "Connect prompts for missing credentials; saved-session commands require Linux.\n"
                         "Service SIGHUP/SIGINT/SIGQUIT/SIGTERM stop workers; --reload edits connection settings.\n"
                         "Whole-machine automatic backup is experimental; see documented source limitations.\n";
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
        if (command == "probe") {
            if (argc == 2) {
                print(opensabba::probe(opensabba::saved_endpoint()));
                std::cout << '\n';
                return 0;
            }
            opensabba::Endpoint endpoint;
            endpoint.host = argv[2];
            for (int i = 3; i < argc; i += 2) {
                if (i + 1 == argc) throw Error("missing option value");
                std::string_view option = argv[i];
                if (option == "--port")
                    endpoint.port = static_cast<std::uint16_t>(parse_number(argv[i + 1], 65535));
                else if (option == "--timeout")
                    endpoint.timeout = std::chrono::seconds(parse_number(argv[i + 1], 300));
                else if (option == "--ca-file") endpoint.ca_file = argv[i + 1];
                else if (option == "--proxy-address") endpoint.proxy_host = argv[i+1];
                else if (option == "--proxy-port")
                    endpoint.proxy_port = static_cast<std::uint16_t>(parse_number(argv[i+1],65535));
                else throw Error("unknown option: " + std::string(option));
            }
            print(opensabba::probe(endpoint));
            std::cout << '\n';
            return 0;
        }
        if (command == "snapshot") {
            if ((argc != 3 && argc != 5) || std::string_view(argv[2]) != "status" ||
                (argc == 5 && std::string_view(argv[3]) != "--minor"))
                throw Error("usage: snapshot status [--minor N]");
            std::optional<std::uint32_t> minor;
            if (argc == 5) {
                const std::string_view input(argv[4]);
                std::uint32_t value{};
                const auto [end, error] = std::from_chars(input.data(), input.data()+input.size(), value);
                if (error != std::errc{} || end != input.data()+input.size() || value >= 255)
                    throw Error("synosnap minor must be between 0 and 254");
                minor = value;
            }
            print(opensabba::snapshot_driver_status(minor));
            std::cout << '\n';
            return 0;
        }
        if (command == "image-stream") return opensabba::lab_image_command(argc, argv);
        if (command == "machine") {
            if (argc >= 3 && std::string_view(argv[2]) != "plan") {
                opensabba::load_saved_server_time();
                return opensabba::lab_machine_capture_command(argc, argv);
            }
            if (argc != 6 || std::string_view(argv[2]) != "plan" || std::string_view(argv[4]) != "--cow-dir")
                throw Error("usage: machine plan DISK --cow-dir DIR");
            print(opensabba::inspect_machine(argv[3], argv[5]));
            std::cout << '\n';
            return 0;
        }
        if (command == "image-spec") {
            if (argc != 7 || std::string_view(argv[3]) != "--sector-size" ||
                std::string_view(argv[5]) != "--image-name")
                throw Error("usage: image-spec IMAGE --sector-size 512|4096 --image-name NAME");
            opensabba::load_saved_server_time();
            const auto now = opensabba::server_time_now();
            opensabba::ImageSource source(argv[2]);
            auto json = opensabba::fixed_image_metadata(source, parse_number(argv[4], 4096),
                                                        argv[6], static_cast<std::uint64_t>(now));
            std::cout.write(reinterpret_cast<const char*>(json.data()), static_cast<std::streamsize>(json.size()));
            std::cout << '\n';
            return 0;
        }
        if (command == "image-layout") {
            if (argc != 5 || std::string_view(argv[3]) != "--sector-size")
                throw Error("usage: image-layout IMAGE --sector-size 512|4096");
            const auto sector = parse_number(argv[4], 4096);
            opensabba::ImageSource source(argv[2]);
            print(opensabba::layout_value(opensabba::inspect_image_layout(source, sector)));
            std::cout << '\n';
            return 0;
        }
        if (command == "connect" || command == "status" || command == "logout" ||
            command == "reconnect" || command == "reload" || command == "heartbeat" ||
            command == "tasks" || command == "service" || command == "events" || command == "backup" ||
            command == "restore")
            return opensabba::lab_session_command(argc, argv);
        if (argc != 3) throw Error("expected a command and file; use --help");
        if (command == "inspect") {
            std::ifstream input(argv[2], std::ios::binary);
            if (!input) throw Error("cannot open input file");
            Bytes bytes;
            char ch;
            while (input.get(ch)) {
                if (bytes.size() == Limits{}.max_bytes) throw Error("byte limit exceeded");
                bytes.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(ch)));
            }
            if (!input.eof()) throw Error("failed to read input");
            print(decode(bytes));
            std::cout << '\n';
        } else if (command == "query-info") {
            auto bytes = encode(opensabba::make_request("query_server_info"));
            std::ofstream output(argv[2], std::ios::binary);
            if (!output) throw Error("cannot open output file");
            output.write(reinterpret_cast<const char*>(bytes.data()),
                         static_cast<std::streamsize>(bytes.size()));
            output.close();
            if (!output) throw Error("failed to write output");
        } else {
            throw Error("unknown command; use --help");
        }
        return 0;
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
