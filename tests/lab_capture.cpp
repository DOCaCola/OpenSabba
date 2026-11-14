#include "lab.hpp"
#include "../src/session_runtime.hpp"
#include "opensabba/machine_capture.hpp"
#include <charconv>
#include <csignal>
#include <iostream>
namespace opensabba {
using pstream::Value;
using pstream::Error;
namespace {
#ifdef __linux__
volatile sig_atomic_t cancel_requested = 0;
void cancel_signal(int) { cancel_requested = 1; }
struct CaptureSignals {
    struct sigaction old_int{}, old_term{};
    CaptureSignals() {
        cancel_requested = 0;
        struct sigaction next{}; next.sa_handler = cancel_signal; sigemptyset(&next.sa_mask);
        if (sigaction(SIGINT, &next, &old_int)) throw Error("cannot install capture cancellation handler");
        if (sigaction(SIGTERM, &next, &old_term)) {
            sigaction(SIGINT, &old_int, nullptr);
            throw Error("cannot install capture cancellation handler");
        }
    }
    ~CaptureSignals() { sigaction(SIGINT, &old_int, nullptr); sigaction(SIGTERM, &old_term, nullptr); }
};
std::uint64_t decimal(std::string_view input) {
    std::uint64_t result{};
    const auto [end,error] = std::from_chars(input.data(),input.data()+input.size(),result);
    if (error != std::errc{} || end != input.data()+input.size() || !result) throw Error("invalid capture numeric option");
    return result;
}
#endif
}
int lab_machine_capture_command(int argc, char** argv) {
#ifndef __linux__
    (void)argc; (void)argv;
    throw Error("machine capture requires Linux");
#else
    if (argc == 4 && std::string_view(argv[2]) == "discard-reservation") {
        discard_machine_reservation(argv[3]);
        std::cout << "Unpublished capture reservation removed: " << std::filesystem::canonical(argv[3]).string() << '\n';
        return 0;
    }
    if (argc == 4 && (std::string_view(argv[2]) == "recover" || std::string_view(argv[2]) == "journal")) {
        const auto journal = inspect_machine_capture(argv[3],std::string_view(argv[2]) == "recover");
        std::cout << "Capture " << journal.id << ": "
                  << session_detail::text(capture_journal_value(journal),"phase")
                  << "\nDirectory: " << session_detail::text(journal.reservation,"directory") << '\n';
        return 0;
    }
    if (argc < 8 || std::string_view(argv[2]) != "capture" ||
        std::string_view(argv[4]) != "--cow-dir" || std::string_view(argv[6]) != "--cow-mib" ||
        (argc-8)%2)
        throw Error("usage: machine capture DISK --cow-dir DIR --cow-mib N [--select-volume MOUNT]...; machine journal|recover|discard-reservation DIRECTORY");
    const auto mib = decimal(argv[7]);
    std::vector<std::string> selected;
    for (int index = 8; index < argc; index += 2) {
        const std::string_view option(argv[index]);
        if (option == "--select-volume") selected.emplace_back(argv[index+1]);
        else throw Error("invalid or repeated machine capture option");
    }
    CaptureSignals signals;
    const auto journal = create_machine_capture(argv[3],argv[5],mib,
        [](const CaptureJournal& reserved) {
            std::cout << "Capture directory: " << session_detail::text(reserved.reservation,"directory") << std::endl;
        }, [] { return cancel_requested != 0; },{},selected);
    std::cout << "Snapshot set ready: " << session_detail::text(journal.reservation,"directory")
              << "\nNo NAS backup was started.\n";
    return 0;
#endif
}
}
