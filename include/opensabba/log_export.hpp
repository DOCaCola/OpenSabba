#pragma once
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace opensabba {
struct DiagnosticCommand {
    std::string name;
    std::vector<std::string> arguments;
};
struct DiagnosticCollection {
    std::filesystem::path system_root{"/"};
    std::filesystem::path log_directory;
    std::string journal_summary;
    std::vector<std::string> secrets;
    // Collectors return a process exit code; output goes to the provided fd.
    // Empty selects the fixed local process runner. Intended for offline tests.
    std::function<int(const DiagnosticCommand&, int)> run;
};
std::filesystem::path default_log_archive();
std::string redact_diagnostic_text(std::string, const std::vector<std::string>&);
void export_diagnostic_archive(const std::filesystem::path&, const DiagnosticCollection&);
}
