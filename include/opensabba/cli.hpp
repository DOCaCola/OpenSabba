#pragma once
#include "opensabba/pstream.hpp"
#include <string>
#include <vector>

namespace opensabba {
class CliError : public pstream::Error {
public:
    int exit_code;
    CliError(int code, std::string message) : Error(std::move(message)), exit_code(code) {}
};
struct CliArguments {
    std::vector<std::string> arguments;
    bool quiet = false;
    bool official = false;
};
// the official agent commands use flags. Additional OpenSabba commands use subcommands.
CliArguments parse_cli(int argc, char** argv);
}
