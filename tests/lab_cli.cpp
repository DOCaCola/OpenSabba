#include "lab.hpp"
#include "opensabba/pstream.hpp"
#include <map>
#include <set>
#include <string_view>

namespace opensabba {
CliArguments parse_lab_cli(int argc, char** argv) {
    CliArguments result{{argv[0]}, false, false};
    if (argc == 1) {
        result.arguments.emplace_back("--usage");
        result.official = true;
        return result;
    }
    const std::string_view first(argv[1]);
    if (!first.starts_with("-")) {
        if (first == "login" || first == "connect" || first == "logout" ||
            first == "status" || first == "reload" || first == "export-log" || first == "registration")
            throw pstream::Error("use official command flags; see --help");
        for (int i = 1; i < argc; ++i) result.arguments.emplace_back(argv[i]);
        return result;
    }
    result.official = true;
    const std::map<std::string, std::string> commands{
        {"c","connect"},{"connect","connect"},{"r","reload"},{"reload","reload"},
        {"l","logout"},{"logout","logout"},{"s","status"},{"status","status"},
        {"v","--version"},{"version","--version"},{"e","export-log"},{"export-log","export-log"},
        {"h","--help"},{"help","--help"}};
    const std::map<std::string,std::string> short_options{
        {"a","address"},{"u","username"},{"p","password"},{"o","otp"},{"f","output-file"}};
    const std::set<std::string> values{
        "address","username","password","otp","output-file","proxy-address","proxy-port",
        "proxy-username","proxy-password","port","ca-file","timeout","password-fd",
        "otp-fd","proxy-password-fd","proxy-auth","proxy-domain","proxy-workstation",
        "proxy-ntlm-version"};
    const std::set<std::string> switches{"online","json","skip-portal"};
    std::string command;
    std::vector<std::string> options;
    std::set<std::string> seen;
    auto option = [&](std::string name, std::string value, bool has_value, int& index) {
        if (auto found = commands.find(name); found != commands.end()) {
            if (!command.empty() || has_value) throw pstream::Error("specify exactly one command");
            command = found->second;
            return;
        }
        if (name == "q") name = "quiet";
        if (auto found = short_options.find(name); found != short_options.end()) name = found->second;
        if (!seen.insert(name).second) throw pstream::Error("duplicate option: --" + name);
        if (name == "quiet") {
            if (has_value) throw pstream::Error("--quiet takes no value");
            result.quiet = true;
            return;
        }
        if (values.contains(name)) {
            if (!has_value) {
                if (++index == argc) throw pstream::Error("missing option value: --" + name);
                value = argv[index];
            }
            options.emplace_back("--" + name);
            options.emplace_back(std::move(value));
        } else if (switches.contains(name) && !has_value) options.emplace_back("--" + name);
        else throw pstream::Error("unknown option: --" + name);
    };
    for (int i = 1; i < argc; ++i) {
        std::string token(argv[i]);
        if (token.starts_with("--")) {
            const auto equal = token.find('=');
            option(token.substr(2, equal == std::string::npos ? equal : equal-2),
                   equal == std::string::npos ? "" : token.substr(equal+1),
                   equal != std::string::npos, i);
        } else if (token.size() > 1 && token[0] == '-') {
            for (std::size_t j = 1; j < token.size(); ++j) {
                const std::string name(1,token[j]);
                const bool takes_value = short_options.contains(name);
                const bool attached = takes_value && j+1 < token.size();
                option(name, attached ? token.substr(j+1) : "", attached, i);
                if (takes_value) break;
            }
        } else throw pstream::Error("unexpected argument: " + token);
    }
    if (command.empty()) throw pstream::Error("specify a command; see --help");
    for (std::size_t i = 0; i < options.size(); ++i) {
        const auto& name = options[i];
        const bool value = values.contains(name.substr(2));
        const bool valid = (command == "connect" || command == "reload") ? value && name != "--output-file" :
            command == "export-log" ? name == "--output-file" :
            command == "status" ? name == "--online" || name == "--json" || name == "--skip-portal" :
            command == "logout" ? name == "--username" || name == "--password" || name == "--password-fd" ||
                name == "--otp" || name == "--otp-fd" : false;
        if (!valid) throw pstream::Error("option " + name + " is not valid for this command");
        if (value) ++i;
    }
    result.arguments.emplace_back(command);
    result.arguments.insert(result.arguments.end(), options.begin(), options.end());
    if (result.quiet && (command == "connect" || command == "reload" || command == "logout")) result.arguments.emplace_back("--quiet");
    return result;
}
}
