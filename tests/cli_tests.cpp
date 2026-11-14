#include "opensabba/cli.hpp"
#include "opensabba/pstream.hpp"
#include <iostream>
#include <stdexcept>

namespace {
opensabba::CliArguments parse(std::initializer_list<std::string> options) {
    std::vector<std::string> strings{"opensabba"};
    strings.insert(strings.end(), options.begin(), options.end());
    std::vector<char*> argv;
    for (auto& string : strings) argv.push_back(string.data());
    return opensabba::parse_cli(static_cast<int>(argv.size()), argv.data());
}
void check(bool condition) { if (!condition) throw std::runtime_error("CLI assertion failed"); }
void refuses(std::initializer_list<std::string> options) {
    try { parse(options); } catch (const opensabba::pstream::Error&) { return; }
    throw std::runtime_error("invalid syntax accepted");
}
}
int main() {
    check(parse({}).arguments[1] == "--usage");
    for (auto pair : {std::pair{"-c","connect"},{"-s","status"},{"-l","logout"},
                      {"-r","reload"},{"-e","export-log"},{"-h","--help"},{"-v","--version"}})
        check(parse({pair.first}).arguments[1] == pair.second);
    auto connect = parse({"-qc","-anas.test","-u","account","--password=with spaces","-o123456"});
    check(connect.quiet && connect.official);
    check(connect.arguments == std::vector<std::string>{
        "opensabba","connect","--address","nas.test","--username","account",
        "--password","with spaces","--otp","123456","--quiet"});
    check(parse({"--quiet","--version"}).quiet);
    check(parse({"-e","-f","archive.zip"}).arguments[2] == "--output-file");
    check(parse({"-r","-a","new-nas","-u","account","-q"}).arguments ==
          std::vector<std::string>{"opensabba","reload","--address","new-nas","--username","account","--quiet"});
    check(parse({"-l","-u","admin","-p","secret","-q"}).arguments ==
          std::vector<std::string>{"opensabba","logout","--username","admin","--password","secret","--quiet"});
    refuses({"--logout","--disconnect"}); refuses({"--logout","--stop-service"});
    for (const auto mode : {"start","run","check"})
        check(parse({"service",mode}).arguments == std::vector<std::string>{"opensabba","service",mode});
    for (const auto name : {"inspect","query-info","probe","reconnect","heartbeat","tasks","events",
                           "image-stream","image-layout","image-spec","machine","snapshot","backup","restore",
                           "__boot-lease-supervisor"}) refuses({name});
    for (const auto mode : {"bind-machine","source","configure-machine","machine","bind-snapshot","configure-origin",
                           "origin","cleanup-cows","recover-boot","reboot-policy","reload"}) refuses({"service",mode});
    for (const auto option : {"--port","--ca-file","--timeout","--password-fd","--otp-fd","--proxy-password-fd",
                             "--proxy-auth","--proxy-domain","--proxy-workstation","--proxy-ntlm-version",
                             "--yes","--cow-dir","--cow-mib","--task","--image-name","--incremental",
                             "--boot-hold-seconds","--select-volume","--rotate","--minor","--block-size",
                             "--compression","--offset","--limit","--apply"}) refuses({"-c",option,"1"});
    refuses({"--status","--online"}); refuses({"--status","--json"});
    refuses({"service","run","--cow-dir","/tmp"});
    for (auto name : {"login","connect","status","logout","reload","export-log","registration"}) refuses({name});
    refuses({"-c","-s"}); refuses({"--quiet"}); refuses({"--quiet=yes","-v"});
    refuses({"-c","-a"}); refuses({"-v","--username","x"}); refuses({"-c","host"});
    refuses({"-c","--address=x","-a","y"}); refuses({"--connect","--online"});
    refuses({"--export-log","--output","x"}); refuses({"--connect","--proxy-host","x"});
    std::cout << "official CLI parsing passed\n";
}
