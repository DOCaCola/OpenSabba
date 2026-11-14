#include "lab.hpp"
#include "opensabba/session.hpp"
#include "opensabba/pstream.hpp"
#include <openssl/crypto.h>
#include <charconv>
#include <algorithm>
#include <climits>
#include <filesystem>
#include <map>
#include <set>
#include <string_view>
#ifndef _WIN32
#include <cerrno>
#include <unistd.h>
#endif
namespace opensabba {
using pstream::Error;
namespace {
unsigned number(const std::string& input,unsigned maximum,bool zero = false) {
    unsigned result{};
    const auto [end,error] = std::from_chars(input.data(),input.data()+input.size(),result);
    if (error != std::errc{} || end != input.data()+input.size() || (!zero && !result) || result > maximum)
        throw Error("invalid lab numeric option");
    return result;
}
#ifndef _WIN32
std::string descriptor_secret(int fd, bool allow_empty) {
    if (isatty(fd)) throw Error("credential descriptors must not refer to a terminal");
    char buffer[4097]{};
    struct WipeBuffer {
        char* data;
        ~WipeBuffer() { OPENSSL_cleanse(data, 4097); }
    } wipe{buffer};
    std::size_t size = 0;
    for (;;) {
        char ch{};
        const auto count = ::read(fd, &ch, 1);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) throw Error("cannot read credential descriptor");
        if (count == 0 || ch == '\n') break;
        if (ch == '\0') throw Error("credential contains a NUL byte");
        if (size == sizeof(buffer)) throw Error("credential exceeds size limit");
        buffer[size++] = ch;
    }
    if (size && buffer[size-1] == '\r') --size;
    if (size > 4096) throw Error("credential exceeds size limit");
    if (!allow_empty && !size) throw Error("password cannot be empty");
    return std::string(buffer, size);
}

#endif
}
int lab_connection_command(int argc,char** argv) {
    const std::set<std::string> extensions{"--port","--ca-file","--timeout","--password-fd","--otp-fd",
        "--proxy-password-fd","--proxy-auth","--proxy-domain","--proxy-workstation","--proxy-ntlm-version"};
    std::vector<std::string> arguments;
    std::map<std::string,std::string> options;
    for (int i = 0; i < argc; ++i) {
        const std::string option(argv[i]);
        if (!extensions.contains(option)) { arguments.push_back(option); continue; }
        if (++i == argc || !options.emplace(option,argv[i]).second) throw Error("missing or repeated lab option");
    }
    struct Wipe {
        std::vector<std::string>& values;
        ~Wipe() { for (auto& value : values) OPENSSL_cleanse(value.data(),value.size()); }
    } wipe{arguments};
    const std::string command(argv[1]);
    if (command == "reload" && (options.contains("--timeout") || options.contains("--password-fd") ||
        options.contains("--otp-fd") || options.contains("--proxy-password-fd")))
        throw Error("connected reload edits address and proxy settings; password authentication requires --connect");
    const auto existing = [&](const std::string& name) {
        return std::find(arguments.begin(),arguments.end(),name) != arguments.end();
    };
    if (options.contains("--otp-fd") && !options.contains("--password-fd"))
        throw Error("--otp-fd requires --password-fd");
    SessionInvocation invocation;
    invocation.noninteractive_credentials = options.contains("--password-fd");
    for (const auto& [descriptor,target] : std::initializer_list<std::pair<std::string,std::string>>{
        {"--password-fd","--password"},{"--otp-fd","--otp"},{"--proxy-password-fd","--proxy-password"}}) {
        if (!options.contains(descriptor)) continue;
        if (existing(target)) throw Error(target+" and "+descriptor+" cannot be combined");
#ifndef _WIN32
        const auto fd = static_cast<int>(number(options.at(descriptor),INT_MAX,true));
        auto secret = descriptor_secret(fd,target != "--password");
        arguments.push_back(target); arguments.push_back(std::move(secret));
#else
        throw Error("credential descriptors require Linux");
#endif
    }
    const auto value = [&](const std::string& option) -> std::string {
        const auto at = std::find(arguments.begin(),arguments.end(),option);
        return at != arguments.end() && at+1 != arguments.end() ? *(at+1) : std::string{};
    };
    const auto scheme = options.contains("--proxy-auth") ? options.at("--proxy-auth") : "basic";
    if (scheme != "basic" && scheme != "ntlm") throw Error("--proxy-auth must be basic or ntlm");
    auto domain = options.contains("--proxy-domain") ? options.at("--proxy-domain") : std::string{};
    const auto workstation = options.contains("--proxy-workstation") ? options.at("--proxy-workstation") : std::string{};
    const auto version = options.contains("--proxy-ntlm-version") ? number(options.at("--proxy-ntlm-version"),2) : 2;
    const bool selectors = options.contains("--proxy-domain") || options.contains("--proxy-workstation") ||
        options.contains("--proxy-ntlm-version");
    auto username = value("--proxy-username");
    if ((scheme == "ntlm" && username.empty()) || (scheme == "basic" && selectors))
        throw Error("NTLM options require --proxy-auth ntlm and proxy credentials");
    if (scheme == "ntlm") {
        const auto separator = username.find(char{92});
        if (separator != std::string::npos) {
            if (!domain.empty() || !separator || separator+1 == username.size())
                throw Error("use either DOMAIN"+std::string(1,char{92})+"USER or --proxy-domain DOMAIN with a plain username");
            domain = username.substr(0,separator); username.erase(0,separator+1);
        }
    }
    std::optional<std::uint16_t> port;
    std::optional<std::string> ca;
    std::optional<std::chrono::seconds> timeout;
    if (options.contains("--port")) port = static_cast<std::uint16_t>(number(options.at("--port"),65535));
    if (options.contains("--ca-file")) ca = std::filesystem::absolute(options.at("--ca-file")).string();
    if (options.contains("--timeout")) timeout = std::chrono::seconds{number(options.at("--timeout"),300)};
    if (port || ca || timeout || options.contains("--proxy-auth") || selectors)
    invocation.prepare_endpoint = [=](Endpoint& endpoint) {
        if (port) endpoint.port = *port;
        if (ca) endpoint.ca_file = *ca;
        if (timeout) endpoint.timeout = *timeout;
        if (options.contains("--proxy-auth") || selectors) {
            if (!endpoint.proxy_credentials) throw Error("proxy selectors require proxy credentials");
            endpoint.proxy_credentials->scheme = scheme;
            endpoint.proxy_credentials->domain = domain;
            endpoint.proxy_credentials->workstation = workstation;
            endpoint.proxy_credentials->ntlm_version = version;
            if (!username.empty()) endpoint.proxy_credentials->username = username;
        }
    };
    std::vector<char*> raw;
    for (auto& argument : arguments) raw.push_back(argument.data());
    return session_command(static_cast<int>(raw.size()),raw.data(),invocation);
}
}
