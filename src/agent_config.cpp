#include "opensabba/agent_config.hpp"
#include <cstdio>
#include <sstream>
#include <string_view>

namespace opensabba {
namespace {
bool space(unsigned char ch) { return ch == ' ' || (ch >= 9 && ch <= 13); }
bool key_char(unsigned char ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
        (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' || ch == '_';
}
bool value_char(unsigned char ch) { return ch > 31 && ch != 127; }
// Configuration parsing rejects the whole file on a syntax error. Quoting strips the
// enclosing quote; comments follow a complete value and optional whitespace.
bool parse_line(std::string_view line, std::string& key, std::string& value) {
    std::size_t at = 0;
    const auto skip = [&] { while (at < line.size() && space(line[at])) ++at; };
    skip();
    const auto begin = at;
    while (at < line.size() && key_char(line[at])) ++at;
    key = std::string(line.substr(begin,at-begin));
    if (at == line.size() || line[at] == '#') { key.clear(); return true; }
    skip();
    if (at == line.size() || line[at++] != '=') return false;
    skip();
    if (at == line.size()) return false;
    const bool quoted = line[at] == '"' || line[at] == '\'';
    const char terminator = quoted ? line[at++] : ' ';
    const auto start = at;
    while (at < line.size() && value_char(line[at]) && line[at] != terminator) ++at;
    value = std::string(line.substr(start,at-start));
    if (quoted && (at == line.size() || line[at++] != terminator)) return false;
    skip();
    return at == line.size() || line[at] == '#';
}
}
std::uint32_t read_disconnect_timeout(const std::filesystem::path& path) {
    constexpr std::uint32_t standard = 1800;
    std::error_code error;
    if (!std::filesystem::is_regular_file(path,error)) return standard;
    auto* file = std::fopen(path.string().c_str(),"r");
    if (!file) return standard;
    struct Close { std::FILE* file; ~Close() { std::fclose(file); } } close{file};
    char buffer[8192];
    std::string key, value, configured;
    while (std::fgets(buffer,sizeof(buffer),file)) {
        if (!parse_line(buffer,key,value)) return standard;
        if (key == "EventTimeout") configured = value;
    }
    int minutes = 0;
    std::istringstream(configured) >> minutes;
    return minutes > 0 ? static_cast<std::uint32_t>(minutes)*std::uint32_t{60} : standard;
}
std::uint32_t disconnect_timeout() {
    static const auto timeout = read_disconnect_timeout(official_agent_config);
    return timeout;
}
bool backup_disconnect_expired(std::uint64_t start, std::uint32_t timeout, std::int64_t now) {
    return start && timeout && now >= 0 && static_cast<std::uint64_t>(now) >= start &&
        static_cast<std::uint64_t>(now)-start >= timeout;
}
}
