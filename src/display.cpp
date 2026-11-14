#include "opensabba/display.hpp"
#include <iomanip>
#include <ostream>

namespace opensabba {
namespace {
using pstream::Value;
void quote(std::ostream& out, const std::string& value) {
    out << '"';
    for (unsigned char ch : value) {
        if (ch == '"' || ch == '\\') out << '\\' << ch;
        else if (ch >= 0x20 && ch < 0x7f) out << ch;
        else out << "\\u00" << std::hex << std::setfill('0')
                 << std::setw(2) << static_cast<unsigned>(ch) << std::dec;
    }
    out << '"';
}
void item(std::ostream& out, std::monostate) { out << "null"; }
void item(std::ostream& out, std::uint64_t value) { out << value; }
void item(std::ostream& out, const std::string& value) { quote(out, value); }
void item(std::ostream& out, const pstream::Bytes& value) {
    out << "{\"$buffer_hex\":\"";
    for (auto ch : value)
        out << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(ch);
    out << std::dec << "\"}";
}
void item(std::ostream& out, const Value::Array& value) {
    out << '[';
    bool first = true;
    for (const auto& element : value) {
        if (!first) out << ',';
        first = false;
        print_json(out, element);
    }
    out << ']';
}
void item(std::ostream& out, const Value::Object& value) {
    out << '{';
    bool first = true;
    for (const auto& [key, element] : value) {
        if (!first) out << ',';
        first = false;
        quote(out, key);
        out << ':';
        print_json(out, element);
    }
    out << '}';
}
}
void print_json(std::ostream& out, const pstream::Value& value) {
    const auto flags = out.flags();
    const auto fill = out.fill();
    std::visit([&](const auto& entry) { item(out, entry); }, value.data);
    out.flags(flags);
    out.fill(fill);
}
}
