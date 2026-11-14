#pragma once
#include "opensabba/pstream.hpp"
#include <string_view>
namespace opensabba::json_detail {
using pstream::Error;
struct Json {
    enum Kind { null, boolean, number, string, array, object } kind = null;
    std::string scalar;
    std::vector<Json> elements;
    std::map<std::string, Json> members;
};
// sched_content is a JSON document carried inside a PStream string. Parse the
// entire document, including unrelated fields, before interpreting its policy.
class Parser {
    std::string_view input;
    std::size_t position = 0;
    [[noreturn]] static void fail() { throw Error("invalid schedule JSON"); }
    void space() {
        while (position < input.size() &&
               (input[position] == ' ' || input[position] == '\n' ||
                input[position] == '\r' || input[position] == '\t')) ++position;
    }
    bool take(char c) {
        space();
        if (position == input.size() || input[position] != c) return false;
        ++position;
        return true;
    }
    unsigned hex() {
        if (position + 4 > input.size()) fail();
        unsigned result = 0;
        for (unsigned i = 0; i < 4; ++i) {
            const char c = input[position++];
            unsigned digit;
            if (c >= '0' && c <= '9') digit = static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f') digit = static_cast<unsigned>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') digit = static_cast<unsigned>(c - 'A' + 10);
            else fail();
            result = result * 16 + digit;
        }
        return result;
    }
    static void utf8(std::string& out, unsigned c) {
        if (c < 0x80) out += static_cast<char>(c);
        else if (c < 0x800) {
            out += static_cast<char>(0xc0 | (c >> 6));
            out += static_cast<char>(0x80 | (c & 0x3f));
        } else if (c < 0x10000) {
            out += static_cast<char>(0xe0 | (c >> 12));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3f));
            out += static_cast<char>(0x80 | (c & 0x3f));
        } else {
            out += static_cast<char>(0xf0 | (c >> 18));
            out += static_cast<char>(0x80 | ((c >> 12) & 0x3f));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3f));
            out += static_cast<char>(0x80 | (c & 0x3f));
        }
    }
    std::string quoted() {
        if (!take('"')) fail();
        std::string out;
        while (position < input.size()) {
            const auto c = static_cast<unsigned char>(input[position++]);
            if (c == '"') return out;
            if (c < 0x20) fail();
            if (c != '\\') { out += static_cast<char>(c); continue; }
            if (position == input.size()) fail();
            switch (input[position++]) {
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'u': {
                unsigned code = hex();
                if (code >= 0xd800 && code <= 0xdbff) {
                    if (position + 2 > input.size() || input.substr(position, 2) != "\\u") fail();
                    position += 2;
                    const unsigned low = hex();
                    if (low < 0xdc00 || low > 0xdfff) fail();
                    code = 0x10000 + ((code - 0xd800) << 10) + low - 0xdc00;
                } else if (code >= 0xdc00 && code <= 0xdfff) fail();
                utf8(out, code);
                break;
            }
            default: fail();
            }
        }
        fail();
    }
    void digits() {
        const auto start = position;
        while (position < input.size() && input[position] >= '0' && input[position] <= '9') ++position;
        if (position == start) fail();
    }
    Json value(unsigned depth) {
        if (depth > 64) fail();
        space();
        if (position == input.size()) fail();
        Json result;
        const char first = input[position];
        if (first == '{') {
            ++position;
            result.kind = Json::object;
            if (take('}')) return result;
            do {
                auto key = quoted();
                if (!take(':')) fail();
                result.members.insert_or_assign(std::move(key), value(depth + 1));
            } while (take(','));
            if (!take('}')) fail();
        } else if (first == '[') {
            ++position;
            result.kind = Json::array;
            if (take(']')) return result;
            do { result.elements.push_back(value(depth + 1)); } while (take(','));
            if (!take(']')) fail();
        } else if (first == '"') {
            result.kind = Json::string;
            result.scalar = quoted();
        } else if (first == 't' || first == 'f' || first == 'n') {
            const std::string_view literal = first == 't' ? "true" : first == 'f' ? "false" : "null";
            if (input.substr(position, literal.size()) != literal) fail();
            position += literal.size();
            result.kind = first == 'n' ? Json::null : Json::boolean;
            result.scalar = literal;
        } else {
            result.kind = Json::number;
            const auto start = position;
            if (input[position] == '-') ++position;
            if (position == input.size()) fail();
            if (input[position] == '0') ++position;
            else digits();
            if (position < input.size() && input[position] == '.') { ++position; digits(); }
            if (position < input.size() && (input[position] == 'e' || input[position] == 'E')) {
                ++position;
                if (position < input.size() && (input[position] == '+' || input[position] == '-')) ++position;
                digits();
            }
            result.scalar = input.substr(start, position - start);
        }
        return result;
    }
public:
    explicit Parser(std::string_view text) : input(text) {}
    Json parse(bool object_only = true) {
        auto result = value(0);
        space();
        if (position != input.size() || (object_only && result.kind != Json::object)) fail();
        return result;
    }
};
}
