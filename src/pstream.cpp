#include "opensabba/pstream.hpp"

#include <limits>
#include <algorithm>
#include <optional>
#include <utility>

namespace opensabba::pstream {
namespace {
constexpr std::uint8_t null_tag = 0x00, integer_tag = 0x01, string_tag = 0x10;
constexpr std::uint8_t buffer_tag = 0x20, end_tag = 0x40, array_tag = 0x41, object_tag = 0x42;

class Budget {
public:
    explicit Budget(Limits limits) : limits_(limits) {}
    void visit(std::size_t depth) {
        if (depth > limits_.max_depth) throw Error("nesting limit exceeded");
        if (nodes_ == limits_.max_nodes) throw Error("node limit exceeded");
        ++nodes_;
    }
protected:
    Limits limits_;
private:
    std::size_t nodes_ = 0;
};

class Writer : public Budget {
public:
    explicit Writer(Limits limits) : Budget(limits) {}
    Bytes run(const Value& value) {
        write(value, 0);
        return std::move(out_);
    }
private:
    Bytes out_;
    void byte(std::uint8_t value) {
        if (out_.size() == limits_.max_bytes) throw Error("byte limit exceeded");
        out_.push_back(value);
    }
    void number(std::uint64_t value, unsigned width) {
        for (unsigned i = width; i > 0; --i)
            byte(static_cast<std::uint8_t>(value >> ((i - 1) * 8)));
    }
    void string(const std::string& value) {
        if (value.size() > std::numeric_limits<std::uint16_t>::max())
            throw Error("string exceeds the 16-bit wire length");
        byte(string_tag);
        number(value.size(), 2);
        for (unsigned char ch : value) byte(ch);
    }
    void write(const Value& value, std::size_t depth) {
        visit(depth);
        std::visit([&](const auto& item) { payload(item, depth); }, value.data);
    }
    void payload(std::monostate, std::size_t) { byte(null_tag); byte(0); }
    void payload(std::uint64_t value, std::size_t) {
        unsigned width = value <= 0xff ? 1 : value <= 0xffff ? 2 :
                         value <= 0xffffffffULL ? 4 : 8;
        byte(integer_tag);
        byte(static_cast<std::uint8_t>(width));
        number(value, width);
    }
    void payload(const std::string& value, std::size_t) { string(value); }
    void payload(const Bytes& value, std::size_t) {
        if (value.size() > std::numeric_limits<std::uint32_t>::max())
            throw Error("buffer exceeds the 32-bit wire length");
        byte(buffer_tag);
        number(value.size(), 4);
        for (auto ch : value) byte(ch);
    }
    void payload(const Value::Array& value, std::size_t depth) {
        byte(array_tag);
        for (const auto& item : value) write(item, depth + 1);
        byte(end_tag);
    }
    void payload(const Value::Object& value, std::size_t depth) {
        byte(object_tag);
        for (const auto& [key, item] : value) {
            visit(depth + 1);
            string(key);
            write(item, depth + 1);
        }
        byte(end_tag);
    }
};

class Reader : public Budget {
public:
    Reader(const ReadExact& source, Limits limits) : Budget(limits), source_(source) {}
    Value run() { return read(0); }
private:
    const ReadExact& source_;
    std::size_t consumed_ = 0;
    std::optional<std::uint8_t> lookahead_;
    void fill(std::span<std::uint8_t> output) {
        if (output.size() > limits_.max_bytes - consumed_) throw Error("byte limit exceeded");
        if (!output.empty()) source_(output);
        consumed_ += output.size();
    }
    std::uint8_t peek() {
        if (!lookahead_) {
            std::uint8_t value;
            fill(std::span(&value, 1));
            lookahead_ = value;
        }
        return *lookahead_;
    }
    std::uint8_t byte() {
        auto result = peek();
        lookahead_.reset();
        return result;
    }
    std::uint64_t number(unsigned width) {
        std::uint64_t value = 0;
        for (unsigned i = 0; i < width; ++i) value = (value << 8) | byte();
        return value;
    }
    Bytes take(std::size_t count) {
        if (count > limits_.max_bytes - consumed_) throw Error("byte limit exceeded");
        Bytes result(count);
        fill(result);
        return result;
    }
    std::string string() {
        auto raw = take(static_cast<std::size_t>(number(2)));
        return std::string(raw.begin(), raw.end());
    }
    Value read(std::size_t depth) {
        visit(depth);
        switch (byte()) {
        case null_tag:
            if (byte() != 0) throw Error("invalid null length");
            return {};
        case integer_tag: {
            auto width = byte();
            if (width != 1 && width != 2 && width != 4 && width != 8)
                throw Error("unsupported integer width");
            return Value{number(width)};
        }
        case string_tag: return Value{string()};
        case buffer_tag: {
            auto raw = take(static_cast<std::size_t>(number(4)));
            return Value{std::move(raw)};
        }
        case array_tag: {
            Value::Array result;
            while (peek() != end_tag) result.push_back(read(depth + 1));
            byte();
            return Value{std::move(result)};
        }
        case object_tag: {
            Value::Object result;
            while (peek() != end_tag) {
                visit(depth + 1);
                if (byte() != string_tag) throw Error("map key must be a string");
                auto key = string();
                auto item = read(depth + 1);
                if (!result.emplace(std::move(key), std::move(item)).second)
                    throw Error("duplicate map key");
            }
            byte();
            return Value{std::move(result)};
        }
        case 0x30:
        case 0x43: throw Error("streamed-file values are not implemented");
        case end_tag: throw Error("unexpected container terminator");
        default: throw Error("unknown value tag");
        }
    }
};
} // namespace

Bytes encode(const Value& value, Limits limits) { return Writer(limits).run(value); }
Value decode(std::span<const std::uint8_t> bytes, Limits limits) {
    if (bytes.size() > limits.max_bytes) throw Error("byte limit exceeded");
    std::size_t pos = 0;
    auto result = read([&](std::span<std::uint8_t> output) {
        if (output.size() > bytes.size() - pos) throw Error("truncated value");
        std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(pos), output.size(), output.begin());
        pos += output.size();
    }, limits);
    if (pos != bytes.size()) throw Error("trailing bytes after root value");
    return result;
}
Value read(const ReadExact& source, Limits limits) { return Reader(source, limits).run(); }
} // namespace opensabba::pstream
