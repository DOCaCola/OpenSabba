#include "opensabba/pstream.hpp"

#include <functional>
#include <iostream>
#include <limits>
#include <algorithm>

using namespace opensabba::pstream;
namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void rejects(const std::function<void()>& operation) {
    try { operation(); } catch (const Error&) { return; }
    throw std::runtime_error("invalid input was accepted");
}
void golden(Value value, Bytes wire) {
    require(encode(value) == wire, "wire encoding mismatch");
    require(decode(wire) == value, "wire decoding mismatch");
    for (std::size_t n = 0; n < wire.size(); ++n)
        rejects([&] { decode(std::span(wire).first(n)); });
}
}
int main() {
    try {
        golden({}, {0, 0});
        golden(Value{std::uint64_t{0}}, {1, 1, 0});
        golden(Value{std::uint64_t{255}}, {1, 1, 255});
        golden(Value{std::uint64_t{256}}, {1, 2, 1, 0});
        golden(Value{std::uint64_t{65535}}, {1, 2, 255, 255});
        golden(Value{std::uint64_t{65536}}, {1, 4, 0, 1, 0, 0});
        golden(Value{std::uint64_t{0xffffffffULL}}, {1, 4, 255, 255, 255, 255});
        golden(Value{std::uint64_t{0x100000000ULL}}, {1, 8, 0, 0, 0, 1, 0, 0, 0, 0});
        golden(Value{std::numeric_limits<std::uint64_t>::max()},
               {1, 8, 255, 255, 255, 255, 255, 255, 255, 255});
        golden(Value{std::string("a\0b", 3)}, {0x10, 0, 3, 'a', 0, 'b'});
        golden(Value{Bytes{0, 255}}, {0x20, 0, 0, 0, 2, 0, 255});
        golden(Value{Value::Array{}}, {0x41, 0x40});
        golden(Value{Value::Object{}}, {0x42, 0x40});
        golden(Value{Value::Object{{"x", Value{Value::Array{{}, Value{std::uint64_t{7}}}}}}},
               {0x42, 0x10, 0, 1, 'x', 0x41, 0, 0, 1, 1, 7, 0x40, 0x40});
        // Hand-authored from the documented format, not a captured NAS exchange.
        golden(Value{Value::Object{{"action", Value{std::string("query_server_info")}}}},
               {0x42, 0x10, 0, 6, 'a','c','t','i','o','n',
                0x10, 0, 17, 'q','u','e','r','y','_','s','e','r','v','e','r','_','i','n','f','o',0x40});
        for (Bytes bad : {Bytes{0, 1}, Bytes{1, 0}, Bytes{1, 3, 0, 0, 0},
                          Bytes{0x40}, Bytes{0xff}, Bytes{0x30}, Bytes{0x43},
                          Bytes{0, 0, 0}, Bytes{0x42, 1, 1, 7, 0x40},
                          Bytes{0x20, 255, 255, 255, 255},
                          Bytes{0x42, 0x10, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0x40}})
            rejects([&] { decode(bad); });
        rejects([] { encode(Value{std::string(65536, 'x')}); });
        Value longest{std::string(65535, 'x')};
        require(decode(encode(longest)) == longest, "maximum string failed");
        Value nested{Value::Array{Value{Value::Array{{}}}}};
        rejects([&] { encode(nested, Limits{1024, 100, 1}); });
        auto nested_wire = encode(nested);
        rejects([&] { decode(nested_wire, Limits{1024, 100, 1}); });
        rejects([&] { encode(nested, Limits{1024, 2, 64}); });
        rejects([&] { decode(nested_wire, Limits{1024, 2, 64}); });
        rejects([] { encode({}, Limits{1, 100, 64}); });
        rejects([] { decode(Bytes{0, 0}, Limits{1, 100, 64}); });
        // A network value must not consume any bytes of the next message/TLS record.
        Bytes sequence{0x42, 0x40, 0x41, 0x01, 0x01, 7, 0x40, 0x16, 0x03, 0x03};
        std::size_t position = 0;
        ReadExact source = [&](std::span<std::uint8_t> output) {
            require(output.size() <= sequence.size() - position, "stream read overrun");
            std::copy_n(sequence.begin() + static_cast<std::ptrdiff_t>(position),
                        output.size(), output.begin());
            position += output.size();
        };
        require(read(source) == Value{Value::Object{}}, "stream map mismatch");
        require(position == 2, "read crossed first message boundary");
        require(read(source) == Value{Value::Array{Value{std::uint64_t{7}}}},
                "stream array mismatch");
        require(position == 7, "read crossed into TLS bytes");
        // Declared length is checked before asking the source for payload bytes.
        Bytes oversized{0x20, 0, 0, 1, 0};
        position = 0;
        rejects([&] {
            read([&](std::span<std::uint8_t> output) {
                require(output.size() <= oversized.size() - position,
                        "oversized payload was requested");
                std::copy_n(oversized.begin() + static_cast<std::ptrdiff_t>(position),
                            output.size(), output.begin());
                position += output.size();
            }, Limits{32, 100, 64});
        });
        std::cout << "Protocol golden vectors, truncation, bounds, and malformed inputs passed\n";
        return 0;
    } catch (const std::exception& exc) {
        std::cerr << exc.what() << '\n';
        return 1;
    }
}
