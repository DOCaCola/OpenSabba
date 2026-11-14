#pragma once
#include "opensabba/pstream.hpp"
#include <algorithm>
#include <array>
#include <functional>
#include <string>
#include <string_view>
#include <vector>
#include <utility>

namespace opensabba::detail {
// Streaming ZIP64 stored entries. Callbacks keep the format independent of
// platform file APIs and allow the same writer to be verified on the host.
class DiagnosticZip {
    std::function<void(std::string_view)> write_;
    std::uint64_t offset_ = 0;
    struct Entry { std::string name; std::uint64_t offset, size; std::uint32_t crc; };
    std::vector<Entry> entries_;
    void bytes(std::string_view value) { write_(value); offset_ += value.size(); }
    void integer(std::uint64_t value, unsigned size) {
        std::array<char,8> buffer{};
        for (unsigned i = 0; i < size; ++i) buffer[i] = static_cast<char>(value >> (i*8));
        bytes(std::string_view(buffer.data(),size));
    }
public:
    explicit DiagnosticZip(std::function<void(std::string_view)> write) : write_(std::move(write)) {}
    void add(const std::string& name, const std::function<std::size_t(char*,std::size_t)>& read) {
        if (name.empty() || name.size() > 65535 || name[0] == '/' ||
            name.find("../") != name.npos || name.find('\\') != name.npos)
            throw pstream::Error("invalid diagnostic archive entry");
        Entry entry{name,offset_,0,0xffffffff};
        integer(0x04034b50,4); integer(45,2); integer(0x808,2);
        integer(0,2); integer(0,2); integer(0x21,2); integer(0,4);
        integer(0xffffffff,4); integer(0xffffffff,4);
        integer(name.size(),2); integer(20,2); bytes(name);
        integer(1,2); integer(16,2); integer(0,8); integer(0,8);
        std::array<char,65536> buffer{};
        for (;;) {
            const auto count = read(buffer.data(),buffer.size());
            if (!count) break;
            for (std::size_t i = 0; i < count; ++i) {
                entry.crc ^= static_cast<unsigned char>(buffer[i]);
                for (unsigned bit = 0; bit < 8; ++bit)
                    entry.crc = (entry.crc >> 1) ^ (0xedb88320U & (0U-(entry.crc & 1U)));
            }
            bytes(std::string_view(buffer.data(),count));
            entry.size += count;
        }
        entry.crc ^= 0xffffffff;
        integer(0x08074b50,4); integer(entry.crc,4); integer(entry.size,8); integer(entry.size,8);
        entries_.push_back(std::move(entry));
    }
    void text(const std::string& name, const std::string& value) {
        std::size_t at = 0;
        add(name,[&](char* buffer, std::size_t size) {
            const auto count = std::min(size,value.size()-at);
            std::copy_n(value.data()+at,count,buffer);
            at += count;
            return count;
        });
    }
    void finish() {
        const auto central = offset_;
        for (const auto& entry : entries_) {
            integer(0x02014b50,4); integer(0x32d,2); integer(45,2); integer(0x808,2);
            integer(0,2); integer(0,2); integer(0x21,2); integer(entry.crc,4);
            integer(0xffffffff,4); integer(0xffffffff,4);
            integer(entry.name.size(),2); integer(28,2); integer(0,2); integer(0,2);
            integer(0,2); integer(0100600U << 16,4); integer(0xffffffff,4); bytes(entry.name);
            integer(1,2); integer(24,2); integer(entry.size,8); integer(entry.size,8); integer(entry.offset,8);
        }
        const auto central_size = offset_-central;
        const auto end = offset_;
        integer(0x06064b50,4); integer(44,8); integer(45,2); integer(45,2);
        integer(0,4); integer(0,4); integer(entries_.size(),8); integer(entries_.size(),8);
        integer(central_size,8); integer(central,8);
        integer(0x07064b50,4); integer(0,4); integer(end,8); integer(1,4);
        integer(0x06054b50,4); integer(0,2); integer(0,2); integer(0xffff,2);
        integer(0xffff,2); integer(0xffffffff,4); integer(0xffffffff,4); integer(0,2);
    }
};
}
