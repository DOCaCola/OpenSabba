#include "opensabba/backup_resume.hpp"
#include "opensabba/pstream.hpp"
#include <charconv>
#include <map>
#include <set>
#include <string>

namespace opensabba {
namespace {
using pstream::Error;
class CheckpointReader {
    std::string_view input_;
    std::size_t at_ = 0;
public:
    explicit CheckpointReader(std::string_view input) : input_(input) {
        if (input.size() > 64*1024) throw Error("backup resume information exceeds the supported size");
    }
    void space() {
        while (at_ < input_.size() && (input_[at_] == ' ' || input_[at_] == '\t' ||
               input_[at_] == '\r' || input_[at_] == '\n')) ++at_;
    }
    bool take(char c) {
        space();
        if (at_ == input_.size() || input_[at_] != c) return false;
        ++at_;
        return true;
    }
    void expect(char c) {
        if (!take(c)) throw Error("invalid backup resume JSON");
    }
    void end() {
        space();
        if (at_ != input_.size()) throw Error("trailing data in backup resume JSON");
    }
    void null() {
        space();
        if (input_.substr(at_, 4) != "null")
            throw Error("non-Linux progress in backup resume information");
        at_ += 4;
    }
    std::string string() {
        expect('"');
        std::string result;
        while (at_ < input_.size()) {
            unsigned char c = static_cast<unsigned char>(input_[at_++]);
            if (c == '"') return result;
            if (c == '\\') {
                if (at_ == input_.size()) break;
                c = static_cast<unsigned char>(input_[at_++]);
                switch (c) {
                case '"': case '\\': case '/': break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'u': {
                    if (input_.size()-at_ < 4) throw Error("truncated backup resume JSON escape");
                    unsigned int code{};
                    const auto [last, error] = std::from_chars(input_.data()+at_, input_.data()+at_+4, code, 16);
                    if (error != std::errc{} || last != input_.data()+at_+4 || code > 127)
                        throw Error("backup resume keys and counters must be ASCII");
                    at_ += 4;
                    c = static_cast<unsigned char>(code);
                    break;
                }
                default: throw Error("invalid backup resume JSON escape");
                }
            } else if (c < 32 || c > 127) {
                throw Error("invalid backup resume JSON string");
            }
            result += static_cast<char>(c);
        }
        throw Error("unterminated backup resume JSON string");
    }
};
std::uint64_t counter(const std::string& value) {
    std::uint64_t result{};
    const auto [last, error] = std::from_chars(value.data(), value.data()+value.size(), result);
    if (value.empty() || error != std::errc{} || last != value.data()+value.size())
        throw Error("invalid backup resume byte count");
    return result;
}
}
std::map<std::string,std::uint64_t> backup_resume_offsets(
    std::string_view json, const std::map<std::string,std::uint64_t>& sizes,
    std::map<std::string,std::uint64_t>* transferred) {
    if (sizes.empty()) throw Error("backup resume has no expected images");
    std::map<std::string,std::uint64_t> offsets;
    std::set<std::string> seen;
    for (const auto& [name,size] : sizes) offsets.emplace(name,0);
    if (transferred) *transferred = offsets;
    if (json.empty()) return offsets; // Resume lookup returns "" when no intervals exist.
    CheckpointReader reader(json);
    reader.expect('{');
    if (reader.take('}')) { reader.end(); return offsets; }
    do {
    const auto image = reader.string();
    if (!sizes.contains(image) || !seen.insert(image).second)
        throw Error("NAS resume information belongs to a different image");
    reader.expect(':');
    reader.expect('{');
    std::map<std::string, std::string> values;
    if (!reader.take('}')) {
        do {
            const auto key = reader.string();
            reader.expect(':');
            if (values.contains(key)) throw Error("duplicate backup resume field");
            if (key == "mac_progress") {
                reader.null();
                values.emplace(key, "");
            } else if (key == "current" || key == "transfer_current") {
                values.emplace(key, reader.string());
            } else throw Error("unsupported backup resume field");
        } while (reader.take(','));
        reader.expect('}');
    }
    if (!values.contains("current") || !values.contains("transfer_current"))
        throw Error("NAS resume information is missing byte counters");
    const auto offset = counter(values.at("current"));
    // Transfer bytes may exceed image size for incompressible LZ4 blocks.
    const auto transfer = counter(values.at("transfer_current"));
    if (transferred) transferred->at(image) = transfer;
    if (offset > sizes.at(image) || offset % 512)
        throw Error("NAS backup checkpoint is outside the saved image");
    offsets[image] = offset;
    } while (reader.take(','));
    reader.expect('}');
    reader.end();
    return offsets;
}
std::uint64_t backup_resume_offset(std::string_view json, std::string_view image, std::uint64_t size) {
    return backup_resume_offsets(json,{{std::string(image),size}}).at(std::string(image));
}
}
