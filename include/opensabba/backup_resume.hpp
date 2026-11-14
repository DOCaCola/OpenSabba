#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <string_view>

namespace opensabba {
// Decode Linux resume-state image counters against the exact registered names.
// An empty record means no persisted intervals. Unknown images are refused.
std::uint64_t backup_resume_offset(std::string_view json, std::string_view image,
                                   std::uint64_t image_size);
std::map<std::string,std::uint64_t> backup_resume_offsets(
    std::string_view json, const std::map<std::string,std::uint64_t>& image_sizes,
    std::map<std::string,std::uint64_t>* transferred = nullptr);
}
