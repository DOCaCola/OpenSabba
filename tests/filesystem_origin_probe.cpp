#include "opensabba/snapshot_driver.hpp"
#include <iostream>

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    try {
        const auto value = opensabba::snapshot_origin_identity(argv[1]);
        const auto& fields = std::get<opensabba::pstream::Value::Object>(value.data);
        std::cout << std::get<std::string>(fields.at("filesystem_uuid").data)
                  << ' ' << std::get<std::uint64_t>(fields.at("size").data) << '\n';
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
