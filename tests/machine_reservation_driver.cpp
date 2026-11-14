#include "opensabba/machine_capture.hpp"
#include <fstream>
#include <iostream>

using namespace opensabba;
using namespace opensabba::pstream;
Value load(const char* name) {
    std::ifstream input(name,std::ios::binary);
    if (!input) throw Error("cannot read reservation fixture");
    const Bytes bytes((std::istreambuf_iterator<char>(input)),{});
    return decode(bytes,{24*1024*1024,1000000,20});
}
int main(int argc, char** argv) {
    try {
        if (argc == 4 && std::string_view(argv[1]) == "verify") {
            verify_machine_reservation(capture_journal_from_value(load(argv[2])),
                                       capture_journal_from_value(load(argv[3])));
        } else if (argc == 3 && std::string_view(argv[1]) == "target") {
            const auto bytes = encode(machine_capture_target(load(argv[2])));
            std::cout.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));
        } else throw Error("invalid reservation test arguments");
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
