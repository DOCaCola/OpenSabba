#include "opensabba/client.hpp"
#include <fstream>
#include <iostream>
int main(int argc,char** argv) {
    try {
        if (argc != 2) throw opensabba::pstream::Error("expected test session");
        std::ifstream file(argv[1],std::ios::binary);
        opensabba::pstream::Bytes bytes{std::istreambuf_iterator<char>(file),{}};
        const auto value = opensabba::pstream::decode(bytes);
        const auto& fields = std::get<opensabba::pstream::Value::Object>(value.data);
        auto text = [&](const char* key) { return std::get<std::string>(fields.at(key).data); };
        opensabba::Endpoint endpoint;
        endpoint.host = text("host"); endpoint.ca_file = text("ca_file");
        endpoint.port = static_cast<std::uint16_t>(std::get<std::uint64_t>(fields.at("port").data));
        const opensabba::SavedAuth auth{text("username"),text("device_uuid"),text("token"),text("ds_id")};
        // Recovery-mode selection is a typed protocol fixture, not a product CLI option.
        opensabba::confirm_registration(endpoint,auth,{"fixture","Linux","fixture-kernel",-18000},
            {2,0,"restore"},[] {});
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
