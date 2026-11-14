#include "opensabba/client.hpp"
#include <iostream>
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    try {
        opensabba::Endpoint endpoint;
        endpoint.host = "127.0.0.1";
        endpoint.port = static_cast<std::uint16_t>(std::stoi(argv[1]));
        endpoint.ca_file = argv[2];
        const auto time = opensabba::get_server_time(endpoint,{"test-user","test-device","test-token","test-nas"});
        std::cout << time.timezone << ' ' << time.difference << ' ' << time.offset << '\n';
    } catch (const opensabba::ServerError& error) {
        std::cerr << error.what() << '\n';
        std::cerr << "get timezone failed (" << error.code.value_or(0)
                  << ": '" << error.server_message << "')\n";
        return 1;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
