#include "opensabba/client.hpp"
#include "opensabba/image.hpp"
#include <csignal>
#include <fstream>
#include <iostream>

int main(int argc, char** argv) {
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif
    try {
        if (argc == 3) {
            opensabba::ImageSource source(argv[2]);
            bool cancelled = false;
            opensabba::stream_image(source, "test-image", 512, [&](const auto&) {
                if (std::string_view(argv[1]) == "mutate") {
                    std::fstream modify(argv[2], std::ios::binary | std::ios::in | std::ios::out);
                    modify.put('X');
                    modify.flush();
                } else cancelled = true;
            }, [&] { return cancelled; });
        } else if (argc == 5) {
            opensabba::Endpoint endpoint;
            endpoint.host = "127.0.0.1";
            endpoint.port = static_cast<std::uint16_t>(std::stoul(argv[1]));
            endpoint.ca_file = argv[2];
            endpoint.timeout = std::chrono::seconds{3};
            const opensabba::SavedAuth auth{"test-user", "test-uuid", "test-token", "test-nas"};
            opensabba::upload_prepared_image(endpoint, auth, 27, argv[3], argv[4], 1024 * 1024);
        } else throw std::runtime_error("invalid test driver arguments");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
