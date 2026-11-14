#include "opensabba/certificate_trust.hpp"
#include <iostream>

int main(int argc, char** argv) {
    try {
        if (argc != 6) return 2;
        opensabba::Endpoint endpoint;
        endpoint.host = argv[1];
        endpoint.port = static_cast<std::uint16_t>(std::stoi(argv[2]));
        if (std::string_view(argv[3]) != "-") endpoint.ca_file = argv[3];
        std::optional<std::string> saved;
        if (std::string_view(argv[4]) != "-") saved = argv[4];
        const std::string_view mode(argv[5]);
        std::function<bool(const opensabba::ServerCertificate&, bool)> prompt;
        if (mode == "interactive") prompt = [](const auto&, bool) { return true; };
        endpoint.trust_certificate = opensabba::certificate_verifier(
            [&] { return saved; }, [&](const std::string& pin) { saved = pin; }, prompt, mode == "quiet");
        opensabba::probe(endpoint);
        std::cout << saved.value_or("") << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
