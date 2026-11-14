#include "opensabba/agent_config.hpp"
#include <chrono>
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace opensabba;
int main() {
    try {
        const auto directory = std::filesystem::temp_directory_path() /
            ("opensabba-agent-config-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directory(directory);
        struct Cleanup {
            std::filesystem::path path;
            ~Cleanup() { std::error_code ignored; std::filesystem::remove_all(path,ignored); }
        } cleanup{directory};
        const auto file = directory/"agent.config";
        const auto check = [](bool value) { if (!value) throw std::runtime_error("agent configuration invariant failed"); };
        check(read_disconnect_timeout(file) == 1800);
        check(read_disconnect_timeout(directory) == 1800);
        const auto config = [&](std::string text, std::uint32_t expected) {
            { std::ofstream output(file); output << text; }
            check(read_disconnect_timeout(file) == expected);
        };
        config("",1800);
        config("# official minutes\n EventTimeout = 2 # comment\n",120);
        config("EventTimeout='3'\n",180);
        config("EventTimeout=\" 4 minutes\"\n",240); // get_int consumes a decimal prefix.
        config("EventTimeout=0\n",1800);
        config("EventTimeout=-1\n",1800);
        config("EventTimeout=bad\n",1800);
        config("eventtimeout=9\n",1800);
        config("EventTimeout=9\nEventTimeout=2\n",120);
        config("EventTimeout=2\nmalformed setting\n",1800); // Entire map is discarded.
        config("EventTimeout='2\n",1800);
        config("EventTimeout=2 junk\n",1800);
        config("EventTimeout=+2\n",120);
        config("EventTimeout=1073741824\n",0); // the official agent 32-bit multiplication wraps.
        config("EventTimeout=2147483647\n",static_cast<std::uint32_t>(2147483647)*std::uint32_t{60});
        check(!backup_disconnect_expired(0,120,99999));
        check(!backup_disconnect_expired(100,0,99999));
        check(!backup_disconnect_expired(100,120,99));
        check(!backup_disconnect_expired(100,120,219));
        check(backup_disconnect_expired(100,120,220));
        check(backup_disconnect_expired(100,120,221));
        check(!backup_disconnect_expired(100,120,-1));
        std::cout << "Official agent EventTimeout parsing and disconnect expiry passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
