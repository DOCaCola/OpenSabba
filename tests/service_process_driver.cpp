#include "opensabba/service_process.hpp"
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

namespace {
volatile std::sig_atomic_t stopped = 0;
void stop(int) { stopped = 1; }
}
int main(int argc, char** argv) {
    if (argc != 4) return 2;
    try {
        if (const auto status = opensabba::daemonize_service()) return *status;
        if (std::string_view(argv[3]) == "early-fail") throw std::runtime_error("failed before PID file");
        for (const auto signal : {SIGHUP,SIGINT,SIGQUIT,SIGTERM}) std::signal(signal,stop);
        opensabba::ServicePidFile pid(argv[1]);
        if (std::string_view(argv[3]) == "fail") throw std::runtime_error("initialization failed");
        const auto mask = umask(0);
        umask(mask);
        std::ofstream evidence(argv[2]);
        evidence << getpid() << '\n' << getsid(0) << '\n' << getpgrp() << '\n'
                 << std::filesystem::current_path().string() << '\n' << mask << '\n';
        evidence.close();
        std::cout << "daemon standard output retained\n" << std::flush;
        while (!stopped) usleep(10000);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
