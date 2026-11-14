#include "opensabba/service_process.hpp"
#include "opensabba/pstream.hpp"
#include <utility>
#ifdef __linux__
#include <cerrno>
#include <cstdio>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#endif

namespace opensabba {
bool daemonize_service() {
#ifdef __linux__
    const auto child = fork();
    if (child < 0) throw pstream::Error("failed to fork service");
    if (child > 0) return false;
    setsid();
    const auto grandchild = fork();
    if (grandchild < 0) throw pstream::Error("failed to fork service grandchild");
    return grandchild == 0;
#else
    throw pstream::Error("service daemonization requires Linux");
#endif
}

ServicePidFile::ServicePidFile(std::filesystem::path path) : path_(std::move(path)) {
#ifdef __linux__
    auto* file = fopen(path_.c_str(),"w");
    if (!file) throw pstream::Error("failed to create service PID file");
    fprintf(file,"%d\n",getpid());
    fclose(file);
    // the official agent logs a chmod error and proceeds after successfully opening the file.
    if (chmod(path_.c_str(),0644) < 0)
        syslog(LOG_ERR,"failed to chmod service PID file at '%s' (%d)",path_.c_str(),errno);
#else
    throw pstream::Error("service PID files require Linux");
#endif
}

ServicePidFile::~ServicePidFile() {
#ifdef __linux__
    unlink(path_.c_str());
#endif
}
}
