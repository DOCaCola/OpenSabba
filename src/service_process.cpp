#include "opensabba/service_process.hpp"
#include "opensabba/pstream.hpp"
#include <utility>
#ifdef __linux__
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#endif

namespace opensabba {
#ifdef __linux__
namespace {
int launcher_release = -1; // Daemon's write end until its PID file exists.
}
#endif

std::optional<int> daemonize_service() {
#ifdef __linux__
    int ready[2];
    if (pipe2(ready,O_CLOEXEC) < 0) throw pstream::Error("failed to create service readiness pipe");
    const auto child = fork();
    if (child < 0) throw pstream::Error("failed to fork service");
    if (child > 0) {
        close(ready[1]);
        char byte;
        ssize_t received;
        do received = read(ready[0],&byte,1); while (received < 0 && errno == EINTR);
        close(ready[0]);
        return received == 1 ? 0 : 1;
    }
    close(ready[0]);
    setsid();
    const auto grandchild = fork();
    if (grandchild < 0) throw pstream::Error("failed to fork service grandchild");
    if (grandchild > 0) {
        close(ready[1]);
        return 0;
    }
    launcher_release = ready[1];
    return std::nullopt;
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
    if (launcher_release >= 0) {
        const char ready = 1;
        ssize_t written;
        do written = write(launcher_release,&ready,1); while (written < 0 && errno == EINTR);
        close(launcher_release);
        launcher_release = -1;
    }
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
