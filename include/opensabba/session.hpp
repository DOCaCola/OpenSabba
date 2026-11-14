#pragma once

#include "opensabba/client.hpp"
#include <filesystem>

namespace opensabba {
// Typed dependency seam for in-process transport/input fixtures. The installed
// CLI does not populate it and exposes no flag or environment counterpart.
struct SessionInvocation {
    bool noninteractive_credentials = false;
    std::function<void(Endpoint&)> prepare_endpoint;
};
int session_command(int argc, char** argv,const SessionInvocation& invocation = {});
Endpoint saved_endpoint();
void load_saved_server_time();
int export_logs_command(const std::filesystem::path& output = {}, bool quiet = false);
}
