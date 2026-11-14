#pragma once
#include "opensabba/cli.hpp"
namespace opensabba {
CliArguments parse_lab_cli(int,char**);
int lab_session_command(int,char**);
int lab_connection_command(int,char**);
int lab_machine_capture_command(int,char**);
int lab_image_command(int,char**);
}
