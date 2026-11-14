#pragma once
#include <istream>
#include <ostream>
#include "opensabba/pstream.hpp"

namespace opensabba {
// The official CLI prompt8: ordinary line input, case-insensitive yes/no, default yes.
bool confirm_connection_template(std::istream&, std::ostream&);
// CLI ->. The display contains only official agent fields.
void show_connection_template(std::ostream&, const pstream::Value& content);
}
