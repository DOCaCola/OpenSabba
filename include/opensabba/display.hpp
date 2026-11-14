#pragma once
#include "opensabba/pstream.hpp"
#include <iosfwd>

namespace opensabba {
// Diagnostic JSON; escapes every non-ASCII/control byte for terminal safety.
void print_json(std::ostream&, const pstream::Value&);
}
