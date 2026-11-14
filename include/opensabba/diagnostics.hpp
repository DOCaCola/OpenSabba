#pragma once
#include "opensabba/pstream.hpp"
#include <functional>
#include <optional>

namespace opensabba {
// Reads only the fixed set of current journals. Reader errors are reported
// without copying potentially sensitive exception text.
using DiagnosticReader = std::function<std::optional<pstream::Value>(const char*)>;
pstream::Value diagnostic_report(const DiagnosticReader&);
pstream::Value diagnostic_summary(const pstream::Value&);
}
