// Child process execution with captured output.
#pragma once

#include "platform.hpp"

#include <string>

namespace luna {

struct ExecResult {
    DWORD exit_code = 0;
    std::string output;
    bool timed_out = false;
    bool started = false;
    std::string error;

    bool ok() const { return started && !timed_out; }
};

// Runs `command_line` through %COMSPEC% /c and captures stdout+stderr.
ExecResult run_shell(const std::string& command_line, DWORD timeout_ms = 60000);

// Runs a single executable with an explicit argument vector, no shell involved.
ExecResult run_exe(const std::string& exe, const std::string& args,
                   DWORD timeout_ms = 60000);

}  // namespace luna
