#include "dispatch.hpp"

#include "luna_config.hpp"

namespace luna {

const std::vector<DispatchEntry>& dispatch_table() {
    static const std::vector<DispatchEntry> kTable = {
        {"shell",    0x0001, handle_shell},
        {"pwd",      0x0002, handle_pwd},
        {"cd",       0x0004, handle_cd},
        {"ls",       0x0008, handle_ls},
        {"cat",      0x0010, handle_cat},
        {"upload",   0x0020, handle_upload},
        {"download", 0x0040, handle_download},
        {"rm",       0x0080, handle_rm},
        {"mkdir",    0x0100, handle_mkdir},
        {"ps",       0x0200, handle_ps},
        {"kill",     0x0400, handle_kill},
        {"env",      0x0800, handle_env},
        {"sysinfo",  0x1000, handle_sysinfo},
        {"sleep",    0x2000, handle_sleep},
        {"exit",     0x4000, handle_exit},
        {"whoami",   0x8000, handle_whoami},
    };
    return kTable;
}

bool dispatch(const std::string& kind, const Json& args, AgentState& state,
              Result& out) {
    for (const auto& entry : dispatch_table()) {
        if (kind != entry.kind) continue;
        if ((LUNA_CAP_MASK & entry.bit) == 0) {
            out.ok = false;
            out.err = "capability " + kind + " not compiled into this build";
            return false;
        }
        out = entry.handler(args, state);
        return true;
    }
    out.ok = false;
    out.err = "unknown task kind: " + kind;
    return false;
}

}  // namespace luna
