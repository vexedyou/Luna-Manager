// Capability-gated command dispatch table.
#pragma once

#include "json.hpp"
#include "modules.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace luna {

struct DispatchEntry {
    const char* kind;
    std::uint32_t bit;
    Result (*handler)(const Json&, AgentState&);
};

const std::vector<DispatchEntry>& dispatch_table();

// Returns false when the kind is unknown or the bit is not in LUNA_CAP_MASK.
bool dispatch(const std::string& kind, const Json& args, AgentState& state,
              Result& out);

}  // namespace luna
