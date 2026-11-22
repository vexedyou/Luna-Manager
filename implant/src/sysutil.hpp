// Windows helpers: text conversion, error formatting, token facts.
#pragma once

#include "platform.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace luna {

std::string to_utf8(const std::wstring& wide);
std::wstring to_wide(const std::string& utf8);
std::string last_error(DWORD code = 0);

struct TokenInfo {
    std::string user;        // DOMAIN\user
    std::string sid;         // S-1-5-...
    std::string integrity;   // Low / Medium / High / System
    bool elevated = false;
};

TokenInfo token_info();
std::string computer_name();
std::string os_version();
std::string architecture();
std::vector<std::string> privileges();

std::string file_time_to_iso(const FILETIME& ft);
std::uint64_t file_time_to_unix(const FILETIME& ft);
std::string join_path(const std::string& base, const std::string& name);

}  // namespace luna
