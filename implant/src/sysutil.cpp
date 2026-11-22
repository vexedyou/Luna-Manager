#include "sysutil.hpp"

#include <sddl.h>

#include <cstdio>
#include <ctime>

#pragma comment(lib, "advapi32.lib")

namespace luna {

std::string to_utf8(const std::wstring& wide) {
    if (wide.empty()) return {};
    const int need = WideCharToMultiByte(CP_UTF8, 0, wide.data(),
                                         static_cast<int>(wide.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string out(static_cast<std::size_t>(need), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                        out.data(), need, nullptr, nullptr);
    return out;
}

std::wstring to_wide(const std::string& utf8) {
    if (utf8.empty()) return {};
    const int need = MultiByteToWideChar(CP_UTF8, 0, utf8.data(),
                                         static_cast<int>(utf8.size()), nullptr, 0);
    if (need <= 0) return {};
    std::wstring out(static_cast<std::size_t>(need), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()),
                        out.data(), need);
    return out;
}

namespace {

std::string hex32(DWORD value) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%08lX", static_cast<unsigned long>(value));
    return buf;
}

}  // namespace

std::string last_error(DWORD code) {
    if (code == 0) code = GetLastError();
    LPWSTR buffer = nullptr;
    const DWORD len = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::string text;
    if (len && buffer) {
        text = to_utf8(std::wstring(buffer, len));
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) {
            text.pop_back();
        }
    }
    if (buffer) LocalFree(buffer);
    if (text.empty()) text = "error";
    return text + " (" + hex32(code) + ")";
}

TokenInfo token_info() {
    TokenInfo info;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        info.user = "unknown";
        return info;
    }

    DWORD len = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &len);
    std::vector<std::uint8_t> buf(len ? len : 256);
    if (GetTokenInformation(token, TokenUser, buf.data(), static_cast<DWORD>(buf.size()), &len)) {
        auto* user = reinterpret_cast<TOKEN_USER*>(buf.data());
        LPWSTR sid_str = nullptr;
        if (ConvertSidToStringSidW(user->User.Sid, &sid_str)) {
            info.sid = to_utf8(sid_str);
            LocalFree(sid_str);
        }
        wchar_t name[256] = {};
        wchar_t domain[256] = {};
        DWORD name_len = 256, domain_len = 256;
        SID_NAME_USE use{};
        if (LookupAccountSidW(nullptr, user->User.Sid, name, &name_len, domain,
                              &domain_len, &use)) {
            info.user = to_utf8(std::wstring(domain) + L"\\" + name);
        } else {
            info.user = info.sid;
        }
    }

    DWORD elevated = 0;
    if (GetTokenInformation(token, TokenElevation, &elevated, sizeof(elevated), &len)) {
        info.elevated = elevated != 0;
    }

    // integrity level
    std::uint8_t label_buf[512] = {};
    if (GetTokenInformation(token, TokenIntegrityLevel, label_buf,
                            static_cast<DWORD>(sizeof(label_buf)), &len)) {
        auto* label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(label_buf);
        const DWORD rid = *GetSidSubAuthority(
            label->Label.Sid, *GetSidSubAuthorityCount(label->Label.Sid) - 1);
        if (rid < SECURITY_MANDATORY_MEDIUM_RID) info.integrity = "Low";
        else if (rid < SECURITY_MANDATORY_HIGH_RID) info.integrity = "Medium";
        else if (rid < SECURITY_MANDATORY_SYSTEM_RID) info.integrity = "High";
        else info.integrity = "System";
    }

    CloseHandle(token);
    return info;
}

std::string computer_name() {
    wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD len = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(buf, &len)) return "unknown";
    return to_utf8(buf);
}

std::string os_version() {
    OSVERSIONINFOW vi{};
    vi.dwOSVersionInfoSize = sizeof(vi);
#pragma warning(push)
#pragma warning(disable : 4996)
    if (!GetVersionExW(&vi)) return "Windows";
#pragma warning(pop)
    char buf[64];
    std::snprintf(buf, sizeof(buf), "Windows %lu.%lu.%lu",
                  static_cast<unsigned long>(vi.dwMajorVersion),
                  static_cast<unsigned long>(vi.dwMinorVersion),
                  static_cast<unsigned long>(vi.dwBuildNumber));
    return buf;
}

std::string architecture() {
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: return "x64";
        case PROCESSOR_ARCHITECTURE_ARM64: return "arm64";
        case PROCESSOR_ARCHITECTURE_INTEL: return "x86";
        default: return "unknown";
    }
}

std::vector<std::string> privileges() {
    std::vector<std::string> out;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token)) {
        return out;
    }
    DWORD len = 0;
    GetTokenInformation(token, TokenPrivileges, nullptr, 0, &len);
    std::vector<std::uint8_t> buf(len ? len : 256);
    if (GetTokenInformation(token, TokenPrivileges, buf.data(),
                            static_cast<DWORD>(buf.size()), &len)) {
        auto* privs = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data());
        for (DWORD i = 0; i < privs->PrivilegeCount; ++i) {
            wchar_t name[256] = {};
            DWORD name_len = 256;
            if (LookupPrivilegeNameW(nullptr, &privs->Privileges[i].Luid, name, &name_len)) {
                std::string entry = to_utf8(name);
                entry += " [";
                entry += (privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "enabled" : "disabled";
                entry += "]";
                out.push_back(entry);
            }
        }
    }
    CloseHandle(token);
    return out;
}

std::uint64_t file_time_to_unix(const FILETIME& ft) {
    ULARGE_INTEGER v{};
    v.LowPart = ft.dwLowDateTime;
    v.HighPart = ft.dwHighDateTime;
    return (v.QuadPart / 10000000ULL) - 11644473600ULL;
}

std::string file_time_to_iso(const FILETIME& ft) {
    const std::uint64_t unix_s = file_time_to_unix(ft);
    std::time_t t = static_cast<std::time_t>(unix_s);
    std::tm tm{};
    gmtime_s(&tm, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

std::string join_path(const std::string& base, const std::string& name) {
    if (base.empty()) return name;
    const char last = base.back();
    if (last == '\\' || last == '/') return base + name;
    return base + "\\" + name;
}

}  // namespace luna
