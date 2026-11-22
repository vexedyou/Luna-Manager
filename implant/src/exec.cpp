#include "exec.hpp"

#include "sysutil.hpp"

#include <vector>

namespace luna {

namespace {

ExecResult run_impl(const std::wstring& application, const std::wstring& command_line,
                    DWORD timeout_ms) {
    ExecResult result;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE out_read = nullptr, out_write = nullptr;
    if (!CreatePipe(&out_read, &out_write, &sa, 0)) {
        result.error = last_error();
        return result;
    }
    SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);

    HANDLE nul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                             OPEN_EXISTING, 0, nullptr);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = out_write;
    si.hStdError = out_write;
    si.hStdInput = (nul != INVALID_HANDLE_VALUE) ? nul : nullptr;

    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> mutable_cmd(command_line.begin(), command_line.end());
    mutable_cmd.push_back(L'\0');

    const DWORD flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
    const BOOL created = CreateProcessW(
        application.empty() ? nullptr : application.c_str(),
        mutable_cmd.data(), nullptr, nullptr, TRUE, flags, nullptr, nullptr, &si, &pi);

    CloseHandle(out_write);
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);

    if (!created) {
        result.error = last_error();
        CloseHandle(out_read);
        return result;
    }
    result.started = true;

    char buffer[4096];
    const ULONGLONG deadline = GetTickCount64() + timeout_ms;
    for (;;) {
        DWORD available = 0;
        if (PeekNamedPipe(out_read, nullptr, 0, nullptr, &available, nullptr) && available) {
            DWORD read = 0;
            const DWORD want = available < sizeof(buffer) ? available : sizeof(buffer);
            if (ReadFile(out_read, buffer, want, &read, nullptr) && read) {
                result.output.append(buffer, read);
                continue;
            }
        }
        if (WaitForSingleObject(pi.hProcess, 25) == WAIT_OBJECT_0) break;
        if (GetTickCount64() > deadline) {
            result.timed_out = true;
            TerminateProcess(pi.hProcess, 1);
            break;
        }
    }

    // drain whatever is left in the pipe
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(out_read, buffer, sizeof(buffer), &read, nullptr) || read == 0) break;
        result.output.append(buffer, read);
    }

    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    result.exit_code = code;

    CloseHandle(out_read);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return result;
}

}  // namespace

ExecResult run_shell(const std::string& command_line, DWORD timeout_ms) {
    wchar_t comspec[MAX_PATH * 2] = {};
    DWORD len = GetEnvironmentVariableW(L"COMSPEC", comspec, MAX_PATH * 2);
    std::wstring shell = (len > 0 && len < MAX_PATH * 2) ? std::wstring(comspec) : L"C:\\Windows\\System32\\cmd.exe";
    std::wstring full = L"\"" + shell + L"\" /c " + to_wide(command_line);
    return run_impl(shell, full, timeout_ms);
}

ExecResult run_exe(const std::string& exe, const std::string& args, DWORD timeout_ms) {
    return run_impl(to_wide(exe), to_wide("\"" + exe + "\" " + args), timeout_ms);
}

}  // namespace luna
