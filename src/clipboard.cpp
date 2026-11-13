#include "ciphervault/clipboard.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

#include "ciphervault/crypto/sha256.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <cstdlib>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace ciphervault {
namespace {

std::string sha256_hex(const std::string& text) {
    return to_hex(Sha256::hash(text));
}

#if defined(_WIN32)

std::wstring utf8_to_wide(const std::string& text) {
    if (text.empty()) return std::wstring();
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(),
                                         static_cast<int>(text.size()), nullptr, 0);
    if (size <= 0) return std::wstring();
    std::wstring wide(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), size);
    return wide;
}

std::string wide_to_utf8(const std::wstring& text) {
    if (text.empty()) return std::string();
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (size <= 0) return std::string();
    std::string out(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size,
                        nullptr, nullptr);
    return out;
}

bool read_clipboard(std::string& out) {
    if (!OpenClipboard(nullptr)) return false;
    bool ok = false;
    HANDLE handle = GetClipboardData(CF_UNICODETEXT);
    if (handle != nullptr) {
        const auto* data = static_cast<const wchar_t*>(GlobalLock(handle));
        if (data != nullptr) {
            out = wide_to_utf8(std::wstring(data));
            GlobalUnlock(handle);
            ok = true;
        }
    }
    CloseClipboard();
    return ok;
}

bool write_clipboard(const std::string& text) {
    const std::wstring wide = utf8_to_wide(text);
    const std::size_t bytes = (wide.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (memory == nullptr) return false;
    void* target = GlobalLock(memory);
    if (target == nullptr) {
        GlobalFree(memory);
        return false;
    }
    std::memcpy(target, wide.c_str(), bytes);
    GlobalUnlock(memory);

    if (!OpenClipboard(nullptr)) {
        GlobalFree(memory);
        return false;
    }
    EmptyClipboard();
    if (SetClipboardData(CF_UNICODETEXT, memory) == nullptr) {
        GlobalFree(memory);
        CloseClipboard();
        return false;
    }
    // Ownership transferred to the clipboard.
    CloseClipboard();
    return true;
}

std::wstring executable_path() {
    std::vector<wchar_t> buffer(MAX_PATH);
    for (;;) {
        const DWORD len = GetModuleFileNameW(nullptr, buffer.data(),
                                             static_cast<DWORD>(buffer.size()));
        if (len == 0) return L"";
        if (len < buffer.size() - 1) return std::wstring(buffer.data(), len);
        buffer.resize(buffer.size() * 2);
    }
}

bool spawn_clear_helper(int seconds, const std::string& hash) {
    const std::wstring exe = executable_path();
    if (exe.empty()) return false;
    const std::wstring command = L"\"" + exe + L"\" --clipboard-clear " +
                                 std::to_wstring(seconds) + L" " +
                                 std::wstring(hash.begin(), hash.end());

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');
    const BOOL ok = CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, FALSE,
                                   CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
    if (!ok) return false;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return true;
}

#else

bool run_filter_write(const char* command, const std::string& input) {
    FILE* pipe = popen(command, "w");
    if (pipe == nullptr) return false;
    bool ok = true;
    if (!input.empty()) {
        ok = std::fwrite(input.data(), 1, input.size(), pipe) == input.size();
    }
    ok = (pclose(pipe) == 0) && ok;
    return ok;
}

bool run_filter_read(const char* command, std::string& output) {
    FILE* pipe = popen(command, "r");
    if (pipe == nullptr) return false;
    char buffer[4096];
    std::size_t got = 0;
    while ((got = std::fread(buffer, 1, sizeof(buffer), pipe)) > 0) {
        output.append(buffer, got);
    }
    return pclose(pipe) == 0;
}

#if !defined(__APPLE__)
bool has_command(const char* name) {
    std::string command = std::string("command -v ") + name + " >/dev/null 2>&1";
    return std::system(command.c_str()) == 0;
}
#endif

bool write_clipboard(const std::string& text) {
#if defined(__APPLE__)
    return run_filter_write("pbcopy", text);
#else
    if (std::getenv("WAYLAND_DISPLAY") != nullptr && has_command("wl-copy")) {
        return run_filter_write("wl-copy", text);
    }
    if (has_command("xclip")) return run_filter_write("xclip -selection clipboard", text);
    if (has_command("xsel")) return run_filter_write("xsel --clipboard --input", text);
    return false;
#endif
}

bool read_clipboard(std::string& out) {
#if defined(__APPLE__)
    return run_filter_read("pbpaste", out);
#else
    if (std::getenv("WAYLAND_DISPLAY") != nullptr && has_command("wl-paste")) {
        return run_filter_read("wl-paste --no-newline", out);
    }
    if (has_command("xclip")) return run_filter_read("xclip -selection clipboard -o", out);
    if (has_command("xsel")) return run_filter_read("xsel --clipboard --output", out);
    return false;
#endif
}

bool spawn_clear_helper(int seconds, const std::string& hash) {
    const pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        // Double fork so the long-lived helper is not a child of this process.
        if (fork() > 0) _exit(0);
        setsid();
        std::this_thread::sleep_for(std::chrono::seconds(seconds));
        std::string current;
        if (read_clipboard(current) && sha256_hex(current) == hash) {
            write_clipboard(std::string());
        }
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return true;
}

#endif

}  // namespace

bool clipboard_supported() {
#if defined(_WIN32)
    return true;
#else
    return std::getenv("WAYLAND_DISPLAY") != nullptr || std::getenv("DISPLAY") != nullptr;
#endif
}

bool clipboard_copy(const std::string& text) { return write_clipboard(text); }

bool clipboard_copy_with_timeout(const std::string& text, int seconds) {
    if (!write_clipboard(text)) return false;
    if (seconds <= 0) return true;
    spawn_clear_helper(seconds, sha256_hex(text));
    return true;
}

int clipboard_clear_helper(int seconds, const std::string& expected_sha256) {
    if (seconds < 0 || seconds > 3600) return 1;
    std::this_thread::sleep_for(std::chrono::seconds(seconds));
    std::string current;
    if (!read_clipboard(current)) return 1;
    if (sha256_hex(current) != expected_sha256) return 0;  // user copied something else
    write_clipboard(std::string());
    return 0;
}

}  // namespace ciphervault
