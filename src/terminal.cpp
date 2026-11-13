#include "ciphervault/terminal.hpp"

#include <cstdio>
#include <iostream>

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace ciphervault {
namespace term {

bool stdin_is_tty() {
#if defined(_WIN32)
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(STDIN_FILENO) != 0;
#endif
}

bool stdout_is_tty() {
#if defined(_WIN32)
    return _isatty(_fileno(stdout)) != 0;
#else
    return isatty(STDOUT_FILENO) != 0;
#endif
}

void enable_virtual_terminal() {
#if defined(_WIN32)
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (out == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0;
    if (GetConsoleMode(out, &mode)) {
        SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
#endif
}

std::size_t width() {
#if defined(_WIN32)
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info)) {
        return static_cast<std::size_t>(info.srWindow.Right - info.srWindow.Left + 1);
    }
#else
    winsize size{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_col > 0) {
        return static_cast<std::size_t>(size.ws_col);
    }
#endif
    return 80;
}

std::string read_line(const std::string& prompt) {
    std::cout << prompt;
    std::cout.flush();
    std::string line;
    if (!std::getline(std::cin, line)) return {};
    return line;
}

std::string read_password(const std::string& prompt) {
    std::cout << prompt;
    std::cout.flush();

#if defined(_WIN32)
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    const bool is_console = GetConsoleMode(in, &mode) != 0;
    if (is_console) {
        // Keep line editing (backspace) but hide the characters.
        SetConsoleMode(in, mode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));
    }
    std::string line;
    std::getline(std::cin, line);
    if (is_console) {
        SetConsoleMode(in, mode);
        std::cout << '\n';
        std::cout.flush();
    }
    return line;
#else
    termios old_settings{};
    const bool is_console = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old_settings) == 0;
    if (is_console) {
        termios new_settings = old_settings;
        new_settings.c_lflag &= static_cast<tcflag_t>(~ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &new_settings);
    }
    std::string line;
    std::getline(std::cin, line);
    if (is_console) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
        std::cout << '\n';
        std::cout.flush();
    }
    return line;
#endif
}

}  // namespace term
}  // namespace ciphervault
