// CipherVault - process entry point
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "ciphervault/cli.hpp"
#include "ciphervault/clipboard.hpp"
#include "ciphervault/terminal.hpp"

namespace {

#if defined(_WIN32)
void configure_console() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    // Opt in to ANSI escape sequences so colours work on Windows 10+.
    ciphervault::term::enable_virtual_terminal();
}
#else
void configure_console() { ciphervault::term::enable_virtual_terminal(); }
#endif

// The detached clipboard helper re-executes this binary as
//   ciphervault --clipboard-clear <seconds> <sha256>
// so that no secret ever appears on a command line.
int handle_internal_command(int argc, char** argv) {
    if (argc != 4) return -1;
    if (std::strcmp(argv[1], "--clipboard-clear") != 0) return -1;

    const int seconds = std::atoi(argv[2]);
    const std::string hash = argv[3];
    return ciphervault::clipboard_clear_helper(seconds, hash);
}

}  // namespace

int main(int argc, char** argv) {
    configure_console();

    const int internal = handle_internal_command(argc, argv);
    if (internal >= 0) return internal;

    return ciphervault::run_cli(argc, argv);
}
