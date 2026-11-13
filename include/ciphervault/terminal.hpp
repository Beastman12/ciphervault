// CipherVault - terminal input helpers
#pragma once

#include <cstddef>
#include <string>

namespace ciphervault {
namespace term {

bool stdin_is_tty();
bool stdout_is_tty();
void enable_virtual_terminal();
std::size_t width();

// Prints |prompt| and reads one line. Returns an empty string on EOF.
std::string read_line(const std::string& prompt);

// Reads a line with echo disabled. Falls back to a normal read when stdin is
// not a terminal (which makes the tool scriptable).
std::string read_password(const std::string& prompt);

}  // namespace term
}  // namespace ciphervault
