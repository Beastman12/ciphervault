// CipherVault - command line entry point
#pragma once

namespace ciphervault {

// Parses |argv| and runs the requested command. Returns a process exit code:
// 0 on success, 1 on runtime errors, 2 on usage errors.
int run_cli(int argc, char** argv);

}  // namespace ciphervault
