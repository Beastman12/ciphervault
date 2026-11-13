// CipherVault - built-in known-answer self test
#pragma once

namespace ciphervault {

// Runs the built-in known-answer tests for every cryptographic primitive.
// Prints one line per check and returns true when all checks pass.
bool run_self_test();

}  // namespace ciphervault
