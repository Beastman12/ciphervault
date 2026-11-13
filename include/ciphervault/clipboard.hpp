// CipherVault - clipboard integration with automatic clearing
#pragma once

#include <string>

namespace ciphervault {

// Copies UTF-8 text to the system clipboard. Returns false when no clipboard
// backend is available (headless Linux, missing xclip/wl-copy).
bool clipboard_copy(const std::string& text);

bool clipboard_supported();

// Copies the text and spawns a detached helper process that clears the
// clipboard after |seconds|. The helper only clears it if the clipboard still
// contains the same value (identified by a SHA-256 digest).
bool clipboard_copy_with_timeout(const std::string& text, int seconds);

// Internal helper entry point used by the detached process. Returns 0 on
// success. Never prints the secret.
int clipboard_clear_helper(int seconds, const std::string& expected_sha256);

}  // namespace ciphervault
