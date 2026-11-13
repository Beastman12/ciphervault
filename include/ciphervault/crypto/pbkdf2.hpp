// CipherVault - PBKDF2-HMAC-SHA-256 (RFC 8018)
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace ciphervault {

// Derives |dk_len| bytes from a password and salt.
// |iterations| must be >= 1; the vault layer enforces a much higher minimum.
std::vector<std::uint8_t> pbkdf2_hmac_sha256(std::string_view password,
                                             const std::uint8_t* salt,
                                             std::size_t salt_len,
                                             std::uint32_t iterations,
                                             std::size_t dk_len);

}  // namespace ciphervault
