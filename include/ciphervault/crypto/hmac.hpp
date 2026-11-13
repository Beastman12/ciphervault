// CipherVault - HMAC-SHA-256 (RFC 2104)
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "ciphervault/crypto/sha256.hpp"

namespace ciphervault {

Digest256 hmac_sha256(const void* key, std::size_t key_len, const void* data,
                      std::size_t data_len);

inline Digest256 hmac_sha256(std::string_view key, std::string_view data) {
    return hmac_sha256(key.data(), key.size(), data.data(), data.size());
}

}  // namespace ciphervault
