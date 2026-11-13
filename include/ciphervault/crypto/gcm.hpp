// CipherVault - AES-256-GCM authenticated encryption (NIST SP 800-38D)
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace ciphervault {

using GcmTag = std::array<std::uint8_t, 16>;
using AesKey = std::array<std::uint8_t, 32>;
using GcmNonce = std::array<std::uint8_t, 12>;

// Encrypts and authenticates |plaintext|. |aad| is authenticated but not
// encrypted (used for the vault header). Returns the ciphertext and writes
// the 16-byte tag to |tag_out|.
std::vector<std::uint8_t> aes256_gcm_encrypt(const AesKey& key, const GcmNonce& nonce,
                                             const std::uint8_t* plaintext,
                                             std::size_t plaintext_len,
                                             const std::uint8_t* aad, std::size_t aad_len,
                                             GcmTag& tag_out);

// Verifies the tag in constant time before decrypting anything. Returns false
// when authentication fails; |plaintext_out| is left untouched in that case.
bool aes256_gcm_decrypt(const AesKey& key, const GcmNonce& nonce,
                        const std::uint8_t* ciphertext, std::size_t ciphertext_len,
                        const std::uint8_t* aad, std::size_t aad_len,
                        const GcmTag& tag, std::vector<std::uint8_t>& plaintext_out);

}  // namespace ciphervault
