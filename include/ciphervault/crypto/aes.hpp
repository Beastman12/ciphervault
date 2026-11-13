// CipherVault - AES-256 block cipher (FIPS 197)
//
// The S-box is evaluated arithmetically (GF(2^8) inversion + affine map)
// instead of being read from a lookup table. That removes the cache-timing
// leak that affects classic table-based AES implementations and keeps the
// code free of data-dependent branches.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace ciphervault {

class Aes256 {
public:
    static constexpr std::size_t kBlockSize = 16;
    static constexpr std::size_t kKeySize = 32;
    static constexpr int kRounds = 14;

    explicit Aes256(const std::array<std::uint8_t, kKeySize>& key) noexcept;
    explicit Aes256(const std::uint8_t key[kKeySize]) noexcept;

    void encrypt_block(const std::uint8_t in[kBlockSize],
                       std::uint8_t out[kBlockSize]) const noexcept;
    void decrypt_block(const std::uint8_t in[kBlockSize],
                       std::uint8_t out[kBlockSize]) const noexcept;

private:
    std::array<std::uint8_t, 16 * (kRounds + 1)> round_keys_;
};

// Exposed for known-answer tests of the core transform.
std::uint8_t aes_sbox(std::uint8_t value) noexcept;
std::uint8_t aes_inv_sbox(std::uint8_t value) noexcept;

}  // namespace ciphervault
