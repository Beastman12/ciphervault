// CipherVault - operating-system CSPRNG
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace ciphervault {

// Fills |buffer| with cryptographically secure random bytes.
// Throws std::runtime_error if the OS entropy source fails.
void random_bytes(void* buffer, std::size_t len);

inline std::vector<std::uint8_t> random_bytes(std::size_t len) {
    std::vector<std::uint8_t> out(len);
    if (len != 0) random_bytes(out.data(), len);
    return out;
}

std::uint32_t random_u32();
std::uint64_t random_u64();

// Uniform integer in [0, bound) using rejection sampling (no modulo bias).
std::uint32_t random_below(std::uint32_t bound);

}  // namespace ciphervault
