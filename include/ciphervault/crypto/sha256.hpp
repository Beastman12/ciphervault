// CipherVault - SHA-256 (FIPS 180-4)
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ciphervault {

using Digest256 = std::array<std::uint8_t, 32>;

class Sha256 {
public:
    Sha256() noexcept;

    void update(const void* data, std::size_t len) noexcept;
    void update(std::string_view data) noexcept { update(data.data(), data.size()); }

    // Returns the digest. The object may continue to be fed afterwards.
    Digest256 digest() const noexcept;

    static Digest256 hash(const void* data, std::size_t len) noexcept;
    static Digest256 hash(std::string_view data) noexcept { return hash(data.data(), data.size()); }

private:
    void compress(const std::uint8_t block[64]) noexcept;

    std::array<std::uint32_t, 8> state_;
    std::array<std::uint8_t, 64> buffer_;
    std::uint64_t total_len_;
    std::size_t buffer_len_;
};

std::string to_hex(const std::uint8_t* data, std::size_t len);
inline std::string to_hex(const Digest256& d) { return to_hex(d.data(), d.size()); }
std::vector<std::uint8_t> from_hex(std::string_view hex);

}  // namespace ciphervault
