#include "ciphervault/crypto/pbkdf2.hpp"

#include <cstring>
#include <stdexcept>

#include "ciphervault/crypto/hmac.hpp"
#include "ciphervault/crypto/secure_memory.hpp"

namespace ciphervault {

std::vector<std::uint8_t> pbkdf2_hmac_sha256(std::string_view password,
                                             const std::uint8_t* salt,
                                             std::size_t salt_len,
                                             std::uint32_t iterations,
                                             std::size_t dk_len) {
    if (iterations == 0) throw std::invalid_argument("PBKDF2 iterations must be > 0");
    if (dk_len == 0) return {};
    if (dk_len > (static_cast<std::size_t>(0xffffffffu) * 32)) {
        throw std::invalid_argument("PBKDF2 output too long");
    }

    std::vector<std::uint8_t> output(dk_len);
    std::vector<std::uint8_t> block_input;
    block_input.reserve(salt_len + 4);
    if (salt_len > 0) block_input.insert(block_input.end(), salt, salt + salt_len);

    ScopeWipe salt_wipe(block_input.data(), block_input.size());

    std::uint8_t u[32];
    std::uint8_t t[32];
    std::size_t produced = 0;
    std::uint32_t block_index = 1;

    while (produced < dk_len) {
        block_input.resize(salt_len);
        block_input.push_back(static_cast<std::uint8_t>(block_index >> 24));
        block_input.push_back(static_cast<std::uint8_t>(block_index >> 16));
        block_input.push_back(static_cast<std::uint8_t>(block_index >> 8));
        block_input.push_back(static_cast<std::uint8_t>(block_index));

        Digest256 first = hmac_sha256(password.data(), password.size(), block_input.data(),
                                      block_input.size());
        std::memcpy(u, first.data(), sizeof(u));
        std::memcpy(t, first.data(), sizeof(t));
        secure_zero(first.data(), first.size());

        for (std::uint32_t i = 1; i < iterations; ++i) {
            Digest256 next = hmac_sha256(password.data(), password.size(), u, sizeof(u));
            std::memcpy(u, next.data(), sizeof(u));
            secure_zero(next.data(), next.size());
            for (std::size_t j = 0; j < sizeof(t); ++j) t[j] ^= u[j];
        }

        const std::size_t take = (dk_len - produced < sizeof(t)) ? dk_len - produced : sizeof(t);
        std::memcpy(output.data() + produced, t, take);
        produced += take;
        ++block_index;
    }

    secure_zero(u, sizeof(u));
    secure_zero(t, sizeof(t));
    secure_zero(block_input.data(), block_input.size());
    return output;
}

}  // namespace ciphervault
