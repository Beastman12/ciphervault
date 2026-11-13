#include "ciphervault/crypto/hmac.hpp"

#include "ciphervault/crypto/secure_memory.hpp"

namespace ciphervault {

Digest256 hmac_sha256(const void* key, std::size_t key_len, const void* data,
                      std::size_t data_len) {
    constexpr std::size_t kBlock = 64;
    std::uint8_t key_block[kBlock] = {};

    if (key_len > kBlock) {
        const Digest256 hashed = Sha256::hash(key, key_len);
        for (std::size_t i = 0; i < hashed.size(); ++i) key_block[i] = hashed[i];
    } else if (key_len > 0) {
        const auto* k = static_cast<const std::uint8_t*>(key);
        for (std::size_t i = 0; i < key_len; ++i) key_block[i] = k[i];
    }

    std::uint8_t ipad[kBlock];
    std::uint8_t opad[kBlock];
    for (std::size_t i = 0; i < kBlock; ++i) {
        ipad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x36);
        opad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x5c);
    }

    Sha256 inner;
    inner.update(ipad, kBlock);
    inner.update(data, data_len);
    const Digest256 inner_digest = inner.digest();

    Sha256 outer;
    outer.update(opad, kBlock);
    outer.update(inner_digest.data(), inner_digest.size());
    const Digest256 result = outer.digest();

    secure_zero(key_block, sizeof(key_block));
    secure_zero(ipad, sizeof(ipad));
    secure_zero(opad, sizeof(opad));
    return result;
}

}  // namespace ciphervault
