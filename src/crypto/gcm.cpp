#include "ciphervault/crypto/gcm.hpp"

#include <cstring>
#include <limits>
#include <stdexcept>

#include "ciphervault/crypto/aes.hpp"
#include "ciphervault/crypto/secure_memory.hpp"

namespace ciphervault {
namespace {

constexpr std::size_t kBlock = 16;

bool ct_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t len) noexcept {
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < len; ++i) diff = static_cast<std::uint8_t>(diff | (a[i] ^ b[i]));
    return diff == 0;
}

// GF(2^128) multiplication of Y by H, using the GCM bit ordering.
// Branch-free so that the tag computation does not leak via control flow.
void gf128_mul(std::uint8_t y[kBlock], const std::uint8_t h[kBlock]) noexcept {
    std::uint8_t z[kBlock] = {};
    std::uint8_t v[kBlock];
    std::memcpy(v, h, kBlock);

    for (int i = 0; i < 128; ++i) {
        const std::uint8_t bit = static_cast<std::uint8_t>((y[i >> 3] >> (7 - (i & 7))) & 1);
        const std::uint8_t mask = static_cast<std::uint8_t>(-static_cast<int>(bit));
        for (int j = 0; j < 16; ++j) z[j] = static_cast<std::uint8_t>(z[j] ^ (v[j] & mask));

        const std::uint8_t lsb = static_cast<std::uint8_t>(v[15] & 1);
        const std::uint8_t reduce = static_cast<std::uint8_t>(-static_cast<int>(lsb));
        for (int j = 15; j > 0; --j) {
            v[j] = static_cast<std::uint8_t>((v[j] >> 1) | ((v[j - 1] & 1) << 7));
        }
        v[0] = static_cast<std::uint8_t>((v[0] >> 1) ^ (0xe1 & reduce));
    }

    std::memcpy(y, z, kBlock);
    secure_zero(z, sizeof(z));
    secure_zero(v, sizeof(v));
}

void ghash_block(std::uint8_t y[kBlock], const std::uint8_t h[kBlock],
                 const std::uint8_t block[kBlock]) noexcept {
    for (int i = 0; i < 16; ++i) y[i] = static_cast<std::uint8_t>(y[i] ^ block[i]);
    gf128_mul(y, h);
}

void ghash_data(std::uint8_t y[kBlock], const std::uint8_t h[kBlock], const std::uint8_t* data,
                std::size_t len) noexcept {
    std::uint8_t block[kBlock];
    while (len >= kBlock) {
        ghash_block(y, h, data);
        data += kBlock;
        len -= kBlock;
    }
    if (len > 0) {
        std::memset(block, 0, kBlock);
        std::memcpy(block, data, len);
        ghash_block(y, h, block);
        secure_zero(block, sizeof(block));
    }
}

void ghash_lengths(std::uint8_t y[kBlock], const std::uint8_t h[kBlock],
                   std::size_t aad_len, std::size_t ct_len) noexcept {
    std::uint8_t block[kBlock];
    const std::uint64_t aad_bits = static_cast<std::uint64_t>(aad_len) * 8;
    const std::uint64_t ct_bits = static_cast<std::uint64_t>(ct_len) * 8;
    for (int i = 0; i < 8; ++i) {
        block[i] = static_cast<std::uint8_t>(aad_bits >> (56 - i * 8));
        block[8 + i] = static_cast<std::uint8_t>(ct_bits >> (56 - i * 8));
    }
    ghash_block(y, h, block);
    secure_zero(block, sizeof(block));
}

void inc32(std::uint8_t counter[kBlock]) noexcept {
    for (int i = 15; i >= 12; --i) {
        counter[i] = static_cast<std::uint8_t>(counter[i] + 1);
        if (counter[i] != 0) break;
    }
}

void ctr_crypt(const AesKey& key, const std::uint8_t j0[kBlock], const std::uint8_t* in,
               std::size_t len, std::uint8_t* out) noexcept {
    Aes256 aes(key);
    std::uint8_t counter[kBlock];
    std::memcpy(counter, j0, kBlock);
    std::uint8_t keystream[kBlock];

    std::size_t offset = 0;
    while (offset < len) {
        inc32(counter);
        aes.encrypt_block(counter, keystream);
        const std::size_t take = (len - offset < kBlock) ? len - offset : kBlock;
        for (std::size_t i = 0; i < take; ++i) out[offset + i] = static_cast<std::uint8_t>(in[offset + i] ^ keystream[i]);
        offset += take;
    }
    secure_zero(counter, sizeof(counter));
    secure_zero(keystream, sizeof(keystream));
}

void compute_tag(const AesKey& key, const std::uint8_t j0[kBlock], const std::uint8_t* aad,
                 std::size_t aad_len, const std::uint8_t* ciphertext, std::size_t ct_len,
                 GcmTag& tag_out) noexcept {
    Aes256 aes(key);
    std::uint8_t zero[kBlock] = {};
    std::uint8_t h[kBlock];
    aes.encrypt_block(zero, h);

    std::uint8_t y[kBlock] = {};
    ghash_data(y, h, aad, aad_len);
    ghash_data(y, h, ciphertext, ct_len);
    ghash_lengths(y, h, aad_len, ct_len);

    std::uint8_t mask[kBlock];
    aes.encrypt_block(j0, mask);
    for (int i = 0; i < 16; ++i) tag_out[i] = static_cast<std::uint8_t>(y[i] ^ mask[i]);

    secure_zero(zero, sizeof(zero));
    secure_zero(h, sizeof(h));
    secure_zero(y, sizeof(y));
    secure_zero(mask, sizeof(mask));
}

}  // namespace

std::vector<std::uint8_t> aes256_gcm_encrypt(const AesKey& key, const GcmNonce& nonce,
                                             const std::uint8_t* plaintext,
                                             std::size_t plaintext_len,
                                             const std::uint8_t* aad, std::size_t aad_len,
                                             GcmTag& tag_out) {
    if (plaintext_len > 0 && plaintext == nullptr) {
        throw std::invalid_argument("GCM plaintext pointer is null");
    }
    if (aad_len > 0 && aad == nullptr) throw std::invalid_argument("GCM AAD pointer is null");
    if (plaintext_len > static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max() / 8) ||
        aad_len > static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max() / 8)) {
        throw std::invalid_argument("GCM input too long");
    }

    std::uint8_t j0[16];
    std::memcpy(j0, nonce.data(), nonce.size());
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;

    std::vector<std::uint8_t> ciphertext(plaintext_len);
    if (plaintext_len > 0) {
        ctr_crypt(key, j0, plaintext, plaintext_len, ciphertext.data());
    }
    compute_tag(key, j0, aad, aad_len, ciphertext.data(), ciphertext.size(), tag_out);
    secure_zero(j0, sizeof(j0));
    return ciphertext;
}

bool aes256_gcm_decrypt(const AesKey& key, const GcmNonce& nonce,
                        const std::uint8_t* ciphertext, std::size_t ciphertext_len,
                        const std::uint8_t* aad, std::size_t aad_len, const GcmTag& tag,
                        std::vector<std::uint8_t>& plaintext_out) {
    if (ciphertext_len > 0 && ciphertext == nullptr) {
        throw std::invalid_argument("GCM ciphertext pointer is null");
    }
    if (aad_len > 0 && aad == nullptr) throw std::invalid_argument("GCM AAD pointer is null");

    std::uint8_t j0[16];
    std::memcpy(j0, nonce.data(), nonce.size());
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;

    GcmTag expected{};
    compute_tag(key, j0, aad, aad_len, ciphertext, ciphertext_len, expected);
    const bool authentic = ct_equal(expected.data(), tag.data(), tag.size());
    secure_zero(expected.data(), expected.size());

    if (!authentic) {
        secure_zero(j0, sizeof(j0));
        return false;
    }

    std::vector<std::uint8_t> plaintext(ciphertext_len);
    if (ciphertext_len > 0) {
        ctr_crypt(key, j0, ciphertext, ciphertext_len, plaintext.data());
    }
    secure_zero(j0, sizeof(j0));
    plaintext_out = std::move(plaintext);
    return true;
}

}  // namespace ciphervault
