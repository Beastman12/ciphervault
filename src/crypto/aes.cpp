#include "ciphervault/crypto/aes.hpp"

#include <cstring>

namespace ciphervault {
namespace {

inline std::uint8_t xtime(std::uint8_t x) noexcept {
    return static_cast<std::uint8_t>((x << 1) ^ ((x >> 7) * 0x1b));
}

inline std::uint8_t gf_mul(std::uint8_t a, std::uint8_t b) noexcept {
    std::uint8_t product = 0;
    for (int i = 0; i < 8; ++i) {
        const std::uint8_t add_mask = static_cast<std::uint8_t>(-(b & 1));
        product ^= static_cast<std::uint8_t>(a & add_mask);
        const std::uint8_t reduce_mask = static_cast<std::uint8_t>(-((a >> 7) & 1));
        a = static_cast<std::uint8_t>((a << 1) ^ (0x1b & reduce_mask));
        b = static_cast<std::uint8_t>(b >> 1);
    }
    return product;
}

inline std::uint8_t gf_pow(std::uint8_t base, std::uint8_t exponent) noexcept {
    std::uint8_t result = 1;
    for (int i = 0; i < 8; ++i) {
        const std::uint8_t use_mask = static_cast<std::uint8_t>(-(exponent & 1));
        const std::uint8_t multiplied = gf_mul(result, base);
        result = static_cast<std::uint8_t>((result & ~use_mask) | (multiplied & use_mask));
        base = gf_mul(base, base);
        exponent = static_cast<std::uint8_t>(exponent >> 1);
    }
    return result;
}

inline std::uint8_t rotl8(std::uint8_t x, int n) noexcept {
    return static_cast<std::uint8_t>((x << n) | (x >> (8 - n)));
}

inline void sub_bytes(std::uint8_t state[16]) noexcept {
    for (int i = 0; i < 16; ++i) state[i] = aes_sbox(state[i]);
}

inline void inv_sub_bytes(std::uint8_t state[16]) noexcept {
    for (int i = 0; i < 16; ++i) state[i] = aes_inv_sbox(state[i]);
}

inline void shift_rows(std::uint8_t s[16]) noexcept {
    std::uint8_t out[16];
    for (int row = 0; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            out[4 * col + row] = s[4 * ((col + row) & 3) + row];
        }
    }
    std::memcpy(s, out, 16);
}

inline void inv_shift_rows(std::uint8_t s[16]) noexcept {
    std::uint8_t out[16];
    for (int row = 0; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            out[4 * col + row] = s[4 * ((col - row + 4) & 3) + row];
        }
    }
    std::memcpy(s, out, 16);
}

inline void mix_columns(std::uint8_t s[16]) noexcept {
    for (int col = 0; col < 4; ++col) {
        std::uint8_t* c = s + 4 * col;
        const std::uint8_t a0 = c[0], a1 = c[1], a2 = c[2], a3 = c[3];
        const std::uint8_t all = static_cast<std::uint8_t>(a0 ^ a1 ^ a2 ^ a3);
        c[0] = static_cast<std::uint8_t>(a0 ^ all ^ xtime(static_cast<std::uint8_t>(a0 ^ a1)));
        c[1] = static_cast<std::uint8_t>(a1 ^ all ^ xtime(static_cast<std::uint8_t>(a1 ^ a2)));
        c[2] = static_cast<std::uint8_t>(a2 ^ all ^ xtime(static_cast<std::uint8_t>(a2 ^ a3)));
        c[3] = static_cast<std::uint8_t>(a3 ^ all ^ xtime(static_cast<std::uint8_t>(a3 ^ a0)));
    }
}

inline void inv_mix_columns(std::uint8_t s[16]) noexcept {
    for (int col = 0; col < 4; ++col) {
        std::uint8_t* c = s + 4 * col;
        const std::uint8_t a0 = c[0], a1 = c[1], a2 = c[2], a3 = c[3];
        c[0] = static_cast<std::uint8_t>(gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^
                                         gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09));
        c[1] = static_cast<std::uint8_t>(gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^
                                         gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d));
        c[2] = static_cast<std::uint8_t>(gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^
                                         gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b));
        c[3] = static_cast<std::uint8_t>(gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^
                                         gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e));
    }
}

inline void add_round_key(std::uint8_t s[16], const std::uint8_t* rk) noexcept {
    for (int i = 0; i < 16; ++i) s[i] ^= rk[i];
}

}  // namespace

std::uint8_t aes_sbox(std::uint8_t value) noexcept {
    // Multiplicative inverse in GF(2^8) (0 maps to 0), then the affine map.
    const std::uint8_t inv = gf_pow(value, 254);
    return static_cast<std::uint8_t>(inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^
                                     rotl8(inv, 4) ^ 0x63);
}

std::uint8_t aes_inv_sbox(std::uint8_t value) noexcept {
    // Invert the affine map, then invert the GF(2^8) element.
    const std::uint8_t b = static_cast<std::uint8_t>(value ^ 0x63);
    const std::uint8_t affine = static_cast<std::uint8_t>(rotl8(b, 1) ^ rotl8(b, 3) ^ rotl8(b, 6));
    return gf_pow(affine, 254);
}

Aes256::Aes256(const std::uint8_t key[kKeySize]) noexcept : round_keys_{} {
    // AES-256 key schedule: Nk = 8, Nr = 14, 60 words.
    constexpr int kNk = 8;
    constexpr int kWords = 4 * (kRounds + 1);
    std::uint8_t w[4 * kWords] = {};
    std::memcpy(w, key, 32);

    std::uint8_t rcon = 0x01;
    for (int i = kNk; i < kWords; ++i) {
        std::uint8_t temp[4];
        std::memcpy(temp, w + 4 * (i - 1), 4);
        if (i % kNk == 0) {
            const std::uint8_t first = temp[0];
            temp[0] = static_cast<std::uint8_t>(aes_sbox(temp[1]) ^ rcon);
            temp[1] = aes_sbox(temp[2]);
            temp[2] = aes_sbox(temp[3]);
            temp[3] = aes_sbox(first);
            rcon = xtime(rcon);
        } else if (i % kNk == 4) {
            for (int j = 0; j < 4; ++j) temp[j] = aes_sbox(temp[j]);
        }
        for (int j = 0; j < 4; ++j) w[4 * i + j] = static_cast<std::uint8_t>(w[4 * (i - kNk) + j] ^ temp[j]);
    }

    std::memcpy(round_keys_.data(), w, round_keys_.size());
    std::memset(w, 0, sizeof(w));
}

Aes256::Aes256(const std::array<std::uint8_t, kKeySize>& key) noexcept : Aes256(key.data()) {}

void Aes256::encrypt_block(const std::uint8_t in[kBlockSize],
                           std::uint8_t out[kBlockSize]) const noexcept {
    std::uint8_t state[16];
    std::memcpy(state, in, 16);

    add_round_key(state, round_keys_.data());
    for (int round = 1; round < kRounds; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys_.data() + 16 * round);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys_.data() + 16 * kRounds);

    std::memcpy(out, state, 16);
    std::memset(state, 0, sizeof(state));
}

void Aes256::decrypt_block(const std::uint8_t in[kBlockSize],
                           std::uint8_t out[kBlockSize]) const noexcept {
    std::uint8_t state[16];
    std::memcpy(state, in, 16);

    add_round_key(state, round_keys_.data() + 16 * kRounds);
    for (int round = kRounds - 1; round >= 1; --round) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round_keys_.data() + 16 * round);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, round_keys_.data());

    std::memcpy(out, state, 16);
    std::memset(state, 0, sizeof(state));
}

}  // namespace ciphervault
