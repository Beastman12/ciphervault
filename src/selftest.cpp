// CipherVault - built-in known-answer self test
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "ciphervault/crypto/aes.hpp"
#include "ciphervault/crypto/gcm.hpp"
#include "ciphervault/crypto/hmac.hpp"
#include "ciphervault/crypto/pbkdf2.hpp"
#include "ciphervault/crypto/random.hpp"
#include "ciphervault/crypto/sha256.hpp"
#include "ciphervault/crypto/secure_memory.hpp"
#include "ciphervault/util.hpp"

namespace ciphervault {

bool run_self_test() {
    int passed = 0;
    int failed = 0;

    auto check = [&](const char* name, bool ok) {
        std::printf("  [%s] %s\n", ok ? "ok" : "FAIL", name);
        if (ok) ++passed;
        else ++failed;
    };

    check("SHA-256 known answer", to_hex(Sha256::hash("abc")) ==
                                      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    check("HMAC-SHA-256 known answer",
          to_hex(hmac_sha256("Jefe", "what do ya want for nothing?")) ==
              "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    const std::string salt = "salt";
    const auto derived = pbkdf2_hmac_sha256(
        "password", reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size(), 1, 32);
    check("PBKDF2-HMAC-SHA256 known answer",
          to_hex(derived.data(), derived.size()) ==
              "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");

    const auto key_bytes =
        from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    AesKey key{};
    std::memcpy(key.data(), key_bytes.data(), key.size());
    const auto plaintext = from_hex("00112233445566778899aabbccddeeff");
    Aes256 aes(key);
    std::uint8_t ciphertext[16];
    aes.encrypt_block(plaintext.data(), ciphertext);
    check("AES-256 FIPS-197 known answer",
          to_hex(ciphertext, 16) == "8ea2b7ca516745bfeafc49904b496089");

    const AesKey zero_key{};
    const GcmNonce zero_nonce{};
    GcmTag tag{};
    const auto ct = aes256_gcm_encrypt(zero_key, zero_nonce, nullptr, 0, nullptr, 0, tag);
    check("AES-256-GCM authentication tag",
          ct.empty() && to_hex(tag.data(), tag.size()) == "530f8afbc74536b9a963b4f1c4cb738b");

    const std::uint8_t a[4] = {1, 2, 3, 4};
    const std::uint8_t b[4] = {1, 2, 3, 4};
    check("constant-time comparison", constant_time_equal(a, b, 4));

    const auto random1 = random_bytes(32);
    const auto random2 = random_bytes(32);
    check("CSPRNG produces distinct output", random1 != random2 && !random1.empty());

    std::printf("\n  %d check(s) passed, %d failed\n", passed, failed);
    return failed == 0;
}

}  // namespace ciphervault
