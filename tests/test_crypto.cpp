#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "ciphervault/crypto/aes.hpp"
#include "ciphervault/crypto/gcm.hpp"
#include "ciphervault/crypto/hmac.hpp"
#include "ciphervault/crypto/pbkdf2.hpp"
#include "ciphervault/crypto/random.hpp"
#include "ciphervault/crypto/sha256.hpp"
#include "test_framework.hpp"

using namespace ciphervault;

namespace {

std::string hash_hex(const std::string& input) {
    return to_hex(Sha256::hash(input));
}

AesKey key_from_hex(const std::string& hex) {
    const auto bytes = from_hex(hex);
    AesKey key{};
    std::memcpy(key.data(), bytes.data(), key.size());
    return key;
}

GcmNonce nonce_from_hex(const std::string& hex) {
    const auto bytes = from_hex(hex);
    GcmNonce nonce{};
    std::memcpy(nonce.data(), bytes.data(), nonce.size());
    return nonce;
}

}  // namespace

TEST(sha256_known_answers) {
    CHECK_EQ(hash_hex(""),
             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK_EQ(hash_hex("abc"),
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK_EQ(hash_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(sha256_incremental_matches_one_shot) {
    const std::string part1 = "The quick brown fox ";
    const std::string part2 = "jumps over the lazy dog";
    Sha256 ctx;
    ctx.update(part1);
    ctx.update(part2);
    CHECK_EQ(to_hex(ctx.digest()), to_hex(Sha256::hash(part1 + part2)));
}

TEST(sha256_million_a) {
    Sha256 ctx;
    std::vector<char> block(1000, 'a');
    for (int i = 0; i < 1000; ++i) ctx.update(block.data(), block.size());
    CHECK_EQ(to_hex(ctx.digest()),
             "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST(hmac_rfc4231_vectors) {
    // Case 1
    std::vector<std::uint8_t> key1(20, 0x0b);
    CHECK_EQ(to_hex(hmac_sha256(key1.data(), key1.size(), "Hi There", 8)),
             "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    // Case 2
    CHECK_EQ(to_hex(hmac_sha256("Jefe", "what do ya want for nothing?")),
             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    // Case 3
    std::vector<std::uint8_t> key3(20, 0xaa);
    std::vector<std::uint8_t> data3(50, 0xdd);
    CHECK_EQ(to_hex(hmac_sha256(key3.data(), key3.size(), data3.data(), data3.size())),
             "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    // Case 6: key larger than the block size
    std::vector<std::uint8_t> key6(131, 0xaa);
    const std::string data6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    CHECK_EQ(to_hex(hmac_sha256(key6.data(), key6.size(), data6.data(), data6.size())),
             "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

TEST(pbkdf2_sha256_vectors) {
    const std::string password = "password";
    const std::string salt = "salt";
    CHECK_EQ(to_hex(pbkdf2_hmac_sha256(
                 password, reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size(), 1, 32)
                 .data(),
             32),
             "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    CHECK_EQ(to_hex(pbkdf2_hmac_sha256(
                 password, reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size(), 2, 32)
                 .data(),
             32),
             "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
    CHECK_EQ(to_hex(pbkdf2_hmac_sha256(
                 password, reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size(), 4096,
                 32)
                 .data(),
             32),
             "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");

    const std::string long_password = "passwordPASSWORDpassword";
    const std::string long_salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
    CHECK_EQ(to_hex(pbkdf2_hmac_sha256(
                 long_password, reinterpret_cast<const std::uint8_t*>(long_salt.data()),
                 long_salt.size(), 4096, 40)
                 .data(),
             40),
             "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9");
}

TEST(aes256_fips197_vector) {
    const AesKey key = key_from_hex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto plaintext = from_hex("00112233445566778899aabbccddeeff");
    Aes256 aes(key);
    std::uint8_t out[16];
    aes.encrypt_block(plaintext.data(), out);
    CHECK_EQ(to_hex(out, 16), "8ea2b7ca516745bfeafc49904b496089");

    std::uint8_t roundtrip[16];
    aes.decrypt_block(out, roundtrip);
    CHECK_EQ(to_hex(roundtrip, 16), "00112233445566778899aabbccddeeff");
}

TEST(aes256_sbox_known_values) {
    CHECK_EQ(static_cast<int>(aes_sbox(0x00)), 0x63);
    CHECK_EQ(static_cast<int>(aes_sbox(0x01)), 0x7c);
    CHECK_EQ(static_cast<int>(aes_sbox(0x53)), 0xed);
    CHECK_EQ(static_cast<int>(aes_sbox(0xff)), 0x16);
    for (int i = 0; i < 256; ++i) {
        CHECK_EQ(static_cast<int>(aes_inv_sbox(aes_sbox(static_cast<std::uint8_t>(i)))),
                 i);
    }
}

TEST(aes256_random_roundtrips) {
    for (int trial = 0; trial < 50; ++trial) {
        AesKey key{};
        random_bytes(key.data(), key.size());
        std::uint8_t plaintext[16];
        random_bytes(plaintext, sizeof(plaintext));
        Aes256 aes(key);
        std::uint8_t ciphertext[16];
        std::uint8_t decrypted[16];
        aes.encrypt_block(plaintext, ciphertext);
        aes.decrypt_block(ciphertext, decrypted);
        CHECK(std::memcmp(plaintext, decrypted, 16) == 0);
    }
}

TEST(gcm_nist_empty_plaintext) {
    const AesKey key{};
    const GcmNonce nonce{};
    GcmTag tag{};
    const auto ciphertext = aes256_gcm_encrypt(key, nonce, nullptr, 0, nullptr, 0, tag);
    CHECK(ciphertext.empty());
    CHECK_EQ(to_hex(tag.data(), tag.size()), "530f8afbc74536b9a963b4f1c4cb738b");
}

TEST(gcm_nist_one_block) {
    const AesKey key{};
    const GcmNonce nonce{};
    const auto plaintext = from_hex("00000000000000000000000000000000");
    GcmTag tag{};
    const auto ciphertext = aes256_gcm_encrypt(key, nonce, plaintext.data(), plaintext.size(),
                                               nullptr, 0, tag);
    CHECK_EQ(to_hex(ciphertext.data(), ciphertext.size()), "cea7403d4d606b6e074ec5d3baf39d18");
    CHECK_EQ(to_hex(tag.data(), tag.size()), "d0d1c8a799996bf0265b98b5d48ab919");
}

TEST(gcm_nist_aad_and_plaintext) {
    const AesKey key =
        key_from_hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    const GcmNonce nonce = nonce_from_hex("cafebabefacedbaddecaf888");
    const auto plaintext = from_hex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
    const auto aad =
        from_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");

    GcmTag tag{};
    const auto ciphertext =
        aes256_gcm_encrypt(key, nonce, plaintext.data(), plaintext.size(), aad.data(), aad.size(),
                           tag);
    CHECK_EQ(to_hex(ciphertext.data(), ciphertext.size()),
             "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
             "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662");
    CHECK_EQ(to_hex(tag.data(), tag.size()), "76fc6ece0f4e1768cddf8853bb2d551b");

    std::vector<std::uint8_t> decrypted;
    CHECK(aes256_gcm_decrypt(key, nonce, ciphertext.data(), ciphertext.size(), aad.data(),
                             aad.size(), tag, decrypted));
    CHECK(decrypted == plaintext);
}

TEST(gcm_detects_tampering) {
    AesKey key{};
    random_bytes(key.data(), key.size());
    GcmNonce nonce{};
    random_bytes(nonce.data(), nonce.size());
    const std::string plaintext = "attack at dawn";
    const std::string aad = "header";
    GcmTag tag{};
    auto ciphertext = aes256_gcm_encrypt(key, nonce,
                                         reinterpret_cast<const std::uint8_t*>(plaintext.data()),
                                         plaintext.size(),
                                         reinterpret_cast<const std::uint8_t*>(aad.data()),
                                         aad.size(), tag);

    std::vector<std::uint8_t> out;
    CHECK(aes256_gcm_decrypt(key, nonce, ciphertext.data(), ciphertext.size(),
                             reinterpret_cast<const std::uint8_t*>(aad.data()), aad.size(), tag,
                             out));

    auto flipped = ciphertext;
    flipped[0] ^= 0x01;
    CHECK(!aes256_gcm_decrypt(key, nonce, flipped.data(), flipped.size(),
                              reinterpret_cast<const std::uint8_t*>(aad.data()), aad.size(), tag,
                              out));

    GcmTag bad_tag = tag;
    bad_tag[15] ^= 0x80;
    CHECK(!aes256_gcm_decrypt(key, nonce, ciphertext.data(), ciphertext.size(),
                              reinterpret_cast<const std::uint8_t*>(aad.data()), aad.size(),
                              bad_tag, out));

    CHECK(!aes256_gcm_decrypt(key, nonce, ciphertext.data(), ciphertext.size(),
                              reinterpret_cast<const std::uint8_t*>("HEADER"), 6, tag, out));
}

TEST(random_output_is_not_constant) {
    const auto a = random_bytes(32);
    const auto b = random_bytes(32);
    CHECK(a != b);
}

TEST(random_below_stays_in_range) {
    bool seen[8] = {};
    for (int i = 0; i < 500; ++i) {
        const std::uint32_t v = random_below(8);
        CHECK(v < 8);
        seen[v] = true;
    }
    for (bool value : seen) CHECK(value);
}

TEST(hex_roundtrip) {
    const auto bytes = from_hex("00ff10abcdef");
    CHECK_EQ(to_hex(bytes.data(), bytes.size()), "00ff10abcdef");
    CHECK_THROWS(from_hex("abc"), std::invalid_argument);
    CHECK_THROWS(from_hex("zz"), std::invalid_argument);
}
