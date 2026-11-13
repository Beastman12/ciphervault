#include "ciphervault/vault.hpp"

#include <algorithm>
#include <ctime>
#include <cstring>
#include <limits>
#include <set>
#include <system_error>

#include "ciphervault/crypto/pbkdf2.hpp"
#include "ciphervault/crypto/random.hpp"
#include "ciphervault/crypto/secure_memory.hpp"
#include "ciphervault/util.hpp"

namespace ciphervault {
namespace {

constexpr std::uint8_t kFormatVersion = 1;
constexpr std::uint8_t kKdfPbkdf2HmacSha256 = 1;
constexpr std::size_t kSaltLen = 16;
constexpr std::size_t kNonceLen = 12;
constexpr std::size_t kTagLen = 16;
constexpr std::size_t kHeaderPrefixLen = 4 + 1 + 1 + 4 + kSaltLen + kNonceLen + 4;
constexpr std::size_t kMaxFileSize = 64u * 1024u * 1024u;
constexpr std::size_t kMaxStringLen = 1024u * 1024u;
constexpr std::size_t kMaxEntries = 100000;
constexpr std::uint16_t kMaxTags = 256;
constexpr std::uint8_t kPayloadVersion = 1;

constexpr std::uint8_t kFileMagic[4] = {'C', 'V', 'L', 'T'};
constexpr std::uint8_t kPayloadMagic[4] = {'C', 'V', 'P', 'L'};

std::int64_t now_unix() { return static_cast<std::int64_t>(std::time(nullptr)); }

AesKey derive_key(const std::string& password, const std::uint8_t* salt, std::size_t salt_len,
                  std::uint32_t iterations) {
    std::vector<std::uint8_t> derived =
        pbkdf2_hmac_sha256(password, salt, salt_len, iterations, 32);
    AesKey key{};
    std::memcpy(key.data(), derived.data(), key.size());
    secure_zero(derived);
    return key;
}

class ByteWriter {
public:
    void u8(std::uint8_t v) { data_.push_back(v); }
    void u16(std::uint16_t v) {
        data_.push_back(static_cast<std::uint8_t>(v >> 8));
        data_.push_back(static_cast<std::uint8_t>(v));
    }
    void u32(std::uint32_t v) {
        for (int i = 3; i >= 0; --i) data_.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }
    void u64(std::uint64_t v) {
        for (int i = 7; i >= 0; --i) data_.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }
    void i64(std::int64_t v) { u64(static_cast<std::uint64_t>(v)); }
    void raw(const void* data, std::size_t len) {
        const auto* p = static_cast<const std::uint8_t*>(data);
        data_.insert(data_.end(), p, p + len);
    }
    void str(std::string_view s) {
        if (s.size() > kMaxStringLen) throw VaultError(VaultErrorKind::Format, "field too long");
        u32(static_cast<std::uint32_t>(s.size()));
        raw(s.data(), s.size());
    }

    std::vector<std::uint8_t>& data() { return data_; }
    const std::vector<std::uint8_t>& data() const { return data_; }

private:
    std::vector<std::uint8_t> data_;
};

class ByteReader {
public:
    ByteReader(const std::uint8_t* data, std::size_t size) : data_(data), size_(size) {}

    std::uint8_t u8() { return *raw(1); }
    std::uint16_t u16() {
        const std::uint8_t* p = raw(2);
        return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
    }
    std::uint32_t u32() {
        const std::uint8_t* p = raw(4);
        return (static_cast<std::uint32_t>(p[0]) << 24) |
               (static_cast<std::uint32_t>(p[1]) << 16) |
               (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
    }
    std::uint64_t u64() {
        const std::uint8_t* p = raw(8);
        std::uint64_t value = 0;
        for (int i = 0; i < 8; ++i) value = (value << 8) | p[i];
        return value;
    }
    std::int64_t i64() { return static_cast<std::int64_t>(u64()); }

    std::string str(std::size_t max_len = kMaxStringLen) {
        const std::uint32_t len = u32();
        if (len > max_len) throw VaultError(VaultErrorKind::Format, "field length out of range");
        const std::uint8_t* p = raw(len);
        return std::string(reinterpret_cast<const char*>(p), len);
    }

    const std::uint8_t* raw(std::size_t len) {
        if (len > size_ - offset_) throw VaultError(VaultErrorKind::Format, "vault data is truncated");
        const std::uint8_t* p = data_ + offset_;
        offset_ += len;
        return p;
    }

    std::size_t remaining() const { return size_ - offset_; }
    void expect_end() const {
        if (remaining() != 0) throw VaultError(VaultErrorKind::Format, "unexpected trailing data");
    }

private:
    const std::uint8_t* data_;
    std::size_t size_;
    std::size_t offset_ = 0;
};

std::vector<std::uint8_t> serialize_payload(const Vault& vault,
                                            const std::vector<Entry>& entries,
                                            std::uint64_t revision) {
    ByteWriter w;
    w.raw(kPayloadMagic, 4);
    w.u8(kPayloadVersion);
    w.str(vault.vault_id());
    w.i64(vault.created());
    w.u64(revision);
    if (entries.size() > kMaxEntries) {
        throw VaultError(VaultErrorKind::Format, "too many entries");
    }
    w.u32(static_cast<std::uint32_t>(entries.size()));
    for (const auto& e : entries) {
        w.str(e.id);
        w.str(e.title);
        w.str(e.username);
        w.str(e.password);
        w.str(e.url);
        w.str(e.notes);
        if (e.tags.size() > kMaxTags) throw VaultError(VaultErrorKind::Format, "too many tags");
        w.u16(static_cast<std::uint16_t>(e.tags.size()));
        for (const auto& tag : e.tags) w.str(tag);
        w.i64(e.created);
        w.i64(e.modified);
    }
    return std::move(w.data());
}

struct Payload {
    std::string vault_id;
    std::int64_t created = 0;
    std::uint64_t revision = 0;
    std::vector<Entry> entries;
};

Payload parse_payload(const std::vector<std::uint8_t>& plaintext) {
    ByteReader r(plaintext.data(), plaintext.size());
    const std::uint8_t* magic = r.raw(4);
    if (std::memcmp(magic, kPayloadMagic, 4) != 0) {
        throw VaultError(VaultErrorKind::Format, "vault payload magic mismatch");
    }
    const std::uint8_t version = r.u8();
    if (version != kPayloadVersion) {
        throw VaultError(VaultErrorKind::Format, "unsupported vault payload version");
    }

    Payload payload;
    payload.vault_id = r.str(64);
    payload.created = r.i64();
    payload.revision = r.u64();
    const std::uint32_t count = r.u32();
    if (count > kMaxEntries) throw VaultError(VaultErrorKind::Format, "entry count out of range");

    std::set<std::string> seen_ids;
    payload.entries.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        Entry e;
        e.id = r.str(64);
        e.title = r.str();
        e.username = r.str();
        e.password = r.str();
        e.url = r.str();
        e.notes = r.str();
        const std::uint16_t tag_count = r.u16();
        if (tag_count > kMaxTags) throw VaultError(VaultErrorKind::Format, "tag count out of range");
        e.tags.reserve(tag_count);
        for (std::uint16_t t = 0; t < tag_count; ++t) e.tags.push_back(r.str(256));
        e.created = r.i64();
        e.modified = r.i64();
        if (e.id.empty()) throw VaultError(VaultErrorKind::Format, "entry has an empty id");
        if (!seen_ids.insert(e.id).second) {
            throw VaultError(VaultErrorKind::Format, "duplicate entry id");
        }
        payload.entries.push_back(std::move(e));
    }
    r.expect_end();
    return payload;
}

std::vector<std::uint8_t> build_header_prefix(const std::array<std::uint8_t, kSaltLen>& salt,
                                              const GcmNonce& nonce, std::uint32_t iterations,
                                              std::uint32_t ciphertext_len) {
    ByteWriter w;
    w.raw(kFileMagic, 4);
    w.u8(kFormatVersion);
    w.u8(kKdfPbkdf2HmacSha256);
    w.u32(iterations);
    w.raw(salt.data(), salt.size());
    w.raw(nonce.data(), nonce.size());
    w.u32(ciphertext_len);
    return std::move(w.data());
}

}  // namespace

Vault::~Vault() { wipe_key(); }

void Vault::wipe_key() noexcept {
    secure_zero(key_.data(), key_.size());
    secure_zero(salt_.data(), salt_.size());
}

Vault::Vault(Vault&& other) noexcept
    : path_(std::move(other.path_)),
      entries_(std::move(other.entries_)),
      key_(other.key_),
      salt_(other.salt_),
      iterations_(other.iterations_),
      vault_id_(std::move(other.vault_id_)),
      created_(other.created_),
      revision_(other.revision_),
      dirty_(other.dirty_) {
    other.wipe_key();
    other.entries_.clear();
    other.vault_id_.clear();
}

Vault& Vault::operator=(Vault&& other) noexcept {
    if (this != &other) {
        wipe_key();
        path_ = std::move(other.path_);
        entries_ = std::move(other.entries_);
        key_ = other.key_;
        salt_ = other.salt_;
        iterations_ = other.iterations_;
        vault_id_ = std::move(other.vault_id_);
        created_ = other.created_;
        revision_ = other.revision_;
        dirty_ = other.dirty_;
        other.wipe_key();
        other.entries_.clear();
        other.vault_id_.clear();
    }
    return *this;
}

Vault Vault::create(const std::filesystem::path& path, const std::string& master_password,
                    std::uint32_t iterations) {
    if (path.empty()) throw VaultError(VaultErrorKind::Io, "vault path is empty");
    if (master_password.empty()) {
        throw VaultError(VaultErrorKind::Io, "master password must not be empty");
    }
    if (iterations < kMinIterations || iterations > kMaxIterations) {
        throw VaultError(VaultErrorKind::Io, "PBKDF2 iteration count is out of range");
    }
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) {
        throw VaultError(VaultErrorKind::Io, "a vault already exists at " + path.string());
    }

    Vault vault;
    vault.path_ = path;
    vault.salt_ = {};
    random_bytes(vault.salt_.data(), vault.salt_.size());
    vault.iterations_ = iterations;
    vault.key_ = derive_key(master_password, vault.salt_.data(), vault.salt_.size(), iterations);
    vault.vault_id_ = random_hex_id();
    vault.created_ = now_unix();
    vault.revision_ = 0;
    vault.dirty_ = true;
    vault.write_file(vault.key_, vault.salt_, vault.iterations_, 1);
    return vault;
}

Vault Vault::open(const std::filesystem::path& path, const std::string& master_password) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        throw VaultError(VaultErrorKind::Io, "vault not found at " + path.string());
    }

    const std::vector<std::uint8_t> file = read_file(path, kMaxFileSize);
    if (file.size() < kHeaderPrefixLen + kTagLen) {
        throw VaultError(VaultErrorKind::Format, "file is too small to be a vault");
    }
    ByteReader header(file.data(), file.size());
    const std::uint8_t* magic = header.raw(4);
    if (std::memcmp(magic, kFileMagic, 4) != 0) {
        throw VaultError(VaultErrorKind::Format, "not a CipherVault file");
    }
    const std::uint8_t version = header.u8();
    if (version != kFormatVersion) {
        throw VaultError(VaultErrorKind::Format, "unsupported vault format version");
    }
    const std::uint8_t kdf = header.u8();
    if (kdf != kKdfPbkdf2HmacSha256) {
        throw VaultError(VaultErrorKind::Format, "unsupported key derivation function");
    }
    const std::uint32_t iterations = header.u32();
    if (iterations < kMinIterations || iterations > kMaxIterations) {
        throw VaultError(VaultErrorKind::Format, "PBKDF2 iteration count is out of range");
    }

    std::array<std::uint8_t, kSaltLen> salt{};
    std::memcpy(salt.data(), header.raw(kSaltLen), kSaltLen);
    GcmNonce nonce{};
    std::memcpy(nonce.data(), header.raw(kNonceLen), kNonceLen);
    const std::uint32_t ct_len = header.u32();
    if (ct_len > kMaxFileSize) throw VaultError(VaultErrorKind::Format, "ciphertext length out of range");
    const std::uint8_t* ciphertext = header.raw(ct_len);
    GcmTag tag{};
    std::memcpy(tag.data(), header.raw(kTagLen), kTagLen);
    header.expect_end();

    if (master_password.empty()) {
        throw VaultError(VaultErrorKind::Authentication, "master password must not be empty");
    }

    AesKey key = derive_key(master_password, salt.data(), salt.size(), iterations);
    ScopeWipe key_wipe(key.data(), key.size());
    std::vector<std::uint8_t> prefix = build_header_prefix(salt, nonce, iterations, ct_len);

    std::vector<std::uint8_t> plaintext;
    const bool ok = aes256_gcm_decrypt(key, nonce, ciphertext, ct_len, prefix.data(), prefix.size(),
                                       tag, plaintext);
    if (!ok) {
        throw VaultError(VaultErrorKind::Authentication,
                         "invalid master password or corrupted vault (authentication failed)");
    }

    {
        ScopeWipe wipe(plaintext.data(), plaintext.size());
        Payload payload = parse_payload(plaintext);

        Vault vault;
        vault.path_ = path;
        vault.entries_ = std::move(payload.entries);
        vault.key_ = key;
        vault.salt_ = salt;
        vault.iterations_ = iterations;
        vault.vault_id_ = std::move(payload.vault_id);
        vault.created_ = payload.created;
        vault.revision_ = payload.revision;
        vault.dirty_ = false;
        return vault;
    }
}

std::string Vault::insert_entry(Entry entry, bool preserve_timestamps) {
    if (entry.id.empty()) {
        do {
            entry.id = random_hex_id();
        } while (find_by_id(entry.id) != nullptr);
    } else if (find_by_id(entry.id) != nullptr) {
        throw VaultError(VaultErrorKind::Format, "duplicate entry id: " + entry.id);
    }

    const std::int64_t now = now_unix();
    if (entry.created == 0) entry.created = now;
    if (!preserve_timestamps || entry.modified == 0) entry.modified = now;
    const std::string id = entry.id;
    entries_.push_back(std::move(entry));
    dirty_ = true;
    return id;
}

std::string Vault::add_entry(Entry entry) { return insert_entry(std::move(entry), false); }

void Vault::add_entries(const std::vector<Entry>& entries, bool preserve_timestamps) {
    for (const auto& entry : entries) insert_entry(entry, preserve_timestamps);
}

bool Vault::update_entry(const std::string& id, Entry updated) {
    for (auto& existing : entries_) {
        if (existing.id == id) {
            updated.id = existing.id;
            updated.created = existing.created;
            updated.modified = now_unix();
            existing = std::move(updated);
            dirty_ = true;
            return true;
        }
    }
    return false;
}

bool Vault::remove_entry(const std::string& id) {
    const auto it = std::find_if(entries_.begin(), entries_.end(),
                                 [&id](const Entry& e) { return e.id == id; });
    if (it == entries_.end()) return false;
    secure_zero(it->password);
    entries_.erase(it);
    dirty_ = true;
    return true;
}

const Entry* Vault::find_by_id(std::string_view id) const {
    for (const auto& entry : entries_) {
        if (entry.id == id) return &entry;
    }
    return nullptr;
}

const Entry* Vault::find_by_id_prefix(std::string_view prefix) const {
    if (prefix.empty()) return nullptr;
    const std::string needle = to_lower(prefix);
    const Entry* match = nullptr;
    for (const auto& entry : entries_) {
        if (starts_with(to_lower(entry.id), needle)) {
            if (match != nullptr) return nullptr;  // ambiguous
            match = &entry;
        }
    }
    return match;
}

void Vault::save() {
    if (path_.empty()) throw VaultError(VaultErrorKind::Io, "vault has no path");
    write_file(key_, salt_, iterations_, revision_ + 1);
}

void Vault::write_file(const AesKey& key, const std::array<std::uint8_t, 16>& salt,
                       std::uint32_t iterations, std::uint64_t revision) {
    std::vector<std::uint8_t> payload = serialize_payload(*this, entries_, revision);
    ScopeWipe payload_wipe(payload.data(), payload.size());

    GcmNonce nonce{};
    random_bytes(nonce.data(), nonce.size());

    std::vector<std::uint8_t> prefix =
        build_header_prefix(salt, nonce, iterations, static_cast<std::uint32_t>(payload.size()));

    GcmTag tag{};
    std::vector<std::uint8_t> ciphertext =
        aes256_gcm_encrypt(key, nonce, payload.data(), payload.size(), prefix.data(), prefix.size(),
                           tag);

    std::vector<std::uint8_t> file;
    file.reserve(prefix.size() + ciphertext.size() + tag.size());
    file.insert(file.end(), prefix.begin(), prefix.end());
    file.insert(file.end(), ciphertext.begin(), ciphertext.end());
    file.insert(file.end(), tag.begin(), tag.end());

    backup_file(path_);
    atomic_write_file(path_, file);

    revision_ = revision;
    dirty_ = false;
}

bool Vault::verify_master_password(const std::string& password) const {
    if (path_.empty() || password.empty()) return false;
    AesKey candidate = derive_key(password, salt_.data(), salt_.size(), iterations_);
    ScopeWipe candidate_wipe(candidate.data(), candidate.size());
    return constant_time_equal(candidate.data(), key_.data(), key_.size());
}

void Vault::change_master_password(const std::string& current_password,
                                   const std::string& new_password) {
    if (!verify_master_password(current_password)) {
        throw VaultError(VaultErrorKind::Authentication, "current master password is incorrect");
    }
    if (new_password.empty()) {
        throw VaultError(VaultErrorKind::Io, "new master password must not be empty");
    }

    std::array<std::uint8_t, kSaltLen> new_salt{};
    random_bytes(new_salt.data(), new_salt.size());
    AesKey new_key = derive_key(new_password, new_salt.data(), new_salt.size(), iterations_);
    ScopeWipe new_key_wipe(new_key.data(), new_key.size());

    write_file(new_key, new_salt, iterations_, revision_ + 1);

    wipe_key();
    key_ = new_key;
    salt_ = new_salt;

    // The backup still uses the old key. Remove it so the old password cannot
    // be used to recover the previous snapshot.
    std::error_code ec;
    std::filesystem::path backup = path_;
    backup += ".bak";
    std::filesystem::remove(backup, ec);
}

}  // namespace ciphervault
