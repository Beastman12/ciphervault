// CipherVault - encrypted vault container
#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "ciphervault/crypto/gcm.hpp"
#include "ciphervault/entry.hpp"

namespace ciphervault {

enum class VaultErrorKind {
    Io,             // file could not be read/written
    Format,         // not a vault, truncated, malformed, unsupported version
    Authentication  // wrong master password or tampered ciphertext
};

class VaultError : public std::runtime_error {
public:
    VaultError(VaultErrorKind kind, const std::string& message)
        : std::runtime_error(message), kind_(kind) {}
    VaultErrorKind kind() const noexcept { return kind_; }

private:
    VaultErrorKind kind_;
};

class Vault {
public:
    static constexpr std::uint32_t kDefaultIterations = 210000;
    static constexpr std::uint32_t kMinIterations = 10000;
    static constexpr std::uint32_t kMaxIterations = 5000000;

    Vault() = default;
    ~Vault();

    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;
    Vault(Vault&& other) noexcept;
    Vault& operator=(Vault&& other) noexcept;

    // Creates a new vault. Fails if the file already exists.
    static Vault create(const std::filesystem::path& path, const std::string& master_password,
                        std::uint32_t iterations = kDefaultIterations);

    // Opens and authenticates an existing vault.
    static Vault open(const std::filesystem::path& path, const std::string& master_password);

    const std::filesystem::path& path() const noexcept { return path_; }
    const std::vector<Entry>& entries() const noexcept { return entries_; }
    const std::string& vault_id() const noexcept { return vault_id_; }
    std::int64_t created() const noexcept { return created_; }
    std::uint64_t revision() const noexcept { return revision_; }
    std::uint32_t iterations() const noexcept { return iterations_; }
    bool dirty() const noexcept { return dirty_; }

    // Returns the generated id. If the supplied id is empty a random one is
    // assigned; timestamps are filled in.
    std::string add_entry(Entry entry);
    // Bulk insert (used by imports). Non-zero timestamps are preserved.
    void add_entries(const std::vector<Entry>& entries, bool preserve_timestamps = false);

    // Preserves id and creation time, updates the modification time.
    bool update_entry(const std::string& id, Entry updated);
    bool remove_entry(const std::string& id);

    const Entry* find_by_id(std::string_view id) const;
    const Entry* find_by_id_prefix(std::string_view prefix) const;

    // Re-encrypts with a fresh nonce and writes atomically. Also refreshes the
    // .bak copy of the previous file version.
    void save();

    // Verifies |current| against the in-memory key without touching disk.
    bool verify_master_password(const std::string& password) const;

    // Re-keys the vault with a new random salt. The .bak file is removed
    // because it is still encrypted under the old password.
    void change_master_password(const std::string& current_password,
                                const std::string& new_password);

private:
    std::string insert_entry(Entry entry, bool preserve_timestamps);
    void write_file(const AesKey& key, const std::array<std::uint8_t, 16>& salt,
                    std::uint32_t iterations, std::uint64_t revision);
    void wipe_key() noexcept;

    std::filesystem::path path_;
    std::vector<Entry> entries_;
    AesKey key_{};
    std::array<std::uint8_t, 16> salt_{};
    std::uint32_t iterations_ = kDefaultIterations;
    std::string vault_id_;
    std::int64_t created_ = 0;
    std::uint64_t revision_ = 0;
    bool dirty_ = false;
};

}  // namespace ciphervault
