#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "ciphervault/crypto/secure_memory.hpp"
#include "ciphervault/entry.hpp"
#include "ciphervault/strength.hpp"
#include "ciphervault/util.hpp"
#include "ciphervault/vault.hpp"
#include "test_framework.hpp"

using namespace ciphervault;

namespace {

class TempDir {
public:
    TempDir() {
        path_ = std::filesystem::temp_directory_path() /
                ("ciphervault_test_" + random_hex_id().substr(0, 12));
        std::filesystem::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

constexpr std::uint32_t kTestIterations = Vault::kMinIterations;
const std::string kMaster = "correct horse battery staple";

Entry make_entry(const std::string& title, const std::string& username,
                 const std::string& password) {
    Entry e;
    e.title = title;
    e.username = username;
    e.password = password;
    e.url = "https://example.com/" + title;
    e.tags = {"personal"};
    return e;
}

std::filesystem::path vault_file(const TempDir& dir) {
    return dir.path() / "test.spm";
}

}  // namespace

TEST(vault_create_and_reopen) {
    TempDir dir;
    const auto file = vault_file(dir);

    {
        Vault vault = Vault::create(file, kMaster, kTestIterations);
        const std::string id = vault.add_entry(make_entry("GitHub", "octocat", "s3cret!"));
        CHECK_EQ(id.size(), std::size_t{32});
        vault.add_entry(make_entry("Mail", "me@example.com", "hunter2!"));
        CHECK_EQ(vault.entries().size(), std::size_t{2});
        vault.save();
        CHECK_EQ(vault.revision(), std::uint64_t{2});
        CHECK(!vault.dirty());
    }

    Vault reopened = Vault::open(file, kMaster);
    CHECK_EQ(reopened.entries().size(), std::size_t{2});
    CHECK_EQ(reopened.iterations(), kTestIterations);
    CHECK_EQ(reopened.created() > 0, true);
    CHECK_EQ(reopened.vault_id().size(), std::size_t{32});
    const Entry* github = reopened.find_by_id_prefix("Git");
    // Prefix search works on the id, not the title.
    CHECK(github == nullptr);
    const Entry* first = reopened.find_by_id(reopened.entries()[0].id);
    CHECK(first != nullptr);
    CHECK_EQ(first->title, std::string("GitHub"));
}

TEST(vault_rejects_wrong_password) {
    TempDir dir;
    const auto file = vault_file(dir);
    {
        Vault vault = Vault::create(file, kMaster, kTestIterations);
        vault.add_entry(make_entry("GitHub", "octocat", "s3cret!"));
        vault.save();
    }

    bool committed = false;
    try {
        Vault::open(file, "wrong password");
    } catch (const VaultError& e) {
        CHECK(e.kind() == VaultErrorKind::Authentication);
        committed = true;
    }
    CHECK(committed);
}

TEST(vault_rejects_tampered_ciphertext) {
    TempDir dir;
    const auto file = vault_file(dir);
    {
        Vault vault = Vault::create(file, kMaster, kTestIterations);
        vault.add_entry(make_entry("GitHub", "octocat", "s3cret!"));
        vault.save();
    }

    auto bytes = read_file(file);
    bytes[bytes.size() - 20] ^= 0x01;  // inside ciphertext
    atomic_write_file(file, bytes);

    CHECK_THROWS(Vault::open(file, kMaster), VaultError);
}

TEST(vault_rejects_tampered_header) {
    TempDir dir;
    const auto file = vault_file(dir);
    {
        Vault vault = Vault::create(file, kMaster, kTestIterations);
        vault.save();
    }

    auto bytes = read_file(file);
    // The iteration count occupies bytes 6..9 (big endian). Changing it must
    // break authentication even though the ciphertext is untouched.
    bytes[9] ^= 0x01;
    atomic_write_file(file, bytes);

    bool format_error = false;
    try {
        Vault::open(file, kMaster);
    } catch (const VaultError& e) {
        format_error = e.kind() == VaultErrorKind::Format ||
                       e.kind() == VaultErrorKind::Authentication;
    }
    CHECK(format_error);
}

TEST(vault_rejects_truncated_file) {
    TempDir dir;
    const auto file = vault_file(dir);
    {
        Vault vault = Vault::create(file, kMaster, kTestIterations);
        vault.save();
    }
    auto bytes = read_file(file);
    bytes.resize(bytes.size() - 2);
    atomic_write_file(file, bytes);
    CHECK_THROWS(Vault::open(file, kMaster), VaultError);
}

TEST(vault_change_master_password) {
    TempDir dir;
    const auto file = vault_file(dir);
    {
        Vault vault = Vault::create(file, kMaster, kTestIterations);
        vault.add_entry(make_entry("GitHub", "octocat", "s3cret!"));
        vault.save();
        vault.change_master_password(kMaster, "a new master passphrase");
    }

    CHECK_THROWS(Vault::open(file, kMaster), VaultError);
    Vault reopened = Vault::open(file, "a new master passphrase");
    CHECK_EQ(reopened.entries().size(), std::size_t{1});
    CHECK(!std::filesystem::exists(std::filesystem::path(file.string() + ".bak")));
}

TEST(vault_update_remove_and_search) {
    TempDir dir;
    const auto file = vault_file(dir);
    Vault vault = Vault::create(file, kMaster, kTestIterations);
    const std::string id = vault.add_entry(make_entry("GitHub", "octocat", "one"));

    Entry updated = *vault.find_by_id(id);
    updated.username = "new-user";
    updated.password = "two";
    updated.tags = {"work", "code"};
    CHECK(vault.update_entry(id, updated));
    CHECK_EQ(vault.find_by_id(id)->username, std::string("new-user"));
    CHECK_EQ(vault.find_by_id(id)->created, updated.created);

    const auto matches = search_entries(vault.entries(), "work code");
    CHECK_EQ(matches.size(), std::size_t{1});
    CHECK_EQ(search_entries(vault.entries(), "nothing-here").size(), std::size_t{0});
    CHECK_EQ(search_entries(vault.entries(), "OCTOCAT").size(), std::size_t{0});
    CHECK_EQ(search_entries(vault.entries(), "NEW-USER").size(), std::size_t{1});

    CHECK(vault.remove_entry(id));
    CHECK(vault.entries().empty());
    CHECK(!vault.remove_entry(id));
    vault.save();

    Vault reopened = Vault::open(file, kMaster);
    CHECK(reopened.entries().empty());
}

TEST(vault_backup_keeps_previous_version) {
    TempDir dir;
    const auto file = vault_file(dir);
    {
        Vault vault = Vault::create(file, kMaster, kTestIterations);
        vault.add_entry(make_entry("First", "a", "1"));
        vault.save();
    }
    const auto backup = std::filesystem::path(file.string() + ".bak");
    CHECK(std::filesystem::exists(backup));

    Vault backup_vault = Vault::open(backup, kMaster);
    CHECK_EQ(backup_vault.entries().size(), std::size_t{0});  // initial empty snapshot

    Vault current = Vault::open(file, kMaster);
    CHECK_EQ(current.entries().size(), std::size_t{1});
}

TEST(vault_create_refuses_to_overwrite) {
    TempDir dir;
    const auto file = vault_file(dir);
    Vault::create(file, kMaster, kTestIterations);
    CHECK_THROWS(Vault::create(file, kMaster, kTestIterations), VaultError);
}

TEST(vault_rejects_weak_iteration_count) {
    TempDir dir;
    const auto file = vault_file(dir);
    CHECK_THROWS(Vault::create(file, kMaster, Vault::kMinIterations - 1), VaultError);
    CHECK_THROWS(Vault::create(file, kMaster, 1), VaultError);
}

TEST(vault_rejects_empty_password) {
    TempDir dir;
    CHECK_THROWS(Vault::create(vault_file(dir), "", kTestIterations), VaultError);
}

TEST(vault_verify_master_password) {
    TempDir dir;
    Vault vault = Vault::create(vault_file(dir), kMaster, kTestIterations);
    CHECK(vault.verify_master_password(kMaster));
    CHECK(!vault.verify_master_password("nope"));
}

TEST(strength_and_generator_sanity) {
    const auto weak = estimate_strength("password123");
    CHECK_EQ(weak.score, 0);
    CHECK(!weak.warnings.empty());

    const auto strong = estimate_strength("vA#9mQ!2xL@p7Rs$");
    CHECK(strong.score >= 3);
}
