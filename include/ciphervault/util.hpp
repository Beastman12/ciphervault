// CipherVault - small string, time and filesystem helpers
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace ciphervault {

std::string to_lower(std::string_view s);
std::string trim(std::string_view s);
bool starts_with(std::string_view s, std::string_view prefix);
bool iequals(std::string_view a, std::string_view b);
bool contains_ci(std::string_view haystack, std::string_view needle);

std::vector<std::string> split(std::string_view s, char delimiter);
std::string join(const std::vector<std::string>& parts, std::string_view separator);

std::string format_timestamp(std::int64_t unix_time);
std::string format_relative_time(std::int64_t unix_time);
std::string human_size(std::uint64_t bytes);
std::string random_hex_id();
std::string get_env(const char* name);

// True when both buffers are equal; the comparison time does not depend on
// the position of the first difference.
bool constant_time_equal(const void* a, const void* b, std::size_t len) noexcept;

std::filesystem::path default_vault_path();
void ensure_private_directory(const std::filesystem::path& dir);
void set_owner_only_permissions(const std::filesystem::path& path);

std::vector<std::uint8_t> read_file(const std::filesystem::path& path,
                                    std::size_t max_size = 64u * 1024u * 1024u);
void atomic_write_file(const std::filesystem::path& path,
                       const std::vector<std::uint8_t>& data);
void backup_file(const std::filesystem::path& path);

std::string path_to_display(const std::filesystem::path& path);

}  // namespace ciphervault
