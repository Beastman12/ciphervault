// CipherVault - credential entry model
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ciphervault {

struct Entry {
    std::string id;  // 128-bit random identifier, hex encoded
    std::string title;
    std::string username;
    std::string password;
    std::string url;
    std::string notes;
    std::vector<std::string> tags;
    std::int64_t created = 0;
    std::int64_t modified = 0;
};

std::string short_id(std::string_view id);

// Case-insensitive match of one query token against every searchable field.
bool entry_matches_token(const Entry& entry, std::string_view token);

// All whitespace-separated tokens must match (AND semantics).
bool entry_matches(const Entry& entry, std::string_view query);

std::vector<const Entry*> search_entries(const std::vector<Entry>& entries,
                                         std::string_view query);

// Case-insensitive sort by title, then username.
void sort_entries(std::vector<Entry>& entries);
void sort_entry_pointers(std::vector<const Entry*>& entries);

}  // namespace ciphervault
