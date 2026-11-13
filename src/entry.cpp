#include "ciphervault/entry.hpp"

#include <algorithm>

#include "ciphervault/util.hpp"

namespace ciphervault {

std::string short_id(std::string_view id) {
    if (id.size() <= 8) return std::string(id);
    return std::string(id.substr(0, 8));
}

bool entry_matches_token(const Entry& entry, std::string_view token) {
    if (token.empty()) return true;
    if (contains_ci(entry.title, token)) return true;
    if (contains_ci(entry.username, token)) return true;
    if (contains_ci(entry.url, token)) return true;
    if (contains_ci(entry.notes, token)) return true;
    for (const auto& tag : entry.tags) {
        if (contains_ci(tag, token)) return true;
    }
    return false;
}

bool entry_matches(const Entry& entry, std::string_view query) {
    const std::vector<std::string> tokens = split(trim(query), ' ');
    for (const auto& token : tokens) {
        if (token.empty()) continue;
        if (!entry_matches_token(entry, token)) return false;
    }
    return true;
}

std::vector<const Entry*> search_entries(const std::vector<Entry>& entries,
                                         std::string_view query) {
    std::vector<const Entry*> matches;
    for (const auto& entry : entries) {
        if (entry_matches(entry, query)) matches.push_back(&entry);
    }
    sort_entry_pointers(matches);
    return matches;
}

namespace {

bool entry_less(const Entry& a, const Entry& b) {
    const std::string at = to_lower(a.title);
    const std::string bt = to_lower(b.title);
    if (at != bt) return at < bt;
    const std::string au = to_lower(a.username);
    const std::string bu = to_lower(b.username);
    if (au != bu) return au < bu;
    return a.id < b.id;
}

}  // namespace

void sort_entries(std::vector<Entry>& entries) {
    std::sort(entries.begin(), entries.end(), entry_less);
}

void sort_entry_pointers(std::vector<const Entry*>& entries) {
    std::sort(entries.begin(), entries.end(),
              [](const Entry* a, const Entry* b) { return entry_less(*a, *b); });
}

}  // namespace ciphervault
