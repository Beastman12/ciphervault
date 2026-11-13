// CipherVault - RFC 4180-style CSV import/export
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace ciphervault {

std::string csv_escape(std::string_view field);
std::string csv_row(const std::vector<std::string>& fields);

// Parses a complete CSV document. Handles quoted fields, escaped quotes
// ("") and embedded newlines. CRLF and LF are both accepted.
std::vector<std::vector<std::string>> csv_parse(std::string_view document,
                                                char delimiter = ',');

// Returns the most frequent delimiter among ',', ';' and '\t' in the first line.
char detect_delimiter(std::string_view document);

}  // namespace ciphervault
