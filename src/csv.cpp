#include "ciphervault/csv.hpp"

#include <algorithm>

namespace ciphervault {

std::string csv_escape(std::string_view field) {
    const bool needs_quotes = field.find_first_of(",\";\r\n") != std::string_view::npos;
    if (!needs_quotes) return std::string(field);

    std::string out;
    out.reserve(field.size() + 2);
    out.push_back('"');
    for (char c : field) {
        if (c == '"') out.push_back('"');
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

std::string csv_row(const std::vector<std::string>& fields) {
    std::string out;
    for (std::size_t i = 0; i < fields.size(); ++i) {
        if (i != 0) out.push_back(',');
        out += csv_escape(fields[i]);
    }
    return out;
}

std::vector<std::vector<std::string>> csv_parse(std::string_view document, char delimiter) {
    std::vector<std::vector<std::string>> rows;
    std::vector<std::string> row;
    std::string field;
    bool in_quotes = false;
    bool field_started = false;

    auto finish_field = [&]() {
        row.push_back(field);
        field.clear();
        field_started = false;
    };
    auto finish_row = [&]() {
        finish_field();
        rows.push_back(row);
        row.clear();
    };

    for (std::size_t i = 0; i < document.size(); ++i) {
        const char c = document[i];
        if (in_quotes) {
            if (c == '"') {
                if (i + 1 < document.size() && document[i + 1] == '"') {
                    field.push_back('"');
                    ++i;
                } else {
                    in_quotes = false;
                }
            } else {
                field.push_back(c);
            }
            continue;
        }

        if (c == '"' && !field_started) {
            in_quotes = true;
            field_started = true;
        } else if (c == delimiter) {
            finish_field();
        } else if (c == '\n') {
            if (!field.empty() && field.back() == '\r') field.pop_back();
            finish_row();
        } else if (c == '\r') {
            // Handled by the '\n' branch; a lone '\r' also ends a record.
            if (i + 1 < document.size() && document[i + 1] == '\n') continue;
            finish_row();
        } else {
            field.push_back(c);
            field_started = true;
        }
    }

    if (in_quotes) {
        // Unbalanced quote: treat the remainder as a field rather than silently
        // discarding imported data.
    }
    if (field_started || !field.empty() || !row.empty()) finish_row();
    return rows;
}

char detect_delimiter(std::string_view document) {
    const std::size_t line_end = document.find('\n');
    const std::string_view first =
        document.substr(0, line_end == std::string_view::npos ? document.size() : line_end);
    const std::size_t commas = static_cast<std::size_t>(std::count(first.begin(), first.end(), ','));
    const std::size_t semis = static_cast<std::size_t>(std::count(first.begin(), first.end(), ';'));
    const std::size_t tabs = static_cast<std::size_t>(std::count(first.begin(), first.end(), '\t'));
    if (semis > commas && semis >= tabs) return ';';
    if (tabs > commas && tabs > semis) return '\t';
    return ',';
}

}  // namespace ciphervault
