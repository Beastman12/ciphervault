#include "ciphervault/strength.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <set>

#include "ciphervault/util.hpp"

namespace ciphervault {
namespace {

double pool_entropy(std::string_view password) {
    bool lower = false, upper = false, digit = false, symbol = false, other = false;
    std::size_t length = 0;
    for (unsigned char c : password) {
        if (c == 0) continue;
        ++length;
        if (c >= 'a' && c <= 'z') lower = true;
        else if (c >= 'A' && c <= 'Z') upper = true;
        else if (c >= '0' && c <= '9') digit = true;
        else if (c < 128) symbol = true;
        else other = true;
    }
    if (length == 0) return 0.0;

    double pool = 0.0;
    if (lower) pool += 26.0;
    if (upper) pool += 26.0;
    if (digit) pool += 10.0;
    if (symbol) pool += 32.0;
    if (other) pool += 100.0;
    return std::log2(pool) * static_cast<double>(length);
}

bool has_sequential_run(std::string_view password, std::size_t run) {
    if (password.size() < run) return false;
    std::size_t ascending = 1;
    std::size_t descending = 1;
    for (std::size_t i = 1; i < password.size(); ++i) {
        const auto prev = static_cast<unsigned char>(password[i - 1]);
        const auto cur = static_cast<unsigned char>(password[i]);
        ascending = (cur == prev + 1) ? ascending + 1 : 1;
        descending = (prev == cur + 1) ? descending + 1 : 1;
        if (ascending >= run || descending >= run) return true;
    }
    return false;
}

bool has_repeated_run(std::string_view password, std::size_t run) {
    if (password.size() < run) return false;
    std::size_t same = 1;
    for (std::size_t i = 1; i < password.size(); ++i) {
        same = (password[i] == password[i - 1]) ? same + 1 : 1;
        if (same >= run) return true;
    }
    return false;
}

std::string normalize_common(std::string_view password) {
    std::string out;
    out.reserve(password.size());
    for (unsigned char c : password) {
        if (std::isalnum(c)) out.push_back(static_cast<char>(std::tolower(c)));
    }
    // "Password123!" still reduces to "password".
    while (!out.empty() && std::isdigit(static_cast<unsigned char>(out.back()))) out.pop_back();
    return out;
}

bool is_common_password(std::string_view password) {
    static const std::array<const char*, 64> kCommon = {
        "password", "passw0rd", "123456",  "12345678", "123456789", "qwerty",
        "qwertyuiop", "abc123", "letmein", "monkey",   "dragon",    "football",
        "baseball", "welcome", "welcome1", "iloveyou", "admin",     "login",
        "master",   "sunshine", "princess", "shadow",  "superman",  "michael",
        "trustno1", "hello",    "freedom",  "whatever", "starwars", "computer",
        "secret",   "mypassword", "password1", "pass",  "test",     "guest",
        "root",     "toor",     "changeme", "qazwsx",  "1q2w3e4r",  "zaq12wsx",
        "hunter2",  "batman",   "soccer",   "hockey",  "killer",    "george",
        "summer",   "winter",   "spring",   "autumn",  "january",   "december",
        "google",   "facebook", "linkedin", "github",  "letmein123", "admin123",
        "root123",  "test123",  "qwerty123", "1234567890"};
    const std::string normalized = normalize_common(password);
    if (normalized.empty()) return false;
    for (const char* common : kCommon) {
        if (normalized == common) return true;
    }
    return false;
}

bool has_keyboard_walk(std::string_view password) {
    static const std::array<const char*, 12> kWalk = {
        "qwerty", "asdf", "zxcv", "qwertyuiop", "asdfgh", "zxcvbn",
        "1234",   "9876", "1qaz", "2wsx",       "poiu",  "lkjh"};
    const std::string lower = to_lower(password);
    for (const char* walk : kWalk) {
        if (lower.find(walk) != std::string::npos) return true;
    }
    return false;
}

std::string label_for(int score) {
    switch (score) {
        case 0: return "very weak";
        case 1: return "weak";
        case 2: return "fair";
        case 3: return "strong";
        default: return "very strong";
    }
}

}  // namespace

StrengthResult estimate_strength(std::string_view password) {
    StrengthResult result;
    result.entropy_bits = pool_entropy(password);

    if (password.empty()) {
        result.score = 0;
        result.label = label_for(0);
        result.warnings.push_back("password is empty");
        return result;
    }

    bool has_lower = false, has_upper = false, has_digit = false, has_symbol = false;
    for (unsigned char c : password) {
        if (c >= 'a' && c <= 'z') has_lower = true;
        else if (c >= 'A' && c <= 'Z') has_upper = true;
        else if (c >= '0' && c <= '9') has_digit = true;
        else has_symbol = true;
    }

    if (is_common_password(password)) {
        result.warnings.push_back("this is one of the most common passwords");
        result.entropy_bits = std::min(result.entropy_bits, 12.0);
    }
    if (has_repeated_run(password, 3)) {
        result.warnings.push_back("contains a repeated character run");
        result.entropy_bits -= 20.0;
        result.entropy_bits = std::min(result.entropy_bits, 25.0);
    }
    if (has_sequential_run(password, 3)) {
        result.warnings.push_back("contains a sequential run (abc / 123)");
        result.entropy_bits -= 10.0;
    }
    if (has_keyboard_walk(password)) {
        result.warnings.push_back("contains a keyboard pattern (qwerty / asdf)");
        result.entropy_bits -= 15.0;
        result.entropy_bits = std::min(result.entropy_bits, 40.0);
    }
    if (password.size() < 12) result.warnings.push_back("shorter than 12 characters");
    if (!has_lower) result.warnings.push_back("no lowercase letters");
    if (!has_upper) result.warnings.push_back("no uppercase letters");
    if (!has_digit) result.warnings.push_back("no digits");
    if (!has_symbol) result.warnings.push_back("no symbols");

    if (result.entropy_bits < 0.0) result.entropy_bits = 0.0;
    double bits = result.entropy_bits;
    if (password.size() < 8) bits = std::min(bits, 24.0);

    if (bits >= 90.0) result.score = 4;
    else if (bits >= 70.0) result.score = 3;
    else if (bits >= 50.0) result.score = 2;
    else if (bits >= 30.0) result.score = 1;
    else result.score = 0;

    if (is_common_password(password)) result.score = 0;
    result.label = label_for(result.score);
    return result;
}

}  // namespace ciphervault
