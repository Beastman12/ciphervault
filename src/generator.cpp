#include "ciphervault/generator.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <vector>

#include "ciphervault/crypto/random.hpp"

namespace ciphervault {
namespace {

constexpr const char* kLower = "abcdefghijklmnopqrstuvwxyz";
constexpr const char* kUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr const char* kDigits = "0123456789";
constexpr const char* kSymbols = "!@#$%^&*()-_=+[]{}:,.?/";
constexpr const char* kAmbiguous = "Il1O0o|`'\"\\;:.,{}[]()/";

std::string filter_ambiguous(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (char c : input) {
        if (std::strchr(kAmbiguous, c) == nullptr) out.push_back(c);
    }
    return out;
}

}  // namespace

std::string build_charset(const GeneratorOptions& options) {
    std::string pool;
    auto add = [&pool](const char* set) { pool += set; };
    if (options.use_lowercase) add(kLower);
    if (options.use_uppercase) add(kUpper);
    if (options.use_digits) add(kDigits);
    if (options.use_symbols) add(kSymbols);

    if (options.exclude_ambiguous) pool = filter_ambiguous(pool);

    // Deduplicate while preserving order (the sets above are disjoint, but a
    // caller could enable a future overlapping set).
    std::string unique;
    for (char c : pool) {
        if (unique.find(c) == std::string::npos) unique.push_back(c);
    }
    return unique;
}

std::string generate_password(const GeneratorOptions& options) {
    if (options.length < 1) throw std::invalid_argument("password length must be at least 1");
    if (options.length > 4096) throw std::invalid_argument("password length is unreasonable");

    const std::string pool = build_charset(options);
    if (pool.empty()) throw std::invalid_argument("no character classes selected");

    std::vector<std::string> classes;
    if (options.use_lowercase) classes.push_back(filter_ambiguous(kLower));
    if (options.use_uppercase) classes.push_back(filter_ambiguous(kUpper));
    if (options.use_digits) classes.push_back(filter_ambiguous(kDigits));
    if (options.use_symbols) classes.push_back(filter_ambiguous(kSymbols));
    if (options.exclude_ambiguous) {
        for (auto& cls : classes) {
            if (cls.empty()) throw std::invalid_argument("character class is empty after filtering");
        }
    }

    if (options.require_each_class && options.length < classes.size()) {
        throw std::invalid_argument("password length is too short for the selected character classes");
    }

    std::string password;
    password.reserve(options.length);

    if (options.require_each_class) {
        for (const auto& cls : classes) {
            password.push_back(cls[random_below(static_cast<std::uint32_t>(cls.size()))]);
        }
    }

    while (password.size() < options.length) {
        password.push_back(pool[random_below(static_cast<std::uint32_t>(pool.size()))]);
    }

    // Fisher-Yates shuffle with CSPRNG indices so the guaranteed characters
    // are not stuck at predictable positions.
    for (std::size_t i = password.size(); i > 1; --i) {
        const std::size_t j = random_below(static_cast<std::uint32_t>(i));
        std::swap(password[i - 1], password[j]);
    }
    return password;
}

double theoretical_entropy(const GeneratorOptions& options) {
    const std::size_t pool = build_charset(options).size();
    if (pool == 0) return 0.0;
    return std::log2(static_cast<double>(pool)) * static_cast<double>(options.length);
}

}  // namespace ciphervault
