// CipherVault - password generation
#pragma once

#include <cstddef>
#include <string>

namespace ciphervault {

struct GeneratorOptions {
    std::size_t length = 20;
    bool use_lowercase = true;
    bool use_uppercase = true;
    bool use_digits = true;
    bool use_symbols = true;
    bool exclude_ambiguous = false;
    bool require_each_class = true;
};

// Builds the candidate character pool for the selected options.
std::string build_charset(const GeneratorOptions& options);

// Generates a password from the operating-system CSPRNG.
// Throws std::invalid_argument for impossible configurations.
std::string generate_password(const GeneratorOptions& options);

// log2(pool_size) * length: the search space of the generated password.
double theoretical_entropy(const GeneratorOptions& options);

}  // namespace ciphervault
