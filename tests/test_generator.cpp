#include <cctype>
#include <set>
#include <string>

#include "ciphervault/crypto/secure_memory.hpp"
#include "ciphervault/csv.hpp"
#include "ciphervault/generator.hpp"
#include "ciphervault/strength.hpp"
#include "ciphervault/util.hpp"
#include "test_framework.hpp"

using namespace ciphervault;

TEST(generator_default_length_and_classes) {
    GeneratorOptions options;
    options.length = 24;
    const std::string password = generate_password(options);
    CHECK_EQ(password.size(), std::size_t{24});

    bool lower = false, upper = false, digit = false, symbol = false;
    for (unsigned char c : password) {
        if (std::islower(c)) lower = true;
        else if (std::isupper(c)) upper = true;
        else if (std::isdigit(c)) digit = true;
        else symbol = true;
    }
    CHECK(lower && upper && digit && symbol);
}

TEST(generator_respects_length_and_uniqueness) {
    GeneratorOptions options;
    options.length = 16;
    std::set<std::string> seen;
    for (int i = 0; i < 200; ++i) seen.insert(generate_password(options));
    CHECK_EQ(seen.size(), std::size_t{200});
}

TEST(generator_excludes_ambiguous_characters) {
    GeneratorOptions options;
    options.length = 64;
    options.exclude_ambiguous = true;
    const std::string charset = build_charset(options);
    for (char c : std::string("Il1O0o")) {
        CHECK(charset.find(c) == std::string::npos);
    }
    const std::string password = generate_password(options);
    for (char c : std::string("Il1O0o")) {
        CHECK(password.find(c) == std::string::npos);
    }
}

TEST(generator_only_digits) {
    GeneratorOptions options;
    options.length = 12;
    options.use_lowercase = false;
    options.use_uppercase = false;
    options.use_symbols = false;
    options.use_digits = true;
    const std::string password = generate_password(options);
    CHECK_EQ(password.size(), std::size_t{12});
    for (unsigned char c : password) CHECK(std::isdigit(c));
}

TEST(generator_rejects_impossible_configuration) {
    GeneratorOptions options;
    options.length = 2;
    CHECK_THROWS(generate_password(options), std::invalid_argument);

    GeneratorOptions none;
    none.use_lowercase = false;
    none.use_uppercase = false;
    none.use_digits = false;
    none.use_symbols = false;
    CHECK_THROWS(generate_password(none), std::invalid_argument);
}

TEST(generator_entropy_is_reasonable) {
    GeneratorOptions options;
    options.length = 20;
    const double bits = theoretical_entropy(options);
    CHECK(bits > 100.0);
    CHECK(bits < 160.0);
}

TEST(strength_scores_common_passwords_low) {
    for (const char* weak : {"password", "123456", "qwerty", "letmein", "Password123!"}) {
        const auto result = estimate_strength(weak);
        CHECK_EQ(result.score, 0);
    }
}

TEST(strength_rewards_random_passwords) {
    GeneratorOptions options;
    options.length = 20;
    const std::string password = generate_password(options);
    const auto result = estimate_strength(password);
    CHECK(result.score >= 3);
    CHECK(result.entropy_bits > 70.0);
}

TEST(strength_penalises_patterns) {
    const auto repeated = estimate_strength("aaaaaaaaaaaaaaaa");
    CHECK(repeated.score <= 1);
    const auto sequential = estimate_strength("abcdefghijklmnop");
    CHECK(sequential.score <= 2);
}

TEST(csv_roundtrip_with_quotes_and_newlines) {
    const std::vector<std::string> fields = {"GitHub", "user,name", "p@ss\"word",
                                             "https://example.com/a,b", "line1\nline2",
                                             "work,code"};
    const std::string row = csv_row(fields);
    const auto parsed = csv_parse(row + "\n");
    CHECK_EQ(parsed.size(), std::size_t{1});
    CHECK_EQ(parsed[0].size(), fields.size());
    for (std::size_t i = 0; i < fields.size(); ++i) CHECK_EQ(parsed[0][i], fields[i]);
}

TEST(csv_parses_crlf_and_multiple_rows) {
    const std::string document = "a,b\r\n\"c\",\"d\"\r\n";
    const auto rows = csv_parse(document);
    CHECK_EQ(rows.size(), std::size_t{2});
    CHECK_EQ(rows[0][0], std::string("a"));
    CHECK_EQ(rows[1][1], std::string("d"));
}

TEST(csv_detects_delimiter) {
    CHECK_EQ(detect_delimiter("a;b;c\n"), ';');
    CHECK_EQ(detect_delimiter("a\tb\tc\n"), '\t');
    CHECK_EQ(detect_delimiter("a,b,c\n"), ',');
}

TEST(string_helpers) {
    CHECK_EQ(trim("  hello \n"), std::string("hello"));
    CHECK_EQ(to_lower("AbC"), std::string("abc"));
    CHECK(contains_ci("Hello World", "WORLD"));
    CHECK(!contains_ci("Hello", "xyz"));
    CHECK(iequals("ABC", "abc"));
    CHECK_EQ(split("a,b,,c", ',').size(), std::size_t{4});
    CHECK_EQ(join({"a", "b"}, "-"), std::string("a-b"));
}

TEST(constant_time_equal_works) {
    const char a[] = {1, 2, 3, 4};
    const char b[] = {1, 2, 3, 4};
    const char c[] = {1, 2, 3, 5};
    CHECK(constant_time_equal(a, b, 4));
    CHECK(!constant_time_equal(a, c, 4));
}

TEST(generated_password_survives_secure_wipe) {
    GeneratorOptions options;
    options.length = 8;
    std::string password = generate_password(options);
    const std::string copy = password;
    secure_zero(password);
    CHECK_EQ(password.size(), copy.size());
    for (char c : password) CHECK_EQ(c, '\0');
}
