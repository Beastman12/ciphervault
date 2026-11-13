// Minimal dependency-free test harness
#pragma once

#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

namespace tf {

using TestFn = void (*)();

struct TestCase {
    const char* name;
    TestFn fn;
};

std::vector<TestCase>& registry();
int& failure_count();

struct Registrar {
    Registrar(const char* name, TestFn fn) { registry().push_back({name, fn}); }
};

inline void report_failure(const char* file, int line, const std::string& message) {
    ++failure_count();
    std::ostringstream out;
    out << file << ':' << line << ": " << message << '\n';
    // Written to stderr as a single line so CI logs stay readable.
    std::fputs(out.str().c_str(), stderr);
}

template <typename T>
std::string to_str(const T& value) {
    std::ostringstream out;
    out << value;
    return out.str();
}

}  // namespace tf

#define TF_CONCAT_INNER(a, b) a##b
#define TF_CONCAT(a, b) TF_CONCAT_INNER(a, b)

#define TEST(name)                                                        \
    static void name();                                                   \
    static ::tf::Registrar TF_CONCAT(tf_registrar_, name)(#name, &name);  \
    static void name()

#define CHECK(condition)                                                          \
    do {                                                                          \
        if (!(condition)) {                                                       \
            ::tf::report_failure(__FILE__, __LINE__, "CHECK failed: " #condition); \
        }                                                                         \
    } while (0)

#define CHECK_EQ(actual, expected)                                                          \
    do {                                                                                    \
        const auto& tf_a = (actual);                                                        \
        const auto& tf_b = (expected);                                                      \
        if (!(tf_a == tf_b)) {                                                              \
            ::tf::report_failure(__FILE__, __LINE__,                                        \
                                 std::string("CHECK_EQ failed: " #actual " == " #expected) + \
                                     " (got " + ::tf::to_str(tf_a) + " vs " +               \
                                     ::tf::to_str(tf_b) + ")");                             \
        }                                                                                   \
    } while (0)

#define CHECK_THROWS(expression, exception_type)                                          \
    do {                                                                                  \
        bool tf_caught = false;                                                           \
        try {                                                                             \
            (void)(expression);                                                           \
        } catch (const exception_type&) {                                                 \
            tf_caught = true;                                                             \
        } catch (...) {                                                                   \
        }                                                                                 \
        if (!tf_caught) {                                                                 \
            ::tf::report_failure(__FILE__, __LINE__,                                      \
                                 "expected " #exception_type " from: " #expression);      \
        }                                                                                 \
    } while (0)
