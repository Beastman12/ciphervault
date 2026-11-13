#include <cstdio>
#include <exception>

#include "test_framework.hpp"

namespace tf {
std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}
int& failure_count() {
    static int failures = 0;
    return failures;
}
}  // namespace tf

int main() {
    int executed = 0;
    for (const auto& test : tf::registry()) {
        const int before = tf::failure_count();
        try {
            test.fn();
        } catch (const std::exception& e) {
            tf::report_failure("(uncaught)", 0,
                               std::string("test '") + test.name + "' threw: " + e.what());
        } catch (...) {
            tf::report_failure("(uncaught)", 0,
                               std::string("test '") + test.name + "' threw an unknown exception");
        }
        ++executed;
        std::printf("[%s] %s\n", tf::failure_count() == before ? "PASS" : "FAIL", test.name);
    }

    std::printf("\n%d test(s), %d failure(s)\n", executed, tf::failure_count());
    return tf::failure_count() == 0 ? 0 : 1;
}
