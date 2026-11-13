// CipherVault - password strength estimation
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace ciphervault {

struct StrengthResult {
    int score = 0;  // 0 (very weak) .. 4 (very strong)
    double entropy_bits = 0.0;
    std::string label;
    std::vector<std::string> warnings;
};

// Heuristic estimator: character-pool entropy with penalties for common
// passwords, repeated runs, sequences and keyboard patterns. It is intended
// for user feedback, not as a formal security proof.
StrengthResult estimate_strength(std::string_view password);

}  // namespace ciphervault
