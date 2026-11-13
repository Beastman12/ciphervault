// CipherVault - secure memory helpers
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ciphervault {

// Overwrites a memory region in a way the optimizer is not allowed to remove.
void secure_zero(void* ptr, std::size_t len) noexcept;

inline void secure_zero(std::string& s) noexcept {
    if (!s.empty()) {
        secure_zero(!s.empty() ? &s[0] : nullptr, s.size());
    }
}

inline void secure_zero(std::vector<std::uint8_t>& v) noexcept {
    if (!v.empty()) secure_zero(v.data(), v.size());
}

// RAII guard that wipes a buffer when it leaves scope.
class ScopeWipe {
public:
    ScopeWipe(void* ptr, std::size_t len) noexcept : ptr_(ptr), len_(len) {}
    ~ScopeWipe() { secure_zero(ptr_, len_); }
    ScopeWipe(const ScopeWipe&) = delete;
    ScopeWipe& operator=(const ScopeWipe&) = delete;

private:
    void* ptr_;
    std::size_t len_;
};

// A byte buffer whose contents are wiped on destruction. Move-only.
class SecureBytes {
public:
    SecureBytes() = default;
    explicit SecureBytes(std::size_t size) : data_(size, 0) {}
    SecureBytes(const std::uint8_t* data, std::size_t size) : data_(data, data + size) {}
    ~SecureBytes() { wipe(); }

    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;

    SecureBytes(SecureBytes&& other) noexcept : data_(std::move(other.data_)) {
        other.data_.clear();
    }
    SecureBytes& operator=(SecureBytes&& other) noexcept {
        if (this != &other) {
            wipe();
            data_ = std::move(other.data_);
            other.data_.clear();
        }
        return *this;
    }

    std::uint8_t* data() noexcept { return data_.data(); }
    const std::uint8_t* data() const noexcept { return data_.data(); }
    std::size_t size() const noexcept { return data_.size(); }
    bool empty() const noexcept { return data_.empty(); }
    std::uint8_t& operator[](std::size_t i) noexcept { return data_[i]; }
    const std::uint8_t& operator[](std::size_t i) const noexcept { return data_[i]; }

    std::vector<std::uint8_t>& vec() noexcept { return data_; }
    const std::vector<std::uint8_t>& vec() const noexcept { return data_; }

    void wipe() noexcept {
        secure_zero(data_);
        data_.clear();
    }

private:
    std::vector<std::uint8_t> data_;
};

}  // namespace ciphervault
