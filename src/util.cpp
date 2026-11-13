#include "ciphervault/util.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <system_error>

#if defined(_WIN32)
#include <windows.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include "ciphervault/crypto/random.hpp"
#include "ciphervault/crypto/secure_memory.hpp"

namespace ciphervault {

std::string to_lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

std::string trim(std::string_view s) {
    std::size_t begin = 0;
    std::size_t end = s.size();
    auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
    while (begin < end && is_space(static_cast<unsigned char>(s[begin]))) ++begin;
    while (end > begin && is_space(static_cast<unsigned char>(s[end - 1]))) --end;
    return std::string(s.substr(begin, end - begin));
}

bool starts_with(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

bool contains_ci(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) return true;
    if (needle.size() > haystack.size()) return false;
    const std::string h = to_lower(haystack);
    const std::string n = to_lower(needle);
    return h.find(n) != std::string::npos;
}

std::vector<std::string> split(std::string_view s, char delimiter) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= s.size()) {
        const std::size_t pos = s.find(delimiter, start);
        if (pos == std::string_view::npos) {
            parts.emplace_back(s.substr(start));
            break;
        }
        parts.emplace_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return parts;
}

std::string join(const std::vector<std::string>& parts, std::string_view separator) {
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) out += separator;
        out += parts[i];
    }
    return out;
}

std::string format_timestamp(std::int64_t unix_time) {
    if (unix_time <= 0) return "-";
    const std::time_t t = static_cast<std::time_t>(unix_time);
    std::tm tm_buf{};
#if defined(_WIN32)
    if (localtime_s(&tm_buf, &t) != 0) return "-";
#else
    if (localtime_r(&t, &tm_buf) == nullptr) return "-";
#endif
    std::ostringstream out;
    out << std::put_time(&tm_buf, "%Y-%m-%d %H:%M");
    return out.str();
}

std::string format_relative_time(std::int64_t unix_time) {
    if (unix_time <= 0) return "never";
    const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    std::int64_t delta = now - unix_time;
    if (delta < 0) delta = 0;
    if (delta < 60) return "just now";
    if (delta < 3600) return std::to_string(delta / 60) + "m ago";
    if (delta < 86400) return std::to_string(delta / 3600) + "h ago";
    if (delta < 86400LL * 30) return std::to_string(delta / 86400) + "d ago";
    if (delta < 86400LL * 365) return std::to_string(delta / (86400LL * 30)) + "mo ago";
    return std::to_string(delta / (86400LL * 365)) + "y ago";
}

std::string human_size(std::uint64_t bytes) {
    static const char* kUnits[] = {"B", "KiB", "MiB", "GiB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 3) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream out;
    out << std::fixed << std::setprecision(unit == 0 ? 0 : 1) << value << ' ' << kUnits[unit];
    return out.str();
}

std::string random_hex_id() {
    const std::vector<std::uint8_t> bytes = random_bytes(16);
    static const char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(32);
    for (std::uint8_t b : bytes) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 0x0f]);
    }
    return out;
}

std::string get_env(const char* name) {
#if defined(_WIN32)
    char* buffer = nullptr;
    std::size_t size = 0;
    if (_dupenv_s(&buffer, &size, name) != 0 || buffer == nullptr) return {};
    std::string value(buffer);
    std::free(buffer);
    return value;
#else
    const char* value = std::getenv(name);
    return value == nullptr ? std::string{} : std::string(value);
#endif
}

bool constant_time_equal(const void* a, const void* b, std::size_t len) noexcept {
    const auto* pa = static_cast<const std::uint8_t*>(a);
    const auto* pb = static_cast<const std::uint8_t*>(b);
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < len; ++i) diff = static_cast<std::uint8_t>(diff | (pa[i] ^ pb[i]));
    return diff == 0;
}

std::filesystem::path default_vault_path() {
    const std::string override_path = get_env("CIPHERVAULT_PATH");
    if (!override_path.empty()) return std::filesystem::u8path(override_path);

#if defined(_WIN32)
    std::string base = get_env("APPDATA");
    if (base.empty()) {
        const std::string profile = get_env("USERPROFILE");
        if (!profile.empty()) base = profile + "\\AppData\\Roaming";
    }
    if (base.empty()) base = ".";
    return std::filesystem::u8path(base) / "CipherVault" / "vault.spm";
#elif defined(__APPLE__)
    const std::string home = get_env("HOME");
    return std::filesystem::u8path(home.empty() ? "." : home) / "Library" /
           "Application Support" / "CipherVault" / "vault.spm";
#else
    std::string base = get_env("XDG_DATA_HOME");
    if (base.empty()) {
        const std::string home = get_env("HOME");
        base = (home.empty() ? std::string(".") : home) + "/.local/share";
    }
    return std::filesystem::u8path(base) / "ciphervault" / "vault.spm";
#endif
}

void ensure_private_directory(const std::filesystem::path& dir) {
    if (dir.empty()) return;
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec && !std::filesystem::exists(dir)) {
        throw std::runtime_error("cannot create directory: " + dir.string());
    }
#if !defined(_WIN32)
    std::filesystem::permissions(dir, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
#endif
}

void set_owner_only_permissions(const std::filesystem::path& path) {
#if defined(_WIN32)
    (void)path;  // NTFS ACLs are inherited from the user profile directory.
#else
    std::error_code ec;
    std::filesystem::permissions(
        path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, ec);
#endif
}

std::vector<std::uint8_t> read_file(const std::filesystem::path& path, std::size_t max_size) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error("cannot open file: " + path.string());
    const std::streamoff size = in.tellg();
    if (size < 0) throw std::runtime_error("cannot read file: " + path.string());
    if (static_cast<std::uint64_t>(size) > max_size) {
        throw std::runtime_error("file is unexpectedly large: " + path.string());
    }
    in.seekg(0);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    if (!data.empty()) {
        in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!in) throw std::runtime_error("failed to read file: " + path.string());
    }
    return data;
}

namespace {

void write_all_and_sync(const std::filesystem::path& path, const std::vector<std::uint8_t>& data) {
#if defined(_WIN32)
    FILE* file = _wfopen(path.wstring().c_str(), L"wb");
#else
    FILE* file = std::fopen(path.string().c_str(), "wb");
#endif
    if (file == nullptr) throw std::runtime_error("cannot create file: " + path.string());

    bool ok = true;
    if (!data.empty()) {
        ok = std::fwrite(data.data(), 1, data.size(), file) == data.size();
    }
    ok = ok && std::fflush(file) == 0;
#if defined(_WIN32)
    ok = ok && _commit(_fileno(file)) == 0;
#else
    ok = ok && fsync(fileno(file)) == 0;
#endif
    std::fclose(file);
    if (!ok) {
        std::error_code ec;
        std::filesystem::remove(path, ec);
        throw std::runtime_error("failed to write file: " + path.string());
    }
}

}  // namespace

void atomic_write_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& data) {
    ensure_private_directory(path.parent_path());

    std::filesystem::path temp = path;
    temp += ".tmp-" + random_hex_id().substr(0, 8);
    write_all_and_sync(temp, data);

    set_owner_only_permissions(temp);
#if defined(_WIN32)
    if (!MoveFileExW(temp.wstring().c_str(), path.wstring().c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::error_code ec;
        std::filesystem::remove(temp, ec);
        throw std::runtime_error("failed to replace file: " + path.string());
    }
#else
    if (std::rename(temp.string().c_str(), path.string().c_str()) != 0) {
        std::error_code ec;
        std::filesystem::remove(temp, ec);
        throw std::runtime_error("failed to replace file: " + path.string());
    }
#endif
    set_owner_only_permissions(path);
}

void backup_file(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) return;
    std::filesystem::path backup = path;
    backup += ".bak";
    std::filesystem::copy_file(path, backup, std::filesystem::copy_options::overwrite_existing, ec);
    if (!ec) set_owner_only_permissions(backup);
}

std::string path_to_display(const std::filesystem::path& path) {
#if defined(__cpp_lib_char8_t)
    const std::u8string value = path.u8string();
    return std::string(value.begin(), value.end());
#else
    return path.u8string();
#endif
}

}  // namespace ciphervault
