#include "ciphervault/crypto/random.hpp"

#include <stdexcept>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(__APPLE__)
#include <cstdlib>
#elif defined(__linux__) || defined(__unix__)
#include <cerrno>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace ciphervault {

void random_bytes(void* buffer, std::size_t len) {
    if (len == 0) return;
    if (buffer == nullptr) throw std::invalid_argument("random_bytes: null buffer");

#if defined(_WIN32)
    auto* p = static_cast<unsigned char*>(buffer);
    std::size_t remaining = len;
    while (remaining > 0) {
        const ULONG chunk = static_cast<ULONG>(remaining > 0x40000000u ? 0x40000000u : remaining);
        const NTSTATUS status =
            BCryptGenRandom(nullptr, p, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status != 0) {
            throw std::runtime_error("BCryptGenRandom failed (status " +
                                     std::to_string(static_cast<long>(status)) + ")");
        }
        p += chunk;
        remaining -= chunk;
    }
#elif defined(__APPLE__)
    arc4random_buf(buffer, len);
#else
    auto* p = static_cast<unsigned char*>(buffer);
    std::size_t remaining = len;

#if defined(__linux__)
    // Prefer getrandom(2); it is never exhausted and needs no file descriptor.
    while (remaining > 0) {
        const ssize_t got = ::getrandom(p, remaining, 0);
        if (got > 0) {
            p += static_cast<std::size_t>(got);
            remaining -= static_cast<std::size_t>(got);
        } else if (got < 0 && (errno == EINTR)) {
            continue;
        } else {
            break;  // fall back to /dev/urandom
        }
    }
#endif

    if (remaining > 0) {
        const int fd = ::open("/dev/urandom", O_RDONLY);
        if (fd < 0) throw std::runtime_error("cannot open /dev/urandom");
        while (remaining > 0) {
            const ssize_t got = ::read(fd, p, remaining);
            if (got > 0) {
                p += static_cast<std::size_t>(got);
                remaining -= static_cast<std::size_t>(got);
            } else if (got < 0 && errno == EINTR) {
                continue;
            } else {
                ::close(fd);
                throw std::runtime_error("failed to read /dev/urandom");
            }
        }
        ::close(fd);
    }
#endif
}

std::uint32_t random_u32() {
    std::uint32_t v = 0;
    random_bytes(&v, sizeof(v));
    return v;
}

std::uint64_t random_u64() {
    std::uint64_t v = 0;
    random_bytes(&v, sizeof(v));
    return v;
}

std::uint32_t random_below(std::uint32_t bound) {
    if (bound == 0) throw std::invalid_argument("random_below: bound must be > 0");
    const std::uint32_t limit = 0xffffffffu - (0xffffffffu % bound);
    for (;;) {
        const std::uint32_t v = random_u32();
        if (v < limit) return v % bound;
    }
}

}  // namespace ciphervault
