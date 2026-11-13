#include "ciphervault/crypto/secure_memory.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <cstring>
#endif

namespace ciphervault {

void secure_zero(void* ptr, std::size_t len) noexcept {
    if (ptr == nullptr || len == 0) return;
#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#else
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len-- > 0) *p++ = 0;
#endif
}

}  // namespace ciphervault
