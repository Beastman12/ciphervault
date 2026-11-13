cmake_minimum_required(VERSION 3.16)

project(ciphervault VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(CIPHERVAULT_BUILD_TESTS "Build the unit test suite" ON)
option(CIPHERVAULT_WERROR "Treat compiler warnings as errors" OFF)

if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8)
    if(CIPHERVAULT_WERROR)
        add_compile_options(/WX)
    endif()
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(CIPHERVAULT_WERROR)
        add_compile_options(-Werror)
    endif()
endif()

find_package(Threads REQUIRED)

# Core library: everything except the CLI entry point. Keeps the crypto and
# vault code reusable and lets the tests link against the same objects.
add_library(ciphervault_core STATIC
    src/clipboard.cpp
    src/csv.cpp
    src/entry.cpp
    src/generator.cpp
    src/selftest.cpp
    src/strength.cpp
    src/terminal.cpp
    src/util.cpp
    src/vault.cpp
    src/crypto/aes.cpp
    src/crypto/gcm.cpp
    src/crypto/hmac.cpp
    src/crypto/pbkdf2.cpp
    src/crypto/random.cpp
    src/crypto/secure_memory.cpp
    src/crypto/sha256.cpp
)

target_include_directories(ciphervault_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(ciphervault_core PUBLIC Threads::Threads)

if(WIN32)
    # BCryptGenRandom - the Windows CSPRNG.
    target_link_libraries(ciphervault_core PUBLIC bcrypt)
endif()

add_executable(ciphervault
    src/main.cpp
    src/cli.cpp
)

target_link_libraries(ciphervault PRIVATE ciphervault_core)

install(TARGETS ciphervault RUNTIME DESTINATION bin)

if(CIPHERVAULT_BUILD_TESTS)
    enable_testing()

    add_executable(ciphervault_tests
        tests/test_main.cpp
        tests/test_crypto.cpp
        tests/test_generator.cpp
        tests/test_vault.cpp
    )

    target_include_directories(ciphervault_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    target_link_libraries(ciphervault_tests PRIVATE ciphervault_core)

    add_test(NAME unit_tests COMMAND ciphervault_tests)
    add_test(NAME crypto_selftest COMMAND ciphervault selftest)
endif()
