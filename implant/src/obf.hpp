// Compile-time string obfuscation.
//
// xenc() is consteval, so every literal wrapped in XLIT() is transformed during
// compilation and only the encoded bytes are emitted. Decoding happens on first
// use at runtime with the operator-supplied key baked into luna_config.hpp.
#pragma once

#include <array>
#include <cstddef>
#include <string>

#include "luna_config.hpp"

namespace luna {

template <std::size_t N>
consteval std::array<char, N> xenc(const char (&s)[N]) {
    std::array<char, N> out{};
    constexpr std::size_t key_len = sizeof(LUNA_XOR_KEY) / sizeof(LUNA_XOR_KEY[0]);
    for (std::size_t i = 0; i < N; ++i) {
        out[i] = static_cast<char>(s[i] ^ static_cast<char>(LUNA_XOR_KEY[i % key_len]));
    }
    return out;
}

template <std::size_t N>
inline std::string xdec(const std::array<char, N>& enc) {
    constexpr std::size_t key_len = sizeof(LUNA_XOR_KEY) / sizeof(LUNA_XOR_KEY[0]);
    std::string out(N ? N - 1 : 0, '\0');
    for (std::size_t i = 0; i + 1 < N; ++i) {
        out[i] = static_cast<char>(enc[i] ^ static_cast<char>(LUNA_XOR_KEY[i % key_len]));
    }
    return out;
}

}  // namespace luna

#define XLIT(s) ::luna::xdec(::luna::xenc(s))
