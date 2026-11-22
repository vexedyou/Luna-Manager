// X25519 over GF(2^255-19), 16-limb 16-bit representation.
// Portable C++20: only 64-bit integer math, so it builds the same under MSVC,
// clang-cl, and mingw-w64 without intrinsics or __int128.
#pragma once

#include <array>
#include <cstdint>
#include <cstring>

namespace luna::curve25519 {

using u8 = std::uint8_t;
using i64 = std::int64_t;
using Fe = std::array<i64, 16>;

inline constexpr Fe kA24 = {0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

inline void carry(Fe& o) {
    for (int i = 0; i < 16; ++i) {
        o[i] += (1LL << 16);
        const i64 c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

inline void select(Fe& p, Fe& q, int b) {
    const i64 c = ~(static_cast<i64>(b) - 1);
    for (int i = 0; i < 16; ++i) {
        const i64 t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

inline void pack(u8 out[32], const Fe& n) {
    Fe m{};
    Fe t = n;
    carry(t);
    carry(t);
    carry(t);
    for (int j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        const int b = static_cast<int>((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        select(t, m, 1 - b);
    }
    for (int i = 0; i < 16; ++i) {
        out[2 * i] = static_cast<u8>(t[i] & 0xff);
        out[2 * i + 1] = static_cast<u8>((t[i] >> 8) & 0xff);
    }
}

inline void unpack(Fe& o, const u8 n[32]) {
    for (int i = 0; i < 16; ++i) {
        o[i] = static_cast<i64>(n[2 * i]) + (static_cast<i64>(n[2 * i + 1]) << 8);
    }
    o[15] &= 0x7fff;
}

inline void add(Fe& o, const Fe& a, const Fe& b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

inline void sub(Fe& o, const Fe& a, const Fe& b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

inline void mul(Fe& o, const Fe& a, const Fe& b) {
    i64 t[31] = {};
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 16; ++j) t[i + j] += a[i] * b[j];
    }
    for (int i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; ++i) o[i] = t[i];
    carry(o);
    carry(o);
}

inline void square(Fe& o, const Fe& a) { mul(o, a, a); }

inline void invert(Fe& o, const Fe& i) {
    Fe c = i;
    for (int a = 253; a >= 0; --a) {
        square(c, c);
        if (a != 2 && a != 4) mul(c, c, i);
    }
    o = c;
}

// Montgomery ladder. p is the u-coordinate of the peer's public key.
inline void scalarmult(u8 q[32], const u8 n[32], const u8 p[32]) {
    u8 z[32];
    std::memcpy(z, n, 32);
    z[31] = static_cast<u8>((n[31] & 127) | 64);
    z[0] &= 248;

    Fe x{};
    unpack(x, p);

    Fe a{}, b{}, c{}, d{}, e{}, f{};
    b = x;
    a[0] = 1;
    d[0] = 1;

    for (int i = 254; i >= 0; --i) {
        const int r = (z[i >> 3] >> (i & 7)) & 1;
        select(a, b, r);
        select(c, d, r);
        add(e, a, c);
        sub(a, a, c);
        add(c, b, d);
        sub(b, b, d);
        square(d, e);
        square(f, a);
        mul(a, c, a);
        mul(c, b, e);
        add(e, a, c);
        sub(a, a, c);
        square(b, a);
        sub(c, d, f);
        mul(a, c, kA24);
        add(a, a, d);
        mul(c, c, a);
        mul(a, d, f);
        mul(d, b, x);
        square(b, e);
        select(a, b, r);
        select(c, d, r);
    }

    Fe inv{};
    invert(inv, c);
    mul(a, a, inv);
    pack(q, a);
}

inline void base_scalarmult(u8 q[32], const u8 n[32]) {
    u8 base[32] = {9};
    scalarmult(q, n, base);
}

inline bool is_zero(const u8 v[32]) {
    u8 acc = 0;
    for (int i = 0; i < 32; ++i) acc |= v[i];
    return acc == 0;
}

}  // namespace luna::curve25519
