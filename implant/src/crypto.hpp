// Session crypto on top of CNG: HMAC-SHA256, HKDF, AES-256-GCM, CSPRNG.
// X25519 lives in x25519.hpp so it stays portable and auditable.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace luna {

using Bytes = std::vector<std::uint8_t>;

constexpr std::size_t kKeyLen = 32;
constexpr std::size_t kNonceLen = 12;
constexpr std::size_t kTagLen = 16;
constexpr std::size_t kAadLen = 7;

extern const std::uint8_t kAad[kAadLen];

Bytes random_bytes(std::size_t count);

Bytes hmac_sha256(const Bytes& key, const std::uint8_t* data, std::size_t len);
Bytes hmac_sha256(const Bytes& key, const Bytes& data);

// HKDF-SHA256, RFC 5869.
Bytes hkdf_sha256(const Bytes& salt, const Bytes& ikm, const Bytes& info,
                  std::size_t out_len);

struct KeyPair {
    Bytes priv;  // 32
    Bytes pub;   // 32
};

KeyPair x25519_keypair();
Bytes x25519_shared(const Bytes& priv, const Bytes& peer_pub);

struct SessionKeys {
    Bytes send_key;
    Bytes recv_key;
    bool operator==(const SessionKeys&) const = default;
};

// salt + both public keys are bound into the info string so a handshake cannot
// be spliced onto a different key pair.
SessionKeys derive_session_keys(const Bytes& own_priv, const Bytes& peer_pub,
                                const Bytes& salt);

// nonce = epoch(4, big endian) || counter(8, big endian)
Bytes make_nonce(std::uint32_t epoch, std::uint64_t counter);

// Returns nonce || ciphertext || tag.
Bytes aes_gcm_seal(const Bytes& key, std::uint32_t epoch, std::uint64_t counter,
                   const Bytes& plaintext);

// Accepts nonce || ciphertext || tag. Throws std::runtime_error on auth failure.
Bytes aes_gcm_open(const Bytes& key, const Bytes& frame);

std::string b64_encode(const Bytes& data);
Bytes b64_decode(const std::string& text);
std::string hex_encode(const Bytes& data);
Bytes hex_decode(const std::string& text);

}  // namespace luna
