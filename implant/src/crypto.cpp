#include "crypto.hpp"

#include "x25519.hpp"

#include "platform.hpp"
#include <bcrypt.h>

#include <cstring>
#include <mutex>
#include <stdexcept>

#pragma comment(lib, "bcrypt.lib")

namespace luna {

const std::uint8_t kAad[kAadLen] = {'l', 'u', 'n', 'a', '-', 'v', '1'};

namespace {

void check(NTSTATUS status, const char* what) {
    if (status < 0) {
        throw std::runtime_error(std::string("bcrypt failure in ") + what);
    }
}

class AlgHandle {
public:
    AlgHandle(LPCWSTR alg, ULONG flags) {
        check(BCryptOpenAlgorithmProvider(&h_, alg, nullptr, flags), "open");
    }
    ~AlgHandle() {
        if (h_) BCryptCloseAlgorithmProvider(h_, 0);
    }
    AlgHandle(const AlgHandle&) = delete;
    AlgHandle& operator=(const AlgHandle&) = delete;
    BCRYPT_ALG_HANDLE get() const { return h_; }

private:
    BCRYPT_ALG_HANDLE h_ = nullptr;
};

class KeyHandle {
public:
    KeyHandle(BCRYPT_ALG_HANDLE alg, const Bytes& key) {
        check(BCryptGenerateSymmetricKey(alg, &h_, nullptr, 0,
                                         const_cast<PUCHAR>(key.data()),
                                         static_cast<ULONG>(key.size()), 0),
              "generate key");
    }
    ~KeyHandle() {
        if (h_) BCryptDestroyKey(h_);
    }
    KeyHandle(const KeyHandle&) = delete;
    KeyHandle& operator=(const KeyHandle&) = delete;
    BCRYPT_KEY_HANDLE get() const { return h_; }

private:
    BCRYPT_KEY_HANDLE h_ = nullptr;
};

class HashHandle {
public:
    HashHandle(BCRYPT_ALG_HANDLE alg, const Bytes& key) {
        check(BCryptCreateHash(alg, &h_, nullptr, 0,
                               key.empty() ? nullptr : const_cast<PUCHAR>(key.data()),
                               static_cast<ULONG>(key.size()), 0),
              "create hash");
    }
    ~HashHandle() {
        if (h_) BCryptDestroyHash(h_);
    }
    HashHandle(const HashHandle&) = delete;
    HashHandle& operator=(const HashHandle&) = delete;
    BCRYPT_HASH_HANDLE get() const { return h_; }

private:
    BCRYPT_HASH_HANDLE h_ = nullptr;
};

BCRYPT_ALG_HANDLE hmac_alg() {
    static AlgHandle alg(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    return alg.get();
}

BCRYPT_ALG_HANDLE gcm_alg() {
    static std::once_flag once;
    static BCRYPT_ALG_HANDLE handle = nullptr;
    std::call_once(once, [] {
        auto* alg = new AlgHandle(BCRYPT_AES_ALGORITHM, 0);
        check(BCryptSetProperty(alg->get(), BCRYPT_CHAINING_MODE,
                                reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                                sizeof(BCRYPT_CHAIN_MODE_GCM), 0),
              "set gcm mode");
        handle = alg->get();
        // intentionally leaked for process lifetime
    });
    return handle;
}

}  // namespace

Bytes random_bytes(std::size_t count) {
    Bytes out(count);
    check(BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(count),
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG),
          "gen random");
    return out;
}

Bytes hmac_sha256(const Bytes& key, const std::uint8_t* data, std::size_t len) {
    HashHandle hash(hmac_alg(), key);
    if (len) {
        check(BCryptHashData(hash.get(), const_cast<PUCHAR>(data),
                             static_cast<ULONG>(len), 0),
              "hash data");
    }
    Bytes out(32);
    check(BCryptFinishHash(hash.get(), out.data(), static_cast<ULONG>(out.size()), 0),
          "finish hash");
    return out;
}

Bytes hmac_sha256(const Bytes& key, const Bytes& data) {
    return hmac_sha256(key, data.data(), data.size());
}

Bytes hkdf_sha256(const Bytes& salt, const Bytes& ikm, const Bytes& info,
                  std::size_t out_len) {
    Bytes prk = hmac_sha256(salt, ikm);  // extract
    Bytes out;
    out.reserve(out_len + 32);
    Bytes block;
    std::uint8_t counter = 1;
    while (out.size() < out_len) {
        Bytes input;
        input.reserve(block.size() + info.size() + 1);
        input.insert(input.end(), block.begin(), block.end());
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter++);
        block = hmac_sha256(prk, input);
        out.insert(out.end(), block.begin(), block.end());
    }
    out.resize(out_len);
    return out;
}

KeyPair x25519_keypair() {
    KeyPair kp;
    kp.priv = random_bytes(32);
    // clamping happens inside scalarmult, but the stored private key is clamped
    // here so both sides agree on what was used
    kp.priv[0] &= 248;
    kp.priv[31] = static_cast<std::uint8_t>((kp.priv[31] & 127) | 64);
    kp.pub.assign(32, 0);
    curve25519::base_scalarmult(kp.pub.data(), kp.priv.data());
    return kp;
}

Bytes x25519_shared(const Bytes& priv, const Bytes& peer_pub) {
    if (priv.size() != 32 || peer_pub.size() != 32) {
        throw std::runtime_error("x25519 key material must be 32 bytes");
    }
    Bytes shared(32);
    curve25519::scalarmult(shared.data(), priv.data(), peer_pub.data());
    if (curve25519::is_zero(shared.data())) {
        throw std::runtime_error("degenerate x25519 shared secret");
    }
    return shared;
}

SessionKeys derive_session_keys(const Bytes& own_priv, const Bytes& peer_pub,
                                const Bytes& salt) {
    const Bytes shared = x25519_shared(own_priv, peer_pub);
    static const Bytes kTx = {'l', 'u', 'n', 'a', '/', 'v', '1', '/', 't', 'x'};
    static const Bytes kRx = {'l', 'u', 'n', 'a', '/', 'v', '1', '/', 'r', 'x'};
    SessionKeys keys;
    keys.send_key = hkdf_sha256(salt, shared, kTx, kKeyLen);
    keys.recv_key = hkdf_sha256(salt, shared, kRx, kKeyLen);
    return keys;
}

Bytes make_nonce(std::uint32_t epoch, std::uint64_t counter) {
    Bytes nonce(kNonceLen);
    for (int i = 0; i < 4; ++i) {
        nonce[i] = static_cast<std::uint8_t>((epoch >> (8 * (3 - i))) & 0xff);
    }
    for (int i = 0; i < 8; ++i) {
        nonce[4 + i] = static_cast<std::uint8_t>((counter >> (8 * (7 - i))) & 0xff);
    }
    return nonce;
}

Bytes aes_gcm_seal(const Bytes& key, std::uint32_t epoch, std::uint64_t counter,
                   const Bytes& plaintext) {
    if (key.size() != kKeyLen) throw std::runtime_error("aes key must be 32 bytes");
    KeyHandle key_handle(gcm_alg(), key);
    const Bytes nonce = make_nonce(epoch, counter);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce.data());
    info.cbNonce = static_cast<ULONG>(nonce.size());
    info.pbAuthData = const_cast<PUCHAR>(kAad);
    info.cbAuthData = static_cast<ULONG>(kAadLen);
    Bytes tag(kTagLen);
    info.pbTag = tag.data();
    info.cbTag = static_cast<ULONG>(tag.size());

    Bytes cipher(plaintext.size());
    ULONG produced = 0;
    check(BCryptEncrypt(key_handle.get(), const_cast<PUCHAR>(plaintext.data()),
                        static_cast<ULONG>(plaintext.size()), &info, nullptr, 0,
                        cipher.empty() ? nullptr : cipher.data(),
                        static_cast<ULONG>(cipher.size()), &produced, 0),
          "seal");

    Bytes frame;
    frame.reserve(nonce.size() + cipher.size() + tag.size());
    frame.insert(frame.end(), nonce.begin(), nonce.end());
    frame.insert(frame.end(), cipher.begin(), cipher.end());
    frame.insert(frame.end(), tag.begin(), tag.end());
    return frame;
}

Bytes aes_gcm_open(const Bytes& key, const Bytes& frame) {
    if (key.size() != kKeyLen) throw std::runtime_error("aes key must be 32 bytes");
    if (frame.size() < kNonceLen + kTagLen) throw std::runtime_error("short frame");

    const std::size_t body_len = frame.size() - kNonceLen - kTagLen;
    KeyHandle key_handle(gcm_alg(), key);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(frame.data());
    info.cbNonce = static_cast<ULONG>(kNonceLen);
    info.pbAuthData = const_cast<PUCHAR>(kAad);
    info.cbAuthData = static_cast<ULONG>(kAadLen);
    info.pbTag = const_cast<PUCHAR>(frame.data() + kNonceLen + body_len);
    info.cbTag = static_cast<ULONG>(kTagLen);

    Bytes plain(body_len);
    ULONG produced = 0;
    const NTSTATUS status =
        BCryptDecrypt(key_handle.get(), const_cast<PUCHAR>(frame.data() + kNonceLen),
                      static_cast<ULONG>(body_len), &info, nullptr, 0,
                      plain.empty() ? nullptr : plain.data(),
                      static_cast<ULONG>(plain.size()), &produced, 0);
    if (status < 0) throw std::runtime_error("frame authentication failed");
    plain.resize(produced);
    return plain;
}

namespace {

constexpr char kB64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

}  // namespace

std::string b64_encode(const Bytes& data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    std::size_t i = 0;
    for (; i + 3 <= data.size(); i += 3) {
        const std::uint32_t v = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
        out.push_back(kB64[(v >> 6) & 63]);
        out.push_back(kB64[v & 63]);
    }
    if (i + 1 == data.size()) {
        const std::uint32_t v = data[i] << 16;
        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
        out.append("==");
    } else if (i + 2 == data.size()) {
        const std::uint32_t v = (data[i] << 16) | (data[i + 1] << 8);
        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
        out.push_back(kB64[(v >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

Bytes b64_decode(const std::string& text) {
    std::int8_t table[256];
    std::memset(table, -1, sizeof(table));
    for (int i = 0; i < 64; ++i) table[static_cast<unsigned char>(kB64[i])] = static_cast<std::int8_t>(i);
    Bytes out;
    out.reserve(text.size() / 4 * 3);
    std::uint32_t acc = 0;
    int bits = 0;
    for (char c : text) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        const std::int8_t v = table[static_cast<unsigned char>(c)];
        if (v < 0) continue;
        acc = (acc << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((acc >> bits) & 0xff));
        }
    }
    return out;
}

std::string hex_encode(const Bytes& data) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (std::uint8_t b : data) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 15]);
    }
    return out;
}

Bytes hex_decode(const std::string& text) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    Bytes out;
    out.reserve(text.size() / 2);
    int high = -1;
    for (char c : text) {
        const int v = nibble(c);
        if (v < 0) continue;
        if (high < 0) {
            high = v;
        } else {
            out.push_back(static_cast<std::uint8_t>((high << 4) | v));
            high = -1;
        }
    }
    return out;
}

}  // namespace luna
