// Transport layer: HTTPS beaconing over WinHTTP, raw framed TCP over Winsock.
// Both share the same handshake and AEAD framing; only the carriage differs.
#pragma once

#include "crypto.hpp"
#include "json.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace luna {

struct Endpoint {
    std::string host;
    std::uint16_t port = 0;
};

std::vector<Endpoint> configured_endpoints();

class Transport {
public:
    virtual ~Transport() = default;

    // Performs the X25519 handshake and installs fresh session keys.
    virtual bool open(const std::string& meta_json, std::string& error) = 0;

    // One encrypted request/response round trip.
    virtual bool beacon(const std::string& request, std::string& response,
                        std::string& error) = 0;

    virtual void close() = 0;

    const std::string& session_id() const { return sid_; }
    bool needs_rehandshake() const { return needs_rehandshake_; }

protected:
    bool handshake(const std::string& meta_json, std::string& error);
    Bytes seal(const std::string& plaintext);
    bool unseal(const Bytes& frame, std::string& out, std::string& error);

    // Transport-specific send of a raw request, returning a raw response.
    virtual bool post_handshake(const std::string& body, std::string& response,
                                std::string& error) = 0;
    virtual bool post_beacon(const Bytes& frame, Bytes& response,
                             std::string& error) = 0;

    Bytes priv_;
    Bytes pub_;
    Bytes send_key_;
    Bytes recv_key_;
    std::uint64_t send_ctr_ = 0;
    std::uint64_t recv_high_ = 0;
    bool recv_started_ = false;
    std::string sid_;
    bool needs_rehandshake_ = false;
    std::size_t endpoint_index_ = 0;
};

std::unique_ptr<Transport> make_transport();

}  // namespace luna
