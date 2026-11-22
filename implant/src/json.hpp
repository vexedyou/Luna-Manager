// Minimal JSON value, parser, and serializer. Strict on input, deterministic on
// output (object keys keep insertion order), no exceptions on malformed data.
#pragma once

#include <charconv>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace luna {

class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Json() = default;
    Json(std::nullptr_t) {}
    Json(bool v) : type_(Type::Bool), bool_(v) {}
    Json(double v) : type_(Type::Number), num_(v) {}
    Json(int v) : type_(Type::Number), num_(v) {}
    Json(std::int64_t v) : type_(Type::Number), num_(static_cast<double>(v)) {}
    Json(const char* v) : type_(Type::String), str_(v) {}
    Json(std::string v) : type_(Type::String), str_(std::move(v)) {}

    static Json array() { Json j; j.type_ = Type::Array; return j; }
    static Json object() { Json j; j.type_ = Type::Object; return j; }

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }
    bool is_object() const { return type_ == Type::Object; }
    bool is_array() const { return type_ == Type::Array; }

    bool as_bool(bool fallback = false) const {
        return type_ == Type::Bool ? bool_ : fallback;
    }
    double as_number(double fallback = 0) const {
        return type_ == Type::Number ? num_ : fallback;
    }
    std::int64_t as_int(std::int64_t fallback = 0) const {
        return type_ == Type::Number ? static_cast<std::int64_t>(num_) : fallback;
    }
    const std::string& as_string() const { return str_; }
    std::string str_or(const std::string& fallback) const {
        return type_ == Type::String ? str_ : fallback;
    }

    const std::vector<Json>& items() const { return arr_; }
    std::vector<Json>& items() { return arr_; }

    void push(Json value) {
        if (type_ != Type::Array) { type_ = Type::Array; arr_.clear(); }
        arr_.push_back(std::move(value));
    }

    void set(const std::string& key, Json value) {
        if (type_ != Type::Object) { type_ = Type::Object; obj_.clear(); }
        for (auto& kv : obj_) {
            if (kv.first == key) { kv.second = std::move(value); return; }
        }
        obj_.emplace_back(key, std::move(value));
    }

    const Json& operator[](const std::string& key) const {
        static const Json kNull;
        for (const auto& kv : obj_) {
            if (kv.first == key) return kv.second;
        }
        return kNull;
    }

    bool has(const std::string& key) const {
        for (const auto& kv : obj_) {
            if (kv.first == key) return true;
        }
        return false;
    }

    const std::vector<std::pair<std::string, Json>>& entries() const { return obj_; }

    std::string dump() const {
        std::string out;
        write(out);
        return out;
    }

    static Json parse(std::string_view text, bool* ok = nullptr) {
        Parser p{text};
        Json value = p.value();
        if (ok) *ok = p.good();
        return value;
    }

private:
    void write(std::string& out) const {
        switch (type_) {
            case Type::Null: out += "null"; break;
            case Type::Bool: out += bool_ ? "true" : "false"; break;
            case Type::Number: {
                char buf[40];
                const auto res = std::to_chars(buf, buf + sizeof(buf), num_);
                out.append(buf, res.ptr);
                break;
            }
            case Type::String: write_string(out, str_); break;
            case Type::Array: {
                out.push_back('[');
                for (std::size_t i = 0; i < arr_.size(); ++i) {
                    if (i) out.push_back(',');
                    arr_[i].write(out);
                }
                out.push_back(']');
                break;
            }
            case Type::Object: {
                out.push_back('{');
                for (std::size_t i = 0; i < obj_.size(); ++i) {
                    if (i) out.push_back(',');
                    write_string(out, obj_[i].first);
                    out.push_back(':');
                    obj_[i].second.write(out);
                }
                out.push_back('}');
                break;
            }
        }
    }

    static void write_string(std::string& out, const std::string& s) {
        static constexpr char kHex[] = "0123456789abcdef";
        out.push_back('"');
        for (unsigned char c : s) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                default:
                    if (c < 0x20) {
                        out += "\\u00";
                        out.push_back(kHex[c >> 4]);
                        out.push_back(kHex[c & 15]);
                    } else {
                        out.push_back(static_cast<char>(c));
                    }
            }
        }
        out.push_back('"');
    }

    struct Parser {
        std::string_view s;
        std::size_t i = 0;
        bool ok = true;

        bool good() const { return ok; }
        void fail() { ok = false; }
        bool eof() const { return i >= s.size(); }
        char peek() const { return i < s.size() ? s[i] : '\0'; }
        void ws() {
            while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) ++i;
        }

        Json value() {
            ws();
            if (eof()) { fail(); return Json(); }
            switch (peek()) {
                case '{': return object();
                case '[': return array();
                case '"': return Json(string());
                case 't':
                    if (s.substr(i, 4) == "true") { i += 4; return Json(true); }
                    fail(); return Json();
                case 'f':
                    if (s.substr(i, 5) == "false") { i += 5; return Json(false); }
                    fail(); return Json();
                case 'n':
                    if (s.substr(i, 4) == "null") { i += 4; return Json(); }
                    fail(); return Json();
                default: return number();
            }
        }

        Json object() {
            Json obj = Json::object();
            ++i;  // {
            ws();
            if (peek() == '}') { ++i; return obj; }
            while (!eof()) {
                ws();
                if (peek() != '"') { fail(); return obj; }
                std::string key = string();
                ws();
                if (peek() != ':') { fail(); return obj; }
                ++i;
                obj.set(key, value());
                ws();
                if (peek() == ',') { ++i; continue; }
                if (peek() == '}') { ++i; return obj; }
                fail();
                return obj;
            }
            fail();
            return obj;
        }

        Json array() {
            Json arr = Json::array();
            ++i;  // [
            ws();
            if (peek() == ']') { ++i; return arr; }
            while (!eof()) {
                arr.push(value());
                ws();
                if (peek() == ',') { ++i; continue; }
                if (peek() == ']') { ++i; return arr; }
                fail();
                return arr;
            }
            fail();
            return arr;
        }

        std::string string() {
            std::string out;
            ++i;  // opening quote
            while (!eof()) {
                const char c = s[i++];
                if (c == '"') return out;
                if (c != '\\') { out.push_back(c); continue; }
                if (eof()) break;
                const char esc = s[i++];
                switch (esc) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        if (i + 4 > s.size()) { fail(); return out; }
                        unsigned code = 0;
                        for (int k = 0; k < 4; ++k) {
                            const char h = s[i++];
                            code <<= 4;
                            if (h >= '0' && h <= '9') code |= static_cast<unsigned>(h - '0');
                            else if (h >= 'a' && h <= 'f') code |= static_cast<unsigned>(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') code |= static_cast<unsigned>(h - 'A' + 10);
                            else { fail(); return out; }
                        }
                        if (code < 0x80) {
                            out.push_back(static_cast<char>(code));
                        } else if (code < 0x800) {
                            out.push_back(static_cast<char>(0xC0 | (code >> 6)));
                            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                        } else {
                            out.push_back(static_cast<char>(0xE0 | (code >> 12)));
                            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                        }
                        break;
                    }
                    default: fail(); return out;
                }
            }
            fail();
            return out;
        }

        Json number() {
            const std::size_t start = i;
            if (peek() == '-') ++i;
            while (!eof()) {
                const char c = peek();
                if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') ++i;
                else break;
            }
            if (i == start) { fail(); return Json(); }
            double value = 0;
            const auto res = std::from_chars(s.data() + start, s.data() + i, value);
            if (res.ec != std::errc{}) { fail(); return Json(); }
            return Json(value);
        }
    };

    Type type_ = Type::Null;
    bool bool_ = false;
    double num_ = 0;
    std::string str_;
    std::vector<Json> arr_;
    std::vector<std::pair<std::string, Json>> obj_;
};

}  // namespace luna
