#include "json.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace vartad {

static const std::string kEmpty;
static const Json kNull;
static const Json::Array kEmptyArray;
static const Json::Object kEmptyObject;

void Json::own() {
    if (a_ && a_.use_count() > 1) a_ = std::make_shared<Array>(*a_);
    if (o_ && o_.use_count() > 1) o_ = std::make_shared<Object>(*o_);
}

const std::string& Json::as_string() const { return type_ == Type::String ? s_ : kEmpty; }

std::string Json::str(const std::string& key, const std::string& fallback) const {
    const Json& v = get(key);
    if (v.type_ == Type::String) return v.s_;
    if (v.type_ == Type::Number) {
        char buf[32];
        std::snprintf(buf, sizeof buf, "%.0f", v.n_);
        return buf;
    }
    return fallback;
}

int64_t Json::integer(const std::string& key, int64_t fallback) const {
    const Json& v = get(key);
    if (v.type_ == Type::Number) return static_cast<int64_t>(v.n_);
    if (v.type_ == Type::String && !v.s_.empty()) {
        char* end = nullptr;
        const long long x = std::strtoll(v.s_.c_str(), &end, 10);
        if (end && *end == 0) return x;
    }
    return fallback;
}

bool Json::boolean(const std::string& key, bool fallback) const { return get(key).as_bool(fallback); }

Json& Json::operator[](const std::string& key) {
    if (type_ != Type::Object) {
        *this = Json(Object{});
    }
    own();
    return (*o_)[key];
}

const Json& Json::get(const std::string& key) const {
    if (type_ != Type::Object) return kNull;
    const auto it = o_->find(key);
    return it == o_->end() ? kNull : it->second;
}

bool Json::has(const std::string& key) const {
    return type_ == Type::Object && o_->count(key) > 0;
}

void Json::push_back(Json v) {
    if (type_ != Type::Array) *this = Json(Array{});
    own();
    a_->push_back(std::move(v));
}

size_t Json::size() const {
    if (type_ == Type::Array) return a_->size();
    if (type_ == Type::Object) return o_->size();
    return 0;
}

const Json& Json::at(size_t i) const {
    if (type_ != Type::Array || i >= a_->size()) return kNull;
    return (*a_)[i];
}

const Json::Array& Json::items() const { return type_ == Type::Array ? *a_ : kEmptyArray; }
const Json::Object& Json::fields() const { return type_ == Type::Object ? *o_ : kEmptyObject; }

// --------------------------------------------------------------------------- serialize

static void escape(const std::string& s, std::string& out) {
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);  // UTF-8 passes through untouched
                }
        }
    }
    out += '"';
}

void Json::dump_to(std::string& out) const {
    switch (type_) {
        case Type::Null: out += "null"; break;
        case Type::Bool: out += b_ ? "true" : "false"; break;
        case Type::Number: {
            char buf[40];
            if (std::isfinite(n_) && n_ == std::floor(n_) && std::fabs(n_) < 9e15)
                std::snprintf(buf, sizeof buf, "%.0f", n_);
            else if (std::isfinite(n_))
                std::snprintf(buf, sizeof buf, "%.17g", n_);
            else
                std::snprintf(buf, sizeof buf, "null");
            out += buf;
            break;
        }
        case Type::String: escape(s_, out); break;
        case Type::Array: {
            out += '[';
            bool first = true;
            for (const auto& v : *a_) {
                if (!first) out += ',';
                first = false;
                v.dump_to(out);
            }
            out += ']';
            break;
        }
        case Type::Object: {
            out += '{';
            bool first = true;
            for (const auto& [k, v] : *o_) {
                if (!first) out += ',';
                first = false;
                escape(k, out);
                out += ':';
                v.dump_to(out);
            }
            out += '}';
            break;
        }
    }
}

std::string Json::dump() const {
    std::string out;
    dump_to(out);
    return out;
}

// ------------------------------------------------------------------------------- parse

namespace {

struct Parser {
    const std::string& s;
    size_t i = 0;
    std::string err;
    int depth = 0;

    void ws() {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) ++i;
    }
    bool fail(const std::string& m) {
        if (err.empty()) err = m + " at offset " + std::to_string(i);
        return false;
    }
    static void utf8(uint32_t cp, std::string& out) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    bool hex4(uint32_t& v) {
        if (i + 4 > s.size()) return fail("short \\u escape");
        v = 0;
        for (int k = 0; k < 4; ++k) {
            const char c = s[i++];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= c - '0';
            else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
            else return fail("bad hex digit");
        }
        return true;
    }
    bool string(std::string& out) {
        if (s[i] != '"') return fail("expected string");
        ++i;
        while (i < s.size()) {
            const char c = s[i++];
            if (c == '"') return true;
            if (c != '\\') {
                out += c;
                continue;
            }
            if (i >= s.size()) break;
            const char e = s[i++];
            switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    uint32_t cp = 0;
                    if (!hex4(cp)) return false;
                    if (cp >= 0xD800 && cp <= 0xDBFF && i + 6 <= s.size() && s[i] == '\\' &&
                        s[i + 1] == 'u') {
                        i += 2;
                        uint32_t lo = 0;
                        if (!hex4(lo)) return false;
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                    utf8(cp, out);
                    break;
                }
                default: return fail("bad escape");
            }
        }
        return fail("unterminated string");
    }
    bool value(Json& out) {
        if (++depth > 64) return fail("nesting too deep");
        ws();
        if (i >= s.size()) return fail("unexpected end");
        const char c = s[i];
        bool ok = true;
        if (c == '{') {
            ++i;
            Json obj = Json::object();
            ws();
            if (i < s.size() && s[i] == '}') {
                ++i;
            } else {
                for (;;) {
                    ws();
                    std::string key;
                    if (i >= s.size() || !string(key)) return fail("expected key");
                    ws();
                    if (i >= s.size() || s[i] != ':') return fail("expected ':'");
                    ++i;
                    Json v;
                    if (!value(v)) return false;
                    obj[key] = std::move(v);
                    ws();
                    if (i < s.size() && s[i] == ',') { ++i; continue; }
                    if (i < s.size() && s[i] == '}') { ++i; break; }
                    return fail("expected ',' or '}'");
                }
            }
            out = std::move(obj);
        } else if (c == '[') {
            ++i;
            Json arr = Json::array();
            ws();
            if (i < s.size() && s[i] == ']') {
                ++i;
            } else {
                for (;;) {
                    Json v;
                    if (!value(v)) return false;
                    arr.push_back(std::move(v));
                    ws();
                    if (i < s.size() && s[i] == ',') { ++i; continue; }
                    if (i < s.size() && s[i] == ']') { ++i; break; }
                    return fail("expected ',' or ']'");
                }
            }
            out = std::move(arr);
        } else if (c == '"') {
            std::string str;
            ok = string(str);
            out = Json(std::move(str));
        } else if (s.compare(i, 4, "true") == 0) {
            i += 4;
            out = Json(true);
        } else if (s.compare(i, 5, "false") == 0) {
            i += 5;
            out = Json(false);
        } else if (s.compare(i, 4, "null") == 0) {
            i += 4;
            out = Json();
        } else if (c == '-' || (c >= '0' && c <= '9')) {
            const char* begin = s.c_str() + i;
            char* end = nullptr;
            const double d = std::strtod(begin, &end);
            if (end == begin) return fail("bad number");
            i += static_cast<size_t>(end - begin);
            out = Json(d);
        } else {
            return fail("unexpected character");
        }
        --depth;
        return ok;
    }
};

}  // namespace

bool Json::parse(const std::string& text, Json& out, std::string& err) {
    Parser p{text, 0, {}, 0};
    Json v;
    if (!p.value(v)) {
        err = p.err;
        return false;
    }
    p.ws();
    if (p.i != text.size()) {
        err = "trailing characters at offset " + std::to_string(p.i);
        return false;
    }
    out = std::move(v);
    return true;
}

}  // namespace vartad
