// vartad - a deliberately small JSON value + parser/serializer.
// Only what the IPC protocol and the rules file need: null, bool, number, string, array, object.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace vartad {

class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };
    using Array = std::vector<Json>;
    using Object = std::map<std::string, Json>;

    Json() = default;
    Json(std::nullptr_t) {}
    Json(bool b) : type_(Type::Bool), b_(b) {}
    Json(int v) : type_(Type::Number), n_(v) {}
    Json(int64_t v) : type_(Type::Number), n_(static_cast<double>(v)) {}
    Json(uint64_t v) : type_(Type::Number), n_(static_cast<double>(v)) {}
    Json(unsigned v) : type_(Type::Number), n_(v) {}
    Json(double v) : type_(Type::Number), n_(v) {}
    Json(const char* s) : type_(Type::String), s_(s) {}
    Json(std::string s) : type_(Type::String), s_(std::move(s)) {}
    Json(Array a) : type_(Type::Array), a_(std::make_shared<Array>(std::move(a))) {}
    Json(Object o) : type_(Type::Object), o_(std::make_shared<Object>(std::move(o))) {}

    static Json array() { return Json(Array{}); }
    static Json object() { return Json(Object{}); }

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }
    bool is_object() const { return type_ == Type::Object; }
    bool is_array() const { return type_ == Type::Array; }
    bool is_string() const { return type_ == Type::String; }

    // Lenient accessors: return the fallback when the type does not match.
    bool as_bool(bool fallback = false) const { return type_ == Type::Bool ? b_ : fallback; }
    double as_number(double fallback = 0) const { return type_ == Type::Number ? n_ : fallback; }
    int64_t as_int(int64_t fallback = 0) const {
        return type_ == Type::Number ? static_cast<int64_t>(n_) : fallback;
    }
    const std::string& as_string() const;
    std::string str(const std::string& key, const std::string& fallback = "") const;
    int64_t integer(const std::string& key, int64_t fallback = 0) const;
    bool boolean(const std::string& key, bool fallback = false) const;

    // Object access. operator[] on a non-object turns it into an empty object.
    Json& operator[](const std::string& key);
    const Json& get(const std::string& key) const;  // returns null Json if missing
    bool has(const std::string& key) const;

    // Array access.
    void push_back(Json v);
    size_t size() const;
    const Json& at(size_t i) const;
    const Array& items() const;
    const Object& fields() const;

    std::string dump() const;
    // Returns false and sets err on malformed input.
    static bool parse(const std::string& text, Json& out, std::string& err);

private:
    void dump_to(std::string& out) const;
    void own();  // copy-on-write for shared containers

    Type type_ = Type::Null;
    bool b_ = false;
    double n_ = 0;
    std::string s_;
    std::shared_ptr<Array> a_;
    std::shared_ptr<Object> o_;
};

}  // namespace vartad
