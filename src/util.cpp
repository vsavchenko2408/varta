#include "util.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#define popen _popen
#define pclose _pclose
#else
#include <sys/wait.h>
#endif

namespace fs = std::filesystem;

namespace varta {

std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool starts_with(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

bool ends_with(const std::string& s, const std::string& x) {
    return s.size() >= x.size() && s.compare(s.size() - x.size(), x.size(), x) == 0;
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == sep) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    out.push_back(cur);
    return out;
}

std::vector<std::string> split_ws(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream in(s);
    std::string tok;
    while (in >> tok) out.push_back(tok);
    return out;
}

std::string join(const std::vector<std::string>& v, const std::string& sep) {
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += sep;
        out += v[i];
    }
    return out;
}

std::optional<bool> parse_bool(const std::string& raw) {
    const std::string s = to_lower(trim(raw));
    if (s == "on" || s == "true" || s == "yes" || s == "1") return true;
    if (s == "off" || s == "false" || s == "no" || s == "0") return false;
    return std::nullopt;
}

std::optional<std::string> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

bool write_file_atomic(const std::string& path, const std::string& content, std::string& err) {
    std::error_code ec;
    const fs::path target(path);
    if (target.has_parent_path()) fs::create_directories(target.parent_path(), ec);

    const fs::path tmp = target.string() + ".varta-tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            err = "cannot write " + tmp.string();
            return false;
        }
        out << content;
        if (!out) {
            err = "write failed for " + tmp.string();
            return false;
        }
    }
    fs::rename(tmp, target, ec);
    if (ec) {
        // Some systems (or antivirus locks on Windows) refuse rename over an existing
        // file; fall back to a direct overwrite.
        fs::remove(tmp, ec);
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        if (!out) {
            err = "cannot write " + target.string();
            return false;
        }
        out << content;
        if (!out) {
            err = "write failed for " + target.string();
            return false;
        }
    }
    return true;
}

static int normalize_exit(int status) {
#ifdef _WIN32
    return status;
#else
    if (status == -1) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
#endif
}

int run(const std::string& cmd, bool quiet) {
    std::string full = cmd;
    if (quiet) {
#ifdef _WIN32
        full += " >NUL 2>&1";
#else
        full += " >/dev/null 2>&1";
#endif
    }
    return normalize_exit(std::system(full.c_str()));
}

std::string run_capture(const std::string& cmd, int& exit_code) {
    std::string out;
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) {
        exit_code = -1;
        return out;
    }
    char buf[4096];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, p)) > 0) out.append(buf, n);
    exit_code = normalize_exit(pclose(p));
    return out;
}

std::string shell_quote(const std::string& s) {
#ifdef _WIN32
    return "\"" + s + "\"";
#else
    std::string out = "'";
    for (char c : s) {
        if (c == '\'')
            out += "'\\''";
        else
            out += c;
    }
    return out + "'";
#endif
}

}  // namespace varta
