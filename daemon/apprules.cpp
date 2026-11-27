#include "apprules.hpp"

#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace vartad {

const char* action_str(Action a) { return a == Action::Allow ? "allow" : "deny"; }
const char* duration_str(Duration d) { return d == Duration::Forever ? "forever" : "session"; }

Json AppRule::to_json() const {
    Json j = Json::object();
    j["id"] = id;
    j["enabled"] = enabled;
    j["action"] = action_str(action);
    j["duration"] = duration_str(duration);
    j["exe"] = exe;
    j["direction"] = direction;
    j["host"] = host;
    j["ip"] = ip;
    j["port"] = static_cast<int>(port);
    j["proto"] = proto;
    j["note"] = note;
    j["created"] = created;
    j["hits"] = hits;
    return j;
}

bool AppRule::from_json(const Json& j, AppRule& r, std::string& err) {
    if (!j.is_object()) {
        err = "rule must be an object";
        return false;
    }
    r = AppRule{};
    r.id = static_cast<uint64_t>(j.integer("id", 0));
    r.enabled = j.boolean("enabled", true);
    const std::string a = j.str("action", "allow");
    if (a != "allow" && a != "deny") {
        err = "action must be allow or deny";
        return false;
    }
    r.action = a == "allow" ? Action::Allow : Action::Deny;
    r.duration = j.str("duration", "forever") == "session" ? Duration::Session : Duration::Forever;
    r.exe = j.str("exe", "*");
    if (r.exe.empty()) r.exe = "*";
    r.direction = j.str("direction");
    if (!r.direction.empty() && r.direction != "in" && r.direction != "out") {
        err = "direction must be in, out or empty";
        return false;
    }
    r.host = j.str("host");
    for (char& c : r.host)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    r.ip = j.str("ip");
    if (!r.ip.empty()) {
        Cidr c;
        if (!Cidr::parse(r.ip, c)) {
            err = "invalid ip/cidr '" + r.ip + "'";
            return false;
        }
    }
    const int64_t port = j.integer("port", 0);
    if (port < 0 || port > 65535) {
        err = "invalid port";
        return false;
    }
    r.port = static_cast<uint16_t>(port);
    r.proto = j.str("proto");
    if (!r.proto.empty() && r.proto != "tcp" && r.proto != "udp") {
        err = "proto must be tcp, udp or empty";
        return false;
    }
    r.note = j.str("note");
    r.created = j.integer("created", 0);
    r.hits = static_cast<uint64_t>(j.integer("hits", 0));
    return true;
}

int AppRule::specificity() const {
    int s = 0;
    if (exe != "*") s += 16;
    if (!host.empty()) s += host[0] == '*' ? 6 : 8;
    if (!ip.empty()) s += 8;
    if (port) s += 4;
    if (!proto.empty()) s += 2;
    if (!direction.empty()) s += 1;
    return s;
}

bool host_matches(const std::string& pattern, const std::string& host) {
    if (pattern.empty()) return true;
    if (host.empty()) return false;
    if (pattern.size() > 2 && pattern[0] == '*' && pattern[1] == '.') {
        const std::string base = pattern.substr(2);
        if (host == base) return true;
        return host.size() > base.size() &&
               host.compare(host.size() - base.size(), base.size(), base) == 0 &&
               host[host.size() - base.size() - 1] == '.';
    }
    return pattern == host;
}

bool same_exe(const std::string& a, const std::string& b) {
#ifdef _WIN32
    // Windows paths are case-insensitive (C:\Windows vs c:\windows).
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
        if (x != y) return false;
    }
    return true;
#else
    return a == b;
#endif
}

bool rule_matches(const AppRule& r, const MatchInput& in) {
    if (!r.enabled) return false;
    if (r.exe != "*" && !same_exe(r.exe, in.exe)) return false;
    if (!r.direction.empty() && r.direction != (in.inbound ? "in" : "out")) return false;
    if (!host_matches(r.host, in.host)) return false;
    if (!r.ip.empty()) {
        Cidr c;
        if (!Cidr::parse(r.ip, c) || !c.contains(in.remote)) return false;
    }
    if (r.port && r.port != in.remote_port) return false;
    if (!r.proto.empty()) {
        const char* p = in.proto == kProtoTcp ? "tcp" : in.proto == kProtoUdp ? "udp" : "";
        if (r.proto != p) return false;
    }
    return true;
}

AppRule* RuleSet::match(const MatchInput& in) {
    AppRule* best = nullptr;
    int best_spec = -1;
    for (auto& r : rules_) {
        if (!rule_matches(r, in)) continue;
        const int s = r.specificity();
        if (s > best_spec || (s == best_spec && r.action == Action::Deny)) {
            best = &r;
            best_spec = s;
        }
    }
    return best;
}

AppRule& RuleSet::add(AppRule r) {
    r.id = next_id_++;
    if (!r.created) r.created = static_cast<int64_t>(std::time(nullptr));
    rules_.push_back(std::move(r));
    return rules_.back();
}

bool RuleSet::remove(uint64_t id) {
    for (auto it = rules_.begin(); it != rules_.end(); ++it) {
        if (it->id == id) {
            rules_.erase(it);
            return true;
        }
    }
    return false;
}

AppRule* RuleSet::find(uint64_t id) {
    for (auto& r : rules_)
        if (r.id == id) return &r;
    return nullptr;
}

Json RuleSet::to_json() const {
    Json arr = Json::array();
    for (const auto& r : rules_) arr.push_back(r.to_json());
    return arr;
}

bool RuleSet::load(const std::string& path, std::string& err) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "cannot open " + path;
        return false;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    Json j;
    if (!Json::parse(ss.str(), j, err)) return false;
    rules_.clear();
    for (const auto& item : j.get("rules").items()) {
        AppRule r;
        std::string e;
        if (!AppRule::from_json(item, r, e)) continue;  // skip bad entries, keep the rest
        r.duration = Duration::Forever;
        add(r);
    }
    return true;
}

bool RuleSet::save(const std::string& path, std::string& err) const {
    Json root = Json::object();
    root["version"] = 1;
    Json arr = Json::array();
    for (const auto& r : rules_)
        if (r.duration == Duration::Forever) arr.push_back(r.to_json());
    root["rules"] = arr;

    std::error_code ec;
    fs::create_directories(fs::path(path).parent_path(), ec);
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            err = "cannot write " + tmp;
            return false;
        }
        // One rule per line keeps the file readable and diff-friendly.
        out << "{\"version\":1,\"rules\":[\n";
        const auto& items = arr.items();
        for (size_t i = 0; i < items.size(); ++i)
            out << "  " << items[i].dump() << (i + 1 < items.size() ? ",\n" : "\n");
        out << "]}\n";
    }
    fs::rename(tmp, path, ec);
    if (ec) {
        err = "cannot replace " + path + ": " + ec.message();
        return false;
    }
    return true;
}

void RuleSet::add_defaults() {
    // System services that must reach the network for the machine to work at all.
#ifdef _WIN32
    static const char* system_allow[] = {
        "System",  // the kernel (pid 4): SMB, NetBIOS...
        "C:\\Windows\\System32\\svchost.exe",  // Windows services: DHCP, time, updates, DNS...
        "C:\\Windows\\System32\\lsass.exe",
        "C:\\Windows\\System32\\services.exe",
    };
#elif defined(__APPLE__)
    static const char* system_allow[] = {
        "/usr/sbin/mDNSResponder",  // DNS for every program
        "/usr/libexec/timed",       // clock synchronisation
        "/usr/libexec/trustd",      // certificate revocation checks
    };
#else
    static const char* system_allow[] = {
        "/usr/lib/systemd/systemd-resolved", "/usr/lib/systemd/systemd-timesyncd",
        "/usr/lib/systemd/systemd-networkd", "/usr/sbin/NetworkManager",
        "/usr/sbin/dhclient",                "/usr/sbin/dhcpcd",
        "/usr/sbin/chronyd",                 "/usr/sbin/ntpd",
        "/usr/lib/apt/methods/http",         "/usr/lib/apt/methods/https",
    };
#endif
    for (const char* exe : system_allow) {
        AppRule r;
        r.action = Action::Allow;
        r.exe = exe;
        r.direction = "out";
        r.note = "default: system service";
        add(r);
    }
}

}  // namespace vartad
