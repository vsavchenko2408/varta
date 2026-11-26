#include "net.hpp"

#include <cctype>
#include <cstring>
#include <set>

#include "util.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

namespace varta {

static bool parse_ipv4(const std::string& s) {
    const auto parts = split(s, '.');
    if (parts.size() != 4) return false;
    for (const auto& p : parts) {
        if (p.empty() || p.size() > 3) return false;
        for (char c : p)
            if (!std::isdigit(static_cast<unsigned char>(c))) return false;
        if (std::stoi(p) > 255) return false;
    }
    return true;
}

static bool parse_ipv6(const std::string& s) {
    if (s.empty() || s.size() > 45) return false;
    unsigned char buf[16];
    return inet_pton(AF_INET6, s.c_str(), buf) == 1;
}

static bool parse_prefix(const std::string& p, int max) {
    if (p.empty() || p.size() > 3) return false;
    for (char c : p)
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    const int v = std::stoi(p);
    return v >= 0 && v <= max;
}

IpFamily ip_family(const std::string& raw) {
    const std::string s = trim(raw);
    const auto slash = s.find('/');
    const std::string addr = s.substr(0, slash);
    const std::string prefix = slash == std::string::npos ? "" : s.substr(slash + 1);

    if (parse_ipv4(addr)) {
        if (slash != std::string::npos && !parse_prefix(prefix, 32)) return IpFamily::None;
        return IpFamily::V4;
    }
    if (parse_ipv6(addr)) {
        if (slash != std::string::npos && !parse_prefix(prefix, 128)) return IpFamily::None;
        return IpFamily::V6;
    }
    return IpFamily::None;
}

bool is_valid_domain(const std::string& s) {
    if (s.empty() || s.size() > 253) return false;
    if (ip_family(s) != IpFamily::None) return false;
    const auto labels = split(s, '.');
    if (labels.size() < 2) return false;
    for (const auto& l : labels) {
        if (l.empty() || l.size() > 63) return false;
        if (l.front() == '-' || l.back() == '-') return false;
        for (char c : l) {
            const unsigned char u = static_cast<unsigned char>(c);
            if (!(std::isalnum(u) || c == '-' || c == '_')) return false;
        }
    }
    return true;
}

bool domain_matches(const std::string& domain, const std::string& parent) {
    if (domain == parent) return true;
    return domain.size() > parent.size() && ends_with(domain, parent) &&
           domain[domain.size() - parent.size() - 1] == '.';
}

bool parse_port_rule(const std::string& raw, PortRule& out) {
    const std::string s = to_lower(trim(raw));
    const auto slash = s.find('/');
    const std::string num = s.substr(0, slash);
    const std::string proto = slash == std::string::npos ? "" : s.substr(slash + 1);
    if (num.empty() || num.size() > 5) return false;
    for (char c : num)
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    const int p = std::stoi(num);
    if (p < 1 || p > 65535) return false;
    out.port = static_cast<uint16_t>(p);
    if (proto.empty() || proto == "any" || proto == "both")
        out.proto = Proto::Both;
    else if (proto == "tcp")
        out.proto = Proto::Tcp;
    else if (proto == "udp")
        out.proto = Proto::Udp;
    else
        return false;
    return true;
}

std::string port_rule_to_string(const PortRule& r) {
    std::string s = std::to_string(r.port);
    if (r.proto == Proto::Tcp) s += "/tcp";
    if (r.proto == Proto::Udp) s += "/udp";
    return s;
}

std::vector<std::string> resolve_host(const std::string& host) {
#ifdef _WIN32
    static bool wsa_ready = false;
    if (!wsa_ready) {
        WSADATA d;
        if (WSAStartup(MAKEWORD(2, 2), &d) == 0) wsa_ready = true;
    }
#endif
    std::set<std::string> found;
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) return {};
    for (addrinfo* p = res; p; p = p->ai_next) {
        char buf[INET6_ADDRSTRLEN] = {0};
        if (p->ai_family == AF_INET) {
            auto* a = reinterpret_cast<sockaddr_in*>(p->ai_addr);
            inet_ntop(AF_INET, &a->sin_addr, buf, sizeof buf);
        } else if (p->ai_family == AF_INET6) {
            auto* a = reinterpret_cast<sockaddr_in6*>(p->ai_addr);
            inet_ntop(AF_INET6, &a->sin6_addr, buf, sizeof buf);
        } else {
            continue;
        }
        const std::string ip = buf;
        // Never block unspecified/loopback answers (that is what a hosts entry returns).
        if (ip == "0.0.0.0" || ip == "::" || ip == "::1" || starts_with(ip, "127.")) continue;
        found.insert(ip);
    }
    freeaddrinfo(res);
    return {found.begin(), found.end()};
}

}  // namespace varta
