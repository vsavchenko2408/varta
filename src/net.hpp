// Varta - validation of domains, IP addresses and CIDR ranges, plus DNS resolution.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace varta {

enum class IpFamily { None, V4, V6 };

// Returns the family of "1.2.3.4", "1.2.3.0/24", "2001:db8::1", "2001:db8::/32", or None.
IpFamily ip_family(const std::string& s);

// True for a syntactically valid host name such as "telemetry.example.com".
bool is_valid_domain(const std::string& s);

// True if `domain` equals `parent` or is a subdomain of it (a.b.example.com vs example.com).
bool domain_matches(const std::string& domain, const std::string& parent);

enum class Proto { Tcp, Udp, Both };

struct PortRule {
    uint16_t port = 0;
    Proto proto = Proto::Both;
};

// Parses "8080", "8080/tcp", "53/udp". Returns false on error.
bool parse_port_rule(const std::string& s, PortRule& out);
std::string port_rule_to_string(const PortRule& r);

// Resolves a host name to its IPv4/IPv6 addresses using the system resolver.
// NOTE: call this before the hosts file is rewritten, otherwise you get 0.0.0.0.
std::vector<std::string> resolve_host(const std::string& host);

}  // namespace varta
