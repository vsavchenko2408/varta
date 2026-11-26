// vartad - IP addresses, IPv4/IPv6 + TCP/UDP header parsing and DNS response parsing.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace vartad {

struct IpAddr {
    bool v6 = false;
    std::array<uint8_t, 16> b{};  // IPv4 uses the first 4 bytes

    static bool parse(const std::string& s, IpAddr& out);
    std::string str() const;
    bool operator==(const IpAddr& o) const;
    bool operator<(const IpAddr& o) const;
    // ::ffff:a.b.c.d -> a.b.c.d
    IpAddr unmapped() const;
};

struct Cidr {
    IpAddr net;
    int prefix = 0;
    static bool parse(const std::string& s, Cidr& out);  // "1.2.3.0/24", "2001:db8::/32", "1.2.3.4"
    bool contains(const IpAddr& ip) const;
};

// What kind of address this is, for display ("Local network", "Loopback"...). Empty = public.
std::string special_range(const IpAddr& ip);

enum : uint8_t { kProtoTcp = 6, kProtoUdp = 17 };

struct PacketInfo {
    IpAddr src, dst;
    uint8_t proto = 0;
    uint16_t sport = 0, dport = 0;
    const uint8_t* payload = nullptr;  // transport payload (after TCP/UDP header)
    size_t payload_len = 0;
};

// Parses a raw IP packet as delivered by NFQUEUE. Only TCP/UDP are accepted.
bool parse_packet(const uint8_t* data, size_t len, PacketInfo& out);

struct DnsAnswer {
    IpAddr ip;
    std::string name;  // the name that was queried (not the CNAME target)
    uint32_t ttl = 0;
};

// Extracts A/AAAA answers from a DNS response message.
std::vector<DnsAnswer> parse_dns_response(const uint8_t* data, size_t len);

}  // namespace vartad
