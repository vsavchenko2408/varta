#include "packet.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <cstring>

namespace vartad {

// ------------------------------------------------------------------------- addresses

bool IpAddr::parse(const std::string& s, IpAddr& out) {
    IpAddr a;
    if (inet_pton(AF_INET, s.c_str(), a.b.data()) == 1) {
        a.v6 = false;
        out = a;
        return true;
    }
    if (inet_pton(AF_INET6, s.c_str(), a.b.data()) == 1) {
        a.v6 = true;
        out = a;
        return true;
    }
    return false;
}

std::string IpAddr::str() const {
    char buf[INET6_ADDRSTRLEN] = {0};
    inet_ntop(v6 ? AF_INET6 : AF_INET, b.data(), buf, sizeof buf);
    return buf;
}

bool IpAddr::operator==(const IpAddr& o) const {
    if (v6 != o.v6) return false;
    return std::memcmp(b.data(), o.b.data(), v6 ? 16 : 4) == 0;
}

bool IpAddr::operator<(const IpAddr& o) const {
    if (v6 != o.v6) return !v6;
    return std::memcmp(b.data(), o.b.data(), v6 ? 16 : 4) < 0;
}

IpAddr IpAddr::unmapped() const {
    static const uint8_t prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (!v6 || std::memcmp(b.data(), prefix, 12) != 0) return *this;
    IpAddr a;
    a.v6 = false;
    std::memcpy(a.b.data(), b.data() + 12, 4);
    return a;
}

bool Cidr::parse(const std::string& s, Cidr& out) {
    const auto slash = s.find('/');
    Cidr c;
    if (!IpAddr::parse(s.substr(0, slash), c.net)) return false;
    const int max = c.net.v6 ? 128 : 32;
    if (slash == std::string::npos) {
        c.prefix = max;
    } else {
        const std::string p = s.substr(slash + 1);
        if (p.empty() || p.size() > 3) return false;
        for (char ch : p)
            if (ch < '0' || ch > '9') return false;
        c.prefix = std::stoi(p);
        if (c.prefix > max) return false;
    }
    out = c;
    return true;
}

bool Cidr::contains(const IpAddr& raw) const {
    const IpAddr ip = raw.unmapped();
    if (ip.v6 != net.v6) return false;
    int bits = prefix;
    for (int i = 0; bits > 0; ++i, bits -= 8) {
        const uint8_t mask = bits >= 8 ? 0xff : static_cast<uint8_t>(0xff << (8 - bits));
        if ((ip.b[i] & mask) != (net.b[i] & mask)) return false;
    }
    return true;
}

std::string special_range(const IpAddr& raw) {
    struct R {
        const char* cidr;
        const char* label;
    };
    static const R ranges[] = {
        {"127.0.0.0/8", "Loopback"},         {"10.0.0.0/8", "Local network"},
        {"172.16.0.0/12", "Local network"},  {"192.168.0.0/16", "Local network"},
        {"169.254.0.0/16", "Link-local"},    {"100.64.0.0/10", "Carrier-grade NAT"},
        {"224.0.0.0/4", "Multicast"},        {"255.255.255.255/32", "Broadcast"},
        {"0.0.0.0/8", "This network"},       {"::1/128", "Loopback"},
        {"fe80::/10", "Link-local"},         {"fc00::/7", "Local network"},
        {"ff00::/8", "Multicast"},
    };
    static std::vector<std::pair<Cidr, const char*>> parsed = [] {
        std::vector<std::pair<Cidr, const char*>> v;
        for (const auto& r : ranges) {
            Cidr c;
            Cidr::parse(r.cidr, c);
            v.emplace_back(c, r.label);
        }
        return v;
    }();
    const IpAddr ip = raw.unmapped();
    for (const auto& [c, label] : parsed)
        if (c.contains(ip)) return label;
    return {};
}

// --------------------------------------------------------------------------- packets

static uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
static uint32_t be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}

bool parse_packet(const uint8_t* d, size_t len, PacketInfo& out) {
    if (len < 1) return false;
    const int version = d[0] >> 4;
    size_t off = 0;
    uint8_t proto = 0;

    if (version == 4) {
        if (len < 20) return false;
        const size_t ihl = static_cast<size_t>(d[0] & 0x0f) * 4;
        if (ihl < 20 || len < ihl) return false;
        // Fragments other than the first carry no transport header.
        if ((be16(d + 6) & 0x1fff) != 0) return false;
        proto = d[9];
        out.src.v6 = out.dst.v6 = false;
        std::memcpy(out.src.b.data(), d + 12, 4);
        std::memcpy(out.dst.b.data(), d + 16, 4);
        off = ihl;
    } else if (version == 6) {
        if (len < 40) return false;
        out.src.v6 = out.dst.v6 = true;
        std::memcpy(out.src.b.data(), d + 8, 16);
        std::memcpy(out.dst.b.data(), d + 24, 16);
        uint8_t next = d[6];
        off = 40;
        // Walk the common extension headers.
        for (int guard = 0; guard < 8; ++guard) {
            if (next == 0 || next == 43 || next == 60) {  // hop-by-hop, routing, dest options
                if (len < off + 8) return false;
                next = d[off];
                off += (static_cast<size_t>(d[off + 1]) + 1) * 8;
            } else if (next == 44) {  // fragment
                if (len < off + 8) return false;
                if ((be16(d + off + 2) & 0xfff8) != 0) return false;  // not the first fragment
                next = d[off];
                off += 8;
            } else {
                break;
            }
        }
        proto = next;
    } else {
        return false;
    }

    out.proto = proto;
    if (proto == kProtoTcp) {
        if (len < off + 20) return false;
        out.sport = be16(d + off);
        out.dport = be16(d + off + 2);
        const size_t doff = static_cast<size_t>(d[off + 12] >> 4) * 4;
        if (doff < 20 || len < off + doff) return false;
        out.payload = d + off + doff;
        out.payload_len = len - off - doff;
        return true;
    }
    if (proto == kProtoUdp) {
        if (len < off + 8) return false;
        out.sport = be16(d + off);
        out.dport = be16(d + off + 2);
        out.payload = d + off + 8;
        out.payload_len = len - off - 8;
        return true;
    }
    return false;
}

// ------------------------------------------------------------------------------- DNS

// Reads a (possibly compressed) domain name starting at `pos`. Advances `pos` past the name
// in the original location. Returns false on malformed data.
static bool read_name(const uint8_t* d, size_t len, size_t& pos, std::string& name) {
    name.clear();
    size_t p = pos;
    bool jumped = false;
    int jumps = 0;
    for (;;) {
        if (p >= len) return false;
        const uint8_t l = d[p];
        if (l == 0) {
            if (!jumped) pos = p + 1;
            return true;
        }
        if ((l & 0xc0) == 0xc0) {
            if (p + 1 >= len || ++jumps > 16) return false;
            const size_t target = static_cast<size_t>((l & 0x3f) << 8) | d[p + 1];
            if (!jumped) pos = p + 2;
            jumped = true;
            p = target;
            continue;
        }
        if ((l & 0xc0) != 0) return false;
        if (p + 1 + l > len) return false;
        if (!name.empty()) name += '.';
        for (size_t k = 0; k < l; ++k) {
            char c = static_cast<char>(d[p + 1 + k]);
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            name += c;
        }
        if (name.size() > 255) return false;
        p += 1 + l;
    }
}

std::vector<DnsAnswer> parse_dns_response(const uint8_t* d, size_t len) {
    std::vector<DnsAnswer> out;
    if (len < 12) return out;
    const uint16_t flags = be16(d + 2);
    if (!(flags & 0x8000)) return out;  // not a response
    if ((flags & 0x000f) != 0) return out;  // rcode != NOERROR
    const uint16_t qd = be16(d + 4), an = be16(d + 6);
    if (qd < 1 || an == 0) return out;

    size_t pos = 12;
    std::string question;
    for (uint16_t q = 0; q < qd; ++q) {
        std::string n;
        if (!read_name(d, len, pos, n)) return out;
        if (q == 0) question = n;
        pos += 4;  // qtype + qclass
        if (pos > len) return out;
    }

    for (uint16_t a = 0; a < an; ++a) {
        std::string n;
        if (!read_name(d, len, pos, n)) return out;
        if (pos + 10 > len) return out;
        const uint16_t type = be16(d + pos);
        const uint32_t ttl = be32(d + pos + 4);
        const uint16_t rdlen = be16(d + pos + 8);
        pos += 10;
        if (pos + rdlen > len) return out;
        if ((type == 1 && rdlen == 4) || (type == 28 && rdlen == 16)) {
            DnsAnswer ans;
            ans.ip.v6 = type == 28;
            std::memcpy(ans.ip.b.data(), d + pos, rdlen);
            ans.name = question.empty() ? n : question;
            ans.ttl = ttl;
            out.push_back(ans);
        }
        pos += rdlen;
    }
    return out;
}

}  // namespace vartad
