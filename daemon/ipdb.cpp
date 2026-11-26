#include "ipdb.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace vartad {

namespace {

// Splits one CSV line, honouring "quoted, fields" and "" escapes.
std::vector<std::string> csv_fields(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    bool quoted = false;
    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (quoted) {
            if (c == '"') {
                if (i + 1 < line.size() && line[i + 1] == '"') {
                    cur += '"';
                    ++i;
                } else {
                    quoted = false;
                }
            } else {
                cur += c;
            }
        } else if (c == '"') {
            quoted = true;
        } else if (c == ',') {
            out.push_back(cur);
            cur.clear();
        } else if (c != '\r') {
            cur += c;
        }
    }
    out.push_back(cur);
    return out;
}

std::string read_all(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

template <typename R>
void sort_ranges(std::vector<R>& v) {
    std::sort(v.begin(), v.end(), [](const R& a, const R& b) { return a.start < b.start; });
}

template <typename R, typename T>
const R* find_range(const std::vector<R>& v, T key) {
    // Last range whose start <= key.
    auto it = std::upper_bound(v.begin(), v.end(), key,
                               [](T k, const R& r) { return k < r.start; });
    if (it == v.begin()) return nullptr;
    --it;
    return key <= it->end ? &*it : nullptr;
}

}  // namespace

uint32_t IpDb::to_u32(const IpAddr& ip) {
    return (uint32_t(ip.b[0]) << 24) | (uint32_t(ip.b[1]) << 16) | (uint32_t(ip.b[2]) << 8) |
           ip.b[3];
}

IpDb::U128 IpDb::to_u128(const IpAddr& ip) {
    U128 v;
    for (int i = 0; i < 8; ++i) v.hi = (v.hi << 8) | ip.b[i];
    for (int i = 8; i < 16; ++i) v.lo = (v.lo << 8) | ip.b[i];
    return v;
}

uint32_t IpDb::intern_org(uint32_t asn, const std::string& org) {
    // Many ranges share one AS: store each (asn, org) pair once.
    const auto it = org_index_.find(asn);
    if (it != org_index_.end()) return it->second;
    const uint32_t idx = static_cast<uint32_t>(orgs_.size());
    orgs_.push_back(org);
    asns_.push_back(asn);
    org_index_[asn] = idx;
    return idx;
}

size_t IpDb::load_asn_csv(const std::string& text, bool v6) {
    std::istringstream in(text);
    std::string line;
    size_t n = 0;
    while (std::getline(in, line)) {
        const auto f = csv_fields(line);
        if (f.size() < 4) continue;
        IpAddr a, b;
        if (!IpAddr::parse(f[0], a) || !IpAddr::parse(f[1], b) || a.v6 != v6 || b.v6 != v6) continue;
        uint32_t asn = 0;
        try {
            asn = static_cast<uint32_t>(std::stoul(f[2]));
        } catch (...) {
            continue;
        }
        const uint32_t idx = intern_org(asn, f[3]);
        if (v6) asn6_.push_back({to_u128(a), to_u128(b), idx});
        else asn4_.push_back({to_u32(a), to_u32(b), idx});
        ++n;
    }
    v6 ? sort_ranges(asn6_) : sort_ranges(asn4_);
    return n;
}

size_t IpDb::load_country_csv(const std::string& text, bool v6) {
    std::istringstream in(text);
    std::string line;
    size_t n = 0;
    while (std::getline(in, line)) {
        const auto f = csv_fields(line);
        if (f.size() < 3 || f[2].size() != 2) continue;
        IpAddr a, b;
        if (!IpAddr::parse(f[0], a) || !IpAddr::parse(f[1], b) || a.v6 != v6 || b.v6 != v6) continue;
        const uint32_t cc = (uint32_t(static_cast<uint8_t>(f[2][0])) << 8) | static_cast<uint8_t>(f[2][1]);
        if (v6) cc6_.push_back({to_u128(a), to_u128(b), cc});
        else cc4_.push_back({to_u32(a), to_u32(b), cc});
        ++n;
    }
    v6 ? sort_ranges(cc6_) : sort_ranges(cc4_);
    return n;
}

size_t IpDb::load(const std::string& dir) {
    asn4_.clear(); asn6_.clear(); cc4_.clear(); cc6_.clear(); orgs_.clear(); asns_.clear(); org_index_.clear();
    size_t n = 0;
    const auto path = [&](const char* f) { return (fs::path(dir) / f).string(); };
    std::error_code ec;
    if (fs::exists(path("asn-ipv4.csv"), ec)) n += load_asn_csv(read_all(path("asn-ipv4.csv")), false);
    if (fs::exists(path("asn-ipv6.csv"), ec)) n += load_asn_csv(read_all(path("asn-ipv6.csv")), true);
    if (fs::exists(path("dbip-country-ipv4.csv"), ec))
        n += load_country_csv(read_all(path("dbip-country-ipv4.csv")), false);
    if (fs::exists(path("dbip-country-ipv6.csv"), ec))
        n += load_country_csv(read_all(path("dbip-country-ipv6.csv")), true);
    return n;
}

IpInfo IpDb::lookup(const IpAddr& raw) const {
    IpInfo info;
    const IpAddr ip = raw.unmapped();
    uint32_t org = UINT32_MAX, cc = 0;
    if (ip.v6) {
        const U128 k = to_u128(ip);
        if (const auto* r = find_range(asn6_, k)) org = r->value;
        if (const auto* r = find_range(cc6_, k)) cc = r->value;
    } else {
        const uint32_t k = to_u32(ip);
        if (const auto* r = find_range(asn4_, k)) org = r->value;
        if (const auto* r = find_range(cc4_, k)) cc = r->value;
    }
    if (org != UINT32_MAX) {
        info.asn = asns_[org];
        info.org = orgs_[org];
    }
    if (cc) {
        info.country = std::string(1, static_cast<char>(cc >> 8)) + static_cast<char>(cc & 0xff);
    }
    return info;
}

const char* IpDb::attribution() {
    return "IP data: DB-IP.com (IP to ASN/Country Lite) and RouteViews, CC BY 4.0, "
           "via github.com/sapics/ip-location-db";
}

std::vector<std::pair<std::string, std::string>> IpDb::download_files() {
    const std::string base = "https://cdn.jsdelivr.net/npm/@ip-location-db/";
    return {
        {base + "asn/asn-ipv4.csv", "asn-ipv4.csv"},
        {base + "asn/asn-ipv6.csv", "asn-ipv6.csv"},
        {base + "dbip-country/dbip-country-ipv4.csv", "dbip-country-ipv4.csv"},
        {base + "dbip-country/dbip-country-ipv6.csv", "dbip-country-ipv6.csv"},
    };
}

}  // namespace vartad
