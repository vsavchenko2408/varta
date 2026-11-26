// vartad - offline IP information database (owner organisation, AS number, country).
//
// Data: ip-location-db CSV files (https://github.com/sapics/ip-location-db)
//   asn-ipv4.csv, asn-ipv6.csv            -> ip_start,ip_end,asn,"organisation"
//   dbip-country-ipv4.csv, -ipv6.csv      -> ip_start,ip_end,country_code
// Licences: CC BY 4.0 - attribution to DB-IP.com and RouteViews is required (shown in the GUI).
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "packet.hpp"

namespace vartad {

struct IpInfo {
    uint32_t asn = 0;
    std::string org;
    std::string country;  // ISO 3166 alpha-2, e.g. "DK"
};

class IpDb {
public:
    // Loads whatever files exist in `dir`. Returns the number of ranges loaded.
    size_t load(const std::string& dir);
    // For tests: feed CSV text directly.
    size_t load_asn_csv(const std::string& text, bool v6);
    size_t load_country_csv(const std::string& text, bool v6);

    IpInfo lookup(const IpAddr& ip) const;
    size_t ranges() const { return asn4_.size() + asn6_.size() + cc4_.size() + cc6_.size(); }
    static const char* attribution();
    static std::vector<std::pair<std::string, std::string>> download_files();  // url, filename

private:
    // Portable 128-bit key (MSVC has no __int128).
    struct U128 {
        uint64_t hi = 0, lo = 0;
        bool operator<(const U128& o) const { return hi != o.hi ? hi < o.hi : lo < o.lo; }
        bool operator<=(const U128& o) const { return !(o < *this); }
    };
    template <typename T>
    struct Range {
        T start, end;
        uint32_t value;  // index into orgs_/asns_ or packed country code
    };
    std::vector<Range<uint32_t>> asn4_, cc4_;
    std::vector<Range<U128>> asn6_, cc6_;
    std::vector<std::string> orgs_;
    std::vector<uint32_t> asns_;
    std::unordered_map<uint32_t, uint32_t> org_index_;

    static uint32_t to_u32(const IpAddr& ip);
    static U128 to_u128(const IpAddr& ip);
    uint32_t intern_org(uint32_t asn, const std::string& org);
};

}  // namespace vartad
