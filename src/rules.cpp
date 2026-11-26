#include "rules.hpp"

#include <filesystem>
#include <set>
#include <sstream>

#include "blocklists.hpp"
#include "net.hpp"
#include "util.hpp"

namespace fs = std::filesystem;

namespace varta {

static bool is_reserved_hostname(const std::string& d) {
    static const std::set<std::string> skip = {
        "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
        "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
        "ip6-allhosts", "0.0.0.0"};
    return skip.count(d) > 0;
}

std::vector<std::string> parse_domain_list(const std::string& text) {
    std::vector<std::string> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        const auto hash = line.find('#');
        if (hash != std::string::npos) line = line.substr(0, hash);
        line = trim(line);
        if (line.empty() || line[0] == '!') continue;  // '!' = adblock comment

        std::string candidate;
        if (starts_with(line, "||")) {
            // Adblock syntax: ||example.com^  (ignore rules with paths/options)
            const auto end = line.find('^');
            if (end == std::string::npos) continue;
            candidate = line.substr(2, end - 2);
        } else {
            const auto toks = split_ws(line);
            if (toks.empty()) continue;
            if (ip_family(toks[0]) != IpFamily::None) {
                // hosts format: "0.0.0.0 a.com b.com"
                for (size_t i = 1; i < toks.size(); ++i) {
                    const std::string d = to_lower(toks[i]);
                    if (!is_reserved_hostname(d) && is_valid_domain(d)) out.push_back(d);
                }
                continue;
            }
            candidate = toks[0];
        }
        candidate = to_lower(candidate);
        if (!is_reserved_hostname(candidate) && is_valid_domain(candidate))
            out.push_back(candidate);
    }
    return out;
}

static bool is_allowed(const std::string& d, const std::vector<std::string>& allow) {
    for (const auto& a : allow)
        if (domain_matches(d, a)) return true;
    return false;
}

RuleSet build_ruleset(const Config& cfg, const std::string& lists_dir, bool resolve) {
    std::set<std::string> domains;
    for (const auto& cat : builtin_categories()) {
        const auto it = cfg.categories.find(cat.id);
        const bool on = it != cfg.categories.end() ? it->second : cat.default_on;
        if (on) domains.insert(cat.domains.begin(), cat.domains.end());
    }
    domains.insert(cfg.block_domains.begin(), cfg.block_domains.end());

    std::error_code ec;
    if (!lists_dir.empty() && fs::is_directory(lists_dir, ec)) {
        for (const auto& entry : fs::directory_iterator(lists_dir, ec)) {
            if (!entry.is_regular_file() || entry.path().extension() != ".txt") continue;
            if (const auto text = read_file(entry.path().string())) {
                const auto list = parse_domain_list(*text);
                domains.insert(list.begin(), list.end());
            }
        }
    }

    RuleSet rs;
    rs.sec = cfg.sec;
    rs.log = cfg.sec.log_blocked;
    for (const auto& d : domains)
        if (!is_allowed(d, cfg.allow_domains)) rs.domains.push_back(d);

    std::set<std::string> v4, v6;
    for (const auto& ip : cfg.block_ips) {
        const auto fam = ip_family(ip);
        if (fam == IpFamily::V4) v4.insert(ip);
        if (fam == IpFamily::V6) v6.insert(ip);
    }
    if (resolve) {
        for (const auto& d : rs.domains) {
            for (const auto& ip : resolve_host(d)) {
                if (ip_family(ip) == IpFamily::V4) v4.insert(ip);
                else v6.insert(ip);
            }
        }
    }
    rs.ipv4.assign(v4.begin(), v4.end());
    rs.ipv6.assign(v6.begin(), v6.end());
    return rs;
}

}  // namespace varta
