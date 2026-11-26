// Varta - turns a Config (+ downloaded lists) into the concrete set of things to block.
#pragma once

#include <string>
#include <vector>

#include "config.hpp"

namespace varta {

struct RuleSet {
    std::vector<std::string> domains;  // for the hosts file, sorted and unique
    std::vector<std::string> ipv4;     // outbound block, IPs or CIDR
    std::vector<std::string> ipv6;
    SecurityConfig sec;
    bool log = false;
};

// Extracts domains from a hosts-format, plain domain-per-line or "||domain^" adblock list.
std::vector<std::string> parse_domain_list(const std::string& text);

// lists_dir: directory with lists downloaded by `varta update` (may not exist).
// resolve: when true, blocked domains are also resolved and their IPs added (slow).
RuleSet build_ruleset(const Config& cfg, const std::string& lists_dir, bool resolve);

}  // namespace varta
