// Varta - user configuration (INI-like text file) and security presets.
#pragma once

#include <map>
#include <string>
#include <vector>

#include "net.hpp"

namespace varta {

struct SecurityConfig {
    bool default_inbound_deny = true;   // drop unsolicited inbound connections
    bool allow_ssh = false;             // keep tcp/22 open when inbound is denied
    bool block_ping = false;            // drop inbound ICMP echo requests
    bool block_smb_netbios = true;      // inbound 137-139, 445
    bool block_rdp = true;              // inbound 3389
    bool block_legacy = true;           // inbound telnet (23) and ftp (21)
    bool block_llmnr_ssdp = true;       // inbound LLMNR 5355, SSDP/UPnP 1900
    bool block_mdns = false;            // inbound mDNS 5353 (breaks AirPlay / printer discovery)
    bool block_smb_to_internet = true;  // outbound 139/445 to public IPs (NTLM hash leak protection)
    bool block_public_doh = false;      // outbound DoH/DoT to big public resolvers (keeps hosts effective)
    bool log_blocked = false;           // log dropped packets
    std::vector<PortRule> allow_in;     // extra inbound ports to open
};

struct Config {
    bool use_hosts = true;
    bool use_firewall = true;
    bool hosts_ipv6 = true;          // also write ":: domain" lines
    bool resolve_domains = false;    // resolve blocked domains to IPs and firewall them too (risky: CDNs)
    bool win_disable_diagtrack = false;  // Windows: disable DiagTrack service + AllowTelemetry=0

    std::map<std::string, bool> categories;  // id -> enabled
    std::vector<std::string> allow_domains;
    std::vector<std::string> block_domains;
    std::vector<std::string> block_ips;
    std::vector<std::string> sources;  // URLs of external hosts/domain lists

    SecurityConfig sec;
};

// Builds the default configuration (categories from the built-in list).
Config default_config();

// Parses config text. Warnings for unknown keys / bad values go to `warnings`.
Config parse_config(const std::string& text, std::vector<std::string>& warnings);
std::string serialize_config(const Config& c);

bool load_config(const std::string& path, Config& out, std::vector<std::string>& warnings);
bool save_config(const std::string& path, const Config& c, std::string& err);

// Presets: "basic", "strict", "paranoid". Returns false for an unknown name.
bool apply_preset(Config& c, const std::string& name);

// Generic setter used by `varta set <key> <value>` and the menu.
// Keys look like "security.block_ping" or "general.use_hosts".
bool set_option(Config& c, const std::string& key, const std::string& value, std::string& err);

struct OptionInfo {
    std::string key;
    std::string description;
};
const std::vector<OptionInfo>& security_options();
const std::vector<OptionInfo>& general_options();
bool get_option(const Config& c, const std::string& key, bool& value);

}  // namespace varta
