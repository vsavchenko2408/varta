#include "config.hpp"

#include <sstream>

#include "blocklists.hpp"
#include "util.hpp"

namespace varta {

namespace {

// Single table that maps option keys to fields. Keeps parse/serialize/menu in sync.
struct BoolField {
    const char* key;
    const char* description;
    bool Config::*general;          // set for "general.*"
    bool SecurityConfig::*security;  // set for "security.*"
};

const BoolField kFields[] = {
    {"general.use_hosts", "Block domains through the hosts file", &Config::use_hosts, nullptr},
    {"general.use_firewall", "Use the OS firewall (nftables / pf / Windows Firewall)",
     &Config::use_firewall, nullptr},
    {"general.hosts_ipv6", "Also null-route domains for IPv6 (:: entries)", &Config::hosts_ipv6,
     nullptr},
    {"general.resolve_domains_to_ips",
     "Resolve blocked domains to IPs and firewall them (may hit shared CDN IPs!)",
     &Config::resolve_domains, nullptr},
    {"general.windows_disable_diagtrack",
     "Windows only: disable DiagTrack service and set AllowTelemetry=0",
     &Config::win_disable_diagtrack, nullptr},

    {"security.default_inbound_deny", "Drop unsolicited inbound connections", nullptr,
     &SecurityConfig::default_inbound_deny},
    {"security.allow_ssh", "Keep SSH (tcp/22) reachable when inbound is denied", nullptr,
     &SecurityConfig::allow_ssh},
    {"security.block_ping", "Ignore inbound ping (ICMP echo)", nullptr, &SecurityConfig::block_ping},
    {"security.block_smb_netbios", "Block inbound SMB/NetBIOS (137-139, 445)", nullptr,
     &SecurityConfig::block_smb_netbios},
    {"security.block_rdp", "Block inbound Remote Desktop (3389)", nullptr,
     &SecurityConfig::block_rdp},
    {"security.block_legacy", "Block inbound Telnet (23) and FTP (21)", nullptr,
     &SecurityConfig::block_legacy},
    {"security.block_llmnr_ssdp", "Block inbound LLMNR (5355) and SSDP/UPnP (1900)", nullptr,
     &SecurityConfig::block_llmnr_ssdp},
    {"security.block_mdns", "Block inbound mDNS (5353) - breaks AirPlay/printer discovery",
     nullptr, &SecurityConfig::block_mdns},
    {"security.block_smb_to_internet", "Block outbound SMB (139/445) to public internet", nullptr,
     &SecurityConfig::block_smb_to_internet},
    {"security.block_public_doh",
     "Block DNS-over-HTTPS/TLS to big public resolvers (so browsers can't bypass hosts)", nullptr,
     &SecurityConfig::block_public_doh},
    {"security.log_blocked", "Log dropped packets", nullptr, &SecurityConfig::log_blocked},
};

bool* field_ptr(Config& c, const std::string& key) {
    for (const auto& f : kFields) {
        if (key != f.key) continue;
        if (f.general) return &(c.*(f.general));
        return &(c.sec.*(f.security));
    }
    return nullptr;
}

const bool* field_ptr(const Config& c, const std::string& key) {
    return field_ptr(const_cast<Config&>(c), key);
}

void add_unique(std::vector<std::string>& v, const std::string& s) {
    for (const auto& x : v)
        if (x == s) return;
    v.push_back(s);
}

}  // namespace

const std::vector<OptionInfo>& security_options() {
    static std::vector<OptionInfo> v = [] {
        std::vector<OptionInfo> out;
        for (const auto& f : kFields)
            if (f.security) out.push_back({f.key, f.description});
        return out;
    }();
    return v;
}

const std::vector<OptionInfo>& general_options() {
    static std::vector<OptionInfo> v = [] {
        std::vector<OptionInfo> out;
        for (const auto& f : kFields)
            if (f.general) out.push_back({f.key, f.description});
        return out;
    }();
    return v;
}

bool get_option(const Config& c, const std::string& key, bool& value) {
    const bool* p = field_ptr(c, key);
    if (!p) return false;
    value = *p;
    return true;
}

Config default_config() {
    Config c;
    for (const auto& cat : builtin_categories()) c.categories[cat.id] = cat.default_on;
    return c;
}

Config parse_config(const std::string& text, std::vector<std::string>& warnings) {
    Config c = default_config();
    std::istringstream in(text);
    std::string line, section;
    int lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        const auto hash = line.find('#');
        if (hash != std::string::npos) line = line.substr(0, hash);
        line = trim(line);
        if (line.empty()) continue;
        const std::string where = "line " + std::to_string(lineno) + ": ";

        if (line.front() == '[' && line.back() == ']') {
            section = to_lower(trim(line.substr(1, line.size() - 2)));
            continue;
        }

        // List sections: one entry per line.
        if (section == "allow_domains" || section == "block_domains") {
            const std::string d = to_lower(line);
            if (!is_valid_domain(d)) {
                warnings.push_back(where + "invalid domain '" + line + "'");
                continue;
            }
            add_unique(section == "allow_domains" ? c.allow_domains : c.block_domains, d);
            continue;
        }
        if (section == "block_ips") {
            if (ip_family(line) == IpFamily::None) {
                warnings.push_back(where + "invalid IP/CIDR '" + line + "'");
                continue;
            }
            add_unique(c.block_ips, line);
            continue;
        }
        if (section == "allow_in") {
            PortRule r;
            if (!parse_port_rule(line, r)) {
                warnings.push_back(where + "invalid port rule '" + line + "' (use 8080/tcp)");
                continue;
            }
            c.sec.allow_in.push_back(r);
            continue;
        }
        if (section == "sources") {
            add_unique(c.sources, line);
            continue;
        }

        // key = value sections
        const auto eq = line.find('=');
        if (eq == std::string::npos) {
            warnings.push_back(where + "expected key = value");
            continue;
        }
        const std::string key = to_lower(trim(line.substr(0, eq)));
        const std::string value = trim(line.substr(eq + 1));

        if (section == "categories") {
            const auto b = parse_bool(value);
            if (!b) {
                warnings.push_back(where + "expected on/off for category '" + key + "'");
                continue;
            }
            if (!find_category(key)) {
                warnings.push_back(where + "unknown category '" + key + "'");
                continue;
            }
            c.categories[key] = *b;
            continue;
        }
        if (section == "general" || section == "security") {
            std::string err;
            if (!set_option(c, section + "." + key, value, err)) warnings.push_back(where + err);
            continue;
        }
        warnings.push_back(where + "unknown section [" + section + "]");
    }
    return c;
}

static const char* onoff(bool b) { return b ? "on" : "off"; }

std::string serialize_config(const Config& c) {
    std::ostringstream o;
    o << "# Varta configuration. Edit by hand or run `varta menu`.\n"
         "# Values: on/off. Lines starting with # are comments.\n\n";

    o << "[general]\n";
    for (const auto& f : kFields) {
        if (!f.general) continue;
        o << "# " << f.description << "\n";
        o << (f.key + 8) << " = " << onoff(c.*(f.general)) << "\n";
    }

    o << "\n[categories]\n";
    for (const auto& cat : builtin_categories()) {
        const auto it = c.categories.find(cat.id);
        const bool on = it != c.categories.end() ? it->second : cat.default_on;
        o << "# " << cat.title << "\n";
        o << cat.id << " = " << onoff(on) << "\n";
    }

    o << "\n[security]\n";
    for (const auto& f : kFields) {
        if (!f.security) continue;
        o << "# " << f.description << "\n";
        o << (f.key + 9) << " = " << onoff(c.sec.*(f.security)) << "\n";
    }

    o << "\n# Extra inbound ports to open, one per line: 8080/tcp, 51820/udp, 3000\n[allow_in]\n";
    for (const auto& r : c.sec.allow_in) o << port_rule_to_string(r) << "\n";

    o << "\n# Domains that must never be blocked (subdomains included)\n[allow_domains]\n";
    for (const auto& d : c.allow_domains) o << d << "\n";

    o << "\n# Your own domains to block\n[block_domains]\n";
    for (const auto& d : c.block_domains) o << d << "\n";

    o << "\n# IPs or CIDR ranges to block outbound (IPv4 and IPv6)\n[block_ips]\n";
    for (const auto& ip : c.block_ips) o << ip << "\n";

    o << "\n# External hosts-format lists, downloaded by `varta update`. Example:\n"
         "# https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts\n[sources]\n";
    for (const auto& s : c.sources) o << s << "\n";
    return o.str();
}

bool load_config(const std::string& path, Config& out, std::vector<std::string>& warnings) {
    const auto text = read_file(path);
    if (!text) return false;
    out = parse_config(*text, warnings);
    return true;
}

bool save_config(const std::string& path, const Config& c, std::string& err) {
    return write_file_atomic(path, serialize_config(c), err);
}

bool set_option(Config& c, const std::string& key_raw, const std::string& value, std::string& err) {
    const std::string key = to_lower(trim(key_raw));
    if (starts_with(key, "categories.")) {
        const std::string id = key.substr(11);
        if (!find_category(id)) {
            err = "unknown category '" + id + "'";
            return false;
        }
        const auto b = parse_bool(value);
        if (!b) {
            err = "expected on/off";
            return false;
        }
        c.categories[id] = *b;
        return true;
    }
    bool* p = field_ptr(c, key);
    if (!p) {
        err = "unknown option '" + key + "'";
        return false;
    }
    const auto b = parse_bool(value);
    if (!b) {
        err = "expected on/off for '" + key + "'";
        return false;
    }
    *p = *b;
    return true;
}

bool apply_preset(Config& c, const std::string& name) {
    SecurityConfig& s = c.sec;
    const auto ports = s.allow_in;  // presets never remove the user's own open ports
    const bool ssh = s.allow_ssh;
    if (name == "basic") {
        s = SecurityConfig{};
        s.default_inbound_deny = false;
        for (const auto& cat : builtin_categories()) c.categories[cat.id] = cat.default_on;
    } else if (name == "strict") {
        s = SecurityConfig{};  // defaults are the "strict" profile
        for (const auto& cat : builtin_categories()) c.categories[cat.id] = cat.default_on;
    } else if (name == "paranoid") {
        s = SecurityConfig{};
        s.block_ping = true;
        s.block_mdns = true;
        s.block_public_doh = true;
        s.log_blocked = true;
        for (const auto& cat : builtin_categories()) c.categories[cat.id] = true;
    } else {
        return false;
    }
    s.allow_in = ports;
    s.allow_ssh = ssh;
    return true;
}

}  // namespace varta
