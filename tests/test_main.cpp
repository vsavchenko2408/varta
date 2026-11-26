// Varta unit tests - no framework, just CHECK macros. Run: ./varta_tests
#include <filesystem>
#include <iostream>
#include <string>

#include "blocklists.hpp"
#include "config.hpp"
#include "firewall.hpp"
#include "hosts.hpp"
#include "net.hpp"
#include "rules.hpp"
#include "util.hpp"

using namespace varta;

static int g_failed = 0, g_passed = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (cond) {                                                              \
            ++g_passed;                                                          \
        } else {                                                                 \
            ++g_failed;                                                          \
            std::cerr << __FILE__ << ":" << __LINE__ << ": FAILED " #cond "\n"; \
        }                                                                        \
    } while (0)

static bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

static void test_net() {
    CHECK(ip_family("1.2.3.4") == IpFamily::V4);
    CHECK(ip_family("10.0.0.0/8") == IpFamily::V4);
    CHECK(ip_family("10.0.0.0/33") == IpFamily::None);
    CHECK(ip_family("256.1.1.1") == IpFamily::None);
    CHECK(ip_family("2001:db8::1") == IpFamily::V6);
    CHECK(ip_family("2001:db8::/32") == IpFamily::V6);
    CHECK(ip_family("example.com") == IpFamily::None);

    CHECK(is_valid_domain("telemetry.example.com"));
    CHECK(!is_valid_domain("localhost"));
    CHECK(!is_valid_domain("-bad.com"));
    CHECK(!is_valid_domain("a..b"));
    CHECK(!is_valid_domain("1.2.3.4"));

    CHECK(domain_matches("a.b.example.com", "example.com"));
    CHECK(domain_matches("example.com", "example.com"));
    CHECK(!domain_matches("badexample.com", "example.com"));

    PortRule r;
    CHECK(parse_port_rule("8080/tcp", r) && r.port == 8080 && r.proto == Proto::Tcp);
    CHECK(parse_port_rule("53/UDP", r) && r.proto == Proto::Udp);
    CHECK(parse_port_rule("3000", r) && r.proto == Proto::Both);
    CHECK(!parse_port_rule("70000", r));
    CHECK(!parse_port_rule("80/icmp", r));
}

static void test_config_roundtrip() {
    Config c = default_config();
    c.sec.block_ping = true;
    c.sec.allow_in.push_back({8080, Proto::Tcp});
    c.categories["meta"] = true;
    c.allow_domains = {"good.example.com"};
    c.block_domains = {"evil.example.com"};
    c.block_ips = {"203.0.113.0/24", "2001:db8::/32"};
    c.sources = {"https://example.com/hosts"};

    std::vector<std::string> warnings;
    const Config d = parse_config(serialize_config(c), warnings);
    CHECK(warnings.empty());
    CHECK(d.sec.block_ping);
    CHECK(d.sec.allow_in.size() == 1 && d.sec.allow_in[0].port == 8080);
    CHECK(d.categories.at("meta"));
    CHECK(d.allow_domains == c.allow_domains);
    CHECK(d.block_domains == c.block_domains);
    CHECK(d.block_ips == c.block_ips);
    CHECK(d.sources == c.sources);
    CHECK(serialize_config(d) == serialize_config(c));

    warnings.clear();
    parse_config("[security]\nblock_ping = maybe\nnope = on\n[block_ips]\nnot-an-ip\n", warnings);
    CHECK(warnings.size() == 3);

    Config p = default_config();
    p.sec.allow_ssh = true;
    CHECK(apply_preset(p, "paranoid"));
    CHECK(p.sec.block_public_doh && p.sec.block_ping && p.sec.allow_ssh);
    CHECK(p.categories.at("meta"));
    CHECK(!apply_preset(p, "whatever"));

    std::string err;
    CHECK(set_option(p, "security.block_rdp", "off", err) && !p.sec.block_rdp);
    CHECK(!set_option(p, "security.unknown", "on", err));
}

static void test_lists_and_rules() {
    const auto d = parse_domain_list(
        "# comment\n"
        "127.0.0.1 localhost\n"
        "0.0.0.0 ads.example.com tracker.example.com # trailing\n"
        "||adblock.example.org^\n"
        "plain.example.net\n"
        "! adblock comment\n"
        "0.0.0.0 0.0.0.0\n");
    CHECK(d.size() == 4);

    Config c = default_config();
    for (auto& [id, on] : c.categories) on = false;
    c.categories["google"] = true;
    c.allow_domains = {"doubleclick.net"};
    c.block_domains = {"mine.example.com"};
    c.block_ips = {"203.0.113.5", "2001:db8::1"};
    const RuleSet rs = build_ruleset(c, "", false);
    bool has_dc = false, has_ga = false, has_mine = false;
    for (const auto& x : rs.domains) {
        has_dc |= domain_matches(x, "doubleclick.net");
        has_ga |= x == "google-analytics.com";
        has_mine |= x == "mine.example.com";
    }
    CHECK(!has_dc);  // allow list removes domain and its subdomains
    CHECK(has_ga && has_mine);
    CHECK(rs.ipv4.size() == 1 && rs.ipv6.size() == 1);

    // Every built-in domain must be valid, otherwise the hosts file gets garbage.
    for (const auto& cat : builtin_categories())
        for (const auto& dom : cat.domains) CHECK(is_valid_domain(dom));
    for (const auto& ip : public_doh_resolvers()) CHECK(ip_family(ip) != IpFamily::None);
}

static void test_hosts() {
    const std::string original = "127.0.0.1 localhost\n::1 localhost\n";
    const std::string sec = render_hosts_section({"a.example.com", "b.example.com"}, true);
    const std::string merged = merge_hosts_section(original, sec);
    CHECK(contains(merged, "0.0.0.0 a.example.com"));
    CHECK(contains(merged, ":: b.example.com"));
    CHECK(count_hosts_domains(merged) == 2);
    // Applying twice must not duplicate the block.
    CHECK(merge_hosts_section(merged, sec) == merged);
    // Removing restores the original exactly.
    CHECK(strip_hosts_section(merged) == original);
    CHECK(count_hosts_domains(original) == 0);

    // CRLF files stay CRLF.
    const std::string win = "127.0.0.1 localhost\r\n";
    const std::string mw = merge_hosts_section(win, sec);
    CHECK(contains(mw, "0.0.0.0 a.example.com\r\n"));
    CHECK(strip_hosts_section(mw) == win);

    // Real file round trip in a temp dir.
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "varta_test";
    fs::create_directories(dir);
    const std::string hp = (dir / "hosts").string(), bp = (dir / "hosts.orig").string();
    fs::remove(bp);
    std::string err;
    CHECK(write_file_atomic(hp, original, err));
    CHECK(hosts_apply(hp, bp, {"x.example.com"}, false, err));
    CHECK(count_hosts_domains(*read_file(hp)) == 1);
    CHECK(*read_file(bp) == original);
    CHECK(hosts_remove(hp, err));
    CHECK(*read_file(hp) == original);
    fs::remove_all(dir);
}

static void test_generators() {
    Config c = default_config();
    c.block_ips = {"203.0.113.0/24", "2001:db8::/32"};
    c.sec.allow_ssh = true;
    c.sec.block_public_doh = true;
    c.sec.allow_in.push_back({51820, Proto::Udp});
    RuleSet rs = build_ruleset(c, "", false);

    const std::string nft = generate_nft(rs);
    CHECK(contains(nft, "table inet varta {"));
    CHECK(contains(nft, "203.0.113.0/24"));
    CHECK(contains(nft, "tcp dport { 22 } accept"));
    CHECK(contains(nft, "51820"));
    CHECK(contains(nft, "@doh4"));
    CHECK(contains(nft, "counter drop comment \"default inbound deny\""));

    const std::string pf = generate_pf(rs);
    CHECK(contains(pf, "table <varta_block> persist { 203.0.113.0/24 2001:db8::/32 }"));
    CHECK(contains(pf, "block drop in quick all"));
    CHECK(contains(pf, "<varta_doh>"));

    const std::string ps = generate_powershell_apply(rs, true);
    CHECK(contains(ps, "-Group $G"));
    CHECK(contains(ps, "'203.0.113.0/24','2001:db8::/32'"));
    CHECK(contains(ps, "DiagTrack"));
    CHECK(contains(ps, "-DefaultInboundAction Block"));
    // PowerShell script must be pure ASCII (no BOM / encoding surprises).
    bool ascii = true;
    for (unsigned char ch : ps) ascii &= ch < 128;
    CHECK(ascii);

    // With inbound allowed there must be no catch-all drop.
    rs.sec.default_inbound_deny = false;
    CHECK(!contains(generate_nft(rs), "default inbound deny"));
    CHECK(!contains(generate_pf(rs), "block drop in quick all"));
}

int main() {
    test_net();
    test_config_roundtrip();
    test_lists_and_rules();
    test_hosts();
    test_generators();
    std::cout << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed ? 1 : 0;
}
