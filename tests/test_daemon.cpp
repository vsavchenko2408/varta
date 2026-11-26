// Unit tests for the vartad building blocks (no kernel / root needed).
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
static int self_pid() { return static_cast<int>(GetCurrentProcessId()); }
static void close_sock(SOCKET s) { closesocket(s); }
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
static void close_sock(int s) { close(s); }
static int self_pid() { return static_cast<int>(getpid()); }
#endif

#include <cstring>
#include <filesystem>
#include <iostream>
#include <vector>

#include "apprules.hpp"
#include "engine.hpp"
#include "ipdb.hpp"
#include "json.hpp"
#include "packet.hpp"
#ifdef _WIN32
#include "procinfo_win.hpp"
#else
#include "linux_daemon.hpp"
#include "procinfo.hpp"
#endif

using namespace vartad;

static int g_failed = 0, g_passed = 0;
#define CHECK(cond)                                                              \
    do {                                                                         \
        if (cond) ++g_passed;                                                    \
        else {                                                                   \
            ++g_failed;                                                          \
            std::cerr << __FILE__ << ":" << __LINE__ << ": FAILED " #cond "\n"; \
        }                                                                        \
    } while (0)

static IpAddr ip(const char* s) {
    IpAddr a;
    IpAddr::parse(s, a);
    return a;
}

static void test_json() {
    Json j;
    std::string err;
    CHECK(Json::parse(R"({"a":1,"b":"x\"yé","c":[true,null,2.5],"d":{"e":-3}})", j, err));
    CHECK(j.integer("a") == 1);
    CHECK(j.str("b") == "x\"y\xc3\xa9");
    CHECK(j.get("c").size() == 3 && j.get("c").at(0).as_bool() && j.get("c").at(1).is_null());
    CHECK(j.get("d").integer("e") == -3);
    Json back;
    CHECK(Json::parse(j.dump(), back, err) && back.dump() == j.dump());
    CHECK(!Json::parse("{\"a\":}", back, err));
    CHECK(!Json::parse("[1,2", back, err));
    CHECK(!Json::parse("{} x", back, err));
    Json o = Json::object();
    o["n"] = static_cast<uint64_t>(1234567890123ULL);
    CHECK(o.dump() == "{\"n\":1234567890123}");
}

static void test_addresses() {
    CHECK(ip("1.2.3.4").str() == "1.2.3.4");
    CHECK(ip("2001:db8::1").v6);
    CHECK(ip("::ffff:1.2.3.4").unmapped() == ip("1.2.3.4"));
    Cidr c;
    CHECK(Cidr::parse("10.0.0.0/8", c) && c.contains(ip("10.9.8.7")) && !c.contains(ip("11.0.0.1")));
    CHECK(Cidr::parse("2001:db8::/32", c) && c.contains(ip("2001:db8:ffff::1")) &&
          !c.contains(ip("2001:db9::1")));
    CHECK(Cidr::parse("192.168.1.0/23", c) && c.contains(ip("192.168.0.5")) && !c.contains(ip("192.168.2.1")));
    CHECK(Cidr::parse("1.2.3.4", c) && c.prefix == 32);
    CHECK(!Cidr::parse("1.2.3.4/40", c));
    CHECK(special_range(ip("192.168.1.10")) == "Local network");
    CHECK(special_range(ip("127.0.0.1")) == "Loopback");
    CHECK(special_range(ip("8.8.8.8")).empty());
}

static std::vector<uint8_t> make_udp_ipv4(const char* src, const char* dst, uint16_t sp, uint16_t dp,
                                          const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> p(28 + payload.size(), 0);
    p[0] = 0x45;
    p[9] = 17;
    const uint16_t total = static_cast<uint16_t>(p.size());
    p[2] = total >> 8; p[3] = total & 0xff;
    inet_pton(AF_INET, src, &p[12]);
    inet_pton(AF_INET, dst, &p[16]);
    p[20] = sp >> 8; p[21] = sp & 0xff;
    p[22] = dp >> 8; p[23] = dp & 0xff;
    const uint16_t ulen = static_cast<uint16_t>(8 + payload.size());
    p[24] = ulen >> 8; p[25] = ulen & 0xff;
    std::memcpy(&p[28], payload.data(), payload.size());
    return p;
}

static void test_packets_and_dns() {
    // DNS response for "www.Example.com" -> CNAME -> 93.184.216.34 and an AAAA record.
    std::vector<uint8_t> dns = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
        // question: www.Example.com A IN
        3, 'w', 'w', 'w', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0x00, 0x01, 0x00, 0x01,
        // answer 1: CNAME pointer to question name -> edge.example.net
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x12,
        4, 'e', 'd', 'g', 'e', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'n', 'e', 't', 0,
        // answer 2: A record, name = pointer to "edge.example.net" (offset 45)
        0xc0, 45, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 93, 184, 216, 34,
        // answer 3: AAAA record
        0xc0, 45, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x10,
        0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0, 1, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46,
    };
    const auto answers = parse_dns_response(dns.data(), dns.size());
    CHECK(answers.size() == 2);
    if (answers.size() == 2) {
        CHECK(answers[0].ip.str() == "93.184.216.34");
        CHECK(answers[0].name == "www.example.com");  // lower-cased, the asked name
        CHECK(answers[0].ttl == 3600);
        CHECK(answers[1].ip.v6);
    }
    // Truncated / malicious input must not crash or loop.
    for (size_t cut = 0; cut < dns.size(); ++cut) parse_dns_response(dns.data(), cut);
    std::vector<uint8_t> loop = {0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0xc0, 0x0c};
    CHECK(parse_dns_response(loop.data(), loop.size()).empty());

    const auto pkt = make_udp_ipv4("10.0.0.2", "1.1.1.1", 40000, 53, dns);
    PacketInfo p;
    CHECK(parse_packet(pkt.data(), pkt.size(), p));
    CHECK(p.proto == kProtoUdp && p.sport == 40000 && p.dport == 53);
    CHECK(p.src.str() == "10.0.0.2" && p.dst.str() == "1.1.1.1");
    CHECK(p.payload_len == dns.size());
    CHECK(!parse_packet(pkt.data(), 10, p));
}

static void test_ipdb() {
    IpDb db;
    CHECK(db.load_asn_csv("1.0.0.0,1.0.0.255,13335,\"Cloudflare, Inc.\"\n"
                          "8.8.8.0,8.8.8.255,15169,Google LLC\n"
                          "garbage line\n",
                          false) == 2);
    CHECK(db.load_asn_csv("2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,15169,Google LLC\n", true) == 1);
    CHECK(db.load_country_csv("8.8.8.0,8.8.8.255,US\n1.0.0.0,1.0.0.255,AU\n", false) == 2);
    IpInfo i = db.lookup(ip("8.8.8.8"));
    CHECK(i.asn == 15169 && i.org == "Google LLC" && i.country == "US");
    i = db.lookup(ip("1.0.0.1"));
    CHECK(i.org == "Cloudflare, Inc." && i.country == "AU");
    i = db.lookup(ip("2001:4860:4860::8888"));
    CHECK(i.asn == 15169 && i.country.empty());
    CHECK(db.lookup(ip("9.9.9.9")).asn == 0);
    CHECK(db.lookup(ip("::ffff:8.8.8.8")).asn == 15169);
}

static void test_rules() {
    RuleSet rs;
    AppRule allow_curl;
    allow_curl.exe = "/usr/bin/curl";
    allow_curl.action = Action::Allow;
    rs.add(allow_curl);

    AppRule deny_tracker;
    deny_tracker.exe = "/usr/bin/curl";
    deny_tracker.host = "*.tracker.com";
    deny_tracker.action = Action::Deny;
    rs.add(deny_tracker);

    AppRule deny_net;
    deny_net.ip = "203.0.113.0/24";
    deny_net.action = Action::Deny;
    rs.add(deny_net);

    MatchInput m;
    m.exe = "/usr/bin/curl";
    m.host = "example.com";
    m.remote = ip("93.184.216.34");
    m.remote_port = 443;
    m.proto = kProtoTcp;
    AppRule* r = rs.match(m);
    CHECK(r && r->action == Action::Allow);

    m.host = "a.tracker.com";
    r = rs.match(m);
    CHECK(r && r->action == Action::Deny && r->host == "*.tracker.com");  // more specific wins

    m.host = "";
    m.exe = "/usr/bin/wget";
    m.remote = ip("203.0.113.7");
    r = rs.match(m);
    CHECK(r && r->ip == "203.0.113.0/24");

    m.remote = ip("198.51.100.1");
    CHECK(rs.match(m) == nullptr);

    // Same specificity: deny wins.
    RuleSet tie;
    AppRule a1; a1.exe = "/bin/x"; a1.action = Action::Allow; tie.add(a1);
    AppRule a2; a2.exe = "/bin/x"; a2.action = Action::Deny; tie.add(a2);
    MatchInput t; t.exe = "/bin/x";
    CHECK(tie.match(t) && tie.match(t)->action == Action::Deny);

    CHECK(host_matches("*.example.com", "example.com"));
    CHECK(host_matches("*.example.com", "a.b.example.com"));
    CHECK(!host_matches("*.example.com", "badexample.com"));

    // JSON round trip + validation.
    AppRule back;
    std::string err;
    CHECK(AppRule::from_json(deny_tracker.to_json(), back, err) && back.host == "*.tracker.com");
    Json bad = Json::object();
    bad["action"] = "maybe";
    CHECK(!AppRule::from_json(bad, back, err));

    // Save/load keeps only "forever" rules.
    AppRule session; session.exe = "/bin/y"; session.duration = Duration::Session; rs.add(session);
    const std::string path = (std::filesystem::temp_directory_path() / "vartad_test_rules.json").string();
    CHECK(rs.save(path, err));
    RuleSet loaded;
    CHECK(loaded.load(path, err));
    CHECK(loaded.all().size() == 3);
    std::filesystem::remove(path);
}

static void test_procinfo() {
    // Open a real listening TCP socket and check that we find ourselves as its owner.
    const auto s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    bind(s, reinterpret_cast<sockaddr*>(&a), sizeof a);
    listen(s, 1);
    socklen_t len = sizeof a;
    getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
    const uint16_t port = ntohs(a.sin_port);

    ProcResolver pr;
    const ProcInfo p = pr.find(kProtoTcp, ip("127.0.0.1"), port, ip("127.0.0.1"), 55555, true);
    CHECK(p.pid == self_pid());
    CHECK(!p.exe.empty() && p.exe.find("varta_daemon_tests") != std::string::npos);
    std::cout << "  procinfo: pid " << p.pid << " exe " << p.exe << " user " << p.user << "\n";
    CHECK(!p.user.empty());
    close_sock(s);

    // UDP, unconnected socket used for an "outgoing" packet.
    const auto u = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in b{};
    b.sin_family = AF_INET;
    b.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(u, reinterpret_cast<sockaddr*>(&b), sizeof b);
    len = sizeof b;
    getsockname(u, reinterpret_cast<sockaddr*>(&b), &len);
    const ProcInfo q = pr.find(kProtoUdp, ip("127.0.0.1"), ntohs(b.sin_port), ip("1.1.1.1"), 53, false);
    CHECK(q.pid == self_pid());
    close_sock(u);
}

// --------------------------------------------------------------- engine with a fake host
struct FakeHost : EngineHost {
    std::vector<std::pair<uint64_t, bool>> verdicts;  // ticket, allow
    std::vector<std::string> lines;                   // everything sent to the GUI
    int reinstalls = 0;
    void verdict(const std::vector<uint64_t>& t, bool allow, const Connection&) override {
        for (uint64_t x : t) verdicts.emplace_back(x, allow);
    }
    void send(uint64_t, const std::string& line) override { lines.push_back(line); }
    void reinstall_capture() override { ++reinstalls; }
    Json last(const std::string& type) const {
        for (auto it = lines.rbegin(); it != lines.rend(); ++it) {
            Json j;
            std::string err;
            if (Json::parse(*it, j, err) && j.str("type") == type) return j;
        }
        return Json();
    }
};

static Connection conn(const char* exe, const char* remote, uint16_t port) {
    Connection c;
    c.proto = kProtoTcp;
    c.local = ip("192.168.1.10");
    c.local_port = 50000;
    c.remote = ip(remote);
    c.remote_port = port;
    c.proc.pid = 1234;
    c.proc.exe = exe;
    c.proc.name = "app";
    return c;
}

static void test_engine() {
    const auto dir = std::filesystem::temp_directory_path() / "vartad_engine_test";
    std::filesystem::remove_all(dir);
    Paths paths;
    paths.config_dir = paths.data_dir = paths.run_dir = dir.string();
    FakeHost host;
    Engine e(paths, host);
    std::string log;
    e.load(log);
    const size_t defaults = e.rules.all().size();
    CHECK(defaults > 0);

    // No GUI: falls back to no_gui_action (allow).
    e.on_connection(conn("/usr/bin/app", "93.184.216.34", 443), 1);
    CHECK(host.verdicts.size() == 1 && host.verdicts[0].second);

    // DNS answer teaches the host name, GUI connected -> "ask".
    const uint8_t dns[] = {0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                           3, 'c', 'o', 'm', 0, 0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4,
                           93, 184, 216, 34};
    e.on_dns(dns, sizeof dns);
    e.client_connected(7);
    CHECK(host.last("hello").str("type") == "hello");
    e.on_connection(conn("/usr/bin/app", "93.184.216.34", 443), 2);
    CHECK(host.verdicts.size() == 1);  // held
    Json ask = host.last("ask");
    CHECK(ask.str("host") == "example.com" && ask.str("exe") == "/usr/bin/app");
    // A retransmit of the same connection joins the same prompt.
    e.on_connection(conn("/usr/bin/app", "93.184.216.34", 443), 3);
    CHECK(e.pending_count() == 1);

    // User: allow app -> this host, forever. Both held tickets are released, a rule is saved.
    Json v = Json::object();
    v["type"] = "verdict";
    v["id"] = ask.integer("id");
    v["action"] = "allow";
    v["scope"] = "exe_host";
    v["duration"] = "forever";
    e.client_message(7, v.dump());
    CHECK(host.verdicts.size() == 3 && host.verdicts[1].second && host.verdicts[2].second);
    CHECK(e.rules.all().size() == defaults + 1 && e.rules.all().back().host == "example.com");
    CHECK(host.last("ask_done").integer("id") == ask.integer("id"));

    // Next time the rule answers without asking.
    e.on_connection(conn("/usr/bin/app", "93.184.216.34", 443), 4);
    CHECK(host.verdicts.size() == 4 && host.verdicts[3].second && e.pending_count() == 0);

    // Multicast never prompts.
    e.on_connection(conn("/usr/bin/other", "239.255.255.250", 1900), 5);
    CHECK(host.verdicts.size() == 5 && host.verdicts[4].second);

    // Unknown destination, answered with "deny once"; then a timeout case.
    e.on_connection(conn("/usr/bin/other", "8.8.8.8", 853), 6);
    ask = host.last("ask");
    v["id"] = ask.integer("id");
    v["action"] = "deny";
    v["scope"] = "once";
    e.client_message(7, v.dump());
    CHECK(host.verdicts.size() == 6 && !host.verdicts[5].second);

    Json set = Json::object();
    set["type"] = "set_setting";
    set["key"] = "prompt_timeout";
    set["value"] = "5";
    e.client_message(7, set.dump());
    CHECK(e.settings.prompt_timeout == 5);
    Connection old = conn("/usr/bin/other", "1.1.1.1", 443);
    old.time_ms = now_ms() - 10000;  // already past the 5 s deadline
    e.on_connection(old, 8);
    e.tick();
    CHECK(host.verdicts.size() == 7 && !host.verdicts[6].second);  // timeout_action = deny

    set["key"] = "auto_allow_dns";
    set["value"] = "off";
    e.client_message(7, set.dump());
    CHECK(host.reinstalls == 1);

    // Rules survive a restart.
    Engine e2(paths, host);
    std::string log2;
    e2.load(log2);
    CHECK(e2.rules.all().size() == defaults + 1);
    CHECK(e2.settings.prompt_timeout == 5);

    // GUI disconnect settles waiting prompts with no_gui_action.
    e.on_connection(conn("/usr/bin/third", "9.9.9.9", 443), 9);
    CHECK(e.pending_count() == 1);
    e.client_disconnected(7);
    CHECK(e.pending_count() == 0 && host.verdicts.back().first == 9 && host.verdicts.back().second);

    // Garbage from the GUI is answered with an error, not a crash.
    e.client_connected(8);
    e.client_message(8, "{not json");
    CHECK(host.last("error").str("message").find("bad json") == 0);
    std::filesystem::remove_all(dir);
}

#ifdef _WIN32
#include "windows_daemon.hpp"
static void test_windows_filter() {
    Settings s;
    const std::string f = WindowsDaemon::capture_filter(s);
    CHECK(f.find("tcp.Syn and not tcp.Ack") != std::string::npos);
    CHECK(f.find("udp.DstPort != 53") != std::string::npos);
    CHECK(f.find("inbound and tcp") != std::string::npos);
    s.ask_inbound = false;
    s.auto_allow_dns = false;
    const std::string g = WindowsDaemon::capture_filter(s);
    CHECK(g.find("inbound and tcp") == std::string::npos && g.find("DstPort != 53") == std::string::npos);
}
#endif

static void test_settings_and_nft() {
    Settings s;
    std::string err;
    CHECK(s.set("mode", "deny", err) && s.mode == "deny");
    CHECK(!s.set("mode", "maybe", err));
    CHECK(s.set("prompt_timeout", "45", err) && s.prompt_timeout == 45);
    CHECK(!s.set("prompt_timeout", "2", err));
    CHECK(s.set("ask_inbound", "off", err) && !s.ask_inbound);
    CHECK(!s.set("nope", "1", err));

#ifndef _WIN32
    const std::string nft = LinuxDaemon::nft_script(s);
    CHECK(nft.find("table inet varta_ask {") != std::string::npos);
    CHECK(nft.find("queue num 0 bypass") != std::string::npos);
    CHECK(nft.find("pkttype unicast") == std::string::npos);  // inbound asking is off
    s.ask_inbound = true;
    CHECK(LinuxDaemon::nft_script(s).find("pkttype unicast") != std::string::npos);
#endif
}

int main() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    test_json();
    test_addresses();
    test_packets_and_dns();
    test_ipdb();
    test_rules();
    test_procinfo();
    test_settings_and_nft();
    test_engine();
#ifdef _WIN32
    test_windows_filter();
#endif
    std::cout << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed ? 1 : 0;
}
