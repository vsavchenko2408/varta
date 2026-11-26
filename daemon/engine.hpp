// vartad - the platform-neutral decision engine.
//
// The OS-specific front end (Linux: NFQUEUE, Windows: WinDivert) captures the first packet
// of each new connection, works out which program owns it and calls Engine::on_connection.
// The engine enriches it (host name from DNS, IP owner/country, tracker category), applies
// rules or asks the GUI, and finally calls EngineHost::verdict. It also speaks the
// JSON-lines protocol with GUI clients; the host only moves bytes.
//
// The engine is not thread-safe: the host must serialise all calls (Linux uses a single
// thread, Windows a mutex).
#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "apprules.hpp"
#include "ipdb.hpp"
#include "json.hpp"
#include "packet.hpp"

namespace vartad {

struct ProcInfo {
    int pid = -1;
    uint32_t uid = UINT32_MAX;  // Linux only
    std::string exe;            // /usr/bin/curl, C:\Program Files\...\app.exe
    std::string name;           // curl, app.exe
    std::string cmdline;
    std::string user;
    bool known() const { return pid > 0 && !exe.empty(); }
};

struct Settings {
    std::string mode = "ask";            // ask | allow (log only) | deny (block unknown)
    int prompt_timeout = 30;             // seconds
    std::string timeout_action = "deny"; // when the user does not answer in time
    std::string no_gui_action = "allow"; // when no GUI is connected (boot, no login yet)
    bool ask_inbound = true;             // also ask for new incoming connections
    bool auto_allow_dns = true;          // let DNS (port 53) through without asking
    int queue = 0;                       // Linux NFQUEUE number
    int history = 3000;                  // connections kept for the GUI log

    Json to_json() const;
    bool set(const std::string& key, const std::string& value, std::string& err);
    bool load(const std::string& path);
    bool save(const std::string& path, std::string& err) const;
};

struct Paths {
#ifdef _WIN32
    std::string config_dir;  // %ProgramData%\Varta
    std::string data_dir;    // %ProgramData%\Varta
    std::string run_dir;     // unused (named pipe \\.\pipe\vartad)
    Paths();
#else
    std::string config_dir = "/etc/varta";
    std::string data_dir = "/var/lib/varta";
    std::string run_dir = "/run/varta";
#endif
    std::string settings() const { return config_dir + "/vartad.conf"; }
    std::string rules() const { return config_dir + "/app-rules.json"; }
    std::string ipdb() const { return data_dir + "/ipdb"; }
    std::string socket() const { return run_dir + "/vartad.sock"; }
};

struct Connection {
    uint64_t id = 0;
    int64_t time_ms = 0;
    bool inbound = false;
    uint8_t proto = 0;
    IpAddr local, remote;
    uint16_t local_port = 0, remote_port = 0;
    ProcInfo proc;
    std::string host;      // from sniffed DNS answers
    IpInfo info;           // owner organisation / country
    std::string special;   // "Local network", "Loopback"...
    std::string category;  // Varta category id when the host is a known tracker
    std::string category_title;
    std::string verdict;   // allow / deny
    std::string reason;    // rule, user, timeout, mode, no-gui...
    uint64_t rule_id = 0;

    Json to_json() const;
    MatchInput match_input() const;
    std::string pending_key() const;
};

class EngineHost {
public:
    virtual ~EngineHost() = default;
    // Release (allow) or drop/reject (deny) the held packets identified by `tickets`.
    virtual void verdict(const std::vector<uint64_t>& tickets, bool allow, const Connection& c) = 0;
    // Queue one protocol line (already terminated with '\n') for a GUI client.
    virtual void send(uint64_t client, const std::string& line) = 0;
    // Settings that change what is captured (ask_inbound, auto_allow_dns) were modified.
    virtual void reinstall_capture() = 0;
};

class Engine {
public:
    Engine(Paths paths, EngineHost& host);

    Settings settings;
    RuleSet rules;
    IpDb ipdb;

    // Loads settings (writing defaults if missing), the IP database and the rules.
    void load(std::string& log);
    size_t reload_ipdb();
    void reload_settings();

    // A new connection: `c.proc` and addresses filled in by the host; `ticket` identifies
    // the held packet. The engine always ends with exactly one host.verdict for the ticket.
    void on_connection(Connection c, uint64_t ticket);
    void on_dns(const uint8_t* dns, size_t len);

    void client_connected(uint64_t client);
    void client_message(uint64_t client, const std::string& line);
    void client_disconnected(uint64_t client);
    bool has_clients() const { return !clients_.empty(); }

    void tick();      // call a few times per second: prompt timeouts
    void shutdown();  // let everything that waits through
    uint64_t next_connection_id() { return next_conn_id_++; }
    size_t pending_count() const { return pending_.size(); }

    // Filled by the host for logging; also exposed in "hello".
    std::string platform = "linux";

private:
    struct Pending {
        Connection conn;
        std::vector<uint64_t> tickets;
        int64_t deadline_ms = 0;
        std::string key;
    };

    void enrich(Connection& c);
    void lookup_tracker(Connection& c) const;
    void decide(Connection& c, const std::vector<uint64_t>& tickets, bool allow,
                const std::string& reason, uint64_t rule_id = 0);
    void resolve_pending(uint64_t id, bool allow, const std::string& reason, uint64_t rule_id = 0);
    void recheck_pending();
    void resolve_all(bool allow, const std::string& reason);

    void send(uint64_t client, const Json& msg);
    void broadcast(const Json& msg);
    void send_state(uint64_t client);
    void broadcast_rules();
    void on_verdict_message(const Json& msg);
    std::string apply_setting(const std::string& key, const std::string& value);
    void save_rules();

    Paths paths_;
    EngineHost& host_;
    std::unordered_map<std::string, std::pair<std::string, int64_t>> dns_;  // ip -> host, expiry
    std::unordered_map<std::string, std::pair<std::string, std::string>> trackers_;
    std::map<uint64_t, Pending> pending_;
    std::deque<Json> history_;
    std::set<uint64_t> clients_;
    uint64_t next_conn_id_ = 1;
    uint64_t stat_allowed_ = 0, stat_denied_ = 0;
};

int64_t now_ms();
const char* proto_name(uint8_t p);

}  // namespace vartad
