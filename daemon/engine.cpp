#include "engine.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include "blocklists.hpp"  // Varta tracker categories

namespace fs = std::filesystem;

namespace vartad {

static constexpr size_t kMaxPending = 256;

int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

#ifdef _WIN32
Paths::Paths() {
    const char* pd = std::getenv("ProgramData");
    const std::string base = std::string(pd ? pd : "C:\\ProgramData") + "\\Varta";
    config_dir = base;
    data_dir = base;
    run_dir = base;
}
#endif

// ---------------------------------------------------------------------------- Settings

Json Settings::to_json() const {
    Json j = Json::object();
    j["mode"] = mode;
    j["prompt_timeout"] = prompt_timeout;
    j["timeout_action"] = timeout_action;
    j["no_gui_action"] = no_gui_action;
    j["ask_inbound"] = ask_inbound;
    j["auto_allow_dns"] = auto_allow_dns;
    j["queue"] = queue;
    j["history"] = history;
    return j;
}

static bool parse_onoff(const std::string& v, bool& out) {
    if (v == "on" || v == "true" || v == "1" || v == "yes") { out = true; return true; }
    if (v == "off" || v == "false" || v == "0" || v == "no") { out = false; return true; }
    return false;
}

static bool parse_int(const std::string& v, int lo, int hi, int& out) {
    try {
        size_t n = 0;
        const int x = std::stoi(v, &n);
        if (n != v.size() || x < lo || x > hi) return false;
        out = x;
        return true;
    } catch (...) {
        return false;
    }
}

bool Settings::set(const std::string& key, const std::string& value, std::string& err) {
    const auto action = [&](std::string& dst) {
        if (value != "allow" && value != "deny") {
            err = key + " must be allow or deny";
            return false;
        }
        dst = value;
        return true;
    };
    if (key == "mode") {
        if (value != "ask" && value != "allow" && value != "deny") {
            err = "mode must be ask, allow or deny";
            return false;
        }
        mode = value;
        return true;
    }
    if (key == "timeout_action") return action(timeout_action);
    if (key == "no_gui_action") return action(no_gui_action);
    if (key == "prompt_timeout") {
        if (!parse_int(value, 5, 600, prompt_timeout)) { err = "prompt_timeout: 5..600"; return false; }
        return true;
    }
    if (key == "history") {
        if (!parse_int(value, 100, 100000, history)) { err = "history: 100..100000"; return false; }
        return true;
    }
    if (key == "queue") {
        if (!parse_int(value, 0, 65535, queue)) { err = "queue: 0..65535"; return false; }
        return true;
    }
    if (key == "ask_inbound" || key == "auto_allow_dns") {
        bool b;
        if (!parse_onoff(value, b)) { err = key + " must be on or off"; return false; }
        (key == "ask_inbound" ? ask_inbound : auto_allow_dns) = b;
        return true;
    }
    err = "unknown setting '" + key + "'";
    return false;
}

bool Settings::load(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;
    std::string line;
    int n = 0;
    while (std::getline(in, line)) {
        ++n;
        const auto hash = line.find('#');
        if (hash != std::string::npos) line.resize(hash);
        const auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        auto trim = [](std::string s) {
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
            size_t b = 0;
            while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
            return s.substr(b);
        };
        std::string err;
        if (!set(trim(line.substr(0, eq)), trim(line.substr(eq + 1)), err))
            std::cerr << "vartad: " << path << ":" << n << ": " << err << std::endl;
    }
    return true;
}

bool Settings::save(const std::string& path, std::string& err) const {
    std::error_code ec;
    fs::create_directories(fs::path(path).parent_path(), ec);
    std::ofstream out(path, std::ios::trunc);
    if (!out) {
        err = "cannot write " + path;
        return false;
    }
    out << "# vartad settings (also editable from the Varta GUI)\n"
        << "# ask = prompt for unknown connections, allow = allow + log, deny = block unknown\n"
        << "mode = " << mode << "\n"
        << "# seconds to wait for an answer, then apply timeout_action\n"
        << "prompt_timeout = " << prompt_timeout << "\n"
        << "timeout_action = " << timeout_action << "\n"
        << "# used while no GUI is connected (e.g. before you log in)\n"
        << "no_gui_action = " << no_gui_action << "\n"
        << "ask_inbound = " << (ask_inbound ? "on" : "off") << "\n"
        << "auto_allow_dns = " << (auto_allow_dns ? "on" : "off") << "\n"
        << "queue = " << queue << "\n"
        << "history = " << history << "\n";
    return true;
}

// -------------------------------------------------------------------------- Connection

const char* proto_name(uint8_t p) {
    return p == kProtoTcp ? "tcp" : p == kProtoUdp ? "udp" : "?";
}

Json Connection::to_json() const {
    Json j = Json::object();
    j["id"] = id;
    j["time"] = time_ms;
    j["dir"] = inbound ? "in" : "out";
    j["proto"] = proto_name(proto);
    j["local"] = local.str();
    j["local_port"] = static_cast<int>(local_port);
    j["remote"] = remote.unmapped().str();
    j["remote_port"] = static_cast<int>(remote_port);
    j["pid"] = proc.pid;
    j["exe"] = proc.exe;
    j["name"] = proc.name;
    j["cmdline"] = proc.cmdline;
    j["user"] = proc.user;
    j["uid"] = static_cast<int64_t>(proc.uid == UINT32_MAX ? -1 : static_cast<int64_t>(proc.uid));
    j["host"] = host;
    j["asn"] = static_cast<int64_t>(info.asn);
    j["org"] = info.org;
    j["country"] = info.country;
    j["special"] = special;
    j["category"] = category;
    j["category_title"] = category_title;
    if (!verdict.empty()) j["verdict"] = verdict;
    if (!reason.empty()) j["reason"] = reason;
    if (rule_id) j["rule_id"] = rule_id;
    return j;
}

MatchInput Connection::match_input() const {
    MatchInput m;
    m.exe = proc.exe;
    m.inbound = inbound;
    m.host = host;
    m.remote = remote.unmapped();
    // For inbound connections the interesting port is our own (listening) port.
    m.remote_port = inbound ? local_port : remote_port;
    m.proto = proto;
    return m;
}

std::string Connection::pending_key() const {
    std::string who = proc.exe.empty() ? "pid:" + std::to_string(proc.pid) : proc.exe;
    return who + "|" + (inbound ? "in" : "out") + "|" + proto_name(proto) + "|" +
           remote.unmapped().str() + "|" + std::to_string(inbound ? local_port : remote_port);
}


// ------------------------------------------------------------------------------ Engine

Engine::Engine(Paths p, EngineHost& host) : paths_(std::move(p)), host_(host) {
    // Index Varta's built-in tracker categories by domain for O(1) lookups.
    for (const auto& cat : varta::builtin_categories())
        for (const auto& d : cat.domains) trackers_[d] = {cat.id, cat.title};
}

void Engine::load(std::string& log) {
    std::error_code ec;
    fs::create_directories(paths_.config_dir, ec);
    settings.load(paths_.settings());
    if (!fs::exists(paths_.settings(), ec)) {
        std::string err;
        settings.save(paths_.settings(), err);
    }
    const size_t n = reload_ipdb();
    log += n ? "IP database: " + std::to_string(n) + " ranges\n"
             : "IP database missing - run `vartad --update-db` for owner/country info\n";
    std::string err;
    if (fs::exists(paths_.rules(), ec)) {
        if (!rules.load(paths_.rules(), err)) log += "cannot load rules: " + err + "\n";
    } else {
        rules.add_defaults();
        save_rules();
    }
    log += std::to_string(rules.all().size()) + " rules loaded from " + paths_.rules() + "\n";
}

size_t Engine::reload_ipdb() { return ipdb.load(paths_.ipdb()); }

void Engine::reload_settings() { settings.load(paths_.settings()); }

void Engine::save_rules() {
    std::string err;
    if (!rules.save(paths_.rules(), err)) std::cerr << "vartad: cannot save rules: " << err << std::endl;
}

// ----------------------------------------------------------------------------- packets

void Engine::on_dns(const uint8_t* data, size_t len) {
    const int64_t now = now_ms();
    for (const auto& a : parse_dns_response(data, len)) {
        const int64_t ttl = std::max<int64_t>(a.ttl, 300);  // keep at least 5 minutes
        dns_[a.ip.str()] = {a.name, now + ttl * 1000};
    }
    if (dns_.size() > 50000) {
        for (auto it = dns_.begin(); it != dns_.end();)
            it = it->second.second < now ? dns_.erase(it) : std::next(it);
    }
}

void Engine::lookup_tracker(Connection& c) const {
    // a.b.tracker.com -> check a.b.tracker.com, b.tracker.com, tracker.com
    std::string h = c.host;
    while (!h.empty()) {
        const auto it = trackers_.find(h);
        if (it != trackers_.end()) {
            c.category = it->second.first;
            c.category_title = it->second.second;
            return;
        }
        const auto dot = h.find('.');
        if (dot == std::string::npos) break;
        h = h.substr(dot + 1);
    }
}

void Engine::enrich(Connection& c) {
    const IpAddr r = c.remote.unmapped();
    const auto it = dns_.find(r.str());
    if (it != dns_.end()) c.host = it->second.first;
    c.special = special_range(r);
    if (c.special.empty()) c.info = ipdb.lookup(r);
    lookup_tracker(c);
}

void Engine::on_connection(Connection c, uint64_t ticket) {
    if (!c.id) c.id = next_conn_id_++;
    if (!c.time_ms) c.time_ms = now_ms();
    enrich(c);
    const std::vector<uint64_t> tickets{ticket};

    // Multicast / broadcast (mDNS, SSDP, NetBIOS...) is local chatter, never worth a prompt.
    if (c.special == "Multicast" || c.special == "Broadcast") {
        host_.verdict(tickets, true, c);
        return;
    }
    if (AppRule* r = rules.match(c.match_input())) {
        ++r->hits;
        decide(c, tickets, r->action == Action::Allow, "rule", r->id);
        return;
    }
    if (settings.mode == "allow") {
        decide(c, tickets, true, "mode: allow all");
        return;
    }
    if (settings.mode == "deny") {
        decide(c, tickets, false, "mode: block unknown");
        return;
    }
    if (clients_.empty()) {
        decide(c, tickets, settings.no_gui_action == "allow", "no GUI connected");
        return;
    }

    // Same program, same destination already waiting (e.g. TCP SYN retransmit): join it.
    const std::string key = c.pending_key();
    for (auto& [pid, pend] : pending_) {
        if (pend.key == key) {
            pend.tickets.push_back(ticket);
            return;
        }
    }
    if (pending_.size() >= kMaxPending) {
        decide(c, tickets, settings.timeout_action == "allow", "too many pending prompts");
        return;
    }
    Pending pend;
    pend.conn = c;
    pend.tickets = tickets;
    pend.deadline_ms = c.time_ms + settings.prompt_timeout * int64_t(1000);
    pend.key = key;
    Json ask = c.to_json();
    ask["type"] = "ask";
    ask["deadline"] = pend.deadline_ms;
    ask["timeout"] = settings.prompt_timeout;
    ask["timeout_action"] = settings.timeout_action;
    pending_.emplace(c.id, std::move(pend));
    broadcast(ask);
}

void Engine::decide(Connection& c, const std::vector<uint64_t>& tickets, bool allow,
                    const std::string& reason, uint64_t rule_id) {
    c.verdict = allow ? "allow" : "deny";
    c.reason = reason;
    c.rule_id = rule_id;
    host_.verdict(tickets, allow, c);
    (allow ? stat_allowed_ : stat_denied_)++;
    Json ev = c.to_json();
    history_.push_back(ev);
    while (history_.size() > static_cast<size_t>(settings.history)) history_.pop_front();
    ev["type"] = "event";
    broadcast(ev);
}

void Engine::resolve_pending(uint64_t id, bool allow, const std::string& reason, uint64_t rule_id) {
    const auto it = pending_.find(id);
    if (it == pending_.end()) return;
    Pending p = std::move(it->second);
    pending_.erase(it);
    decide(p.conn, p.tickets, allow, reason, rule_id);
    Json done = Json::object();
    done["type"] = "ask_done";
    done["id"] = id;
    broadcast(done);
}

void Engine::resolve_all(bool allow, const std::string& reason) {
    std::vector<uint64_t> ids;
    for (const auto& [id, p] : pending_) ids.push_back(id);
    for (uint64_t id : ids) resolve_pending(id, allow, reason);
}

void Engine::recheck_pending() {
    std::vector<std::pair<uint64_t, AppRule*>> hits;
    for (auto& [id, p] : pending_)
        if (AppRule* r = rules.match(p.conn.match_input())) hits.emplace_back(id, r);
    for (auto& [id, r] : hits) {
        ++r->hits;
        resolve_pending(id, r->action == Action::Allow, "rule", r->id);
    }
}

void Engine::tick() {
    const int64_t now = now_ms();
    std::vector<uint64_t> expired;
    for (const auto& [id, p] : pending_)
        if (p.deadline_ms <= now) expired.push_back(id);
    for (uint64_t id : expired) resolve_pending(id, settings.timeout_action == "allow", "timeout");
}

void Engine::shutdown() { resolve_all(true, "daemon stopped"); }

// ------------------------------------------------------------------------ GUI protocol

void Engine::send(uint64_t client, const Json& msg) { host_.send(client, msg.dump() + "\n"); }

void Engine::broadcast(const Json& msg) {
    const std::string line = msg.dump() + "\n";
    for (uint64_t c : clients_) host_.send(c, line);
}

void Engine::broadcast_rules() {
    Json m = Json::object();
    m["type"] = "rules";
    m["rules"] = rules.to_json();
    broadcast(m);
}

void Engine::send_state(uint64_t client) {
    Json hello = Json::object();
    hello["type"] = "hello";
    hello["version"] = "0.3.0";
    hello["platform"] = platform;
    hello["settings"] = settings.to_json();
    hello["ipdb_ranges"] = static_cast<uint64_t>(ipdb.ranges());
    hello["ipdb_attribution"] = IpDb::attribution();
    hello["allowed"] = stat_allowed_;
    hello["denied"] = stat_denied_;
    send(client, hello);

    Json hist = Json::object();
    hist["type"] = "history";
    Json arr = Json::array();
    for (const auto& e : history_) arr.push_back(e);
    hist["events"] = arr;
    send(client, hist);

    Json r = Json::object();
    r["type"] = "rules";
    r["rules"] = rules.to_json();
    send(client, r);

    for (const auto& [id, p] : pending_) {
        Json ask = p.conn.to_json();
        ask["type"] = "ask";
        ask["deadline"] = p.deadline_ms;
        ask["timeout"] = settings.prompt_timeout;
        ask["timeout_action"] = settings.timeout_action;
        send(client, ask);
    }
}

void Engine::client_connected(uint64_t client) {
    clients_.insert(client);
    send_state(client);
}

void Engine::client_disconnected(uint64_t client) {
    clients_.erase(client);
    // Nobody left to ask: settle everything that is waiting.
    if (clients_.empty() && !pending_.empty()) resolve_all(settings.no_gui_action == "allow", "GUI disconnected");
}

void Engine::on_verdict_message(const Json& msg) {
    const uint64_t id = static_cast<uint64_t>(msg.integer("id"));
    const auto it = pending_.find(id);
    if (it == pending_.end()) return;  // already timed out or answered by another GUI
    const bool allow = msg.str("action") == "allow";
    const std::string scope = msg.str("scope", "once");
    if (scope == "once") {
        resolve_pending(id, allow, "user (once)");
        return;
    }

    const Connection& c = it->second.conn;
    AppRule r;
    r.action = allow ? Action::Allow : Action::Deny;
    r.duration = msg.str("duration", "forever") == "session" ? Duration::Session : Duration::Forever;
    r.exe = c.proc.exe.empty() ? "*" : c.proc.exe;
    r.direction = c.inbound ? "in" : "out";
    r.note = "created from prompt";
    const std::string ip = c.remote.unmapped().str();
    const uint16_t port = c.inbound ? c.local_port : c.remote_port;
    const std::string proto = proto_name(c.proto);
    if (scope == "exe") {
        // Unknown program + "any destination" would be a global rule; narrow it to the IP.
        if (r.exe == "*") r.ip = ip;
    } else if (scope == "exe_host") {
        if (!c.host.empty()) r.host = c.host;
        else r.ip = ip;
    } else if (scope == "exe_domain") {
        if (!c.host.empty()) {
            // *.example.com from www.example.com (keeps the last two labels)
            const std::string& h = c.host;
            const auto last = h.rfind('.');
            const auto prev = (last == std::string::npos || last == 0) ? std::string::npos : h.rfind('.', last - 1);
            r.host = prev == std::string::npos ? h : "*." + h.substr(prev + 1);
        } else {
            r.ip = ip;
        }
    } else if (scope == "exe_ip") {
        r.ip = ip;
    } else if (scope == "exe_port") {
        r.port = port;
        r.proto = proto;
    } else if (scope == "exe_host_port") {
        if (!c.host.empty()) r.host = c.host;
        else r.ip = ip;
        r.port = port;
        r.proto = proto;
    } else {
        resolve_pending(id, allow, "user (once)");
        return;
    }
    const uint64_t rid = rules.add(r).id;
    if (r.duration == Duration::Forever) save_rules();
    resolve_pending(id, allow, "user (new rule)", rid);
    recheck_pending();  // the new rule may answer other waiting prompts too
    broadcast_rules();
}

std::string Engine::apply_setting(const std::string& key, const std::string& value) {
    if (key == "queue") return "queue can only be changed in vartad.conf (restart needed)";
    Settings next = settings;
    std::string err;
    if (!next.set(key, value, err)) return err;
    const bool capture_change = next.ask_inbound != settings.ask_inbound ||
                                next.auto_allow_dns != settings.auto_allow_dns;
    settings = next;
    if (!settings.save(paths_.settings(), err)) std::cerr << "vartad: " << err << std::endl;
    if (capture_change) host_.reinstall_capture();
    // Switching away from "ask" settles everything that is waiting.
    if (settings.mode != "ask") resolve_all(settings.mode == "allow", "mode changed");
    return {};
}

void Engine::client_message(uint64_t client, const std::string& line) {
    Json msg;
    std::string perr;
    auto reply_error = [&](const std::string& m) {
        Json e = Json::object();
        e["type"] = "error";
        e["message"] = m;
        send(client, e);
    };
    if (!Json::parse(line, msg, perr)) return reply_error("bad json: " + perr);
    const std::string type = msg.str("type");

    if (type == "verdict") {
        on_verdict_message(msg);
    } else if (type == "get_state") {
        send_state(client);
    } else if (type == "rule_add") {
        AppRule r;
        std::string err;
        if (!AppRule::from_json(msg.get("rule"), r, err)) return reply_error(err);
        if (r.note.empty()) r.note = "added in GUI";
        rules.add(r);
        save_rules();
        recheck_pending();
        broadcast_rules();
    } else if (type == "rule_update") {
        AppRule* r = rules.find(static_cast<uint64_t>(msg.integer("id")));
        if (!r) return reply_error("no such rule");
        Json merged = r->to_json();
        for (const auto& [k, v] : msg.get("rule").fields()) merged[k] = v;
        AppRule updated;
        std::string err;
        if (!AppRule::from_json(merged, updated, err)) return reply_error(err);
        updated.id = r->id;
        updated.created = r->created;
        updated.hits = r->hits;
        *r = updated;
        save_rules();
        recheck_pending();
        broadcast_rules();
    } else if (type == "rule_delete") {
        if (!rules.remove(static_cast<uint64_t>(msg.integer("id")))) return reply_error("no such rule");
        save_rules();
        broadcast_rules();
    } else if (type == "set_setting") {
        const std::string err = apply_setting(msg.str("key"), msg.str("value"));
        if (!err.empty()) return reply_error(err);
        Json m = Json::object();
        m["type"] = "settings";
        m["settings"] = settings.to_json();
        broadcast(m);
    } else if (type == "clear_history") {
        history_.clear();
        Json m = Json::object();
        m["type"] = "history";
        m["events"] = Json::array();
        broadcast(m);
    } else {
        reply_error("unknown message type '" + type + "'");
    }
}

}  // namespace vartad
