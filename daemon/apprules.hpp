// vartad - per-application connection rules.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "json.hpp"
#include "packet.hpp"

namespace vartad {

enum class Action { Allow, Deny };
enum class Duration { Session, Forever };  // "once" answers never become rules

struct Connection;  // defined in daemon.hpp

struct AppRule {
    uint64_t id = 0;
    bool enabled = true;
    Action action = Action::Allow;
    Duration duration = Duration::Forever;
    std::string exe = "*";   // program path or "*"
    std::string direction;   // "", "out", "in"
    std::string host;        // "", "example.com", "*.example.com"
    std::string ip;          // "", "1.2.3.4", "10.0.0.0/8"
    uint16_t port = 0;       // 0 = any
    std::string proto;       // "", "tcp", "udp"
    std::string note;        // free text ("default", "created from prompt"...)
    int64_t created = 0;     // unix time
    uint64_t hits = 0;

    Json to_json() const;
    static bool from_json(const Json& j, AppRule& out, std::string& err);
    int specificity() const;
};

struct MatchInput {
    std::string exe;
    bool inbound = false;
    std::string host;
    IpAddr remote;
    uint16_t remote_port = 0;  // for inbound: the local (listening) port
    uint8_t proto = 0;
};

bool host_matches(const std::string& pattern, const std::string& host);
bool rule_matches(const AppRule& r, const MatchInput& in);

class RuleSet {
public:
    // Best matching enabled rule, or nullptr. Most specific wins; on a tie Deny wins.
    AppRule* match(const MatchInput& in);

    AppRule& add(AppRule r);  // assigns id/created
    bool remove(uint64_t id);
    AppRule* find(uint64_t id);
    const std::vector<AppRule>& all() const { return rules_; }

    Json to_json() const;  // all rules (for the GUI)
    bool load(const std::string& path, std::string& err);
    bool save(const std::string& path, std::string& err) const;  // Forever rules only
    void add_defaults();

private:
    std::vector<AppRule> rules_;
    uint64_t next_id_ = 1;
};

const char* action_str(Action a);
const char* duration_str(Duration d);

}  // namespace vartad
