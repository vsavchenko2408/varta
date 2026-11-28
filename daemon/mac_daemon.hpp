// vartad - macOS front end (no Apple developer account needed).
//
// macOS has no NFQUEUE/WinDivert equivalent outside Apple's Network Extension framework, which
// only runs when signed with a paid Apple developer certificate. Without it vartad works as a
// "see and block" firewall:
//   * libpcap (BPF) watches the first packet of every new connection and DNS answers;
//   * libproc finds the program that owns the socket;
//   * the engine applies rules / asks the GUI exactly as on Linux and Windows;
//   * "deny" puts the remote address into a pf table (anchor com.apple/varta_ask), which
//     rejects further traffic to it and kills the connection that is already open;
//   * block_inbound: pf keeps state for outgoing UDP and drops UDP from the internet that is
//     not a reply (local network, DHCP and mDNS still pass).
// Limits (shown in the GUI and README): the first packets of a connection get out before the
// decision, and a blocked address is blocked for every program, not only the one that asked.
// A Network Extension backend can implement EngineHost later without touching the engine.
#pragma once

#include <map>
#include <set>
#include <string>
#include <vector>

#include "engine.hpp"
#include "procinfo_mac.hpp"

struct pcap;

namespace vartad {

class MacDaemon : public EngineHost {
public:
    explicit MacDaemon(Paths p, bool verbose = false);
    ~MacDaemon() override;
    int run();  // blocks until SIGINT/SIGTERM

    static std::string pf_rules(const Settings& s);
    // BPF program: new TCP connections (SYN without ACK, IPv4 and IPv6) and all UDP.
    static const char* capture_filter() {
        return "(tcp[tcpflags] & (tcp-syn|tcp-ack)) == tcp-syn or "
               "(ip6 and tcp and (ip6[53] & 0x12) == 0x02) or udp";
    }

    // EngineHost
    void verdict(const std::vector<uint64_t>& tickets, bool allow, const Connection& c) override;
    void send(uint64_t client, const std::string& line) override;
    void reinstall_capture() override;  // reloads the pf rules (block_inbound)

private:
    struct Client {
        int fd = -1;
        uint32_t uid = 0;
        std::string in, out;
    };
    struct Iface {
        std::string name;
        ::pcap* handle = nullptr;
        int fd = -1;
        int link = 0;  // DLT_*
    };

    bool open_server();
    bool open_signals();
    void refresh_interfaces();
    void close_interfaces();
    void read_packets(Iface& i);
    void on_packet(const uint8_t* ip, size_t len);
    bool install_pf();
    void remove_pf();
    void sync_block_table(bool force);
    void block_now(const IpAddr& ip);
    void accept_client();
    void read_client(uint64_t id, Client& c);
    void flush_client(Client& c);
    void close_client(Client& c);
    void log_verbose(const std::string& s) const;

    Paths paths_;
    Engine engine_;
    ProcResolver procs_;
    bool verbose_ = false;
    bool running_ = true;
    int server_fd_ = -1;
    int sig_pipe_[2] = {-1, -1};
    std::map<std::string, Iface> ifaces_;
    std::set<IpAddr> local_addrs_;
    int64_t ifaces_checked_ms_ = 0;

    // New-flow detection: a flow is reported again only after it was idle this long.
    std::map<std::string, int64_t> flows_;
    uint64_t next_ticket_ = 1;

    // Addresses currently in the pf table and why.
    std::string pf_token_;
    bool pf_loaded_ = false;
    std::map<IpAddr, int64_t> temp_blocks_;      // denied in a prompt / by a program rule: until
    std::map<IpAddr, std::string> host_ips_;     // learned from DNS for hosts with a deny rule
    std::set<std::string> table_;                // last list pushed to pf
    std::string rules_sig_;
    int64_t last_sync_ms_ = 0;

    std::map<uint64_t, Client> clients_;
    uint64_t next_client_ = 1;
};

}  // namespace vartad
