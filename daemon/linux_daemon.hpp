// vartad - Linux front end: NFQUEUE capture, nftables/iptables rules, Unix socket for the GUI.
#pragma once

#include <map>
#include <string>
#include <vector>

#include "engine.hpp"
#include "procinfo.hpp"

struct nfq_handle;
struct nfq_q_handle;
struct nfgenmsg;
struct nfq_data;

namespace vartad {

class LinuxDaemon : public EngineHost {
public:
    explicit LinuxDaemon(Paths p);
    ~LinuxDaemon() override;
    int run();  // blocks until SIGINT/SIGTERM

    static std::string nft_script(const Settings& s);
    // Fallback for kernels without the nft "queue" expression: iptables NFQUEUE target.
    static std::vector<std::string> iptables_commands(const Settings& s, bool install);

    // EngineHost
    void verdict(const std::vector<uint64_t>& tickets, bool allow, const Connection& c) override;
    void send(uint64_t client, const std::string& line) override;
    void reinstall_capture() override { install_nft(); }

private:
    struct Client {
        int fd = -1;
        uint32_t uid = 0;
        std::string in, out;
    };

    static int nfq_callback(nfq_q_handle* qh, nfgenmsg* msg, nfq_data* nfa, void* data);
    int on_packet(nfq_data* nfa);
    bool open_queue();
    bool open_server();
    bool open_signals();
    bool install_nft();
    void remove_nft();
    void accept_client();
    void read_client(uint64_t id, Client& c);
    void flush_client(Client& c);
    void close_client(Client& c);

    Paths paths_;
    Engine engine_;
    ProcResolver procs_;
    nfq_handle* nfq_ = nullptr;
    nfq_q_handle* qh_ = nullptr;
    int nfq_fd_ = -1, server_fd_ = -1, signal_fd_ = -1;
    bool running_ = true;
    bool nft_installed_ = false;
    bool iptables_installed_ = false;
    std::map<uint64_t, Client> clients_;
    uint64_t next_client_ = 1;
};

}  // namespace vartad
