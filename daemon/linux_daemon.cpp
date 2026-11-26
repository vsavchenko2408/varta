#include "linux_daemon.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/netfilter.h>
#include <poll.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

extern "C" {
#include <libnetfilter_queue/libnetfilter_queue.h>
}

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

namespace fs = std::filesystem;

namespace vartad {

// Packets we deny are re-injected with this mark so our own chain rejects/drops them.
static constexpr uint32_t kDenyMark = 0x56415254;  // "VART"
static constexpr size_t kMaxClientBuffer = 8 * 1024 * 1024;

static void log(const std::string& s) { std::cerr << "vartad: " << s << std::endl; }

LinuxDaemon::LinuxDaemon(Paths p) : paths_(p), engine_(p, *this) { engine_.platform = "linux"; }

LinuxDaemon::~LinuxDaemon() {
    if (nft_installed_ || iptables_installed_) remove_nft();
    if (qh_) nfq_destroy_queue(qh_);
    if (nfq_) nfq_close(nfq_);
    if (server_fd_ >= 0) {
        close(server_fd_);
        unlink(paths_.socket().c_str());
    }
    for (auto& [id, c] : clients_)
        if (c.fd >= 0) close(c.fd);
    if (signal_fd_ >= 0) close(signal_fd_);
}

std::string LinuxDaemon::nft_script(const Settings& s) {
    const std::string q = std::to_string(s.queue);
    char mark[16];
    std::snprintf(mark, sizeof mark, "0x%08x", kDenyMark);
    std::ostringstream o;
    o << "table inet varta_ask\n"
         "delete table inet varta_ask\n"
         "table inet varta_ask {\n"
         "    chain output {\n"
         // Priority 10: runs after Varta's static table (priority 0), so already-blocked
         // trackers never reach the prompt.
         "        type filter hook output priority 10; policy accept;\n"
      << "        meta mark " << mark << " counter reject comment \"denied by vartad\"\n"
         "        oifname \"lo\" accept\n";
    if (s.auto_allow_dns) o << "        meta l4proto { tcp, udp } th dport 53 accept\n";
    o << "        ct state new meta l4proto { tcp, udp } queue num " << q << " bypass\n"
         "    }\n"
         "    chain input {\n"
         "        type filter hook input priority 10; policy accept;\n"
      << "        meta mark " << mark << " counter drop comment \"denied by vartad\"\n"
         "        iifname \"lo\" accept\n"
         // DNS answers go through the queue only so we can learn ip -> host names.
         "        udp sport 53 queue num " << q << " bypass\n";
    if (s.ask_inbound) {
        o << "        udp sport 67 udp dport 68 accept\n"
             "        udp sport 547 udp dport 546 accept\n"
             "        ct state new meta pkttype unicast meta l4proto { tcp, udp } queue num "
          << q << " bypass\n";
    }
    o << "    }\n}\n";
    return o.str();
}

std::vector<std::string> LinuxDaemon::iptables_commands(const Settings& s, bool install) {
    const std::string q = std::to_string(s.queue);
    char mark[16];
    std::snprintf(mark, sizeof mark, "0x%08x", kDenyMark);
    std::vector<std::string> cmds;
    for (const char* tool : {"iptables", "ip6tables"}) {
        const std::string t = std::string(tool) + " -w -t mangle ";
        // Always clean up first so install is idempotent.
        cmds.push_back(t + "-D OUTPUT -j VARTA_OUT");
        cmds.push_back(t + "-D INPUT -j VARTA_IN");
        cmds.push_back(t + "-F VARTA_OUT");
        cmds.push_back(t + "-X VARTA_OUT");
        cmds.push_back(t + "-F VARTA_IN");
        cmds.push_back(t + "-X VARTA_IN");
        cmds.push_back(std::string(tool) + " -w -t filter -D OUTPUT -m mark --mark " + mark + " -j REJECT");
        if (!install) continue;
        const std::string nfq = " -j NFQUEUE --queue-num " + q + " --queue-bypass";
        cmds.push_back("!" + t + "-N VARTA_OUT");
        // Denied packets come back marked: let them leave mangle so filter can REJECT them
        // (an immediate error for the program instead of a slow timeout).
        cmds.push_back("!" + t + "-A VARTA_OUT -m mark --mark " + mark + " -j RETURN");
        cmds.push_back("!" + t + "-A VARTA_OUT -o lo -j RETURN");
        if (s.auto_allow_dns) {
            cmds.push_back("!" + t + "-A VARTA_OUT -p udp --dport 53 -j RETURN");
            cmds.push_back("!" + t + "-A VARTA_OUT -p tcp --dport 53 -j RETURN");
        }
        cmds.push_back("!" + t + "-A VARTA_OUT -p tcp -m conntrack --ctstate NEW" + nfq);
        cmds.push_back("!" + t + "-A VARTA_OUT -p udp -m conntrack --ctstate NEW" + nfq);
        cmds.push_back("!" + t + "-N VARTA_IN");
        cmds.push_back("!" + t + "-A VARTA_IN -m mark --mark " + mark + " -j DROP");
        cmds.push_back("!" + t + "-A VARTA_IN -i lo -j RETURN");
        cmds.push_back("!" + t + "-A VARTA_IN -p udp --sport 53" + nfq);
        if (s.ask_inbound) {
            cmds.push_back("!" + t + "-A VARTA_IN -p udp --sport 67 --dport 68 -j RETURN");
            cmds.push_back("!" + t + "-A VARTA_IN -p udp --sport 547 --dport 546 -j RETURN");
            for (const char* p : {"tcp", "udp"})
                cmds.push_back("!" + t + "-A VARTA_IN -p " + p +
                               " -m conntrack --ctstate NEW -m pkttype --pkt-type unicast" + nfq);
        }
        cmds.push_back("!" + std::string(tool) + " -w -t filter -I OUTPUT 1 -m mark --mark " + mark + " -j REJECT");
        cmds.push_back("!" + t + "-A OUTPUT -j VARTA_OUT");
        cmds.push_back("!" + t + "-A INPUT -j VARTA_IN");
    }
    return cmds;  // commands starting with '!' must succeed
}

static bool run_commands(const std::vector<std::string>& cmds) {
    for (const auto& c : cmds) {
        const bool must = !c.empty() && c[0] == '!';
        const std::string cmd = (must ? c.substr(1) : c) + " 2>/dev/null";
        if (std::system(cmd.c_str()) != 0 && must) {
            std::cerr << "vartad: command failed: " << cmd << std::endl;
            return false;
        }
    }
    return true;
}

bool LinuxDaemon::install_nft() {
    std::error_code ec;
    fs::create_directories(paths_.run_dir, ec);
    const std::string path = paths_.run_dir + "/vartad.nft";
    {
        std::ofstream out(path, std::ios::trunc);
        out << nft_script(engine_.settings);
    }
    if (!iptables_installed_) {
        const std::string cmd = "nft -f '" + path + "' 2>/dev/null";
        if (std::system(cmd.c_str()) == 0) {
            nft_installed_ = true;
            return true;
        }
        log("nftables 'queue' is not available in this kernel - falling back to iptables NFQUEUE");
    }
    if (run_commands(iptables_commands(engine_.settings, true))) {
        iptables_installed_ = true;
        return true;
    }
    run_commands(iptables_commands(engine_.settings, false));
    log("could not install interception rules (nft and iptables both failed)");
    return false;
}

void LinuxDaemon::remove_nft() {
    if (nft_installed_ && std::system("nft delete table inet varta_ask 2>/dev/null") == 0)
        nft_installed_ = false;
    if (iptables_installed_) {
        run_commands(iptables_commands(engine_.settings, false));
        iptables_installed_ = false;
    }
}

bool LinuxDaemon::open_queue() {
    nfq_ = nfq_open();
    if (!nfq_) {
        log("nfq_open failed (are you root? is nfnetlink_queue available?)");
        return false;
    }
    qh_ = nfq_create_queue(nfq_, static_cast<uint16_t>(engine_.settings.queue), &LinuxDaemon::nfq_callback, this);
    if (!qh_) {
        log("cannot bind NFQUEUE " + std::to_string(engine_.settings.queue) +
            " - is another firewall (e.g. OpenSnitch) or vartad already using it?");
        return false;
    }
    if (nfq_set_mode(qh_, NFQNL_COPY_PACKET, 0xffff) < 0) {
        log("nfq_set_mode failed");
        return false;
    }
    nfq_set_queue_maxlen(qh_, 4096);
    // FAIL_OPEN: if our queue is ever full the kernel accepts instead of dropping.
    // UID_GID: the kernel tells us the socket owner even when the process is already gone.
    const uint32_t flags = NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_UID_GID;
    if (nfq_set_queue_flags(qh_, flags, flags) < 0) log("warning: kernel does not support queue flags");
    nfq_fd_ = nfq_fd(nfq_);
    const int one = 1;
    setsockopt(nfq_fd_, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof one);
    const int rcvbuf = 4 * 1024 * 1024;
    setsockopt(nfq_fd_, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof rcvbuf);
    fcntl(nfq_fd_, F_SETFL, fcntl(nfq_fd_, F_GETFL) | O_NONBLOCK);
    return true;
}

bool LinuxDaemon::open_server() {
    std::error_code ec;
    fs::create_directories(paths_.run_dir, ec);
    chmod(paths_.run_dir.c_str(), 0755);
    unlink(paths_.socket().c_str());

    server_fd_ = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (server_fd_ < 0) return false;
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::snprintf(addr.sun_path, sizeof addr.sun_path, "%s", paths_.socket().c_str());
    if (bind(server_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0 ||
        listen(server_fd_, 8) < 0) {
        log(std::string("cannot listen on ") + paths_.socket() + ": " + std::strerror(errno));
        return false;
    }
    // Only root and members of group "varta" may connect (and therefore answer prompts).
    if (group* g = getgrnam("varta")) {
        if (chown(paths_.socket().c_str(), 0, g->gr_gid) != 0) log("warning: chown socket failed");
        chmod(paths_.socket().c_str(), 0660);
    } else {
        chmod(paths_.socket().c_str(), 0600);
        log("group 'varta' does not exist - only root can use the GUI. "
            "Run: sudo groupadd varta && sudo usermod -aG varta $USER");
    }
    return true;
}

bool LinuxDaemon::open_signals() {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    sigprocmask(SIG_BLOCK, &set, nullptr);
    signal(SIGPIPE, SIG_IGN);
    signal_fd_ = signalfd(-1, &set, SFD_NONBLOCK | SFD_CLOEXEC);
    return signal_fd_ >= 0;
}

// ----------------------------------------------------------------------------- packets

int LinuxDaemon::nfq_callback(nfq_q_handle*, nfgenmsg*, nfq_data* nfa, void* data) {
    return static_cast<LinuxDaemon*>(data)->on_packet(nfa);
}

void LinuxDaemon::verdict(const std::vector<uint64_t>& tickets, bool allow, const Connection&) {
    for (uint64_t t : tickets) {
        const uint32_t id = static_cast<uint32_t>(t);
        if (allow)
            nfq_set_verdict(qh_, id, NF_ACCEPT, 0, nullptr);
        else  // re-run our chain with the deny mark -> reject (out) / drop (in)
            nfq_set_verdict2(qh_, id, NF_REPEAT, kDenyMark, 0, nullptr);
    }
}

int LinuxDaemon::on_packet(nfq_data* nfa) {
    nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return 0;
    const uint32_t id = ntohl(ph->packet_id);
    const bool inbound = ph->hook == NF_INET_LOCAL_IN;

    unsigned char* data = nullptr;
    const int len = nfq_get_payload(nfa, &data);
    PacketInfo p;
    if (len <= 0 || !parse_packet(data, static_cast<size_t>(len), p)) {
        nfq_set_verdict(qh_, id, NF_ACCEPT, 0, nullptr);
        return 0;
    }
    // DNS answers: learn names, always accept.
    if (inbound && p.proto == kProtoUdp && p.sport == 53) {
        engine_.on_dns(p.payload, p.payload_len);
        nfq_set_verdict(qh_, id, NF_ACCEPT, 0, nullptr);
        return 0;
    }

    Connection c;
    c.inbound = inbound;
    c.proto = p.proto;
    if (inbound) {
        c.local = p.dst; c.local_port = p.dport;
        c.remote = p.src; c.remote_port = p.sport;
    } else {
        c.local = p.src; c.local_port = p.sport;
        c.remote = p.dst; c.remote_port = p.dport;
    }
    c.proc = procs_.find(p.proto, c.local, c.local_port, c.remote, c.remote_port, inbound);
    if (c.proc.uid == UINT32_MAX) {
        uint32_t uid = 0;
        if (nfq_get_uid(nfa, &uid)) {
            c.proc.uid = uid;
            c.proc.user = ProcResolver::user_name(uid);
        }
    }
    engine_.on_connection(std::move(c), id);
    return 0;
}

// ------------------------------------------------------------------------ GUI clients

void LinuxDaemon::close_client(Client& c) {
    if (c.fd >= 0) close(c.fd);
    c.fd = -1;
}

void LinuxDaemon::send(uint64_t client, const std::string& line) {
    const auto it = clients_.find(client);
    if (it == clients_.end() || it->second.fd < 0) return;
    Client& c = it->second;
    c.out += line;
    if (c.out.size() > kMaxClientBuffer) {
        log("GUI client is not reading - disconnecting it");
        close_client(c);
        return;
    }
    flush_client(c);
}

void LinuxDaemon::flush_client(Client& c) {
    while (c.fd >= 0 && !c.out.empty()) {
        const ssize_t n = ::send(c.fd, c.out.data(), c.out.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n > 0) c.out.erase(0, static_cast<size_t>(n));
        else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        else close_client(c);
    }
}

void LinuxDaemon::accept_client() {
    for (;;) {
        const int fd = accept4(server_fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) return;
        Client c;
        c.fd = fd;
        ucred cred{};
        socklen_t len = sizeof cred;
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0) c.uid = cred.uid;
        log("GUI connected (uid " + std::to_string(c.uid) + ")");
        const uint64_t id = next_client_++;
        clients_[id] = std::move(c);
        engine_.client_connected(id);
    }
}

void LinuxDaemon::read_client(uint64_t id, Client& c) {
    char buf[16384];
    for (;;) {
        const ssize_t n = recv(c.fd, buf, sizeof buf, MSG_DONTWAIT);
        if (n > 0) {
            c.in.append(buf, static_cast<size_t>(n));
            if (c.in.size() > kMaxClientBuffer) return close_client(c);
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        } else {
            return close_client(c);
        }
    }
    size_t nl;
    while (c.fd >= 0 && (nl = c.in.find('\n')) != std::string::npos) {
        const std::string line = c.in.substr(0, nl);
        c.in.erase(0, nl + 1);
        if (!line.empty()) engine_.client_message(id, line);
    }
}

// --------------------------------------------------------------------------------- run

int LinuxDaemon::run() {
    if (geteuid() != 0) {
        log("must run as root");
        return 1;
    }
    std::string info;
    engine_.load(info);
    std::istringstream lines(info);
    for (std::string l; std::getline(lines, l);) log(l);

    if (!open_signals() || !open_queue() || !open_server()) return 1;
    if (!install_nft()) return 1;
    log("running - mode '" + engine_.settings.mode + "', queue " + std::to_string(engine_.settings.queue));

    std::vector<char> buf(256 * 1024);
    int64_t last_tick = now_ms();
    while (running_) {
        std::vector<pollfd> fds;
        std::vector<uint64_t> ids;
        fds.push_back({nfq_fd_, POLLIN, 0});
        fds.push_back({server_fd_, POLLIN, 0});
        fds.push_back({signal_fd_, POLLIN, 0});
        for (const auto& [id, c] : clients_) {
            fds.push_back({c.fd, static_cast<short>(POLLIN | (c.out.empty() ? 0 : POLLOUT)), 0});
            ids.push_back(id);
        }

        const int r = poll(fds.data(), fds.size(), 250);
        if (r < 0 && errno != EINTR) {
            log(std::string("poll: ") + std::strerror(errno));
            break;
        }

        if (fds[2].revents & POLLIN) {
            signalfd_siginfo si{};
            while (read(signal_fd_, &si, sizeof si) == sizeof si) {
                if (si.ssi_signo == SIGHUP) {
                    log("SIGHUP: reloading IP database and settings");
                    engine_.reload_settings();
                    log("IP database: " + std::to_string(engine_.reload_ipdb()) + " ranges");
                    install_nft();
                } else {
                    running_ = false;
                }
            }
        }
        if (fds[0].revents & POLLIN) {
            for (;;) {
                const ssize_t len = recv(nfq_fd_, buf.data(), buf.size(), MSG_DONTWAIT);
                if (len < 0) {
                    if (errno == ENOBUFS) {
                        log("warning: kernel queue overflow, some packets were auto-accepted");
                        continue;
                    }
                    break;
                }
                nfq_handle_packet(nfq_, buf.data(), static_cast<int>(len));
            }
        }
        if (fds[1].revents & POLLIN) accept_client();
        for (size_t i = 3; i < fds.size(); ++i) {
            auto it = clients_.find(ids[i - 3]);
            if (it == clients_.end() || it->second.fd < 0) continue;
            Client& c = it->second;
            const short ev = fds[i].revents;
            if ((ev & (POLLERR | POLLHUP | POLLNVAL)) && !(ev & POLLIN)) {
                close_client(c);
                continue;
            }
            if (ev & POLLIN) read_client(it->first, c);
            if (c.fd >= 0 && (ev & POLLOUT)) flush_client(c);
        }
        // Forget closed clients (the engine settles their prompts if none are left).
        for (auto it = clients_.begin(); it != clients_.end();) {
            if (it->second.fd < 0) {
                const uint64_t id = it->first;
                it = clients_.erase(it);
                log("GUI disconnected");
                engine_.client_disconnected(id);
            } else {
                ++it;
            }
        }
        const int64_t now = now_ms();
        if (now - last_tick >= 250) {
            last_tick = now;
            engine_.tick();
        }
    }

    log("shutting down");
    // Never leave packets stuck in the kernel: let everything that waits go through.
    engine_.shutdown();
    remove_nft();
    return 0;
}

}  // namespace vartad
