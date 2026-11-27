#include "mac_daemon.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <grp.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

namespace fs = std::filesystem;

namespace vartad {

static constexpr const char* kAnchor = "com.apple/varta_ask";
static constexpr const char* kTable = "varta_deny";
static constexpr size_t kMaxClientBuffer = 8 * 1024 * 1024;
static constexpr int64_t kFlowIdleMs = 120 * 1000;           // same flow reported again after this
static constexpr int64_t kTempBlockMs = 30 * 60 * 1000;      // one-off denies last 30 minutes
static constexpr int64_t kIfaceCheckMs = 10 * 1000;

static int g_sig_write = -1;
static void on_signal(int sig) {
    const char c = static_cast<char>(sig);
    if (g_sig_write >= 0) (void)!write(g_sig_write, &c, 1);
}

static void log(const std::string& s) { std::cerr << "vartad: " << s << std::endl; }

static std::string shell_quote(const std::string& s) {
    std::string o = "'";
    for (char c : s) {
        if (c == '\'') o += "'\\''";
        else o += c;
    }
    return o + "'";
}

static int sh(const std::string& cmd) { return std::system((cmd + " >/dev/null 2>&1").c_str()); }

static std::string run_capture(const std::string& cmd) {
    std::string out;
    if (FILE* f = popen((cmd + " 2>&1").c_str(), "r")) {
        char buf[512];
        while (fgets(buf, sizeof buf, f)) out += buf;
        pclose(f);
    }
    return out;
}

MacDaemon::MacDaemon(Paths p, bool verbose) : paths_(p), engine_(p, *this), verbose_(verbose) {
    engine_.platform = "macos";
}

MacDaemon::~MacDaemon() {
    close_interfaces();
    if (pf_loaded_) remove_pf();
    if (server_fd_ >= 0) {
        close(server_fd_);
        unlink(paths_.socket().c_str());
    }
    for (auto& [id, c] : clients_)
        if (c.fd >= 0) close(c.fd);
    for (int fd : sig_pipe_)
        if (fd >= 0) close(fd);
}

void MacDaemon::log_verbose(const std::string& s) const {
    if (verbose_) log(s);
}

// ---------------------------------------------------------------------------------- pf

std::string MacDaemon::pf_rules() {
    std::ostringstream o;
    o << "# vartad (Varta interactive firewall): addresses you denied\n"
      << "table <" << kTable << "> persist\n"
      // "return": the program gets an immediate connection reset instead of a timeout.
      << "block return out quick from any to <" << kTable << ">\n"
      << "block drop in quick from <" << kTable << "> to any\n";
    return o.str();
}

bool MacDaemon::install_pf() {
    const std::string file = (fs::path(paths_.run_dir) / "pf-varta-ask.conf").string();
    {
        std::ofstream out(file, std::ios::trunc);
        out << pf_rules();
    }
    // The stock /etc/pf.conf evaluates every "com.apple/*" sub-anchor. Make sure that main
    // ruleset is loaded (pf may never have been enabled on this Mac).
    if (run_capture("pfctl -s rules").find("com.apple/*") == std::string::npos) sh("pfctl -f /etc/pf.conf");
    if (sh("pfctl -a " + std::string(kAnchor) + " -f " + shell_quote(file)) != 0) {
        log("pfctl rejected the rules in " + file);
        return false;
    }
    // Enable pf with a reference token: pf stays on for as long as anyone holds a token.
    const std::string out = run_capture("pfctl -E");
    const auto t = out.find("Token : ");
    if (t != std::string::npos) {
        pf_token_ = out.substr(t + 8);
        while (!pf_token_.empty() && (pf_token_.back() == '\n' || pf_token_.back() == '\r')) pf_token_.pop_back();
    }
    pf_loaded_ = true;
    table_.clear();
    sync_block_table(true);
    return true;
}

void MacDaemon::remove_pf() {
    sh("pfctl -a " + std::string(kAnchor) + " -F all");
    if (!pf_token_.empty()) sh("pfctl -X " + shell_quote(pf_token_));
    pf_loaded_ = false;
}

void MacDaemon::block_now(const IpAddr& ip) {
    const std::string s = ip.str();
    if (!pf_loaded_ || table_.count(s)) return;
    table_.insert(s);
    sh("pfctl -a " + std::string(kAnchor) + " -t " + kTable + " -T add " + s);
    // Close connections that are already open to it (states live outside the anchor).
    sh("pfctl -k " + std::string(ip.v6 ? "::/0" : "0.0.0.0/0") + " -k " + s);
    log_verbose("blocked " + s);
}

void MacDaemon::sync_block_table(bool force) {
    const int64_t now = now_ms();
    if (!force && now - last_sync_ms_ < 2000) return;
    last_sync_ms_ = now;

    std::set<std::string> want;
    std::vector<std::string> deny_hosts;
    for (const AppRule& r : engine_.rules.all()) {
        if (!r.enabled || r.action != Action::Deny) continue;
        if (!r.ip.empty()) want.insert(r.ip);
        if (!r.host.empty()) deny_hosts.push_back(r.host);
    }
    for (auto it = host_ips_.begin(); it != host_ips_.end();) {
        bool still = false;
        for (const auto& h : deny_hosts) still = still || host_matches(h, it->second);
        if (!still) {
            it = host_ips_.erase(it);
            continue;
        }
        want.insert(it->first.str());
        ++it;
    }
    for (auto it = temp_blocks_.begin(); it != temp_blocks_.end();) {
        if (it->second < now) {
            it = temp_blocks_.erase(it);
            continue;
        }
        want.insert(it->first.str());
        ++it;
    }
    if (!force && want == table_) return;
    const std::string file = (fs::path(paths_.run_dir) / "pf-varta-deny.txt").string();
    {
        std::ofstream out(file, std::ios::trunc);
        for (const auto& a : want) out << a << "\n";
    }
    if (pf_loaded_)
        sh("pfctl -a " + std::string(kAnchor) + " -t " + kTable + " -T replace -f " + shell_quote(file));
    table_ = std::move(want);
}

// ---------------------------------------------------------------------------- capture

void MacDaemon::refresh_interfaces() {
    ifaces_checked_ms_ = now_ms();
    char err[PCAP_ERRBUF_SIZE];
    pcap_if_t* all = nullptr;
    if (pcap_findalldevs(&all, err) != 0) {
        log(std::string("pcap_findalldevs: ") + err);
        return;
    }
    std::set<std::string> present;
    std::set<IpAddr> locals;
    for (pcap_if_t* d = all; d; d = d->next) {
        if (d->flags & PCAP_IF_LOOPBACK) continue;
        if (!(d->flags & PCAP_IF_UP)) continue;
        bool has_ip = false;
        for (pcap_addr_t* a = d->addresses; a; a = a->next) {
            if (!a->addr) continue;
            IpAddr ip;
            if (a->addr->sa_family == AF_INET) {
                std::memcpy(ip.b.data(), &reinterpret_cast<sockaddr_in*>(a->addr)->sin_addr, 4);
            } else if (a->addr->sa_family == AF_INET6) {
                ip.v6 = true;
                std::memcpy(ip.b.data(), &reinterpret_cast<sockaddr_in6*>(a->addr)->sin6_addr, 16);
            } else {
                continue;
            }
            locals.insert(ip);
            has_ip = true;
        }
        if (has_ip) present.insert(d->name);
    }
    pcap_freealldevs(all);
    local_addrs_ = std::move(locals);

    for (auto it = ifaces_.begin(); it != ifaces_.end();) {
        if (!present.count(it->first)) {
            log("interface " + it->first + " gone");
            pcap_close(it->second.handle);
            it = ifaces_.erase(it);
        } else {
            ++it;
        }
    }
    for (const auto& name : present) {
        if (ifaces_.count(name)) continue;
        pcap_t* h = pcap_create(name.c_str(), err);
        if (!h) continue;
        pcap_set_snaplen(h, 2048);  // DNS answers need the payload
        pcap_set_promisc(h, 0);
        pcap_set_immediate_mode(h, 1);
        pcap_set_timeout(h, 50);
        if (pcap_activate(h) < 0) {
            log("cannot capture on " + name + ": " + pcap_geterr(h));
            pcap_close(h);
            continue;
        }
        const int link = pcap_datalink(h);
        if (link != DLT_EN10MB && link != DLT_NULL && link != DLT_LOOP && link != DLT_RAW
#ifdef DLT_IPV4
            && link != DLT_IPV4 && link != DLT_IPV6
#endif
        ) {
            pcap_close(h);
            continue;
        }
        bpf_program prog{};
        if (pcap_compile(h, &prog, capture_filter(), 1, PCAP_NETMASK_UNKNOWN) != 0 || pcap_setfilter(h, &prog) != 0) {
            log("cannot set filter on " + name + ": " + pcap_geterr(h));
            pcap_freecode(&prog);
            pcap_close(h);
            continue;
        }
        pcap_freecode(&prog);
        pcap_setnonblock(h, 1, err);
        Iface i;
        i.name = name;
        i.handle = h;
        i.fd = pcap_get_selectable_fd(h);
        i.link = link;
        ifaces_[name] = i;
        log("watching " + name);
    }
}

void MacDaemon::close_interfaces() {
    for (auto& [n, i] : ifaces_) pcap_close(i.handle);
    ifaces_.clear();
}

void MacDaemon::read_packets(Iface& i) {
    struct Cb {
        static void handle(u_char* user, const pcap_pkthdr* h, const u_char* bytes) {
            auto* ctx = reinterpret_cast<std::pair<MacDaemon*, int>*>(user);
            size_t off = 0;
            size_t len = h->caplen;
            switch (ctx->second) {
                case DLT_EN10MB: {
                    if (len < 14) return;
                    uint16_t type = static_cast<uint16_t>(bytes[12] << 8 | bytes[13]);
                    off = 14;
                    if (type == 0x8100 && len >= 18) {  // VLAN tag
                        type = static_cast<uint16_t>(bytes[16] << 8 | bytes[17]);
                        off = 18;
                    }
                    if (type != 0x0800 && type != 0x86DD) return;
                    break;
                }
                case DLT_NULL:
                case DLT_LOOP: off = 4; break;
                default: off = 0; break;
            }
            if (len <= off) return;
            ctx->first->on_packet(bytes + off, len - off);
        }
    };
    std::pair<MacDaemon*, int> ctx{this, i.link};
    for (int rounds = 0; rounds < 32; ++rounds) {
        const int n = pcap_dispatch(i.handle, 256, &Cb::handle, reinterpret_cast<u_char*>(&ctx));
        if (n <= 0) break;
    }
}

void MacDaemon::on_packet(const uint8_t* data, size_t len) {
    PacketInfo p;
    if (!parse_packet(data, len, p)) return;
    const IpAddr src = p.src.unmapped(), dst = p.dst.unmapped();
    const bool from_local = local_addrs_.count(src) > 0;
    const bool to_local = local_addrs_.count(dst) > 0;

    // DNS answers: learn ip -> host names, and block addresses of denied hosts before use.
    if (p.proto == kProtoUdp && p.sport == 53 && to_local) {
        engine_.on_dns(p.payload, p.payload_len);
        std::vector<std::string> deny_hosts;
        for (const AppRule& r : engine_.rules.all())
            if (r.enabled && r.action == Action::Deny && !r.host.empty()) deny_hosts.push_back(r.host);
        if (!deny_hosts.empty()) {
            for (const auto& a : parse_dns_response(p.payload, p.payload_len)) {
                for (const auto& h : deny_hosts) {
                    if (!host_matches(h, a.name)) continue;
                    host_ips_[a.ip] = a.name;
                    block_now(a.ip);
                    break;
                }
            }
        }
        return;
    }

    bool inbound;
    if (from_local) inbound = false;
    else if (to_local) inbound = true;
    else return;  // not ours (bridged / promiscuous leftovers)

    if (inbound) {
        if (p.proto != kProtoTcp || !engine_.settings.ask_inbound) return;
    } else if (p.proto == kProtoUdp) {
        if (p.dport == 53 && engine_.settings.auto_allow_dns) return;
        if (p.dport == 67 || p.dport == 547 || p.dport == 5353 || p.sport == 5353) return;  // DHCP, mDNS
    }

    Connection c;
    c.inbound = inbound;
    c.proto = p.proto;
    if (inbound) {
        c.local = dst; c.local_port = p.dport;
        c.remote = src; c.remote_port = p.sport;
    } else {
        c.local = src; c.local_port = p.sport;
        c.remote = dst; c.remote_port = p.dport;
    }

    // Report every flow once (TCP SYN retransmits and UDP streams would repeat).
    const int64_t now = now_ms();
    const std::string key = std::to_string(c.proto) + "|" + c.local.str() + "|" + std::to_string(c.local_port) + "|" +
                            c.remote.str() + "|" + std::to_string(c.remote_port);
    auto it = flows_.find(key);
    if (it != flows_.end() && now - it->second < kFlowIdleMs) {
        it->second = now;
        return;
    }
    flows_[key] = now;
    if (flows_.size() > 50000) {
        for (auto f = flows_.begin(); f != flows_.end();) f = now - f->second > kFlowIdleMs ? flows_.erase(f) : std::next(f);
    }

    c.proc = procs_.find(c.proto, c.local, c.local_port, c.remote, c.remote_port, inbound);
    engine_.on_connection(std::move(c), next_ticket_++);
}

void MacDaemon::verdict(const std::vector<uint64_t>&, bool allow, const Connection& c) {
    const std::string what = (c.proc.exe.empty() ? std::string("?") : c.proc.exe) + (c.inbound ? " <- " : " -> ") +
                             (c.host.empty() ? c.remote.str() : c.host + " " + c.remote.str()) + ":" +
                             std::to_string(c.remote_port) + " (" + c.reason + ")";
    log_verbose((allow ? "allow " : "deny  ") + what);
    if (allow) return;
    if (!c.special.empty() && c.special != "Local network" && c.special != "Carrier-grade NAT") return;
    // The packets already left: block the address from now on and cut the open connection.
    const AppRule* r = c.rule_id ? engine_.rules.find(c.rule_id) : nullptr;
    if (r && !r->host.empty() && !c.host.empty()) host_ips_[c.remote] = c.host;  // kept while the rule exists
    else if (!(r && !r->ip.empty())) temp_blocks_[c.remote] = now_ms() + kTempBlockMs;
    block_now(c.remote);
}

// ------------------------------------------------------------------------ GUI clients

bool MacDaemon::open_server() {
    std::error_code ec;
    fs::create_directories(paths_.run_dir, ec);
    chmod(paths_.run_dir.c_str(), 0755);
    unlink(paths_.socket().c_str());
    server_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd_ < 0) return false;
    fcntl(server_fd_, F_SETFL, fcntl(server_fd_, F_GETFL) | O_NONBLOCK);
    fcntl(server_fd_, F_SETFD, FD_CLOEXEC);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::snprintf(addr.sun_path, sizeof addr.sun_path, "%s", paths_.socket().c_str());
    if (bind(server_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0 || listen(server_fd_, 8) < 0) {
        log(std::string("cannot listen on ") + paths_.socket() + ": " + std::strerror(errno));
        return false;
    }
    // Administrators (group "admin") may connect and answer prompts, like they may change
    // the macOS firewall in System Settings.
    if (group* g = getgrnam("admin")) {
        if (chown(paths_.socket().c_str(), 0, g->gr_gid) != 0) log("warning: chown socket failed");
        chmod(paths_.socket().c_str(), 0660);
    } else {
        chmod(paths_.socket().c_str(), 0600);
    }
    return true;
}

bool MacDaemon::open_signals() {
    if (pipe(sig_pipe_) != 0) return false;
    for (int fd : sig_pipe_) {
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
    g_sig_write = sig_pipe_[1];
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);
    return true;
}

void MacDaemon::close_client(Client& c) {
    if (c.fd >= 0) close(c.fd);
    c.fd = -1;
}

void MacDaemon::send(uint64_t client, const std::string& line) {
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

void MacDaemon::flush_client(Client& c) {
    while (c.fd >= 0 && !c.out.empty()) {
        const ssize_t n = ::send(c.fd, c.out.data(), c.out.size(), 0);
        if (n > 0) c.out.erase(0, static_cast<size_t>(n));
        else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        else close_client(c);
    }
}

void MacDaemon::accept_client() {
    for (;;) {
        const int fd = accept(server_fd_, nullptr, nullptr);
        if (fd < 0) return;
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        const int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
        Client c;
        c.fd = fd;
        uid_t uid = 0;
        gid_t gid = 0;
        if (getpeereid(fd, &uid, &gid) == 0) c.uid = uid;
        log("GUI connected (uid " + std::to_string(c.uid) + ")");
        const uint64_t id = next_client_++;
        clients_[id] = std::move(c);
        engine_.client_connected(id);
    }
}

void MacDaemon::read_client(uint64_t id, Client& c) {
    char buf[16384];
    for (;;) {
        const ssize_t n = recv(c.fd, buf, sizeof buf, 0);
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

int MacDaemon::run() {
    if (geteuid() != 0) {
        log("must run as root");
        return 1;
    }
    std::string info;
    engine_.load(info);
    std::istringstream lines(info);
    for (std::string l; std::getline(lines, l);) log(l);

    if (!open_signals() || !open_server()) return 1;
    if (!install_pf()) return 1;
    refresh_interfaces();
    if (ifaces_.empty()) log("warning: no network interface to watch yet");
    log("running - mode '" + engine_.settings.mode + "'");

    int64_t last_tick = now_ms();
    while (running_) {
        std::vector<pollfd> fds;
        std::vector<uint64_t> ids;
        fds.push_back({server_fd_, POLLIN, 0});
        fds.push_back({sig_pipe_[0], POLLIN, 0});
        for (const auto& [n, i] : ifaces_)
            if (i.fd >= 0) fds.push_back({i.fd, POLLIN, 0});
        const size_t first_client = fds.size();
        for (const auto& [id, c] : clients_) {
            fds.push_back({c.fd, static_cast<short>(POLLIN | (c.out.empty() ? 0 : POLLOUT)), 0});
            ids.push_back(id);
        }

        const int r = poll(fds.data(), static_cast<nfds_t>(fds.size()), 100);
        if (r < 0 && errno != EINTR) {
            log(std::string("poll: ") + std::strerror(errno));
            break;
        }

        if (fds[1].revents & POLLIN) {
            char sig;
            while (read(sig_pipe_[0], &sig, 1) == 1) {
                if (sig == SIGHUP) {
                    log("SIGHUP: reloading IP database and settings");
                    engine_.reload_settings();
                    log("IP database: " + std::to_string(engine_.reload_ipdb()) + " ranges");
                } else {
                    running_ = false;
                }
            }
        }
        // BPF descriptors do not always wake poll() reliably; reading them every round
        // (non-blocking) keeps the delay under ~100 ms either way.
        for (auto& [n, i] : ifaces_) read_packets(i);
        if (fds[0].revents & POLLIN) accept_client();
        for (size_t k = first_client; k < fds.size(); ++k) {
            auto it = clients_.find(ids[k - first_client]);
            if (it == clients_.end() || it->second.fd < 0) continue;
            Client& c = it->second;
            const short ev = fds[k].revents;
            if ((ev & (POLLERR | POLLHUP | POLLNVAL)) && !(ev & POLLIN)) {
                close_client(c);
                continue;
            }
            if (ev & POLLIN) read_client(it->first, c);
            if (c.fd >= 0 && (ev & POLLOUT)) flush_client(c);
        }
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
            sync_block_table(false);
        }
        if (now - ifaces_checked_ms_ >= kIfaceCheckMs) refresh_interfaces();
    }

    log("shutting down");
    engine_.shutdown();
    close_interfaces();
    remove_pf();
    return 0;
}

}  // namespace vartad
