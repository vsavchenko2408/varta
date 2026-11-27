#include "procinfo.hpp"

#include <dirent.h>
#include <pwd.h>
#include <unistd.h>

#include <climits>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>

namespace vartad {

namespace {

int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Parses "0100007F:0035" (IPv4) or 32-hex-digit IPv6 + ":PORT" as printed by /proc/net/*.
// The kernel prints each 32-bit word in host byte order (little-endian on x86/ARM).
bool parse_proc_addr(const std::string& s, bool v6, IpAddr& ip, uint16_t& port) {
    const auto colon = s.find(':');
    if (colon == std::string::npos) return false;
    const std::string hex = s.substr(0, colon);
    if (hex.size() != (v6 ? 32u : 8u)) return false;
    ip = IpAddr{};
    ip.v6 = v6;
    const size_t words = v6 ? 4 : 1;
    for (size_t w = 0; w < words; ++w) {
        uint32_t word = 0;
        for (size_t k = 0; k < 8; ++k) {
            const int h = hexval(hex[w * 8 + k]);
            if (h < 0) return false;
            word = (word << 4) | static_cast<uint32_t>(h);
        }
        // word is the host-order integer; its in-memory bytes are the network bytes.
        std::memcpy(ip.b.data() + w * 4, &word, 4);
    }
    port = static_cast<uint16_t>(std::stoul(s.substr(colon + 1), nullptr, 16));
    return true;
}

bool addr_any(const IpAddr& a) {
    for (int i = 0; i < (a.v6 ? 16 : 4); ++i)
        if (a.b[i]) return false;
    return true;
}

std::string read_small(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

}  // namespace

bool ProcResolver::find_inode(uint8_t proto, const IpAddr& local, uint16_t local_port,
                              const IpAddr& remote, uint16_t remote_port, bool inbound,
                              SockEntry& out) {
    const char* base = proto == kProtoTcp ? "/proc/net/tcp" : "/proc/net/udp";
    const IpAddr loc = local.unmapped(), rem = remote.unmapped();

    int best_score = -1;
    // Search both tables: dual-stack AF_INET6 sockets carry IPv4 traffic as ::ffff:a.b.c.d.
    for (int pass = 0; pass < 2; ++pass) {
        const bool v6 = pass == 1;
        std::ifstream in(std::string(base) + (v6 ? "6" : ""));
        std::string line;
        std::getline(in, line);  // header
        while (std::getline(in, line)) {
            std::istringstream ls(line);
            std::string sl, l, r, st, txrx, trtm, retr, uid, timeout, inode;
            if (!(ls >> sl >> l >> r >> st >> txrx >> trtm >> retr >> uid >> timeout >> inode)) continue;
            IpAddr lip, rip;
            uint16_t lport = 0, rport = 0;
            if (!parse_proc_addr(l, v6, lip, lport) || !parse_proc_addr(r, v6, rip, rport)) continue;
            if (lport != local_port) continue;
            const uint64_t ino = std::stoull(inode);
            if (ino == 0) continue;  // TIME_WAIT etc.

            // Score how well the entry matches; pick the best.
            int score = 1;
            const IpAddr lu = lip.unmapped(), ru = rip.unmapped();
            if (!addr_any(lu) && lu == loc) score += 2;
            if (inbound) {
                if (proto == kProtoTcp && st == "0A") score += 4;  // LISTEN
            } else {
                if (rport == remote_port && ru == rem) score += 4;  // connected socket
                else if (rport != 0) continue;  // connected to someone else
            }
            if (score > best_score) {
                best_score = score;
                out.inode = ino;
                out.uid = static_cast<uint32_t>(std::stoul(uid));
            }
        }
    }
    return best_score >= 0;
}

void ProcResolver::rebuild_inode_map() {
    inode_pid_.clear();
    DIR* proc = opendir("/proc");
    if (!proc) return;
    while (dirent* e = readdir(proc)) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        const int pid = std::atoi(e->d_name);
        const std::string fddir = std::string("/proc/") + e->d_name + "/fd";
        DIR* fds = opendir(fddir.c_str());
        if (!fds) continue;
        while (dirent* f = readdir(fds)) {
            if (f->d_name[0] == '.') continue;
            char target[64];
            const std::string link = fddir + "/" + f->d_name;
            const ssize_t n = readlink(link.c_str(), target, sizeof target - 1);
            if (n <= 8) continue;
            target[n] = 0;
            if (std::strncmp(target, "socket:[", 8) != 0) continue;
            const uint64_t ino = std::strtoull(target + 8, nullptr, 10);
            // Keep the lowest PID (usually the parent that created the socket).
            const auto it = inode_pid_.find(ino);
            if (it == inode_pid_.end() || pid < it->second) inode_pid_[ino] = pid;
        }
        closedir(fds);
    }
    closedir(proc);
}

int ProcResolver::pid_for_inode(uint64_t inode) {
    auto it = inode_pid_.find(inode);
    if (it != inode_pid_.end()) {
        // Verify the cached mapping is still true (PIDs and inodes get reused).
        char target[64];
        bool ok = false;
        const std::string fddir = "/proc/" + std::to_string(it->second) + "/fd";
        if (DIR* fds = opendir(fddir.c_str())) {
            const std::string want = "socket:[" + std::to_string(inode) + "]";
            while (dirent* f = readdir(fds)) {
                const std::string link = fddir + "/" + f->d_name;
                const ssize_t n = readlink(link.c_str(), target, sizeof target - 1);
                if (n > 0 && want.compare(0, std::string::npos, target, static_cast<size_t>(n)) == 0) {
                    ok = true;
                    break;
                }
            }
            closedir(fds);
        }
        if (ok) return it->second;
    }
    rebuild_inode_map();
    it = inode_pid_.find(inode);
    return it == inode_pid_.end() ? -1 : it->second;
}

std::string ProcResolver::user_name(uint32_t uid) {
    if (uid == UINT32_MAX) return {};
    passwd pw{};
    passwd* res = nullptr;
    char buf[1024];
    if (getpwuid_r(uid, &pw, buf, sizeof buf, &res) == 0 && res) return res->pw_name;
    return std::to_string(uid);
}

ProcInfo ProcResolver::describe_pid(int pid) {
    ProcInfo p;
    if (pid <= 0) return p;
    p.pid = pid;
    const std::string base = "/proc/" + std::to_string(pid);
    char buf[PATH_MAX];
    const ssize_t n = readlink((base + "/exe").c_str(), buf, sizeof buf - 1);
    if (n > 0) {
        buf[n] = 0;
        p.exe = buf;
        // An upgraded binary shows up as "/usr/bin/x (deleted)".
        const std::string del = " (deleted)";
        if (p.exe.size() > del.size() && p.exe.compare(p.exe.size() - del.size(), del.size(), del) == 0)
            p.exe.resize(p.exe.size() - del.size());
    }
    std::string cmd = read_small(base + "/cmdline");
    for (char& c : cmd)
        if (c == 0) c = ' ';
    while (!cmd.empty() && cmd.back() == ' ') cmd.pop_back();
    if (cmd.size() > 400) cmd = cmd.substr(0, 400) + "...";
    p.cmdline = cmd;

    std::string comm = read_small(base + "/comm");
    while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r')) comm.pop_back();
    p.name = comm;
    if (p.name.empty() && !p.exe.empty()) p.name = p.exe.substr(p.exe.rfind('/') + 1);

    std::istringstream st(read_small(base + "/status"));
    std::string line;
    while (std::getline(st, line)) {
        if (line.compare(0, 4, "Uid:") == 0) {
            std::istringstream ls(line.substr(4));
            uint32_t ruid = 0;
            if (ls >> ruid) p.uid = ruid;
            break;
        }
    }
    p.user = user_name(p.uid);
    return p;
}

ProcInfo ProcResolver::find(uint8_t proto, const IpAddr& local, uint16_t local_port,
                            const IpAddr& remote, uint16_t remote_port, bool inbound) {
    SockEntry se;
    if (!find_inode(proto, local, local_port, remote, remote_port, inbound, se)) return {};
    const int pid = pid_for_inode(se.inode);
    if (pid <= 0) {
        ProcInfo p;
        p.uid = se.uid;
        p.user = user_name(se.uid);
        return p;
    }
    return describe_pid(pid);
}

std::string own_exe_dir() {
    char buf[4096];
    const ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    std::string path(buf, static_cast<size_t>(n));
    const size_t slash = path.find_last_of('/');
    return slash == std::string::npos ? std::string() : path.substr(0, slash);
}

}  // namespace vartad
