#include "procinfo_mac.hpp"

#include <libproc.h>
#include <mach-o/dyld.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include <climits>
#include <cstring>

namespace vartad {

static constexpr int64_t kCacheMs = 1500;  // reuse a socket table this fresh before rescanning

// insi_faddr and insi_laddr are two distinct anonymous unions with the same layout.
template <typename U>
static IpAddr addr_from(const U& u, uint8_t vflag) {
    IpAddr a;
    if (vflag & INI_IPV4) {
        std::memcpy(a.b.data(), &u.ina_46.i46a_addr4, 4);
    } else {
        a.v6 = true;
        std::memcpy(a.b.data(), &u.ina_6, 16);
        a = a.unmapped();
    }
    return a;
}

static IpAddr from_in_sockinfo(const in_sockinfo& si, bool remote) {
    return remote ? addr_from(si.insi_faddr, si.insi_vflag) : addr_from(si.insi_laddr, si.insi_vflag);
}

static bool is_any(const IpAddr& a) {
    for (uint8_t x : a.b)
        if (x) return false;
    return true;
}

void ProcResolver::rebuild() {
    socks_.clear();
    built_ms_ = now_ms();
    std::vector<int> pids(4096);
    int n = proc_listallpids(pids.data(), static_cast<int>(pids.size() * sizeof(int)));
    if (n <= 0) return;
    if (n > static_cast<int>(pids.size())) n = static_cast<int>(pids.size());
    std::vector<proc_fdinfo> fds(512);
    for (int i = 0; i < n; ++i) {
        const int pid = pids[i];
        if (pid <= 0) continue;
        int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.data(), static_cast<int>(fds.size() * sizeof(proc_fdinfo)));
        if (bytes <= 0) continue;
        if (static_cast<size_t>(bytes) >= fds.size() * sizeof(proc_fdinfo)) {
            // Many descriptors: grow once and ask again.
            fds.resize(fds.size() * 16);
            bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.data(), static_cast<int>(fds.size() * sizeof(proc_fdinfo)));
            if (bytes <= 0) continue;
        }
        const int count = bytes / static_cast<int>(sizeof(proc_fdinfo));
        for (int k = 0; k < count; ++k) {
            if (fds[k].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
            socket_fdinfo sfi{};
            if (proc_pidfdinfo(pid, fds[k].proc_fd, PROC_PIDFDSOCKETINFO, &sfi, sizeof sfi) < static_cast<int>(sizeof sfi))
                continue;
            const socket_info& si = sfi.psi;
            if (si.soi_family != AF_INET && si.soi_family != AF_INET6) continue;
            const in_sockinfo* in = nullptr;
            Sock s;
            s.pid = pid;
            if (si.soi_kind == SOCKINFO_TCP) {
                in = &si.soi_proto.pri_tcp.tcpsi_ini;
                s.proto = kProtoTcp;
            } else if (si.soi_kind == SOCKINFO_IN && si.soi_protocol == IPPROTO_UDP) {
                in = &si.soi_proto.pri_in;
                s.proto = kProtoUdp;
            } else {
                continue;
            }
            s.lport = ntohs(static_cast<uint16_t>(in->insi_lport));
            s.fport = ntohs(static_cast<uint16_t>(in->insi_fport));
            s.laddr = from_in_sockinfo(*in, false);
            s.faddr = from_in_sockinfo(*in, true);
            s.connected = s.fport != 0 && !is_any(s.faddr);
            socks_.push_back(s);
        }
    }
}

int ProcResolver::lookup(uint8_t proto, const IpAddr& local, uint16_t lport, const IpAddr& remote,
                         uint16_t rport, bool inbound) const {
    const IpAddr l = local.unmapped(), r = remote.unmapped();
    int fallback = 0;
    for (const Sock& s : socks_) {
        if (s.proto != proto || s.lport != lport) continue;
        if (!is_any(s.laddr) && !(s.laddr == l)) continue;
        if (s.connected) {
            if (s.faddr == r && s.fport == rport) return s.pid;  // exact 4-tuple
            continue;
        }
        // Listening (inbound) or unconnected UDP socket on that port.
        if (!fallback || (inbound && proto == kProtoTcp)) fallback = s.pid;
    }
    return fallback;
}

ProcInfo ProcResolver::find(uint8_t proto, const IpAddr& local, uint16_t local_port, const IpAddr& remote,
                            uint16_t remote_port, bool inbound) {
    int pid = 0;
    if (now_ms() - built_ms_ < kCacheMs) pid = lookup(proto, local, local_port, remote, remote_port, inbound);
    if (!pid) {
        rebuild();
        pid = lookup(proto, local, local_port, remote, remote_port, inbound);
    }
    return describe_pid(pid);
}

std::string ProcResolver::user_name(uint32_t uid) {
    if (uid == UINT32_MAX) return {};
    passwd pw{};
    passwd* res = nullptr;
    char buf[1024];
    if (getpwuid_r(uid, &pw, buf, sizeof buf, &res) == 0 && res) return res->pw_name;
    return std::to_string(uid);
}

// Command line from KERN_PROCARGS2: int argc, exec path, padding NULs, then argv[].
static std::string command_line(int pid) {
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
    size_t size = 0;
    int argmax = 0;
    size_t len = sizeof argmax;
    int mib2[2] = {CTL_KERN, KERN_ARGMAX};
    if (sysctl(mib2, 2, &argmax, &len, nullptr, 0) != 0 || argmax <= 0) return {};
    std::vector<char> buf(static_cast<size_t>(argmax));
    size = buf.size();
    if (sysctl(mib, 3, buf.data(), &size, nullptr, 0) != 0 || size < sizeof(int)) return {};
    int argc = 0;
    std::memcpy(&argc, buf.data(), sizeof argc);
    size_t p = sizeof(int);
    while (p < size && buf[p]) ++p;  // exec path
    while (p < size && !buf[p]) ++p;  // padding
    std::string out;
    for (int i = 0; i < argc && p < size; ++i) {
        const char* s = buf.data() + p;
        const size_t l = strnlen(s, size - p);
        if (!out.empty()) out += ' ';
        out.append(s, l);
        p += l + 1;
    }
    if (out.size() > 400) out = out.substr(0, 400) + "...";
    return out;
}

ProcInfo ProcResolver::describe_pid(int pid) {
    ProcInfo p;
    if (pid <= 0) return p;
    p.pid = pid;
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(pid, path, sizeof path) > 0) p.exe = path;
    proc_bsdinfo bi{};
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sizeof bi) == static_cast<int>(sizeof bi)) {
        p.uid = bi.pbi_uid;
        p.user = user_name(bi.pbi_uid);
        p.name = bi.pbi_name[0] ? bi.pbi_name : bi.pbi_comm;
    }
    if (!p.exe.empty()) p.name = p.exe.substr(p.exe.rfind('/') + 1);
    p.cmdline = command_line(pid);
    return p;
}

std::string own_exe_dir() {
    char buf[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(getpid(), buf, sizeof buf) <= 0) return {};
    std::string path(buf);
    const size_t slash = path.find_last_of('/');
    return slash == std::string::npos ? std::string() : path.substr(0, slash);
}

}  // namespace vartad
