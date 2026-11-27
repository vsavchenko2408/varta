#include "procinfo_win.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <cstring>
#include <vector>

namespace vartad {

static constexpr int64_t kSocketMemoryMs = 10 * 60 * 1000;  // remember socket owners 10 min
static constexpr int64_t kDescribeCacheMs = 5000;           // PIDs get reused; keep this short

std::string ProcResolver::utf8(const wchar_t* w, size_t len) {
    if (!w) return {};
    const int n = len == static_cast<size_t>(-1) ? -1 : static_cast<int>(len);
    const int size = WideCharToMultiByte(CP_UTF8, 0, w, n, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string out(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, n, out.data(), size, nullptr, nullptr);
    if (n == -1 && !out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

std::wstring ProcResolver::wide(const std::string& s) {
    if (s.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), size);
    return out;
}

void ProcResolver::note_socket(uint8_t proto, uint16_t local_port, uint32_t pid) {
    if (!local_port || pid == 0) return;
    std::lock_guard<std::mutex> lock(mu_);
    sockets_[(uint32_t(proto) << 16) | local_port] = {pid, now_ms()};
    if (sockets_.size() > 20000) {
        const int64_t cutoff = now_ms() - kSocketMemoryMs;
        for (auto it = sockets_.begin(); it != sockets_.end();)
            it = it->second.second < cutoff ? sockets_.erase(it) : std::next(it);
    }
}

namespace {

template <typename T>
std::vector<char> table(DWORD (WINAPI* fn)(PVOID, PDWORD, BOOL, ULONG, T, ULONG), ULONG family, T cls) {
    std::vector<char> buf;
    DWORD size = 0;
    for (int attempt = 0; attempt < 4; ++attempt) {
        const DWORD rc = fn(buf.empty() ? nullptr : buf.data(), &size, FALSE, family, cls, 0);
        if (rc == NO_ERROR) return buf;
        if (rc != ERROR_INSUFFICIENT_BUFFER) break;
        buf.resize(size + 4096);  // the table may grow between calls
    }
    return {};
}

bool same_v4(DWORD a, const IpAddr& ip) {
    const IpAddr u = ip.unmapped();
    return !u.v6 && std::memcmp(&a, u.b.data(), 4) == 0;
}

bool same_v6(const UCHAR* a, const IpAddr& ip) { return ip.v6 && std::memcmp(a, ip.b.data(), 16) == 0; }

uint16_t port_of(DWORD p) { return ntohs(static_cast<u_short>(p & 0xffff)); }

}  // namespace

int ProcResolver::pid_from_tables(uint8_t proto, const IpAddr& local, uint16_t local_port,
                                  const IpAddr& remote, uint16_t remote_port, bool inbound) {
    int best = -1, best_score = -1;
    auto consider = [&](int score, DWORD pid) {
        if (score > best_score) {
            best_score = score;
            best = static_cast<int>(pid);
        }
    };
    (void)local;
    if (proto == kProtoTcp) {
        const auto t4 = table(GetExtendedTcpTable, AF_INET, TCP_TABLE_OWNER_PID_ALL);
        if (!t4.empty()) {
            const auto* t = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(t4.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& r = t->table[i];
                if (port_of(r.dwLocalPort) != local_port) continue;
                if (inbound) consider(r.dwState == MIB_TCP_STATE_LISTEN ? 4 : 1, r.dwOwningPid);
                else if (port_of(r.dwRemotePort) == remote_port && same_v4(r.dwRemoteAddr, remote)) consider(5, r.dwOwningPid);
                else consider(0, r.dwOwningPid);
            }
        }
        const auto t6 = table(GetExtendedTcpTable, AF_INET6, TCP_TABLE_OWNER_PID_ALL);
        if (!t6.empty()) {
            const auto* t = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(t6.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& r = t->table[i];
                if (port_of(r.dwLocalPort) != local_port) continue;
                if (inbound) consider(r.dwState == MIB_TCP_STATE_LISTEN ? 4 : 1, r.dwOwningPid);
                else if (port_of(r.dwRemotePort) == remote_port && same_v6(r.ucRemoteAddr, remote)) consider(5, r.dwOwningPid);
                else consider(0, r.dwOwningPid);
            }
        }
    } else {
        const auto u4 = table(GetExtendedUdpTable, AF_INET, UDP_TABLE_OWNER_PID);
        if (!u4.empty()) {
            const auto* t = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(u4.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i)
                if (port_of(t->table[i].dwLocalPort) == local_port) consider(2, t->table[i].dwOwningPid);
        }
        const auto u6 = table(GetExtendedUdpTable, AF_INET6, UDP_TABLE_OWNER_PID);
        if (!u6.empty()) {
            const auto* t = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(u6.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i)
                if (port_of(t->table[i].dwLocalPort) == local_port) consider(1, t->table[i].dwOwningPid);
        }
    }
    return best;
}

namespace {

struct UnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};
using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

std::string command_line(HANDLE h) {
    // ProcessCommandLineInformation (60), Windows 8.1+. Needs only limited query rights.
    static auto fn = reinterpret_cast<NtQueryInformationProcessFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess")));
    if (!fn) return {};
    ULONG len = 0;
    std::vector<char> buf(1024);
    LONG st = fn(h, 60, buf.data(), static_cast<ULONG>(buf.size()), &len);
    if (st < 0 && len > buf.size() && len < (1u << 20)) {
        buf.resize(len);
        st = fn(h, 60, buf.data(), static_cast<ULONG>(buf.size()), &len);
    }
    if (st < 0) return {};
    const auto* us = reinterpret_cast<const UnicodeString*>(buf.data());
    if (!us->Buffer || !us->Length) return {};
    std::string s = ProcResolver::utf8(us->Buffer, us->Length / sizeof(wchar_t));
    if (s.size() > 400) s = s.substr(0, 400) + "...";
    return s;
}

std::string process_user(HANDLE h) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(h, TOKEN_QUERY, &token)) return {};
    std::string out;
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<char> buf(size);
    if (size && GetTokenInformation(token, TokenUser, buf.data(), size, &size)) {
        const auto* tu = reinterpret_cast<const TOKEN_USER*>(buf.data());
        wchar_t name[256], domain[256];
        DWORD nlen = 256, dlen = 256;
        SID_NAME_USE use;
        if (LookupAccountSidW(nullptr, tu->User.Sid, name, &nlen, domain, &dlen, &use))
            out = ProcResolver::utf8(name);
    }
    CloseHandle(token);
    return out;
}

}  // namespace

ProcInfo ProcResolver::describe_pid(uint32_t pid) {
    ProcInfo p;
    p.pid = static_cast<int>(pid);
    if (pid == 4) {  // the kernel itself (SMB, NetBIOS, HTTP.sys...)
        p.exe = p.name = "System";
        p.user = "SYSTEM";
        return p;
    }
    if (pid == 0) {
        p.name = "System Idle Process";
        return p;
    }
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return p;
    wchar_t path[32768];
    DWORD len = static_cast<DWORD>(std::size(path));
    if (QueryFullProcessImageNameW(h, 0, path, &len)) {
        p.exe = utf8(path, len);
        const auto slash = p.exe.find_last_of("\\/");
        p.name = slash == std::string::npos ? p.exe : p.exe.substr(slash + 1);
    }
    p.user = process_user(h);
    p.cmdline = command_line(h);
    CloseHandle(h);
    return p;
}

ProcInfo ProcResolver::find(uint8_t proto, const IpAddr& local, uint16_t local_port, const IpAddr& remote,
                            uint16_t remote_port, bool inbound) {
    int pid = -1;
    const int64_t now = now_ms();
    {
        std::lock_guard<std::mutex> lock(mu_);
        const auto it = sockets_.find((uint32_t(proto) << 16) | local_port);
        if (it != sockets_.end() && now - it->second.second < kSocketMemoryMs) pid = static_cast<int>(it->second.first);
    }
    if (pid < 0) pid = pid_from_tables(proto, local, local_port, remote, remote_port, inbound);
    if (pid < 0) return {};

    std::lock_guard<std::mutex> lock(mu_);
    const auto it = described_.find(static_cast<uint32_t>(pid));
    if (it != described_.end() && now - it->second.second < kDescribeCacheMs) return it->second.first;
    ProcInfo info = describe_pid(static_cast<uint32_t>(pid));
    described_[static_cast<uint32_t>(pid)] = {info, now};
    if (described_.size() > 4096) described_.clear();
    return info;
}

std::string own_exe_dir() {
    wchar_t buf[MAX_PATH * 4];
    const DWORD n = GetModuleFileNameW(nullptr, buf, DWORD(sizeof(buf) / sizeof(buf[0])));
    if (n == 0 || n >= sizeof(buf) / sizeof(buf[0])) return {};
    std::string path = ProcResolver::utf8(buf, n);
    const size_t slash = path.find_last_of("\\/");
    return slash == std::string::npos ? std::string() : path.substr(0, slash);
}

}  // namespace vartad
