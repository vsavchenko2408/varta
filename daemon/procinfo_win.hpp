// vartad (Windows) - finds which process owns a socket.
//
// Two sources:
//   1. WinDivert SOCKET-layer events (bind / connect / accept) carry the process id directly;
//      they are remembered per (protocol, local port). This also catches short-lived programs.
//   2. The IP Helper tables (GetExtendedTcpTable / GetExtendedUdpTable) as a fallback -
//      the Windows equivalent of /proc/net/tcp on Linux.
// The program path, user and command line come from OpenProcess / the process token / ntdll.
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

#include "engine.hpp"  // ProcInfo
#include "packet.hpp"

namespace vartad {

class ProcResolver {
public:
    ProcInfo find(uint8_t proto, const IpAddr& local, uint16_t local_port, const IpAddr& remote,
                  uint16_t remote_port, bool inbound);
    // Called from the WinDivert socket-event thread.
    void note_socket(uint8_t proto, uint16_t local_port, uint32_t pid);

    static ProcInfo describe_pid(uint32_t pid);
    static std::string utf8(const wchar_t* w, size_t len = static_cast<size_t>(-1));
    static std::wstring wide(const std::string& s);

private:
    int pid_from_tables(uint8_t proto, const IpAddr& local, uint16_t local_port, const IpAddr& remote,
                        uint16_t remote_port, bool inbound);

    std::mutex mu_;
    std::unordered_map<uint32_t, std::pair<uint32_t, int64_t>> sockets_;  // proto<<16|port -> pid, time
    std::unordered_map<uint32_t, std::pair<ProcInfo, int64_t>> described_; // pid -> info, time
};

}  // namespace vartad
