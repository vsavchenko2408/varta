// vartad - finds which process owns a socket (Linux /proc based).
//
// How it works:
//   1. /proc/net/{tcp,tcp6,udp,udp6} list every socket with its local/remote address and inode.
//   2. /proc/<pid>/fd/* are symlinks like "socket:[12345]" -> inode-to-pid map.
//   3. /proc/<pid>/exe, cmdline and status give program path, arguments and user.
// Limitation: a process that sends one UDP packet and exits immediately may be gone before
// we look. eBPF would close that gap and is planned as a later backend.
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

#include "engine.hpp"  // ProcInfo
#include "packet.hpp"

namespace vartad {


class ProcResolver {
public:
    // inbound=false: socket bound to local_port talking to remote (outgoing connection).
    // inbound=true:  listening/bound socket on local_port receiving a new connection.
    ProcInfo find(uint8_t proto, const IpAddr& local, uint16_t local_port, const IpAddr& remote,
                  uint16_t remote_port, bool inbound);

    static ProcInfo describe_pid(int pid);
    static std::string user_name(uint32_t uid);

private:
    struct SockEntry {
        uint64_t inode = 0;
        uint32_t uid = 0;
    };
    bool find_inode(uint8_t proto, const IpAddr& local, uint16_t local_port, const IpAddr& remote,
                    uint16_t remote_port, bool inbound, SockEntry& out);
    int pid_for_inode(uint64_t inode);
    void rebuild_inode_map();

    std::unordered_map<uint64_t, int> inode_pid_;
};

}  // namespace vartad
