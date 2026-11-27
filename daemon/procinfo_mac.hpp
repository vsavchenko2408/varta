// vartad - finds which process owns a socket (macOS, libproc based).
//
// How it works: proc_listallpids() lists every process; proc_pidinfo(PROC_PIDLISTFDS) lists a
// process' file descriptors and proc_pidfdinfo(PROC_PIDFDSOCKETINFO) describes each socket
// (protocol, local/remote address and port). This is what lsof does. A table of all sockets is
// cached and rebuilt when a lookup misses.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

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
    struct Sock {
        int pid = 0;
        uint8_t proto = 0;
        uint16_t lport = 0, fport = 0;
        IpAddr laddr, faddr;  // faddr unset (all zero) for listening / unconnected sockets
        bool connected = false;
    };
    int lookup(uint8_t proto, const IpAddr& local, uint16_t lport, const IpAddr& remote, uint16_t rport,
               bool inbound) const;
    void rebuild();

    std::vector<Sock> socks_;
    int64_t built_ms_ = 0;
};

}  // namespace vartad
