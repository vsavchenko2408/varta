// vartad - PowerShell scripts that let vartad manage Windows Defender Firewall for incoming
// traffic (setting block_inbound). Portable so the generated scripts can be unit-tested.
//
//  * enable_script: remembers the current profile settings once (CSV backup), then turns the
//    firewall on for all profiles with inbound blocked by default and its "Do you want to allow
//    ... networks" pop-ups off. Outgoing traffic stays allowed (Varta handles it).
//  * sync_script: makes the rule group "Varta (allowed inbound)" contain exactly the given
//    allow rules - one per incoming connection YOU allowed in Varta (never for Varta's
//    built-in defaults), as narrow as that decision: program, protocol, local port, remote
//    address.
//  * restore_script: puts the remembered profile settings back and removes Varta's rules.
#pragma once

#include <cstdint>
#include <set>
#include <string>

namespace vartad::winfw {

inline constexpr const char* kGroup = "Varta (allowed inbound)";

struct InboundAllow {
    std::string program;   // full path, or "System" for the kernel
    std::string protocol;  // "TCP", "UDP" or "" (any)
    uint16_t local_port = 0;  // 0 = any (only used with TCP/UDP)
    std::string remote;    // address or CIDR, "" = any

    std::string name() const;          // stable rule Name: Varta-<hash>
    std::string display_name() const;  // "Varta: app.exe (TCP 445 from 1.2.3.4)"
    bool operator<(const InboundAllow& o) const;
};

std::string ps_quote(const std::string& s);  // 'single-quoted' PowerShell string
std::string enable_script(const std::string& backup_csv);
std::string sync_script(const std::set<InboundAllow>& rules);
std::string restore_script(const std::string& backup_csv);

}  // namespace vartad::winfw
