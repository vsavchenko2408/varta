// Varta - OS specific paths, privilege checks, DNS cache flush and autostart.
#pragma once

#include <string>

namespace varta {

struct Paths {
    std::string home;       // config + state directory
    std::string config;     // varta.conf
    std::string hosts;      // system hosts file
    std::string backup;     // original hosts backup
    std::string lists_dir;  // downloaded lists
    std::string work_dir;   // generated firewall scripts
};

Paths default_paths();
Paths paths_for_home(const std::string& home, const std::string& hosts);

bool is_admin();
const char* admin_hint();  // "run with sudo" / "run from an Administrator terminal"

void flush_dns_cache();

std::string executable_path();

// Linux: systemd unit, macOS: LaunchDaemon. Windows rules persist, so nothing to do there.
bool autostart_enable(std::string& msg);
bool autostart_disable(std::string& msg);

// Enables ANSI colours and UTF-8 on the Windows console; no-op elsewhere.
void init_console();

}  // namespace varta
