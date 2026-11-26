// Varta - firewall backends.
//
// Each backend is split in two parts:
//   * a pure generator that turns a RuleSet into a script (testable on any OS), and
//   * apply/remove/status functions that hand the script to the native tool:
//       Linux   -> nftables  (`nft -f`, own table "inet varta")
//       macOS   -> pf        (`pfctl -a com.apple/varta -f`, own anchor)
//       Windows -> Windows Defender Firewall via PowerShell (rule group "Varta")
#pragma once

#include <string>

#include "rules.hpp"

namespace varta {

enum class Os { Linux, MacOS, Windows };

Os current_os();
const char* os_name(Os os);
bool parse_os(const std::string& s, Os& out);

std::string generate_nft(const RuleSet& rs);
std::string generate_pf(const RuleSet& rs);
// diagtrack: also disable the Windows telemetry service.
std::string generate_powershell_apply(const RuleSet& rs, bool diagtrack);
std::string generate_powershell_remove(bool restore_diagtrack);

std::string generate_firewall(Os os, const RuleSet& rs, bool diagtrack);

struct FirewallStatus {
    bool active = false;
    std::string details;
};

// work_dir: where generated scripts are written before being applied.
bool firewall_apply(const RuleSet& rs, const std::string& work_dir, bool diagtrack,
                    std::string& err);
bool firewall_remove(const std::string& work_dir, bool restore_diagtrack, std::string& err);
FirewallStatus firewall_status(bool verbose);

}  // namespace varta
