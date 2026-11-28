// vartad - PowerShell scripts that let vartad manage Windows Defender Firewall for incoming
// traffic (setting block_inbound). Portable so the generated scripts can be unit-tested.
//
//  * enable_script: remembers the current profile settings once (CSV backup), then turns the
//    firewall on for all profiles with inbound blocked by default and its "Do you want to allow
//    ... networks" pop-ups off. Outgoing traffic stays allowed (Varta handles it).
//  * sync_script: makes the rule group "Varta (allowed inbound)" contain exactly one allow rule
//    per program you allowed incoming connections for in Varta.
//  * restore_script: puts the remembered profile settings back and removes Varta's rules.
#pragma once

#include <set>
#include <string>

namespace vartad::winfw {

inline constexpr const char* kGroup = "Varta (allowed inbound)";

std::string ps_quote(const std::string& s);  // 'single-quoted' PowerShell string
std::string enable_script(const std::string& backup_csv);
std::string sync_script(const std::set<std::string>& programs);
std::string restore_script(const std::string& backup_csv);

}  // namespace vartad::winfw
