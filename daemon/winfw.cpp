#include "winfw.hpp"

#include <cstdio>
#include <sstream>

namespace vartad::winfw {

std::string ps_quote(const std::string& s) {
    std::string o = "'";
    for (char c : s) {
        o += c;
        if (c == '\'') o += '\'';  // '' inside a single-quoted PowerShell string
    }
    return o + "'";
}

std::string enable_script(const std::string& backup_csv) {
    std::ostringstream o;
    o << "$ErrorActionPreference = 'Stop'\n"
      << "$b = " << ps_quote(backup_csv) << "\n"
      << "if (-not (Test-Path -LiteralPath $b)) {\n"
      << "  Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, NotifyOnListen |\n"
      << "    Export-Csv -NoTypeInformation -LiteralPath $b\n"
      << "}\n"
      << "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True "
         "-DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen False\n";
    return o.str();
}

static std::string key(const InboundAllow& r) {
    return r.program + "|" + r.protocol + "|" + std::to_string(r.local_port) + "|" + r.remote;
}

bool InboundAllow::operator<(const InboundAllow& o) const { return key(*this) < key(o); }

std::string InboundAllow::name() const {
    // FNV-1a over the lower-cased key: the same decision always maps to the same rule.
    uint64_t h = 1469598103934665603ull;
    for (char c : key(*this)) {
        const unsigned char u = static_cast<unsigned char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
        h = (h ^ u) * 1099511628211ull;
    }
    char buf[32];
    std::snprintf(buf, sizeof buf, "Varta-%016llx", static_cast<unsigned long long>(h));
    return buf;
}

std::string InboundAllow::display_name() const {
    std::string leaf = program.substr(program.find_last_of("\\/") == std::string::npos ? 0 : program.find_last_of("\\/") + 1);
    std::string d = "Varta: " + leaf;
    std::string extra;
    if (!protocol.empty()) extra += protocol + (local_port ? " " + std::to_string(local_port) : "");
    if (!remote.empty()) extra += (extra.empty() ? "from " : " from ") + remote;
    return extra.empty() ? d : d + " (" + extra + ")";
}

std::string sync_script(const std::set<InboundAllow>& rules) {
    std::ostringstream o;
    o << "$g = " << ps_quote(kGroup) << "\n"
      << "$want = @(\n";
    for (const auto& r : rules) {
        o << "  @{ Name = " << ps_quote(r.name()) << "; DisplayName = " << ps_quote(r.display_name())
          << "; Program = " << ps_quote(r.program);
        if (!r.protocol.empty()) {
            o << "; Protocol = " << ps_quote(r.protocol);
            if (r.local_port) o << "; LocalPort = " << ps_quote(std::to_string(r.local_port));
        }
        if (!r.remote.empty()) o << "; RemoteAddress = " << ps_quote(r.remote);
        o << " }\n";
    }
    o << ")\n"
      << "$names = @($want | ForEach-Object { $_.Name })\n"
      << "$have = @{}\n"
      << "Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue | ForEach-Object {\n"
      << "  if ($names -notcontains $_.Name) { $_ | Remove-NetFirewallRule } else { $have[$_.Name] = 1 }\n"
      << "}\n"
      << "foreach ($w in $want) {\n"
      << "  if (-not $have.ContainsKey($w.Name)) {\n"
      << "    New-NetFirewallRule @w -Group $g -Direction Inbound -Action Allow -Profile Any | Out-Null\n"
      << "  }\n"
      << "}\n";
    return o.str();
}

std::string restore_script(const std::string& backup_csv) {
    std::ostringstream o;
    o << "$g = " << ps_quote(kGroup) << "\n"
      << "Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n"
      << "$b = " << ps_quote(backup_csv) << "\n"
      << "if (Test-Path -LiteralPath $b) {\n"
      << "  Import-Csv -LiteralPath $b | ForEach-Object {\n"
      << "    Set-NetFirewallProfile -Name $_.Name -Enabled $_.Enabled "
         "-DefaultInboundAction $_.DefaultInboundAction -NotifyOnListen $_.NotifyOnListen\n"
      << "  }\n"
      << "  Remove-Item -LiteralPath $b\n"
      << "}\n";
    return o.str();
}

}  // namespace vartad::winfw
