#include "winfw.hpp"

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

std::string sync_script(const std::set<std::string>& programs) {
    std::ostringstream o;
    o << "$g = " << ps_quote(kGroup) << "\n"
      << "$want = @(";
    bool first = true;
    for (const auto& p : programs) {
        o << (first ? "" : ", ") << ps_quote(p);
        first = false;
    }
    o << ")\n"
      << "$have = @{}\n"
      // -contains / ContainsKey compare case-insensitively, like Windows paths.
      << "Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue | ForEach-Object {\n"
      << "  $p = ($_ | Get-NetFirewallApplicationFilter).Program\n"
      << "  if ($want -notcontains $p -or $have.ContainsKey($p)) { $_ | Remove-NetFirewallRule } else { $have[$p] = 1 }\n"
      << "}\n"
      << "foreach ($w in $want) {\n"
      << "  if (-not $have.ContainsKey($w)) {\n"
      << "    New-NetFirewallRule -DisplayName ('Varta: ' + (Split-Path $w -Leaf)) -Group $g "
         "-Direction Inbound -Action Allow -Program $w -Profile Any | Out-Null\n"
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
