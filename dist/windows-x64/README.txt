Varta for Windows - prebuilt service (cross-compiled with MinGW-w64, not yet run on real Windows)

vartad.exe        interactive firewall service
varta.exe         static tracker/telemetry blocker (hosts + Windows Firewall)
WinDivert.dll/.sys  unmodified official WinDivert 2.2.2 (LGPL v3, see WinDivert-LICENSE.txt);
                  release zip SHA-256 63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15
install.ps1       run in an Administrator PowerShell

The GUI (varta-gui.exe) needs Qt for Windows and is NOT in this folder.
Get the complete package from GitHub Actions (artifact "Varta-windows-x64") or build it,
see README.md, section "Windows".
Without the GUI the service still works: it applies your rules and, with no GUI connected,
uses no_gui_action (default: allow) for unknown connections. Mode "deny" blocks everything unknown.
