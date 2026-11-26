# Removes Varta. Rules and settings in %ProgramData%\Varta are kept unless you pass -Purge.
param([switch]$Purge)
$ErrorActionPreference = "Continue"
$dst = Join-Path $env:ProgramFiles "Varta"
Get-Process varta-gui -ErrorAction SilentlyContinue | Stop-Process -Force
if (Test-Path (Join-Path $dst "vartad.exe")) { & (Join-Path $dst "vartad.exe") --uninstall-service }
Remove-Item -Force (Join-Path ([Environment]::GetFolderPath("CommonPrograms")) "Varta Firewall.lnk") -ErrorAction SilentlyContinue
Remove-Item -Force (Join-Path ([Environment]::GetFolderPath("CommonStartup")) "Varta Firewall.lnk") -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2   # let the driver handle close before deleting the files
Remove-Item -Recurse -Force $dst -ErrorAction SilentlyContinue
if ($Purge) { Remove-Item -Recurse -Force (Join-Path $env:ProgramData "Varta") }
Write-Host "Varta removed."
