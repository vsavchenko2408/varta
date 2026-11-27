# Installs Varta on Windows: run in an Administrator PowerShell from the unpacked folder.
#   Set-ExecutionPolicy -Scope Process Bypass; .\install.ps1
$ErrorActionPreference = "Stop"
$src = $PSScriptRoot
$dst = Join-Path $env:ProgramFiles "Varta"

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Please run this script from an Administrator PowerShell." }

foreach ($f in "vartad.exe", "WinDivert.dll", "WinDivert64.sys") {
    if (-not (Test-Path (Join-Path $src $f))) { throw "$f is missing in $src" }
}

# The driver must carry a valid signature (it is the unmodified official WinDivert build).
$sig = Get-AuthenticodeSignature (Join-Path $src "WinDivert64.sys")
if ($sig.Status -ne "Valid") { throw "WinDivert64.sys signature is not valid: $($sig.Status)" }
Write-Host "WinDivert64.sys signed by: $($sig.SignerCertificate.Subject)"

# Stop an older version first.
Get-Process varta-gui -ErrorAction SilentlyContinue | Stop-Process -Force
if (Get-Service vartad -ErrorAction SilentlyContinue) {
    Write-Host "==> Stopping the old vartad service"
    & (Join-Path $dst "vartad.exe") --uninstall-service | Out-Host
}

Write-Host "==> Copying files to $dst"
New-Item -ItemType Directory -Force $dst | Out-Null
# Copy file by file and skip unchanged ones: Windows keeps the WinDivert driver loaded (and
# its file locked) after vartad stops, so overwriting an identical WinDivert64.sys would fail.
Get-ChildItem -Recurse -File $src | ForEach-Object {
    $rel = $_.FullName.Substring($src.Length).TrimStart('\')
    $target = Join-Path $dst $rel
    if ((Test-Path $target) -and ((Get-FileHash $target).Hash -eq (Get-FileHash $_.FullName).Hash)) { return }
    New-Item -ItemType Directory -Force (Split-Path $target) | Out-Null
    Copy-Item -Force $_.FullName $target
}

Write-Host "==> Downloading the offline IP database (~90 MB)"
& (Join-Path $dst "vartad.exe") --update-db
if ($LASTEXITCODE -ne 0) { Write-Warning "IP database download failed - run 'vartad --update-db' later." }

Write-Host "==> Installing and starting the service"
& (Join-Path $dst "vartad.exe") --install-service
if ($LASTEXITCODE -ne 0) { throw "service installation failed - see $env:ProgramData\Varta\vartad.log" }

$gui = Join-Path $dst "varta-gui.exe"
if (Test-Path $gui) {
    Write-Host "==> Start menu entry and autostart for the GUI"
    $shell = New-Object -ComObject WScript.Shell
    $menu = Join-Path ([Environment]::GetFolderPath("CommonPrograms")) "Varta Firewall.lnk"
    $lnk = $shell.CreateShortcut($menu); $lnk.TargetPath = $gui; $lnk.Save()
    $startup = Join-Path ([Environment]::GetFolderPath("CommonStartup")) "Varta Firewall.lnk"
    $lnk = $shell.CreateShortcut($startup); $lnk.TargetPath = $gui; $lnk.Arguments = "--hidden"; $lnk.Save()
    Start-Process $gui
}

Write-Host ""
Write-Host "Done. Varta is running. Emergency stop:  sc stop vartad"
Write-Host "Log file: $env:ProgramData\Varta\vartad.log"
