# Signing Firewall - one-command installer (Windows PowerShell)
# Usage: irm https://raw.githubusercontent.com/adityaaravind/signing-firewall/main/install.ps1 | iex
$ErrorActionPreference = "Stop"
$Repo = "adityaaravind/signing-firewall"
$InstallDir = Join-Path $env:LOCALAPPDATA "signing-firewall\bin"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$Dest = Join-Path $InstallDir "signing-firewall.py"
if (Test-Path "signing-firewall.py") {
  Write-Host "Installing local signing-firewall.py ..."
  Copy-Item "signing-firewall.py" $Dest -Force
} else {
  Write-Host "Downloading signing-firewall.py from GitHub ..."
  Invoke-WebRequest -Uri "https://raw.githubusercontent.com/$Repo/main/signing-firewall.py" -OutFile $Dest
}
Write-Host ""
Write-Host "Installed to $Dest"
Write-Host "Run it with:"
Write-Host "  python $Dest serve"
Write-Host "  python $Dest dashboard"
Write-Host ""
Write-Host "Web app will be at http://127.0.0.1:8765/ when serve is running."
