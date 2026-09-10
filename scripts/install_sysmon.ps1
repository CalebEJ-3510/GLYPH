<#
.SYNOPSIS
    Downloads Sysmon and applies the keylogger-detection-optimized config.

.DESCRIPTION
    This script:
      1. Downloads Sysmon64 from the official Sysinternals URL.
      2. Installs / updates Sysmon with the bundled config in docs/sysmon_config.xml.

    Run from an elevated (Administrator) PowerShell prompt inside the VM.

.NOTES
    Intended for use in an ISOLATED LAB VM only.
    Do NOT run on production systems.
#>

[CmdletBinding()]
param(
    [string]$SysmonUrl  = "https://download.sysinternals.com/files/Sysmon.zip",
    [string]$ConfigPath = "$PSScriptRoot\..\docs\sysmon_config.xml",
    [string]$InstallDir = "$env:TEMP\sysmon_install"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "[*] Glyph — Sysmon Installer" -ForegroundColor Cyan
Write-Host "[*] Target config: $ConfigPath"

# 1. Create working directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

# 2. Download Sysmon
$zipPath = Join-Path $InstallDir "Sysmon.zip"
if (-not (Test-Path $zipPath)) {
    Write-Host "[*] Downloading Sysmon from $SysmonUrl ..."
    Invoke-WebRequest -Uri $SysmonUrl -OutFile $zipPath -UseBasicParsing
} else {
    Write-Host "[*] Sysmon zip already present, skipping download."
}

Expand-Archive -Path $zipPath -DestinationPath $InstallDir -Force
$sysmonExe = Join-Path $InstallDir "Sysmon64.exe"
if (-not (Test-Path $sysmonExe)) {
    $sysmonExe = Join-Path $InstallDir "Sysmon.exe"
}
Write-Host "[+] Sysmon binary: $sysmonExe"

# 3. Verify config exists
if (-not (Test-Path $ConfigPath)) {
    Write-Error "Config not found at $ConfigPath"
}

# 4. Install / update Sysmon
$sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($null -eq $sysmonService) {
    $sysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
}

if ($null -ne $sysmonService) {
    Write-Host "[*] Sysmon already installed — updating config ..."
    & $sysmonExe -c $ConfigPath
} else {
    Write-Host "[*] Installing Sysmon ..."
    & $sysmonExe -accepteula -i $ConfigPath
}

Write-Host "[+] Sysmon installed/updated successfully." -ForegroundColor Green
Write-Host "[*] Verify with: Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5"