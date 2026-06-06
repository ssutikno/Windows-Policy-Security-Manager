<#
.SYNOPSIS
    Installs and registers the WWPO Client Agent as a Windows Service.
.DESCRIPTION
    Creates C:\ProgramData\WWPO, configures access permissions, generates config.json,
    registers the WWPOAgent service, and starts it.
#>

# Enforce Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator."
    Exit 1
}

$MasterIP = Read-Host -Prompt "Enter WWPO Master Server IP/FQDN (e.g., 192.168.1.100 or localhost)"
$MasterPort = Read-Host -Prompt "Enter Master Port [8080]"
if ([string]::IsNullOrWhiteSpace($MasterPort)) { $MasterPort = "8080" }

$SetupToken = Read-Host -Prompt "Enter Enrollment Setup Token"

$TargetDir = "C:\ProgramData\WWPO"
if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}

# Copy agent binary
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$BinarySrc = Join-Path $ScriptPath "agent.exe"
$BinaryDest = Join-Path $TargetDir "agent.exe"

if (Test-Path $BinarySrc) {
    Copy-Item $BinarySrc $BinaryDest -Force
} else {
    Write-Error "agent.exe not found in installer directory."
    Exit 1
}

# Create config.json
$Config = @{
    master_ip = $MasterIP
    master_port = [int]$MasterPort
    agent_id = ""
    connection_secret = ""
    setup_token = $SetupToken
}
$ConfigJson = $Config | ConvertTo-Json -Depth 5
$ConfigPath = Join-Path $TargetDir "config.json"
Set-Content -Path $ConfigPath -Value $ConfigJson -Encoding utf8

# Lock down permissions to SYSTEM and Administrators only
icacls $TargetDir /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" "BUILTIN\Administrators:(OI)(CI)(F)" /t | Out-Null

# Install Service
$ServiceName = "WWPOAgent"
$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($Service) {
    Write-Host "Updating existing WWPOAgent service..."
    Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Remove-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

Write-Host "Registering WWPOAgent Windows Service..."
New-Service -Name $ServiceName -BinaryPathName "`"$BinaryDest`"" -DisplayName "WWPO Client Agent" -Description "Manages security configuration and enforcements for WWPO Workgroups." -StartupType Automatic | Out-Null

# Start Service
Write-Host "Starting WWPOAgent service..."
Start-Service -Name $ServiceName
Write-Host "Installation completed successfully! Check C:\ProgramData\WWPO for configurations."
