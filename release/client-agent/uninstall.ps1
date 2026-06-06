<#
.SYNOPSIS
    Uninstalls the WWPO Client Agent and removes the WWPOAgent service.
#>

# Enforce Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator."
    Exit 1
}

$ServiceName = "WWPOAgent"
$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($Service) {
    Write-Host "Stopping WWPOAgent service..."
    Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Write-Host "Deleting WWPOAgent service..."
    Remove-Service -Name $ServiceName -ErrorAction SilentlyContinue
}

$TargetDir = "C:\ProgramData\WWPO"
if (Test-Path $TargetDir) {
    Write-Host "Removing installation files at $TargetDir..."
    Remove-Item -Path $TargetDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "WWPO Client Agent successfully uninstalled."
