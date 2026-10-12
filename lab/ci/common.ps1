# Shared helpers for the CI telemetry job (dot-sourced by the other scripts).
# Phases are appended as JSON lines to work\phases.jsonl; Export-Evtx.ps1 builds
# work\manifest.json from them. Timestamps are UTC, ISO 8601 (same clock as Sysmon).

$ErrorActionPreference = 'Stop'
$script:Work = Join-Path $PSScriptRoot '..\..\work'
New-Item -ItemType Directory -Force -Path $script:Work | Out-Null
$script:PhaseFile = Join-Path $script:Work 'phases.jsonl'

function Get-UtcStamp {
    (Get-Date).ToUniversalTime().ToString('o')
}

function Add-Phase {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Start,
        [Parameter(Mandatory)][string]$End,
        [string]$Status = 'ok',
        [string]$Message = '',
        [string]$Guid = ''
    )
    $line = [ordered]@{ id = $Id; start = $Start; end = $End; status = $Status; message = $Message; guid = $Guid } |
        ConvertTo-Json -Compress
    Add-Content -Path $script:PhaseFile -Value $line -Encoding utf8
}

function Invoke-Logged {
    # Run a command line through cmd.exe so Sysmon sees a normal child process.
    param([Parameter(Mandatory)][string]$CommandLine)
    # Start-Process with ONE argument string passes it verbatim (no PowerShell re-quoting).
    Write-Host "  > $CommandLine"
    Start-Process -FilePath 'cmd.exe' -ArgumentList "/d /c $CommandLine" -Wait -NoNewWindow
}
