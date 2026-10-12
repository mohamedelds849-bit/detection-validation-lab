# Export the event logs the rules read to work\evtx\*.evtx and build work\manifest.json
# (environment + phase windows). These EVTX files are uploaded as a CI artifact: real
# telemetry that can be opened in Event Viewer or re-hunted with Chainsaw.

. (Join-Path $PSScriptRoot 'common.ps1')

Start-Sleep -Seconds 5   # let Sysmon flush
$out = Join-Path $script:Work 'evtx'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$channels = @(
    'Microsoft-Windows-Sysmon/Operational',
    'Security',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-TaskScheduler/Operational'
)
foreach ($c in $channels) {
    $file = Join-Path $out (($c -replace '[/ ]', '_') + '.evtx')
    wevtutil epl $c $file /ow:true
    if ($LASTEXITCODE -ne 0) { Write-Warning "could not export $c" } else { Write-Host "exported $c" }
}

$manifest = [ordered]@{}
$envFile = Join-Path $script:Work 'environment.json'
if (Test-Path $envFile) {
    (Get-Content -Raw $envFile | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $manifest[$_.Name] = $_.Value }
}
$manifest['phases'] = @(Get-Content $script:PhaseFile | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $script:Work 'manifest.json') -Encoding utf8
Write-Host "manifest: $($manifest['phases'].Count) phases"
