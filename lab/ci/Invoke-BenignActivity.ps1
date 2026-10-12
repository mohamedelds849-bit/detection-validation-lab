# Benign phase: normal admin activity, including NEAR-MISSES that look like the
# detections but must NOT raise an alert (building blocks are allowed).
# Each line says which rule it challenges.

. (Join-Path $PSScriptRoot 'common.ps1')

$start = Get-UtcStamp
Start-Sleep -Seconds 1

# dvl_001: v1 fired on "-Encoding ascii" (real Office setup command, baseline). Same pattern here.
Invoke-Logged 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-Date | Out-File -FilePath $env:TEMP\dvl-benign.txt -Encoding ascii"'
# dvl_001: -ExecutionPolicy starts with -e but is not -EncodedCommand
Invoke-Logged 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-Service -Name Sysmon64 | Select-Object -ExpandProperty Status"'

# dvl_002: reading and deleting tasks is not creating one
Invoke-Logged 'schtasks.exe /Query /FO LIST /TN "\Microsoft\Windows\Defrag\ScheduledDefrag"'
Invoke-Logged 'schtasks.exe /Query /FO CSV'

# dvl_003: reading the Run key, and writing a key that is not Run
Invoke-Logged 'reg.exe query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"'
Invoke-Logged 'reg.exe add "HKCU\Software\DetectionValidationLab" /v Benign /t REG_SZ /d hello /f'
Invoke-Logged 'reg.exe delete "HKCU\Software\DetectionValidationLab" /f'

# dvl_004 / dvl_005: two different recon commands from ONE parent = building blocks,
# under the burst threshold (3 distinct command lines in 5 minutes)
Invoke-Logged 'whoami & net localgroup'

# dvl_007 / dvl_008: listing users is not creating one
Invoke-Logged 'net user runneradmin'
Invoke-Logged 'powershell.exe -NoProfile -Command "Get-LocalUser | Select-Object -First 3 Name"'

Start-Sleep -Seconds 2
$end = Get-UtcStamp
Add-Phase -Id 'benign' -Start $start -End $end
Write-Host "benign phase: $start -> $end"
# Gap so the next phase cannot fall into this window's grace period.
Start-Sleep -Seconds 8
