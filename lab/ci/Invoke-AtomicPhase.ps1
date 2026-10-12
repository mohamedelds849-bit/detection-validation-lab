# Run each Atomic Red Team test listed in lab/atomics.yaml inside its own time window,
# then its cleanup command OUTSIDE the window, then a gap. Only standard tests from the
# pinned atomics folder are run, by GUID (see docs/ATOMICS.md for the safety review).

. (Join-Path $PSScriptRoot 'common.ps1')
Import-Module powershell-yaml
Import-Module Invoke-AtomicRedTeam

$plan = Get-Content -Raw (Join-Path $PSScriptRoot '..\atomics.yaml') | ConvertFrom-Yaml
$atomics = Join-Path $script:Work 'atomics'

foreach ($test in $plan.tests) {
    $folder = $test.technique
    Write-Host "== $($test.id) $folder $($test.name)"
    $start = Get-UtcStamp
    $status = 'ok'; $message = ''
    try {
        Invoke-AtomicTest $folder -TestGuids $test.guid -PathToAtomicsFolder $atomics -TimeoutSeconds 60 | Out-Host
    } catch {
        $status = 'error'; $message = $_.Exception.Message
        Write-Warning "test $($test.id) failed: $message"
    }
    Start-Sleep -Seconds 3
    $end = Get-UtcStamp
    Add-Phase -Id $test.id -Start $start -End $end -Status $status -Message $message -Guid $test.guid

    # Wait past the 5 s grace period so cleanup events are never attributed to the test.
    Start-Sleep -Seconds 7
    try {
        Invoke-AtomicTest $folder -TestGuids $test.guid -PathToAtomicsFolder $atomics -Cleanup | Out-Host
    } catch {
        Write-Warning "cleanup of $($test.id) failed: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds 8
}
Write-Host 'atomic phase done'
