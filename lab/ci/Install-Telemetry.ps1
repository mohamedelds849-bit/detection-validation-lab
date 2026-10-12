# Install the telemetry stack on the disposable Windows runner:
#   - Sysmon (latest from Sysinternals; its version is recorded in the manifest)
#     with the SwiftOnSecurity configuration pinned to one commit + SHA-256 check
#   - audit policy "User Account Management" (Security 4720) by GUID, so it works
#     whatever the OS language
#   - Invoke-AtomicRedTeam + powershell-yaml from the PowerShell Gallery (pinned)
#   - only the atomics YAML files we run, from the pinned atomic-red-team commit
# Run as administrator (GitHub-hosted Windows runners are).

. (Join-Path $PSScriptRoot 'common.ps1')

$SysmonConfigCommit = '1836897f12fbd6a0a473665ef6abc34a6b497e31'
$SysmonConfigSha256 = '055febc600e6d7448cdf3812307275912927a62b1f94d0d933b64b294bc87162'
$AtomicsCommit      = '388942adbd9641f4dfdcf079d7efe9a75ec0ac43'
$InvokeArtVersion   = '2.3.0'
$PsYamlVersion      = '0.4.12'
$Techniques         = @('T1027', 'T1053.005', 'T1547.001', 'T1082', 'T1087.001', 'T1033', 'T1218.005', 'T1136.001')

$tmp = Join-Path $script:Work 'install'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

Write-Host '== Sysmon'
$zip = Join-Path $tmp 'Sysmon.zip'
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip -UseBasicParsing
Expand-Archive -Path $zip -DestinationPath (Join-Path $tmp 'sysmon') -Force
$config = Join-Path $tmp 'sysmonconfig.xml'
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/$SysmonConfigCommit/sysmonconfig-export.xml" -OutFile $config -UseBasicParsing
$hash = (Get-FileHash -Algorithm SHA256 $config).Hash.ToLower()
if ($hash -ne $SysmonConfigSha256) { throw "Sysmon config SHA-256 mismatch: $hash" }
$sysmonExe = Join-Path $tmp 'sysmon\Sysmon64.exe'
& $sysmonExe -accepteula -i $config | Out-Host
if ($LASTEXITCODE -ne 0) { throw "Sysmon install failed ($LASTEXITCODE)" }
wevtutil sl 'Microsoft-Windows-Sysmon/Operational' /ms:268435456
$svc = Get-Service -Name Sysmon64
if ($svc.Status -ne 'Running') { throw 'Sysmon64 service is not running' }
$sysmonVersion = (Get-Item $sysmonExe).VersionInfo.FileVersion
Write-Host "Sysmon $sysmonVersion running"

Write-Host '== Audit policy'
# {0CCE9235-...} = User Account Management (4720 user created)
auditpol /set /subcategory:'{0CCE9235-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Host
wevtutil sl Security /ms:268435456

Write-Host '== Invoke-AtomicRedTeam'
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name powershell-yaml -RequiredVersion $PsYamlVersion -Scope CurrentUser -Force
Install-Module -Name Invoke-AtomicRedTeam -RequiredVersion $InvokeArtVersion -Scope CurrentUser -Force

Write-Host '== Atomics (only the tests we run)'
$atomics = Join-Path $script:Work 'atomics'
foreach ($t in $Techniques) {
    $dir = Join-Path $atomics $t
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/$AtomicsCommit/atomics/$t/$t.yaml" `
        -OutFile (Join-Path $dir "$t.yaml") -UseBasicParsing
}

$envInfo = [ordered]@{
    host            = $env:COMPUTERNAME
    os              = (Get-CimInstance Win32_OperatingSystem).Caption + ' ' + [Environment]::OSVersion.Version.ToString()
    sysmon_version  = $sysmonVersion
    sysmon_config   = "SwiftOnSecurity/sysmon-config@$SysmonConfigCommit"
    atomics_commit  = $AtomicsCommit
    invoke_atomicredteam = $InvokeArtVersion
}
$envInfo | ConvertTo-Json | Set-Content -Path (Join-Path $script:Work 'environment.json') -Encoding utf8
Write-Host 'telemetry stack ready'
