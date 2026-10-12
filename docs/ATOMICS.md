# Atomic Red Team tests — what runs in CI and why it is safe

**Where:** only in the `telemetry` job, on a GitHub-hosted `windows-latest` runner: a
fresh virtual machine created for the job and **destroyed when the job ends**. Never on
a personal, school or company machine.

**What:** 8 standard tests from the official `atomics/` folder of
[redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team), pinned to
commit `388942ad…`, run by GUID with Invoke-AtomicRedTeam 2.3.0. No test is modified, no
custom attack code exists in this repository.

**Selection rules:**
- payload is benign (prints text, lists information, or creates an object that points
  to nothing harmful);
- every test that creates something has an official **cleanup** command, which the
  harness runs right after the test;
- no network download, no credential access, no security-tool tampering, no log
  clearing, no lateral movement (a unit test, `test_no_forbidden_technique_families_in_the_plan`,
  fails if such a technique is added to `lab/atomics.yaml`).

| ID | Technique (ATT&CK v19) | Atomic test (GUID) | What it really does | Cleanup |
|---|---|---|---|---|
| A1 | T1027 Obfuscated Files or Information | Execute base64-encoded PowerShell (`a50d5a97`) | `powershell -EncodedCommand` of `Write-Host "Hey, Atomic!"` | nothing created |
| A2 | T1053.005 Scheduled Task | Scheduled task Local (`42f53695`) | `schtasks /create /tn spawn /tr cmd.exe /sc once /st 20:10` (the job is over long before) | `schtasks /delete /tn spawn` |
| A3 | T1547.001 Registry Run Keys | Reg Key Run (`e55be3fd`) | HKCU Run value → `C:\Path\AtomicRedTeam.exe` (file does not exist) | value deleted |
| A4 | T1082 System Information Discovery | System Information Discovery (`66703791`) | `systeminfo`, `reg query` of disk enum key | nothing created |
| A5 | T1087.001 Local Account discovery | Enumerate all accounts on Windows (Local) (`80887bec`) | `net user`, `dir C:\Users`, `cmdkey /list`, `net localgroup` | nothing created |
| A6 | T1033 System Owner/User Discovery | User Discovery - whoami (`aab580c7`) | `whoami /all` | nothing created |
| A7 | T1218.005 Mshta | Mshta used to Execute PowerShell (`8707a805`) | `mshta` inline script starts PowerShell `Write-Host "Hello, MSHTA!"` | nothing created |
| A8 | T1136.001 Local Account | Create a new user in a command prompt (`6657864e`) | `net user /add T1136.001_CMD <test password>` | `net user /del` |

Note on ATT&CK v19: the T1027 test is mapped by Atomic Red Team to the parent technique;
my rule dvl_001 uses the precise sub-technique **T1027.010 Command Obfuscation**. Both
T1027.010 and T1218.005 are under the **Stealth** tactic (TA0005) in v19, which replaced
the former "Defense Evasion" name.

**What these tests are not:** a real adversary. They run in the open, with default
arguments, without evasion. A rule that catches them proves the telemetry pipeline and
the rule logic work on real Windows events — not that the rule catches a skilled
attacker. That is why the gates also check silence on clean logs (goodlog) and on a
third-party attack corpus.
