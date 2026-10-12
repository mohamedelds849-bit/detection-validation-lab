# Tuning log — rules v1 → v2 on real clean logs

**Dataset:** Nextron Systems `evtx-baseline` v0.8.5, `win10-client.tgz` (SHA-256
`d48f1b32…6808e`). A real Windows 10 client used normally for a while: 352 `.evtx`
files. The Sysmon log alone holds **342,116 events** (2,215 process creations, 216,136
registry value writes) and the Security log 3,448 events. The machine installed Office,
Opera, Greenshot, Zoom, iTunes, Google Drive, Spotify, K-Lite, Python and .NET runtimes:
exactly the noise a detection meets on a real endpoint.

This baseline is the one SigmaHQ itself uses for its `goodlog-tests.yml` workflow. It is
not mine, I did not write a single line of it.

**Engine:** Chainsaw 2.16.5, `sigma-event-logs-all.yml` mapping. Run locally on Windows
on 2026-10-11 (`python -m dvl hunt --evtx <baseline> ...`, about 35 s).

## Result

| Rule | v1 alert hits | v2 alert hits | What changed |
|---|---|---|---|
| dvl_001 encoded PowerShell | 2 | 0 | regex: flag **followed by a base64 blob** |
| dvl_002 schtasks /create | 11 | 1 | filter parent under Program Files |
| dvl_003 Run key written | 16 | 3 | filter targets under Program Files + WiX Burn RunOnce |
| dvl_006 mshta → shell | 0 | 0 | — |
| dvl_007 user created (4720) | 3 | 1 | filter `defaultuser0`, `WDAGUtilityAccount` |
| dvl_008 net user /add | 0 | 0 | — |
| **Total alerts** | **32** | **5** | the 5 are accepted in `lab/known_fps.yaml`, each with a reason |
| dvl_004 building block | 1 | 1 | `whoami` from PowerShell — not an alert by design |

The correlation dvl_005 never fired on the baseline (one recon command in the whole log).

## What each false positive taught

1. **dvl_001 — `-Encoding ascii` is not `-EncodedCommand`.** v1 matched the substring
   ` -en`. Office setup runs `powershell.exe ... Out-File ... -Encoding ascii`, which
   contains ` -En`. PowerShell accepts any unambiguous prefix of `-EncodedCommand`, so a
   prefix list alone is fragile. v2 requires the flag **and** a base64 argument of 20+
   characters. Tested in `tests/test_rule_logic.py` against the exact Office command.
2. **dvl_002 — installers create tasks.** 10 of 11 hits were Office Click-to-Run, whose
   parent lives under `C:\Program Files\`. Writing there needs admin rights, so that
   parent is a weaker signal. The 11th (K-Lite installer from `%TEMP%\is-*.tmp`) cannot
   be filtered in the rule: attackers also run from `%TEMP%`. It is accepted **by name**
   in the environment allow-list.
3. **dvl_003 — Run keys are written all the time by installers.** The useful question
   is not *who writes* (installers run from `%TEMP%`, like malware) but *what will run*:
   a target under `Program Files` (10 hits) needs admin rights to plant. WiX "Burn"
   bundles (.NET, Python) resume after reboot with `RunOnce … /burn.runonce` (3 hits).
   Spotify, OneDrive clean-up and `grpconv -o` remain: they are accepted by exact value,
   not filtered, because "a per-user app in AppData starting at logon" is also what
   malware looks like.
4. **dvl_007 — Windows creates accounts by itself.** `defaultuser0` (setup) and
   `WDAGUtilityAccount` (Application Guard) are built-in → filtered by name. The first
   user created during OOBE (subject = machine account) is accepted per machine.

## Rule filter vs allow-list

- **Rule filter** (in the Sigma file): true for every environment (built-in accounts,
  Program Files targets, Burn). It changes what the rule means → it is in Git history.
- **Allow-list** (`lab/known_fps.yaml`): true for *this* machine only (Spotify, K-Lite).
  Every entry needs a reason and all its conditions must match; an entry that no longer
  matches is reported as *stale*. This is how a SOC handles per-client tuning without
  weakening the shared rule.

## What tuning cost (detection side)

Every filter is a blind spot. Written down so it can be checked:
- dvl_002: a task created by a process running from `Program Files` is not seen (e.g. an
  abused vendor updater).
- dvl_003: a Run value pointing to a LOLBin under `Program Files` with malicious
  arguments is not seen; a fake `\Package Cache\…/burn.runonce` value is not seen.
- dvl_007: an attacker who names his account `defaultuser0` is not seen.

## Second real dataset: SigmaHQ regression corpus

204 real EVTX recordings of attack techniques (SigmaHQ commit `da9bb07d`), made for
*their* rules. v2 rules fire on exactly 3 files, all expected
(`lab/sigmahq_corpus_expectations.yaml`). v1 missed `WMIC useraccount get /ALL`
(account discovery) → added to dvl_004 in v2.
Two documented **gaps** remain on this corpus: `reg add …\Run` recorded with Sysmon
EID 1 only (dvl_003 reads EID 13), and user creation through `[ADSI]` in PowerShell
(dvl_008 only sees `net.exe`; dvl_007 would need the Security log).
