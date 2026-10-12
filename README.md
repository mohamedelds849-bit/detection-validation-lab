# Detection Validation Lab — Sigma rules tested on real Windows telemetry

A **defensive detection-engineering** project: 8 Windows detections (7 Sigma rules + 1
Sigma correlation) mapped to MITRE ATT&CK v19, and a CI pipeline that tests them the way
SigmaHQ tests its own rules — **on real event logs, never on log lines I wrote myself**:

| Gate | Real data | Question it answers | Status |
|---|---|---|---|
| 1. **Telemetry** | a fresh GitHub Windows runner + **Sysmon**, benign admin activity, then **8 standard Atomic Red Team tests** | Does each rule fire on the real events of its technique, and stay silent on normal admin work? | **CI only — PASS 8/8, 0 false positives** (run `38193919332`, 2026-10-12) |
| 2. **Goodlog** | Nextron `evtx-baseline` Windows 10 client: 342,116 Sysmon events + Security log of a real, used machine | How noisy is each rule on a clean machine? | **Run locally: PASS** (5 alert hits, all accepted with a written reason) |
| 3. **Samples** | SigmaHQ regression corpus: 204 real EVTX attack recordings (+ 8 vendored in the repo) | Do the rules fire where expected, and only there? | **Run locally: PASS** (3/3 expected hits, 0 unexpected) |

The detection engine is **Chainsaw** (WithSecure), a real EVTX hunting tool used in
incident response. My Python package `dvl` runs it, evaluates the correlation rule, and
compares the hits with written expectations.

**Author:** Mohamed Elansari — cybersecurity engineering student.
**Status (2026-10-12):** rules, `dvl`, 92 tests and the workflow are built. Gates 2 and 3
were run on my PC (Windows 11, Chainsaw 2.16.5). **Gate 1 needs a Windows machine with
Sysmon on which running Atomic tests is acceptable: it runs only in GitHub Actions and
first ran on 2026-10-12 (run `38193919332`): **8/8 Atomic tests detected by their rule, 0 false positives in the benign admin phase**, on Windows Server 2025 + Sysmon 15.22. The deliberately broken rule (mshta mutant) made the gate fail, as it should.

> Defensive only. No exploit, no attack code: the CI runs unmodified, benign Atomic Red
> Team tests (print text, list users, create then delete a task / Run value / local user)
> on a disposable runner that is destroyed after the job. Details and safety review:
> [docs/ATOMICS.md](docs/ATOMICS.md).

---

## Why this project

My other detection project (`soc-detection-lab`) validates Wazuh rules in CI, but on log
lines I wrote. The obvious interview question is *"how do you know your rules work on
real logs, and how noisy are they?"*. This project answers with real data:

- **real attack telemetry**: Sysmon on a real Windows Server (CI runner), Atomic Red Team tests;
- **real benign telemetry**: a clean Windows 10 baseline (SigmaHQ's own goodlog source);
- **real third-party attack recordings**: the SigmaHQ regression corpus.

The tuning story is real too: rules **v1 raised 32 alerts on the clean Windows 10
baseline, v2 raises 5**, each accepted with a reason ([docs/TUNING.md](docs/TUNING.md)).
Example: v1 flagged Office setup because `-Encoding ascii` contains ` -en`, a prefix of
`-EncodedCommand`.

## The detections

| Key | Detection | Log source | ATT&CK (v19) | Level |
|---|---|---|---|---|
| dvl_001 | PowerShell with `-EncodedCommand` (any prefix) + base64 blob | Sysmon 1 | T1027.010, T1059.001 | medium |
| dvl_002 | `schtasks /create` (parent not under Program Files) | Sysmon 1 | T1053.005 | medium |
| dvl_003 | Value written under Run/RunOnce (installer filters) | Sysmon 13 | T1547.001 | medium |
| dvl_004 | Recon tool (whoami, systeminfo, net user/localgroup, cmdkey /list, quser, wmic useraccount) — **building block** | Sysmon 1 | T1033, T1082, T1087.001 | informational |
| dvl_005 | **Correlation**: ≥ 3 distinct recon command lines, same parent, 5 min | dvl_004 hits | T1033, T1082, T1087.001 | high |
| dvl_006 | mshta spawns PowerShell/cmd/wscript/cscript/rundll32 | Sysmon 1 | T1218.005 | high |
| dvl_007 | Local user created (built-in accounts filtered) | Security 4720 | T1136.001 | medium |
| dvl_008 | `net user ... /add` | Sysmon 1 | T1136.001 | medium |

dvl_007 and dvl_008 see the same technique from two log sources on purpose: if one
source is missing (no Sysmon, or no audit policy), the other still fires.

Coverage layer for the ATT&CK Navigator: [reports/coverage-layer.json](reports/coverage-layer.json)
(yellow until the CI proves a rule on real telemetry; the CI produces a green version).

## How it works

```
                     rules/sigma/*.yml  (7 single-event Sigma rules)
                     rules/correlation/dvl_005 (Sigma value_count correlation)
                               |
 EVTX files ----> Chainsaw hunt (Sigma + mapping) ----> hits ----> dvl correlate (dvl_005)
   |                                                                  |
   | CI runner: Sysmon + benign phase + 8 Atomic tests               v
   | Nextron Windows 10 baseline                          dvl gates: telemetry / goodlog / samples
   | SigmaHQ regression corpus                             expectations in lab/*.yaml
                                                           exit 0 = pass, 1 = fail, 2 = bad input
```

- **Time windows** (gate 1): the PowerShell harness records the UTC start/end of the
  benign phase and of each Atomic test in `work/manifest.json`. A hit counts for a test
  only inside its window (1 s before, 5 s after); cleanup runs outside the window.
- **Building blocks**: informational rules are recorded but never count as an alert
  (the idea comes from Elastic's "building block rules").
- **Allow-list** (`lab/known_fps.yaml`): environment-specific accepted false positives,
  each with a reason; all conditions must match; unused entries are reported as stale.
- **Mutation self-test** (CI): the workflow breaks dvl_006 on purpose and checks that
  gate 1 turns red. Locally, 3 mutation tests do the same on the real samples.

## Run it (Windows, Python 3.11)

```
pip install -r requirements-dev.txt
python scripts/get_chainsaw.py                    # pinned Chainsaw 2.16.5, SHA-256 checked, into tools/
sigma check rules/                                # pySigma validators: 0 issues
python -m pytest                                  # 92 tests (real-EVTX tests need Chainsaw)

# Gate 3 on the vendored real samples
python -m dvl hunt --evtx tests/data/real_evtx --out work/sample-hits.json
python -m dvl samples --hits work/sample-hits.json

# Gate 2 on the Windows 10 baseline (download win10-client.tgz from NextronSystems/evtx-baseline v0.8.5, ~840 MB extracted)
python -m dvl hunt --evtx <extracted>/Logs_Client --out work/goodlog-hits.json
python -m dvl goodlog --hits work/goodlog-hits.json
```

Gate 1 runs only in CI (`.github/workflows/detection-validation.yml`, job `telemetry`):
do **not** run `lab/ci/*.ps1` on your own PC — they install Sysmon, change the audit
policy and run Atomic tests.

## Results (verified)

| Check | Result |
|---|---|
| `python -m pytest` (Windows 11, Chainsaw installed) | **92 passed** |
| `sigma check rules/` (sigma-cli 3.1.0) | 0 errors, 0 issues |
| Gate 2, Nextron win10-client v0.8.5, rules **v1** | 32 alert hits (16 Run key, 11 schtasks, 3 user created, 2 encoded PS) |
| Gate 2, same baseline, rules **v2** | **5 alert hits, all accepted** (3 Run key, 1 schtasks, 1 user created) + 1 building block |
| Gate 3, SigmaHQ corpus (204 EVTX, commit `da9bb07d`) | 3 hits = 3 expected, 0 unexpected |
| Gate 3, 8 vendored samples | 8/8 as expected (incl. 2 documented gaps) |
| Gate 1, CI Windows runner (Windows Server 2025, Sysmon 15.22, run `38193919332`) | **8/8 PASS, 0 false positives**; mutant rule correctly fails the gate |

Local reports: [reports/](reports/).

## What is real, what is not

- **Real:** Chainsaw, Sysmon, Windows event logs, Atomic Red Team tests, the Windows 10
  baseline, the SigmaHQ recordings. No log line in this repo is written by me.
- **Not real:** no SIEM (Chainsaw replaces it), no enterprise network or Active
  Directory, no real attacker (Atomic tests are open and non-evasive), and the CI runner
  is a Windows **Server** image with developer tools, not a user workstation.
- **Built with AI assistance**; every number above was produced by running the tools.

## Limits (more in [REVIEW.md](REVIEW.md))

- Gate 1 is unproven until the first CI run; first runs usually need fixes
  (soc-detection-lab needed 4).
- 8 detections and 9 techniques: a small, deliberate scope, not a coverage claim.
- The goodlog baseline is one machine from 2022; FP numbers are for that machine only.
- The correlation runs in Python (Chainsaw does not support Sigma correlations); a SIEM
  would run it natively.
- Known gaps: Run key via `reg add` without Sysmon registry events; user creation via
  `[ADSI]` or `New-LocalUser` without the Security log; encoded commands passed in other
  ways (`-e` with a variable, `[Convert]::FromBase64String` inside a script).

## Layout

```
rules/sigma/            7 Sigma rules        rules/correlation/  1 correlation rule
dvl/                    Python: chainsaw.py, correlate.py, evaluate.py (3 gates), cli.py ...
lab/atomics.yaml        Atomic tests + expected rules      lab/known_fps.yaml  allow-list
lab/*expectations.yaml  expected hits on real samples      lab/ci/*.ps1        CI harness (runner only)
tests/                  92 tests; tests/data/real_evtx = 8 real SigmaHQ recordings (DRL 1.1)
docs/TUNING.md          v1 -> v2 on real logs      docs/ATOMICS.md  safety review of the tests
LEARN.md (FR)           how it works, interview Q&A, CV lines      REVIEW.md  self-review
```

Licences: my code MIT; third-party data and tools in [NOTICE](NOTICE).
