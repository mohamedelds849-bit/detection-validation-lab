# Self-review — detection-validation-lab (2026-10-12)

Reviewer stance: SOC lead who will ask "did it really run, on what, and how noisy is it?"

## What was checked by running it

| Check | Result |
|---|---|
| `python -m pytest` on Windows 11 with Chainsaw 2.16.5 in `tools/` | 92 passed, 0 skipped |
| `sigma check rules/` | 0 errors / 0 condition errors / 0 issues |
| Gate 2 on Nextron win10-client v0.8.5 (rules v1, then v2) | 32 → 5 alert hits, 5 accepted, 0 unexpected, 0 stale entries |
| Gate 3 on SigmaHQ regression corpus (204 EVTX) | 3 expected hits, nothing else |
| Gate 3 on the 8 vendored samples | PASS |
| 3 mutations on real samples (wmic branch removed, base64 length 20→2000, schtasks any verb) | all 3 caught |
| PowerShell CI scripts | parsed with the PowerShell parser: 0 errors. **Not executed** (they install Sysmon and run Atomic tests: runner only) |
| Workflow YAML | parses; **never run** |
| gitleaks 8 (`git` on 6 commits + `dir`) | no leaks found |

## Problems found and fixed during the build

1. **Chainsaw silently ignores a Sigma rule without `description`/`date`.** My first
   test rule produced "No valid detection rules were found" and nothing else. A lint test
   now requires those fields, and `test_chainsaw_loads_all_seven_single_event_rules`
   hunts with each rule alone so a skipped rule fails the build.
2. **dvl_001 v1 false positive** on Office setup (`-Encoding ascii` contains ` -en`).
   Rewritten as a regex that needs a base64 argument; the Office command is now a test.
3. **dvl_003 v1 was unusable**: 16 alerts on one clean machine. Tuned on *what the value
   starts* rather than *who writes it*; 3 remaining hits accepted by exact value.
4. **dvl_004 v1 missed `WMIC useraccount`** (real SigmaHQ sample) → added.
5. **Cleanup attributed to the test window**: cleanup started right after the window end,
   inside the 5 s grace → a 7 s pause now separates them.
6. **Allow-list too weak**: v1 of `known_fps.yaml` matched one field; an entry like
   `TargetUserName = user` would hide any account called "user". Entries now need ALL
   conditions (e.g. account name AND creator is the machine account).

## Limits that remain (honest list)

- **Gate 1 has never run.** Likely first-run issues: Defender on the runner blocking the
  mshta test (then A7 = MISSED — a real finding, to document, not to hide); Sysmon or
  module download failures; a different Sysmon field format on Server 2025. Until the
  first green run, nothing may be claimed about real-telemetry detection rates.
- **Atomic tests are not adversaries.** Default arguments, no obfuscation beyond A1, no
  evasion. Passing gate 1 = the pipeline and rule logic work on real events.
- **The benign phase is scripted** (about 10 commands). It catches regressions on
  near-misses; it is not a false-positive *rate*. The only FP measurement is gate 2, on
  one Windows 10 machine (2022) — not a SOC's fleet.
- **Correlation semantics are mine.** Sigma does not define what happens after a
  value_count alert; I restart counting after the triggering event. A SIEM may differ.
  Grouping by parent process misses an attacker who opens one shell per command.
- **The rule filters are blind spots** (listed in docs/TUNING.md "What tuning cost").
- **dvl_001** still misses encoded content passed without the flag
  (`[Convert]::FromBase64String` inside a script, `-e $var`), and fires on any process
  whose command line *looks* like `-e <20 base64 chars>` inside a string.
- **Building block level**: `informational` = building block is my convention, not a
  Sigma standard; a SIEM would use a flag (Elastic: `building_block_type`).
- **No SIEM, no dashboard.** Chainsaw is an IR tool; in a SOC the same Sigma rules would
  be converted with pySigma backends (Splunk SPL, Sentinel KQL, Elastic) — not done here.

## Safety review

- No exploit, no malware, no credential access. The only attack-like activity is 8
  unmodified Atomic Red Team tests run **only** on a disposable GitHub runner; a test
  blocks the forbidden families (credential dumping, impact, defense impairment, log
  clearing, downloads, lateral movement).
- The scripts in `lab/ci/` refuse nothing by themselves: README and LEARN say clearly not
  to run them on a personal or company PC.
- No secrets: Atomic A8's default password lives in the upstream test, not in this repo;
  gitleaks: no leaks (table above).

## Recommendations (next steps)

1. Push, run the workflow, fix what breaks, and record the run history (like the 4 runs
   of soc-detection-lab). Then update README/LEARN/CV with the real gate 1 numbers.
2. Download the `real-telemetry` artifact and open the EVTX in Event Viewer: be able to
   show the Sysmon event that fired each rule.
3. Add the Nextron Windows 11 baseline to gate 2 (second clean machine).
4. Convert the rules with a pySigma backend (e.g. `sigma convert -t splunk` or
   `-t kusto`) and keep the queries next to the rules.
5. Feed the same EVTX into soc-detection-lab's Wazuh manager (case 19 from another angle).
