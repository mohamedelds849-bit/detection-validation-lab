"""Pure-Python checks of the trickiest rule logic (Chainsaw is not needed).

dvl_001's regex is evaluated with Python `re`; the pattern only uses syntax that
Python and Rust regex (Chainsaw) read the same way.
"""
from __future__ import annotations

import base64
import re

import pytest

from dvl.rules import load_rule_file
from tests.conftest import ROOT


def _regex():
    doc = load_rule_file(ROOT / "rules" / "sigma" / "dvl_001_powershell_encoded_command.yml")
    return re.compile(doc["detection"]["selection_flag"]["CommandLine|re"])


ATOMIC_B64 = base64.b64encode('Write-Host "Hey, Atomic!"'.encode("utf-16-le")).decode()


@pytest.mark.parametrize("cmd", [
    f"powershell.exe -EncodedCommand {ATOMIC_B64}",            # Atomic T1027 test 2
    f"powershell -exec bypass -e {ATOMIC_B64}",                # SigmaHQ sample style
    f"powershell.exe -enc {ATOMIC_B64}",
    f"powershell.exe -ec {ATOMIC_B64}",
    f"powershell.exe /EncodedCommand {ATOMIC_B64}",
    f"pwsh -ENCODEDCOMMAND '{ATOMIC_B64}'",
])
def test_encoded_command_variants_match(cmd):
    assert _regex().search(cmd)


@pytest.mark.parametrize("cmd", [
    # real false positive of rules v1 on the Windows 10 baseline (Office setup)
    "powershell.exe -NoProfile -Command \"& { Out-File -FilePath 'C:\\x.scratch' -InputObject '0' -Encoding ascii }\"",
    "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Get-Date",
    "powershell.exe -ep bypass -File C:\\scripts\\inventory.ps1",
    "powershell.exe -Command \"$e = 1\"",
    "powershell.exe -EncodedCommand $EncodedCommand",          # the Atomic parent process
    "powershell.exe -e short",                                 # not a base64 blob
])
def test_lookalikes_do_not_match(cmd):
    assert not _regex().search(cmd)


def test_v1_contains_logic_would_have_fired_on_the_office_command():
    """Documents WHY v2 exists: the v1 needle ' -en' is inside '-Encoding'."""
    office = "powershell.exe -NoProfile -Command \"Out-File -InputObject '0' -Encoding ascii\""
    assert " -en" in office.lower()


def test_run_key_filters_keep_the_atomic_value():
    doc = load_rule_file(ROOT / "rules" / "sigma" / "dvl_003_registry_run_key_set.yml")
    det = doc["detection"]
    atomic_details = "C:\\Path\\AtomicRedTeam.exe"
    for prefix in det["filter_target_program_files"]["Details|startswith"]:
        assert not atomic_details.lower().startswith(prefix.lower())
    needles = det["filter_burn_runonce"]["Details|contains|all"]
    assert not all(n.lower() in atomic_details.lower() for n in needles)


def test_account_filter_does_not_hide_the_atomic_account():
    doc = load_rule_file(ROOT / "rules" / "sigma" / "dvl_007_local_account_created.yml")
    assert "T1136.001_CMD" not in doc["detection"]["filter_builtin"]["TargetUserName"]
