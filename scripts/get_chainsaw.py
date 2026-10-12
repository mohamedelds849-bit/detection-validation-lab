"""Download the pinned Chainsaw release into tools/chainsaw/ and verify its SHA-256.

    python scripts/get_chainsaw.py            # Windows or Linux x86_64, auto-detected

The hashes are the "digest" values published by GitHub for the release assets of
WithSecureOpenSource/chainsaw v2.16.5 (checked again locally for the Windows zip).
tools/ is git-ignored.
"""
from __future__ import annotations

import hashlib
import io
import platform
import shutil
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

VERSION = "2.16.5"
BASE = f"https://github.com/WithSecureOpenSource/chainsaw/releases/download/v{VERSION}/"
ASSETS = {
    "Windows": ("chainsaw_x86_64-pc-windows-msvc.zip",
                "f47a724ea61547056a0128f201d160c0c4a81c02c481c80bd3c138669c44989a"),
    "Linux": ("chainsaw_x86_64-unknown-linux-gnu.tar.gz",
              "7a7289d15f085af9bce39dfa3052adf0b4c78cab0dbfb91c2dbe38322909ce02"),
}
DEST = Path(__file__).resolve().parent.parent / "tools"


def main() -> int:
    system = platform.system()
    if system not in ASSETS:
        print(f"unsupported OS {system}", file=sys.stderr)
        return 2
    name, expected = ASSETS[system]
    print(f"downloading {name} ...")
    with urllib.request.urlopen(BASE + name, timeout=120) as resp:  # noqa: S310 (fixed https URL)
        data = resp.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        print(f"SHA-256 mismatch: got {digest}, expected {expected}", file=sys.stderr)
        return 1
    target = DEST / "chainsaw"
    if target.exists():
        shutil.rmtree(target)
    DEST.mkdir(parents=True, exist_ok=True)
    if name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            archive.extractall(DEST)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            archive.extractall(DEST, filter="data")
    binary = target / ("chainsaw.exe" if system == "Windows" else "chainsaw")
    if not binary.exists() or not (target / "mappings" / "sigma-event-logs-all.yml").exists():
        print(f"unexpected archive layout: {binary} or its mappings/ folder is missing", file=sys.stderr)
        return 1
    binary.chmod(0o755)
    print(f"OK: {binary} (sha256 verified)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
