"""Download apktool and jadx into revdroid/tools/ (cross-platform, needs Java 11+).

Usage:  python scripts/install_tools.py
Re-run any time to upgrade to the latest GitHub release.
Pin versions (recommended for Docker/CI):  APKTOOL_VERSION=3.0.3 JADX_VERSION=1.5.6 python scripts/install_tools.py
"""
from __future__ import annotations

import io
import json
import os
import shutil
import stat
import sys
import urllib.request
import zipfile
from pathlib import Path

TOOLS = Path(os.getenv("REVDROID_TOOLS_DIR") or Path(__file__).resolve().parent.parent / "tools")
UA = {"User-Agent": "revdroid-installer"}


def latest_release(repo: str, version: str | None = None) -> dict:
    which = f"tags/v{version}" if version else "latest"
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/{which}", headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def download(url: str) -> bytes:
    print(f"  downloading {url}")
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.read()


def install_apktool() -> None:
    rel = latest_release("iBotPeaches/Apktool", os.getenv("APKTOOL_VERSION"))
    asset = next(a for a in rel["assets"] if a["name"].endswith(".jar"))
    (TOOLS / "apktool.jar").write_bytes(download(asset["browser_download_url"]))
    print(f"  apktool {rel['tag_name']} -> tools/apktool.jar")


def install_jadx() -> None:
    rel = latest_release("skylot/jadx", os.getenv("JADX_VERSION"))
    # the plain "jadx-<ver>.zip" is the CLI+GUI bundle; skip the -gui-only builds
    asset = next(a for a in rel["assets"]
                 if a["name"].startswith("jadx-") and a["name"].endswith(".zip") and "gui" not in a["name"])
    target = TOOLS / "jadx"
    shutil.rmtree(target, ignore_errors=True)
    zipfile.ZipFile(io.BytesIO(download(asset["browser_download_url"]))).extractall(target)
    launcher = target / "bin" / "jadx"
    if launcher.exists():
        launcher.chmod(launcher.stat().st_mode | stat.S_IEXEC)
    print(f"  jadx {rel['tag_name']} -> tools/jadx/")


if __name__ == "__main__":
    if shutil.which("java") is None:
        sys.exit("Java is not on PATH. Install JDK 17+ first (e.g. Eclipse Temurin).")
    TOOLS.mkdir(exist_ok=True)
    print("Installing apktool ..."); install_apktool()
    print("Installing jadx ...");    install_jadx()
    print("Done. Start the backend and open /api/health to verify.")
