"""Locate and run the external reverse-engineering tools (apktool, jadx) safely."""
from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .config import settings

log = logging.getLogger("revdroid.tools")
IS_WINDOWS = sys.platform == "win32"


class ToolError(RuntimeError):
    """A tool was missing, failed, or timed out. Message is safe to show the user."""


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str


def run(cmd: list[str], timeout: int, env: dict | None = None) -> RunResult:
    """Run a command with a hard timeout and kill the whole process tree on expiry.

    jadx/apktool start a JVM from a launcher script, so killing only the
    launcher would leave the JVM running. We start a new process group and
    kill the group instead.
    """
    kwargs: dict = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace", env=env, **kwargs)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        proc.communicate()
        raise ToolError(f"{Path(cmd[0]).name} timed out after {timeout}s")
    return RunResult(proc.returncode, out, err)


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        if IS_WINDOWS:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except Exception:  # noqa: BLE001 - best effort
        proc.kill()


def java_cmd() -> str | None:
    return shutil.which(settings.java_path) or None


def apktool_cmd() -> list[str] | None:
    """Return the argv prefix that launches apktool, or None if not installed."""
    candidates = [settings.apktool_path] if settings.apktool_path else []
    candidates += [str(settings.tools_dir / "apktool.jar"), "apktool"]
    for c in candidates:
        if c.endswith(".jar") and Path(c).is_file():
            java = java_cmd()
            return [java, "-jar", c] if java else None
        found = shutil.which(c)
        if found:
            return [found]
    return None


def jadx_cmd() -> list[str] | None:
    launcher = "jadx.bat" if IS_WINDOWS else "jadx"
    candidates = [settings.jadx_path] if settings.jadx_path else []
    candidates += [str(settings.tools_dir / "jadx" / "bin" / launcher), "jadx"]
    for c in candidates:
        if Path(c).is_file():
            return [c]
        found = shutil.which(c)
        if found:
            return [found]
    return None


def _version(cmd: list[str] | None, args: list[str]) -> dict:
    if not cmd:
        return {"ready": False, "version": None, "detail": "not found - run scripts/install_tools.py"}
    try:
        res = run(cmd + args, timeout=60)
        text = (res.stdout or res.stderr).strip().splitlines()
        version = text[-1].strip() if text else "unknown"
        return {"ready": res.returncode == 0, "version": version, "detail": " ".join(cmd)}
    except (OSError, ToolError) as exc:
        return {"ready": False, "version": None, "detail": str(exc)}


def health() -> dict:
    java = java_cmd()
    java_info = _version([java] if java else None, ["-version"])
    if java_info["ready"]:  # `java -version` prints to stderr; first line is the useful one
        res = run([java, "-version"], timeout=30)
        java_info["version"] = (res.stderr or res.stdout).strip().splitlines()[0]
    try:
        from importlib.metadata import version
        import androguard  # noqa: F401
        andro = {"ready": True, "version": version("androguard"), "detail": "python package"}
    except Exception as exc:  # noqa: BLE001
        andro = {"ready": False, "version": None, "detail": f"import failed: {exc}"}
    tools = {
        "java": java_info,
        "apktool": _version(apktool_cmd(), ["--version"]),
        "jadx": _version(jadx_cmd(), ["--version"]),
        "androguard": andro,
    }
    return {"status": "ok" if all(t["ready"] for t in tools.values()) else "degraded", "tools": tools}
