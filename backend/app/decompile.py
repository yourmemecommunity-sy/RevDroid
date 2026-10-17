"""Run jadx to turn DEX bytecode into Java source, without ever crashing the server."""
from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Any

from . import tools
from .config import settings

log = logging.getLogger("revdroid.decompile")


def decompile(apk: Path, out_dir: Path) -> dict[str, Any]:
    """Returns {"ok", "sources_dir", "java_files", "warning"}. Never raises for tool problems.

    jadx exits non-zero when *some* classes fail to decompile, which is normal
    for obfuscated apps. We treat any produced source as success and report
    the failure count as a warning.
    """
    cmd = tools.jadx_cmd()
    if not cmd:
        return {"ok": False, "sources_dir": None, "java_files": 0,
                "warning": "jadx is not installed, code analysis skipped"}
    shutil.rmtree(out_dir, ignore_errors=True)
    env = dict(os.environ)
    # The heap is the #1 cause of jadx failures on big apps. JADX_OPTS is read by the jadx launcher.
    env["JADX_OPTS"] = f"-Xmx{settings.jadx_heap}"
    argv = cmd + ["-d", str(out_dir), "--no-res", "--show-bad-code",
                  "--threads-count", str(settings.jadx_threads), "--log-level", "error", str(apk)]
    warning = None
    try:
        res = tools.run(argv, timeout=settings.jadx_timeout, env=env)
        output = res.stdout + res.stderr
        if "OutOfMemoryError" in output:
            warning = (f"jadx ran out of memory with a {settings.jadx_heap} heap; results may be partial. "
                       "Raise JADX_HEAP in .env (e.g. 4g).")
        elif res.returncode != 0:
            errors = output.count("ERROR")
            warning = f"jadx finished with errors ({errors} reported); some classes may be missing"
    except tools.ToolError as exc:  # timeout: keep whatever was written so far
        warning = f"{exc}; analysed the partial output. Raise JADX_TIMEOUT_SEC for large APKs."
    except OSError as exc:
        return {"ok": False, "sources_dir": None, "java_files": 0, "warning": f"could not start jadx: {exc}"}

    sources = out_dir / "sources"
    count = sum(1 for _ in sources.rglob("*.java")) if sources.exists() else 0
    if warning:
        log.warning(warning)
    return {"ok": count > 0, "sources_dir": str(sources) if count else None, "java_files": count,
            "warning": warning if count else (warning or "jadx produced no Java sources")}
