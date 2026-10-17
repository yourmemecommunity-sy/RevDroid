"""The scan pipeline: identity -> manifest -> decompile -> code scan -> score.

Runs in a worker thread. Each step writes its own JSON file, so a failure
late in the pipeline still leaves the earlier results on disk, and the
final result.json is what the API and the PDF read.
"""
from __future__ import annotations

import logging
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from . import db, storage
from .code_scanner import scan as scan_code
from .config import settings
from .decompile import decompile
from .findings import sort_findings
from .identity import extract_identity, load_apk, signing_findings
from .manifest import analyze_manifest, decode_with_apktool, load_manifest_root
from .scoring import score

log = logging.getLogger("revdroid.pipeline")
_slots = threading.BoundedSemaphore(settings.max_concurrent_scans)


def _stage(scan_id: str, stage: str, progress: int) -> None:
    log.info("[%s] %s", scan_id[:8], stage)
    db.update_scan(scan_id, status="running", stage=stage, progress=progress)


def run_scan(scan_id: str, upload: dict[str, Any]) -> None:
    """Entry point for the background task. Never raises."""
    with _slots:  # jadx is CPU/RAM heavy: only N scans at once, the rest wait in "queued"
        started = time.monotonic()
        folder = storage.scan_dir(scan_id)
        decoded_dir, jadx_dir = folder / "decoded", folder / "jadx"
        warnings: list[str] = []
        try:
            _stage(scan_id, "Reading app identity", 10)
            apk = load_apk(storage.apk_path(scan_id))
            identity = extract_identity(apk)
            storage.write_json(scan_id, "identity", identity)
            db.update_scan(scan_id, package_name=identity["package_name"], app_name=identity["app_name"],
                           version_name=identity["version_name"])

            _stage(scan_id, "Decoding manifest with apktool", 25)
            decoded = decode_with_apktool(storage.apk_path(scan_id), decoded_dir)
            if decoded is None:
                warnings.append("apktool could not decode resources; manifest read with androguard instead")
            manifest = analyze_manifest(load_manifest_root(decoded, apk), identity, decoded)
            storage.write_json(scan_id, "manifest", manifest)

            _stage(scan_id, "Decompiling DEX with jadx (slowest step)", 40)
            dec = decompile(storage.apk_path(scan_id), jadx_dir)
            if dec["warning"]:
                warnings.append(dec["warning"])

            _stage(scan_id, "Scanning code for secrets and insecure patterns", 75)
            code = scan_code(Path(dec["sources_dir"]) if dec["sources_dir"] else None, decoded,
                             identity["package_name"])
            if code["stats"]["truncated"]:
                warnings.append("code scan hit its time budget; results are partial")
            storage.write_json(scan_id, "code", code)

            _stage(scan_id, "Scoring", 92)
            findings = sort_findings(signing_findings(identity) + manifest["findings"] + code["findings"])
            risk = score(findings, manifest["permissions"])
            result = {
                "scan_id": scan_id,
                "file": upload,
                "identity": identity,
                "risk": risk,
                "permissions": manifest["permissions"],
                "declared_permissions": manifest["declared_permissions"],
                "components": manifest["components"],
                "manifest_flags": manifest["flags"],
                "findings": findings,
                "endpoints": code["endpoints"],
                "stats": {"java_files": dec["java_files"], **code["stats"],
                          "total_seconds": round(time.monotonic() - started, 1)},
                "warnings": warnings,
            }
            storage.write_json(scan_id, "result", result)
            db.update_scan(scan_id, status="done", stage="Complete", progress=100,
                           risk_score=risk["score"], grade=risk["grade"], finding_count=len(findings),
                           finished_at=db.now(), error="; ".join(warnings) or None)
            log.info("[%s] done in %.1fs: score %s (%s), %d findings", scan_id[:8],
                     time.monotonic() - started, risk["score"], risk["grade"], len(findings))
        except Exception as exc:  # noqa: BLE001 - a broken APK must never take the server down
            log.exception("[%s] scan failed", scan_id[:8])
            db.update_scan(scan_id, status="failed", stage="Failed", error=_friendly(exc), finished_at=db.now())
        finally:
            if not settings.keep_decompiled:  # decompiled code can be hundreds of MB
                shutil.rmtree(jadx_dir, ignore_errors=True)
                shutil.rmtree(decoded_dir, ignore_errors=True)


def _friendly(exc: Exception) -> str:
    name = type(exc).__name__
    msg = str(exc)[:300]
    if "zip" in msg.lower() or name in ("BadZipFile", "BadZipfile"):
        return "The APK archive is corrupt or uses an unsupported ZIP layout."
    if "manifest" in msg.lower() or "axml" in msg.lower():
        return f"Could not parse AndroidManifest.xml: {msg}"
    return f"Analysis failed ({name}): {msg}"
