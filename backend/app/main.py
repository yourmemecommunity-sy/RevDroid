"""RevDroid API.

Routes (all under /api):
  GET    /health                 tool availability
  POST   /scans                  upload an APK -> {scan_id}
  GET    /scans                  history
  GET    /scans/{id}             status (queued/running/done/failed + progress)
  GET    /scans/{id}/result      full analysis result
  GET    /scans/{id}/report.pdf  PDF report
  DELETE /scans/{id}             delete scan + files
"""
from __future__ import annotations

import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from . import db, storage, tools
from .config import settings
from .logging_setup import setup_logging
from .pipeline import run_scan
from .report import build_pdf

setup_logging()
log = logging.getLogger("revdroid.api")


def _cleanup_expired() -> None:
    if settings.retention_days <= 0:
        return
    for scan_id in db.expired_scan_ids(settings.retention_days):
        storage.delete_scan_files(scan_id)
        db.delete_scan(scan_id)
        log.info("retention: deleted scan %s", scan_id[:8])


def _cleanup_orphans() -> None:
    """Remove scan folders that have no DB row (e.g. crash during upload)."""
    if not settings.scans_dir.exists():
        return
    for folder in settings.scans_dir.iterdir():
        if folder.is_dir() and storage.is_valid_scan_id(folder.name) and db.get_scan(folder.name) is None:
            storage.delete_scan_files(folder.name)
        for tmp in folder.glob("*.tmp") if folder.is_dir() else []:
            tmp.unlink(missing_ok=True)


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    _cleanup_orphans()
    _cleanup_expired()
    health = tools.health()
    for name, t in health["tools"].items():
        log.info("tool %-10s %s %s", name, "READY" if t["ready"] else "MISSING", t["version"] or t["detail"])
    yield


app = FastAPI(title="RevDroid", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_methods=["*"],
                   allow_headers=["*"])


@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception):
    log.exception("unhandled error")
    return JSONResponse(status_code=500, content={"detail": "Internal server error. Check the backend log."})


def _require_scan(scan_id: str) -> dict:
    if not storage.is_valid_scan_id(scan_id):
        raise HTTPException(400, "Invalid scan id")
    row = db.get_scan(scan_id)
    if not row:
        raise HTTPException(404, "Scan not found")
    return row


@app.get("/api/health")
async def health():
    return await run_in_threadpool(tools.health)


@app.post("/api/scans", status_code=202)
async def create_scan(file: UploadFile = File(...)):
    scan_id = storage.new_scan_id()
    try:
        upload = await run_in_threadpool(storage.save_upload, scan_id, file.filename or "", file.file)
    except storage.UploadError as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        await file.close()
    db.insert_scan(scan_id, upload)
    threading.Thread(target=run_scan, args=(scan_id, upload), name=f"scan-{scan_id[:8]}", daemon=True).start()
    log.info("scan %s queued for %s (%d bytes)", scan_id[:8], upload["file_name"], upload["size_bytes"])
    return {"scan_id": scan_id, "status": "queued", **upload}


@app.get("/api/scans")
async def list_scans(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    return {"scans": db.list_scans(limit, offset)}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    return _require_scan(scan_id)


@app.get("/api/scans/{scan_id}/result")
async def get_result(scan_id: str):
    row = _require_scan(scan_id)
    if row["status"] == "failed":
        raise HTTPException(422, row["error"] or "Scan failed")
    result = storage.read_json(scan_id, "result")
    if row["status"] != "done" or result is None:
        raise HTTPException(409, f"Scan is not finished yet ({row['stage']})")
    return result


@app.get("/api/scans/{scan_id}/report.pdf")
async def get_report(scan_id: str):
    row = _require_scan(scan_id)
    result = storage.read_json(scan_id, "result")
    if row["status"] != "done" or result is None:
        raise HTTPException(409, "Report is available once the scan has finished")
    pdf = await run_in_threadpool(build_pdf, result)
    name = (result["identity"].get("package_name") or "app").replace('"', "")
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="revdroid-{name}.pdf"'})


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    row = _require_scan(scan_id)
    if row["status"] in ("queued", "running"):
        raise HTTPException(409, "Wait for the scan to finish before deleting it")
    await run_in_threadpool(storage.delete_scan_files, scan_id)
    db.delete_scan(scan_id)
    return {"deleted": scan_id}
