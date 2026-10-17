"""Per-scan folders, upload validation and hashing."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import uuid
import zipfile
from pathlib import Path
from typing import Any, BinaryIO

from .config import settings

SCAN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
CHUNK = 1024 * 1024


class UploadError(ValueError):
    """Upload rejected. Message is safe to show the user."""


def new_scan_id() -> str:
    return uuid.uuid4().hex


def is_valid_scan_id(scan_id: str) -> bool:
    return bool(SCAN_ID_RE.match(scan_id or ""))


def scan_dir(scan_id: str) -> Path:
    # scan_id goes into a filesystem path: only ever accept our own uuid4 hex format
    if not is_valid_scan_id(scan_id):
        raise UploadError("Invalid scan id")
    return settings.scans_dir / scan_id


def apk_path(scan_id: str) -> Path:
    return scan_dir(scan_id) / "app.apk"


def save_upload(scan_id: str, filename: str, stream: BinaryIO) -> dict[str, Any]:
    """Stream the upload to disk while enforcing the size limit and hashing it.

    The user's filename is only stored as metadata, never used as a path.
    """
    if not filename or not filename.lower().endswith(".apk"):
        raise UploadError("Only .apk files are accepted")
    folder = scan_dir(scan_id)
    folder.mkdir(parents=True, exist_ok=False)
    dest = apk_path(scan_id)
    md5, sha1, sha256, size = hashlib.md5(), hashlib.sha1(), hashlib.sha256(), 0
    try:
        with dest.open("wb") as out:
            while chunk := stream.read(CHUNK):
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise UploadError(f"File is larger than the {settings.max_upload_mb} MB limit")
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                out.write(chunk)
        if size == 0:
            raise UploadError("The uploaded file is empty")
        validate_apk(dest)
    except Exception:
        shutil.rmtree(folder, ignore_errors=True)
        raise
    return {"file_name": Path(filename).name[:200], "size_bytes": size,
            "md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def validate_apk(path: Path) -> None:
    """An APK is a ZIP that contains a binary AndroidManifest.xml and at least one dex file."""
    with path.open("rb") as fh:
        if fh.read(4) != b"PK\x03\x04":
            raise UploadError("Not a valid APK: the file is not a ZIP archive")
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
    except zipfile.BadZipFile as exc:
        raise UploadError("Not a valid APK: the ZIP structure is corrupt") from exc
    if "AndroidManifest.xml" not in names:
        raise UploadError("Not a valid APK: AndroidManifest.xml is missing")
    if not any(n.startswith("classes") and n.endswith(".dex") for n in names):
        raise UploadError("Not a valid APK: no classes.dex found (split APK or resource-only package?)")


def write_json(scan_id: str, name: str, data: Any) -> None:
    path = scan_dir(scan_id) / f"{name}.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)  # atomic: readers never see a half-written file


def read_json(scan_id: str, name: str) -> Any | None:
    path = scan_dir(scan_id) / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def delete_scan_files(scan_id: str) -> None:
    shutil.rmtree(scan_dir(scan_id), ignore_errors=True)
