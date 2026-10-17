"""Lightweight SQLite scan history (stdlib sqlite3, one connection per call)."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            TEXT PRIMARY KEY,
    file_name     TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    package_name  TEXT,
    app_name      TEXT,
    version_name  TEXT,
    status        TEXT NOT NULL,          -- queued | running | done | failed
    stage         TEXT,                   -- human-readable current step
    progress      INTEGER DEFAULT 0,      -- 0..100
    error         TEXT,
    risk_score    INTEGER,
    grade         TEXT,
    finding_count INTEGER,
    created_at    TEXT NOT NULL,
    finished_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(settings.db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.scans_dir.mkdir(parents=True, exist_ok=True)
    with connect() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
        # scans interrupted by a server restart can never finish: mark them failed
        c.execute("UPDATE scans SET status='failed', error='Interrupted by a server restart', finished_at=? "
                  "WHERE status IN ('queued','running')", (now(),))


def insert_scan(scan_id: str, upload: dict[str, Any]) -> None:
    with connect() as c:
        c.execute("INSERT INTO scans (id, file_name, size_bytes, sha256, status, stage, created_at) "
                  "VALUES (?,?,?,?, 'queued', 'Queued', ?)",
                  (scan_id, upload["file_name"], upload["size_bytes"], upload["sha256"], now()))


ALLOWED = {"package_name", "app_name", "version_name", "status", "stage", "progress", "error",
           "risk_score", "grade", "finding_count", "finished_at"}


def update_scan(scan_id: str, **fields: Any) -> None:
    bad = set(fields) - ALLOWED  # column names are never user input, but keep it explicit
    if bad:
        raise ValueError(f"unknown columns {bad}")
    cols = ", ".join(f"{k}=?" for k in fields)
    with connect() as c:
        c.execute(f"UPDATE scans SET {cols} WHERE id=?", (*fields.values(), scan_id))


def get_scan(scan_id: str) -> dict[str, Any] | None:
    with connect() as c:
        row = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return dict(row) if row else None


def list_scans(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    with connect() as c:
        rows = c.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
                         (limit, offset)).fetchall()
    return [dict(r) for r in rows]


def delete_scan(scan_id: str) -> bool:
    with connect() as c:
        return c.execute("DELETE FROM scans WHERE id=?", (scan_id,)).rowcount > 0


def expired_scan_ids(days: int) -> list[str]:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    with connect() as c:
        rows = c.execute("SELECT id FROM scans WHERE created_at < ? AND status IN ('done','failed')",
                         (cutoff,)).fetchall()
    return [r["id"] for r in rows]
