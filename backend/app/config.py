"""Central settings, read once from environment / .env."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_DIR = BACKEND_DIR.parent
load_dotenv(BACKEND_DIR / ".env")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("REVDROID_DATA_DIR", PROJECT_DIR / "data")).resolve())
    tools_dir: Path = field(default_factory=lambda: Path(os.getenv("REVDROID_TOOLS_DIR", PROJECT_DIR / "tools")).resolve())
    apktool_path: str = os.getenv("APKTOOL_PATH", "")        # jar or launcher; blank = auto-detect
    jadx_path: str = os.getenv("JADX_PATH", "")              # launcher; blank = auto-detect
    java_path: str = os.getenv("JAVA_PATH", "java")
    max_upload_mb: int = _int("MAX_UPLOAD_MB", 150)
    apktool_timeout: int = _int("APKTOOL_TIMEOUT_SEC", 180)
    jadx_timeout: int = _int("JADX_TIMEOUT_SEC", 600)
    jadx_heap: str = os.getenv("JADX_HEAP", "2g")            # raise to 4g/6g for very large APKs
    jadx_threads: int = _int("JADX_THREADS", 4)
    max_concurrent_scans: int = _int("MAX_CONCURRENT_SCANS", 2)
    keep_decompiled: bool = _bool("KEEP_DECOMPILED", False)  # false = delete jadx/apktool output after a scan
    scan_library_code: bool = _bool("SCAN_LIBRARY_CODE", False)
    retention_days: int = _int("SCAN_RETENTION_DAYS", 30)    # 0 = keep forever
    cors_origins: tuple[str, ...] = tuple(
        o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip())
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    @property
    def scans_dir(self) -> Path:
        return self.data_dir / "scans"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "revdroid.db"

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


settings = Settings()
