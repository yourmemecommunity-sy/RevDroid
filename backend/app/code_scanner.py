"""Walk decompiled sources + decoded resources and apply the regex rules."""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Iterable

from .config import settings
from .findings import finding
from .network import EndpointCollector
from .rules import PLACEHOLDERS, RULES, WEBVIEW_BRIDGE, WEBVIEW_JS, Rule

log = logging.getLogger("revdroid.scanner")

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_LOCATIONS = 25
SNIPPET_LEN = 160
TIME_BUDGET_SEC = 240

# Third-party code: scanning it mostly finds the library's own (harmless) constants.
LIBRARY_PREFIXES = (
    "android/", "androidx/", "kotlin/", "kotlinx/", "com/google/", "com/android/", "okhttp3/", "okio/",
    "retrofit2/", "io/reactivex/", "rx/", "org/apache/", "org/json/", "com/squareup/", "com/facebook/",
    "dagger/", "javax/", "j$/", "org/intellij/", "org/jetbrains/", "com/fasterxml/", "com/bumptech/",
    "io/fabric/", "com/crashlytics/", "org/bouncycastle/", "com/airbnb/", "io/grpc/", "org/chromium/",
    "com/journeyapps/", "com/github/", "org/slf4j/", "net/sqlcipher/", "io/flutter/", "com/amazonaws/",
)


def mask(secret: str) -> str:
    """Show just enough to recognise a secret, never enough to use it."""
    s = secret.strip()
    if len(s) <= 6:
        return "*" * len(s)
    keep = 4 if len(s) >= 16 else 2
    return s[:keep] + "*" * min(len(s) - keep, 16) + f" ({len(s)} chars)"


def _snippet(line_text: str, secret_span: tuple[int, int] | None) -> str:
    text = line_text
    if secret_span:
        a, b = secret_span
        text = text[:a] + mask(text[a:b]) + text[b:]
    text = text.strip()
    return text if len(text) <= SNIPPET_LEN else text[:SNIPPET_LEN - 3] + "..."


def iter_files(roots: Iterable[tuple[Path, str]], app_package: str | None) -> Iterable[tuple[Path, str]]:
    """Yield (path, display_path). Library packages are skipped unless they are the app's own package."""
    app_prefix = (app_package or "").replace(".", "/") + "/"
    for root, label in roots:
        if not root or not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in {".java", ".kt", ".xml", ".json", ".properties"}:
                continue
            rel = p.relative_to(root).as_posix()
            if label == "sources" and not settings.scan_library_code and rel.startswith(LIBRARY_PREFIXES) \
                    and not rel.startswith(app_prefix):
                continue
            if label == "res" and not (rel.startswith("res/values") or rel.startswith("res/xml")
                                       or rel.startswith("res/raw")):
                continue
            yield p, f"{label}/{rel}"


def scan(sources_dir: Path | None, decoded_dir: Path | None, app_package: str | None) -> dict[str, Any]:
    hits: dict[str, list[dict[str, Any]]] = {r.id: [] for r in RULES}
    counts: dict[str, int] = {r.id: 0 for r in RULES}
    webview_bridge: list[dict[str, Any]] = []
    webview_js_only: list[dict[str, Any]] = []
    endpoints = EndpointCollector()
    secret_values: set[str] = set()  # every secret found, so it can be masked wherever it reappears
    started = time.monotonic()
    files_scanned, truncated = 0, False

    roots = [(sources_dir, "sources"), (decoded_dir, "res")]
    for path, display in iter_files(roots, app_package):
        if time.monotonic() - started > TIME_BUDGET_SEC:
            truncated = True
            log.warning("scan time budget exceeded after %d files", files_scanned)
            break
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files_scanned += 1
        lower = text.lower()
        lines = text.splitlines()
        ext = path.suffix.lower()
        secret_lines: set[int] = set()  # one secret per line: the most specific rule (listed first) wins

        for i, line in enumerate(lines, 1):
            endpoints.feed_line(line, display, i)

        for rule in RULES:
            if ext not in rule.exts or (rule.hint and not any(h in lower for h in rule.hint)):
                continue
            if rule.multiline:
                for m in rule.regex.finditer(text):
                    ln = text.count("\n", 0, m.start()) + 1
                    _record(rule, hits, counts, display, ln, lines[ln - 1] if ln <= len(lines) else "", None)
                continue
            for i, line in enumerate(lines, 1):
                if rule.hint and not any(h in line.lower() for h in rule.hint):
                    continue
                for m in rule.regex.finditer(line):
                    if rule.secret:
                        value = m.group(1)
                        if i in secret_lines or (rule.placeholder_check and PLACEHOLDERS.match(value)):
                            continue
                        secret_lines.add(i)
                        secret_values.add(value)
                        _record(rule, hits, counts, display, i, line, m.span(1))
                    else:
                        _record(rule, hits, counts, display, i, line, None)

        if ext in (".java", ".kt") and "setjavascriptenabled" in lower:
            js = [i for i, l in enumerate(lines, 1) if WEBVIEW_JS.search(l)]
            bridge = [i for i, l in enumerate(lines, 1) if WEBVIEW_BRIDGE.search(l)]
            if js:
                target = webview_bridge if bridge else webview_js_only
                ln = bridge[0] if bridge else js[0]
                target.append({"file": display, "line": ln, "snippet": _snippet(lines[ln - 1], None)})

    findings = []
    by_id = {r.id: r for r in RULES}
    for rid, locs in hits.items():
        if locs:
            r = by_id[rid]
            findings.append(finding(
                id=r.id, title=r.title, severity=r.severity, category=r.category, source="code",
                description=r.description, recommendation=r.recommendation, cwe=r.cwe, masvs=r.masvs,
                evidence=locs[0]["snippet"], locations=locs, occurrences=counts[rid]))
    if webview_bridge:
        findings.append(finding(
            id="WEB-JS-BRIDGE", title="WebView exposes a JavaScript bridge with JavaScript enabled",
            severity="high", category="webview", source="code", cwe="CWE-749", masvs="MASVS-PLATFORM-2",
            description="addJavascriptInterface lets page JavaScript call into Java. If the WebView ever loads "
                        "untrusted or HTTP content, that script can invoke the app's exposed methods "
                        "(remote code execution on Android < 4.2).",
            recommendation="Only load trusted HTTPS content in WebViews that use a bridge, annotate only the "
                           "minimum methods with @JavascriptInterface, and prefer WebMessageListener.",
            evidence=webview_bridge[0]["snippet"], locations=webview_bridge[:MAX_LOCATIONS],
            occurrences=len(webview_bridge)))
    if webview_js_only:
        findings.append(finding(
            id="WEB-JS-ENABLED", title="WebView with JavaScript enabled", severity="low", category="webview",
            source="code", cwe="CWE-79", masvs="MASVS-PLATFORM-2",
            description="JavaScript in a WebView widens the attack surface for XSS if untrusted content loads.",
            recommendation="Enable JavaScript only where needed and only for trusted HTTPS origins.",
            evidence=webview_js_only[0]["snippet"], locations=webview_js_only[:MAX_LOCATIONS],
            occurrences=len(webview_js_only)))

    _mask_everywhere(findings, secret_values)
    return {"findings": findings, "endpoints": endpoints.result(),
            "stats": {"files_scanned": files_scanned, "truncated": truncated,
                      "seconds": round(time.monotonic() - started, 1)}}


def _mask_everywhere(findings: list[dict[str, Any]], secrets: set[str]) -> None:
    """jadx inlines constants, so a secret often reappears in other lines (e.g. a Log call).
    Mask every known secret value in every stored snippet."""
    values = sorted((v for v in secrets if len(v) >= 4), key=len, reverse=True)
    if not values:
        return
    def clean(text: str | None) -> str | None:
        if not text:
            return text
        for v in values:
            if v in text:
                text = text.replace(v, mask(v))
        return text
    for f in findings:
        f["evidence"] = clean(f["evidence"])
        for loc in f["locations"]:
            loc["snippet"] = clean(loc.get("snippet"))


def _record(rule: Rule, hits, counts, display: str, line_no: int, line: str,
            span: tuple[int, int] | None) -> None:
    counts[rule.id] += 1
    if len(hits[rule.id]) < MAX_LOCATIONS:
        hits[rule.id].append({"file": display, "line": line_no, "snippet": _snippet(line, span)})
