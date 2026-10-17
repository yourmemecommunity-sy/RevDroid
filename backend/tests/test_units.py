from pathlib import Path

from app.code_scanner import mask, scan
from app.findings import finding
from app.network import EndpointCollector
from app.permissions import classify
from app.scoring import grade_for, score


def test_mask_never_reveals_secret():
    s = "AKIAIOSFODNN7EXAMPLE"
    m = mask(s)
    assert s not in m and m.startswith("AKIA") and "20 chars" in m
    assert mask("abc") == "***"


def test_permission_classes():
    assert classify("android.permission.READ_SMS")["protection_level"] == "dangerous"
    assert classify("android.permission.SYSTEM_ALERT_WINDOW")["protection_level"] == "signature"
    assert classify("android.permission.INTERNET")["protection_level"] == "normal"
    assert classify("com.example.MY_PERMISSION")["protection_level"] == "custom"


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / "sources" / "com" / "example" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return tmp / "sources"


def test_scanner_rules_and_placeholders(tmp_path):
    src = _write(tmp_path, "A.java", '\n'.join([
        'String password = "hunter2pass";',          # real password
        'String passwordLabel = "Enter password";',  # UI text: ignored
        'String PASSWORD_KEY = "password";',         # placeholder: ignored
        'MessageDigest.getInstance("SHA-1");',
        'Cipher.getInstance("AES");',                 # defaults to ECB
        'Cipher.getInstance("AES/GCM/NoPadding");',   # fine
        'String u = "http://insecure.example.org/api";',
        'String k = "-----BEGIN PRIVATE KEY-----";',
        'Log.d("x", "token=" + hunter2pass);',
    ]))
    out = scan(src, None, "com.example")
    ids = {f["id"]: f for f in out["findings"]}
    assert {"SEC-PASSWORD", "CRY-WEAK-HASH", "CRY-ECB", "NET-HTTP-URL", "SEC-PRIVATE-KEY", "LOG-SENSITIVE"} <= set(ids)
    assert ids["SEC-PASSWORD"]["occurrences"] == 1
    assert ids["CRY-ECB"]["occurrences"] == 1
    assert ids["SEC-PASSWORD"]["locations"][0]["line"] == 1
    # the password must be masked everywhere, including the Log line where it reappears
    assert all("hunter2pass" not in (l["snippet"] or "") for f in out["findings"] for l in f["locations"])
    assert out["endpoints"]["domains"][0]["domain"] == "insecure.example.org"


def test_library_code_skipped(tmp_path):
    p = tmp_path / "sources" / "okhttp3" / "X.java"
    p.parent.mkdir(parents=True)
    p.write_text('MessageDigest.getInstance("MD5");', encoding="utf-8")
    assert scan(tmp_path / "sources", None, "com.example")["findings"] == []


def test_trust_all_multiline(tmp_path):
    src = _write(tmp_path, "T.java", "class T {\n  public void checkServerTrusted(X509Certificate[] c, String a) {\n  }\n}\n")
    f = next(f for f in scan(src, None, "com.example")["findings"] if f["id"] == "NET-TRUST-ALL")
    assert f["locations"][0]["line"] == 2


def test_endpoints_filter_noise():
    c = EndpointCollector()
    c.feed_line('x = "http://schemas.android.com/apk/res/android"; y = "https://api.example.com/v1";', "f", 1)
    c.feed_line('ip = "10.0.0.5"; v = "8.8.8.8";', "f", 2)
    r = c.result()
    assert [d["domain"] for d in r["domains"]] == ["api.example.com"]
    assert {i["ip"]: i["scope"] for i in r["ips"]} == {"10.0.0.5": "private", "8.8.8.8": "public"}


def _f(sev, cat="crypto", occ=1, id="X"):
    return finding(id=id, title="t", severity=sev, category=cat, description="d", recommendation="r",
                   source="code", occurrences=occ)


def test_scoring_caps_and_grades():
    assert score([], [])["score"] == 0 and score([], [])["grade"] == "A"
    # repeating one issue does not explode the score
    assert score([_f("medium", occ=500)], [])["score"] == 5 + 3
    # category cap: crypto capped at 20
    assert score([_f("high", id=str(i)) for i in range(5)], [])["score"] == 20
    # a single critical forces at least D
    assert score([_f("critical", cat="secrets")], [])["grade"] == "D"
    assert [grade_for(x) for x in (0, 10, 11, 25, 26, 45, 46, 65, 66, 100)] == list("AABBCCDDFF")
