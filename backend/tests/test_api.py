import io
import json
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from app import tools
from app.main import app
from conftest import FIXTURE_APK, PLANTED_SECRETS


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _upload(client, name, data):
    return client.post("/api/scans", files={"file": (name, data, "application/vnd.android.package-archive")})


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert set(r.json()["tools"]) == {"java", "apktool", "jadx", "androguard"}


@pytest.mark.parametrize("name,data,msg", [
    ("notes.txt", b"PK\x03\x04hello", "Only .apk"),
    ("empty.apk", b"", "empty"),
    ("fake.apk", b"this is not a zip", "not a ZIP"),
    ("truncated.apk", b"PK\x03\x04" + b"\0" * 200, "corrupt"),
])
def test_rejects_bad_uploads(client, name, data, msg):
    r = _upload(client, name, data)
    assert r.status_code == 400 and msg in r.json()["detail"]


def test_rejects_zip_without_manifest(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("classes.dex", b"dex\n035")
    r = _upload(client, "nomanifest.apk", buf.getvalue())
    assert r.status_code == 400 and "AndroidManifest.xml" in r.json()["detail"]


def test_invalid_and_missing_ids(client):
    assert client.get("/api/scans/..%2F..%2Fetc").status_code in (400, 404)
    assert client.get("/api/scans/not-a-scan-id").status_code == 400
    assert client.get("/api/scans/" + "0" * 32).status_code == 404


EXPECTED = {
    # manifest
    "MAN-DEBUGGABLE", "MAN-ALLOW-BACKUP", "MAN-CLEARTEXT", "NSC-CLEARTEXT", "NSC-USER-CA",
    "MAN-EXPORTED-PROVIDER", "MAN-EXPORTED-SERVICE", "MAN-EXPORTED-RECEIVER", "MAN-EXPORTED-ACTIVITY",
    "MAN-SENSITIVE-PERMS", "MAN-OLD-MINSDK",
    # signing
    "SIGN-DEBUG", "SIGN-JANUS",
    # code
    "SEC-AWS-ACCESS-KEY", "SEC-PASSWORD", "SEC-GENERIC-KEY", "SEC-PRIVATE-KEY", "SEC-XML-SECRET",
    "SEC-GOOGLE-API-KEY", "SEC-FIREBASE-URL", "CRY-WEAK-HASH", "CRY-ECB", "CRY-HARDCODED-KEY", "CRY-STATIC-IV",
    "NET-TRUST-ALL", "NET-HOSTNAME-ALL", "NET-HTTP-URL", "WEB-JS-BRIDGE", "WEB-FILE-ACCESS",
    "LOG-SENSITIVE", "STO-WORLD-READABLE", "INJ-SQL-CONCAT",
}


@pytest.mark.skipif(not FIXTURE_APK.exists(), reason="run tests/fixtures/build_vulnapp.py first")
@pytest.mark.skipif(not (tools.jadx_cmd() and tools.apktool_cmd()), reason="apktool/jadx not installed")
def test_end_to_end_fixture(client):
    r = _upload(client, "vulnapp.apk", FIXTURE_APK.read_bytes())
    assert r.status_code == 202
    scan_id = r.json()["scan_id"]
    for _ in range(120):
        status = client.get(f"/api/scans/{scan_id}").json()
        if status["status"] in ("done", "failed"):
            break
        time.sleep(1)
    assert status["status"] == "done", status
    result = client.get(f"/api/scans/{scan_id}/result").json()

    ids = {f["id"] for f in result["findings"]}
    missing = EXPECTED - ids
    assert not missing, f"missed planted issues: {missing}"

    comps = {c["name"].rsplit(".", 1)[-1]: c for c in result["components"]}
    exported_names = {l["snippet"].split()[1].rsplit(".", 1)[-1].rstrip(">")
                      for f in result["findings"] if f["id"].startswith("MAN-EXPORTED") for l in f["locations"]}
    assert "PrivateService" not in exported_names and "GuardedService" not in exported_names
    assert "MainActivity" not in exported_names  # launcher activity is expected to be exported
    assert comps["SmsReceiver"]["exported"] is True  # implicit export via intent-filter

    assert result["identity"]["package_name"] == "com.revdroid.vulnapp"
    assert result["risk"]["grade"] == "F"
    assert "203.0.113.42" in {i["ip"] for i in result["endpoints"]["ips"]}
    assert "api.vulnbank.example.com" in {d["domain"] for d in result["endpoints"]["domains"]}

    # secrets must never appear in full anywhere we expose: API result, PDF, files on disk
    blob = json.dumps(result)
    for s in PLANTED_SECRETS:
        assert s not in blob, f"secret leaked in result: {s[:4]}..."
    pdf = client.get(f"/api/scans/{scan_id}/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF") and len(pdf.content) > 5000

    # history + delete
    assert any(s["id"] == scan_id for s in client.get("/api/scans").json()["scans"])
    assert client.delete(f"/api/scans/{scan_id}").status_code == 200
    assert client.get(f"/api/scans/{scan_id}").status_code == 404
