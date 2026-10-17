import os
import sys
import tempfile
from pathlib import Path

# Isolate tests from real scan data: must be set before the app is imported.
_tmp = tempfile.mkdtemp(prefix="revdroid-test-")
os.environ["REVDROID_DATA_DIR"] = _tmp
os.environ["SCAN_RETENTION_DAYS"] = "0"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FIXTURE_APK = Path(__file__).resolve().parent / "fixtures" / "vulnapp.apk"

# Fake secrets planted in the fixture. None of them may ever appear in full in any output.
PLANTED_SECRETS = [
    "AKIAIOSFODNN7EXAMPLE",
    "sk_test_51RevDroidFakeKey0000",
    "Sup3rS3cret!",
    "0123456789abcdef",
    "s3cr3t-backend-value-123",
    "AIzaSyDUMMY_KEY_FOR_REVDROID_TESTS_0000",
    "MIIEfake",  # private key body
]
