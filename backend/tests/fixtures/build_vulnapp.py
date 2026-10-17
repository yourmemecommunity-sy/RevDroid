"""Build the deliberately vulnerable test APK (tests/fixtures/vulnapp.apk) from source.

Needs: JDK 11+ and an Android SDK with build-tools + a platform.
    python tests/fixtures/build_vulnapp.py            # uses ANDROID_HOME / ANDROID_SDK_ROOT
    python tests/fixtures/build_vulnapp.py C:/AndroidSDK

Signed with a throwaway *debug* certificate and only the v1 scheme on purpose,
so RevDroid's signing checks have something to find.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "vulnapp"
OUT = HERE / "vulnapp.apk"
EXE = ".exe" if os.name == "nt" else ""
BAT = ".bat" if os.name == "nt" else ""


def latest(d: Path) -> Path:
    def key(p: Path):
        return [int(x) if x.isdigit() else 0 for x in p.name.replace("android-", "").replace("-", ".").split(".")]
    return sorted((p for p in d.iterdir() if p.is_dir()), key=key)[-1]


def run(*cmd: str | Path) -> None:
    print("  $", " ".join(str(c) for c in cmd)[:160])
    subprocess.run([str(c) for c in cmd], check=True)


def main() -> None:
    sdk = Path(sys.argv[1] if len(sys.argv) > 1 else os.getenv("ANDROID_HOME") or os.getenv("ANDROID_SDK_ROOT") or "")
    if not (sdk / "build-tools").exists():
        sys.exit("Android SDK not found. Pass its path or set ANDROID_HOME.")
    bt = latest(sdk / "build-tools")
    android_jar = latest(sdk / "platforms") / "android.jar"
    print(f"build-tools {bt.name}, platform {android_jar.parent.name}")

    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        run(bt / f"aapt2{EXE}", "compile", "--dir", SRC / "res", "-o", t / "res.zip")
        run(bt / f"aapt2{EXE}", "link", "-I", android_jar, "--manifest", SRC / "AndroidManifest.xml",
            "-o", t / "base.apk", t / "res.zip")
        classes = t / "classes"
        sources = [str(p) for p in (SRC / "src").rglob("*.java")]
        run("javac", "-nowarn", "-Xlint:-options", "-source", "11", "-target", "11", "-cp", android_jar,
            "-d", classes, *sources)
        dex_dir = t / "dex"
        dex_dir.mkdir()
        run(bt / f"d8{BAT}", "--min-api", "19", "--lib", android_jar, "--output", dex_dir,
            *[str(p) for p in classes.rglob("*.class")])
        with zipfile.ZipFile(t / "base.apk", "a") as z:
            z.write(dex_dir / "classes.dex", "classes.dex")
        run(bt / f"zipalign{EXE}", "-f", "4", t / "base.apk", t / "aligned.apk")
        ks = t / "debug.keystore"
        run("keytool", "-genkeypair", "-keystore", ks, "-storepass", "android", "-keypass", "android",
            "-alias", "androiddebugkey", "-keyalg", "RSA", "-keysize", "2048", "-validity", "365",
            "-dname", "CN=Android Debug,O=Android,C=US")
        run(bt / f"apksigner{BAT}", "sign", "--ks", ks, "--ks-pass", "pass:android",
            "--v1-signing-enabled", "true", "--v2-signing-enabled", "false", "--v3-signing-enabled", "false",
            "--out", OUT, t / "aligned.apk")
    print(f"built {OUT} ({OUT.stat().st_size:,} bytes)")


if __name__ == "__main__":
    if shutil.which("javac") is None:
        sys.exit("javac not found on PATH")
    main()
