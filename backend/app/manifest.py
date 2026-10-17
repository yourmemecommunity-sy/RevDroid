"""Decode AndroidManifest.xml with apktool and turn it into permissions + findings."""
from __future__ import annotations

import logging
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from . import tools
from .config import settings
from .findings import finding
from .permissions import classify

log = logging.getLogger("revdroid.manifest")
A = "{http://schemas.android.com/apk/res/android}"
COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")


def decode_with_apktool(apk: Path, out_dir: Path) -> Path | None:
    """Decode manifest + resources (no smali). Returns the output dir, or None on failure."""
    cmd = tools.apktool_cmd()
    if not cmd:
        log.warning("apktool not available; falling back to androguard's manifest parser")
        return None
    shutil.rmtree(out_dir, ignore_errors=True)
    try:
        res = tools.run(cmd + ["d", "-f", "-s", "--no-assets", "-o", str(out_dir), str(apk)],
                        timeout=settings.apktool_timeout)
    except (OSError, tools.ToolError) as exc:
        log.warning("apktool failed: %s", exc)
        return None
    if not (out_dir / "AndroidManifest.xml").exists():
        log.warning("apktool exit %s, no manifest: %s", res.returncode, res.stderr[-500:])
        return None
    return out_dir


def load_manifest_root(decoded: Path | None, apk_obj) -> ET.Element:
    """Prefer apktool's text manifest; fall back to androguard's binary-XML decoder."""
    if decoded:
        try:
            return ET.parse(decoded / "AndroidManifest.xml").getroot()
        except ET.ParseError as exc:
            log.warning("apktool manifest unparsable (%s); using androguard", exc)
    from lxml import etree  # androguard dependency
    return ET.fromstring(etree.tostring(apk_obj.get_android_manifest_xml()))


def _attr(el: ET.Element, name: str) -> str | None:
    return el.get(A + name)


def _is_true(v: str | None) -> bool:
    return (v or "").strip().lower() == "true"


def _component_exported(el: ET.Element, kind: str, target_sdk: int) -> tuple[bool, str]:
    exported = _attr(el, "exported")
    if exported is not None:
        return _is_true(exported), "android:exported=\"" + exported + "\""
    if el.find("intent-filter") is not None:
        return True, "implicitly exported (has an intent-filter, no android:exported)"
    if kind == "provider" and target_sdk < 17:
        return True, "implicitly exported (provider default before API 17)"
    return False, ""


def _is_launcher(el: ET.Element) -> bool:
    for f in el.findall("intent-filter"):
        actions = {_attr(a, "name") for a in f.findall("action")}
        cats = {_attr(c, "name") for c in f.findall("category")}
        if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in cats:
            return True
    return False


def _resolve_xml_res(decoded: Path | None, ref: str | None) -> Path | None:
    if not decoded or not ref or not ref.startswith("@xml/"):
        return None
    p = decoded / "res" / "xml" / (ref[len("@xml/"):] + ".xml")
    return p if p.exists() else None


def analyze_manifest(root: ET.Element, identity: dict[str, Any], decoded: Path | None) -> dict[str, Any]:
    target_sdk = identity.get("target_sdk") or 1
    min_sdk = identity.get("min_sdk") or 1
    app = root.find("application")
    if app is None:
        app = ET.Element("application")
    findings: list[dict[str, Any]] = []
    loc = [{"file": "AndroidManifest.xml", "line": None, "snippet": None}]

    # ---------------- permissions ----------------
    names = set()
    for tag in ("uses-permission", "uses-permission-sdk-23"):
        for el in root.findall(tag):
            if n := _attr(el, "name"):
                names.add(n)
    permissions = sorted((classify(n) for n in names), key=lambda p: (
        {"signature": 0, "dangerous": 1, "custom": 2, "normal": 3}[p["protection_level"]], p["name"]))
    declared = [{"name": _attr(el, "name"), "protection_level": _attr(el, "protectionLevel") or "normal"}
                for el in root.findall("permission")]

    high_impact = [p["short_name"] for p in permissions if p["high_impact"]]
    if high_impact:
        findings.append(finding(
            id="MAN-SENSITIVE-PERMS", title=f"Requests {len(high_impact)} high-impact permission(s)",
            severity="medium" if len(high_impact) >= 3 else "low", category="permissions", source="manifest",
            evidence=", ".join(high_impact), masvs="MASVS-PRIVACY-1", cwe="CWE-250",
            description="These permissions give access to SMS, calls, microphone, other apps or the screen. "
                        "Malware abuses exactly these, and Google Play restricts several of them.",
            recommendation="Remove every permission the app does not strictly need; prefer intents "
                           "(e.g. the SMS app or a file picker) over broad permissions.", locations=loc))

    # ---------------- application flags ----------------
    if _is_true(_attr(app, "debuggable")):
        findings.append(finding(
            id="MAN-DEBUGGABLE", title="App is debuggable", severity="high", category="configuration",
            source="manifest", evidence='android:debuggable="true"', cwe="CWE-489", masvs="MASVS-RESILIENCE-2",
            description="Anyone with USB access can attach a debugger, read the app's private data with run-as, "
                        "and change its behaviour at runtime.",
            recommendation="Never ship a debuggable build. Remove the attribute and let the release build type "
                           "set debuggable=false.", locations=loc))
    if _is_true(_attr(app, "testOnly")):
        findings.append(finding(
            id="MAN-TESTONLY", title="APK is marked testOnly", severity="low", category="configuration",
            source="manifest", evidence='android:testOnly="true"', cwe="CWE-489",
            description="testOnly builds come from the IDE's run button and are not meant for distribution.",
            recommendation="Build releases with the release build type (./gradlew assembleRelease).",
            locations=loc))

    backup = _attr(app, "allowBackup")
    if _is_true(backup) or backup is None:
        explicit = backup is not None
        findings.append(finding(
            id="MAN-ALLOW-BACKUP", title="Application data can be backed up",
            severity="medium" if explicit else "low", category="configuration", source="manifest",
            evidence='android:allowBackup="true"' if explicit else "android:allowBackup not set (defaults to true)",
            cwe="CWE-530", masvs="MASVS-STORAGE-2",
            description="Backups (adb backup on older devices, cloud and device-to-device transfer) can copy "
                        "the app's databases, shared preferences and tokens off the device.",
            recommendation='Set android:allowBackup="false", or use dataExtractionRules / fullBackupContent '
                           "to exclude credentials and tokens.", locations=loc))

    cleartext = _attr(app, "usesCleartextTraffic")
    nsc_ref = _attr(app, "networkSecurityConfig")
    if _is_true(cleartext):
        findings.append(finding(
            id="MAN-CLEARTEXT", title="Cleartext (HTTP) traffic is allowed", severity="medium",
            category="network", source="manifest", evidence='android:usesCleartextTraffic="true"',
            cwe="CWE-319", masvs="MASVS-NETWORK-1",
            description="Unencrypted HTTP lets anyone on the same network read or change the traffic.",
            recommendation="Use HTTPS everywhere and remove usesCleartextTraffic, or limit cleartext to specific "
                           "debug domains through a network security config.", locations=loc))
    elif cleartext is None and nsc_ref is None and target_sdk < 28:
        findings.append(finding(
            id="MAN-CLEARTEXT-DEFAULT", title="Cleartext traffic allowed by default (targetSdk < 28)",
            severity="low", category="network", source="manifest", evidence=f"targetSdkVersion={target_sdk}",
            cwe="CWE-319", masvs="MASVS-NETWORK-1",
            description="Apps targeting API 27 or lower may use plain HTTP unless they opt out.",
            recommendation="Raise targetSdkVersion, or set usesCleartextTraffic=\"false\".", locations=loc))

    # network security config file
    nsc_path = _resolve_xml_res(decoded, nsc_ref)
    if nsc_path:
        try:
            nsc = ET.parse(nsc_path).getroot()
            nsc_loc = [{"file": f"res/xml/{nsc_path.name}", "line": None, "snippet": None}]
            for el in nsc.iter():
                if el.tag in ("base-config", "domain-config") and _is_true(el.get("cleartextTrafficPermitted")):
                    findings.append(finding(
                        id="NSC-CLEARTEXT", title="Network security config permits cleartext",
                        severity="medium", category="network", source="manifest",
                        evidence=f'<{el.tag} cleartextTrafficPermitted="true">', cwe="CWE-319",
                        masvs="MASVS-NETWORK-1", locations=nsc_loc,
                        description="The network security config explicitly allows unencrypted HTTP.",
                        recommendation="Set cleartextTrafficPermitted=\"false\" outside of debug-overrides."))
                    break
            for parent in nsc.iter():
                if parent.tag == "debug-overrides":
                    continue
                for certs in parent.findall("trust-anchors/certificates"):
                    if certs.get("src") == "user":
                        findings.append(finding(
                            id="NSC-USER-CA", title="App trusts user-installed CA certificates",
                            severity="medium", category="network", source="manifest",
                            evidence='<certificates src="user"/>', cwe="CWE-295", masvs="MASVS-NETWORK-1",
                            locations=nsc_loc,
                            description="Any CA the user (or malware, or an MDM) installs can intercept the "
                                        "app's TLS traffic.",
                            recommendation="Trust only system CAs in release builds; put user CAs under "
                                           "<debug-overrides>."))
                        break
        except ET.ParseError:
            log.warning("could not parse %s", nsc_path)

    if min_sdk < 21:
        findings.append(finding(
            id="MAN-OLD-MINSDK", title=f"Supports very old Android versions (minSdk {min_sdk})",
            severity="low", category="configuration", source="manifest", evidence=f"minSdkVersion={min_sdk}",
            cwe="CWE-1104", masvs="MASVS-CODE-3",
            description="Android versions below 5.0 no longer receive security patches and lack modern "
                        "platform protections.",
            recommendation="Raise minSdkVersion to at least 23 if your audience allows it.", locations=loc))

    # ---------------- components ----------------
    components: list[dict[str, Any]] = []
    exposed: dict[str, list[dict[str, Any]]] = {k: [] for k in COMPONENTS}
    for kind in COMPONENTS:
        for el in app.findall(kind):
            name = _attr(el, "name") or "?"
            exported, why = _component_exported(el, kind, target_sdk)
            perm = _attr(el, "permission")
            if kind == "provider":
                perm = perm or (_attr(el, "readPermission") and _attr(el, "writePermission") and "read/write")
            launcher = kind.startswith("activity") and _is_launcher(el)
            comp = {"type": kind, "name": name, "exported": exported, "permission": perm,
                    "launcher": launcher, "reason": why}
            components.append(comp)
            if exported and not perm and not launcher:
                exposed[kind].append(comp)

    meta = {
        "provider": ("high", "CWE-926", "Other apps can query, insert, update or delete data through these "
                     "providers, and path-traversal or SQL injection bugs in them become remotely reachable."),
        "service": ("medium", "CWE-926", "Any installed app can start or bind to these services and trigger "
                    "their work."),
        "receiver": ("medium", "CWE-925", "Any app can send broadcasts to these receivers, including forged "
                     "system-like events."),
        "activity": ("medium", "CWE-926", "Any app can launch these screens directly, possibly skipping a login "
                     "screen or passing malicious extras."),
        "activity-alias": ("medium", "CWE-926", "Any app can launch these activity aliases directly."),
    }
    for kind, items in exposed.items():
        if not items:
            continue
        sev, cwe, why = meta[kind]
        label = "content provider" if kind == "provider" else kind.replace("-", " ")
        findings.append(finding(
            id=f"MAN-EXPORTED-{kind.upper()}",
            title=f"{len(items)} exported {label}(s) without permission protection",
            severity=sev, category="components", source="manifest", cwe=cwe, masvs="MASVS-PLATFORM-1",
            evidence=", ".join(i["name"].rsplit(".", 1)[-1] for i in items[:6]) + ("..." if len(items) > 6 else ""),
            description=why,
            recommendation='Set android:exported="false" unless other apps must use the component; otherwise '
                           "protect it with an android:permission whose protectionLevel is signature, and "
                           "validate every incoming Intent.",
            locations=[{"file": "AndroidManifest.xml", "line": None, "snippet": f"<{kind} {i['name']}> {i['reason']}"}
                       for i in items[:25]],
            occurrences=len(items)))

    return {
        "permissions": permissions,
        "declared_permissions": declared,
        "components": components,
        "flags": {
            "debuggable": _is_true(_attr(app, "debuggable")),
            "allow_backup": backup if backup is not None else "default (true)",
            "uses_cleartext_traffic": cleartext if cleartext is not None else "default",
            "network_security_config": nsc_ref,
        },
        "findings": findings,
    }
