"""Static APK analysis — jadx decompile + manifest attack-surface + secret leads.

Fills the mobile lane's static gap: `frida`/`control` cover DYNAMIC only, yet
MASTG (MASVS-CODE / MASVS-STORAGE) wants the decompiled sources and the manifest
reviewed. This decompiles an APK with jadx, extracts the exported-component
attack surface + risky manifest flags, and greps the Java for hardcoded
secrets/endpoints as LEADS. For a full SAST pass over the output, run
`run_opengrep_source(<out>/sources)` on the decompiled tree — this tool does not
duplicate that engine (single concern).

All work is local/offline (no target traffic); nothing routes through Burp.
"""

from __future__ import annotations

import plistlib
import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _check_tool, _run_cmd

_ANDROID_NS = "http://schemas.android.com/apk/res/android"


# Compact, high-precision secret/endpoint leads (mirrors extract_js_secrets
# intent for decompiled Java). Value-shaped, low false-positive.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("firebase_url", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}")),
    ("bearer", re.compile(r"[Bb]earer\s+[A-Za-z0-9._\-]{12,}")),
    ("secret_kv", re.compile(
        r"(?i)(?:api[_-]?key|secret|password|passwd|token|client[_-]?secret)"
        r"\s*[=:]\s*[\"'][^\"']{6,}[\"']")),
]
_ENDPOINT = re.compile(r"https?://[A-Za-z0-9._\-]+(?::\d+)?(?:/[^\s\"'<>]*)?")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _attr(el: ET.Element, name: str) -> str:
    return el.attrib.get(f"{{{_ANDROID_NS}}}{name}", "")


def _parse_manifest(path: Path) -> dict:
    """Attack-surface signals from a jadx-decompiled AndroidManifest.xml."""
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return {"error": f"could not parse {path}"}
    out: dict = {
        "package": root.attrib.get("package", ""),
        "permissions": [], "exported": [], "flags": {},
    }
    for perm in root.iter("uses-permission"):
        n = _attr(perm, "name")
        if n:
            out["permissions"].append(n)
    app = root.find("application")
    if app is not None:
        for flag in ("debuggable", "allowBackup", "usesCleartextTraffic"):
            v = _attr(app, flag)
            if v:
                out["flags"][flag] = v
        for comp in app:
            kind = _local(comp.tag)
            if kind not in ("activity", "service", "receiver", "provider"):
                continue
            exported = _attr(comp, "exported")
            has_filter = comp.find("intent-filter") is not None
            # Explicitly exported, OR (pre-S implicit) a component with an
            # intent-filter and no exported flag -> reachable by other apps.
            if exported == "true" or (exported == "" and has_filter):
                out["exported"].append({
                    "type": kind,
                    "name": _attr(comp, "name") or "?",
                    "exported_attr": exported or "(implicit via intent-filter)",
                    "permission": _attr(comp, "permission") or "",
                })
    return out


def _scan_sources(src_root: Path, cap: int) -> tuple[list[str], list[str]]:
    """Grep decompiled .java for secret leads and endpoints (bounded)."""
    secrets: list[str] = []
    endpoints: set[str] = set()
    if not src_root.exists():
        return secrets, sorted(endpoints)
    files = 0
    for jf in src_root.rglob("*.java"):
        files += 1
        if files > 20000 or len(secrets) >= cap:
            break
        try:
            text = jf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name, pat in _SECRET_PATTERNS:
            m = pat.search(text)
            if m:
                secrets.append(f"{name}: {jf.name}: {m.group(0)[:80]}")
                if len(secrets) >= cap:
                    break
        for m in _ENDPOINT.finditer(text):
            endpoints.add(m.group(0)[:120])
            if len(endpoints) >= 200:
                break
    return secrets, sorted(endpoints)


def _ipa_info(app_dir: Path) -> dict:
    """Attack-surface signals from an iOS app's Info.plist (binary or XML)."""
    p = app_dir / "Info.plist"
    if not p.is_file():
        return {"error": "no Info.plist"}
    try:
        with p.open("rb") as fh:
            pl = plistlib.load(fh)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {"error": "could not parse Info.plist"}
    schemes: list[str] = []
    for url_type in pl.get("CFBundleURLTypes", []) or []:
        schemes += list(url_type.get("CFBundleURLSchemes", []) or [])
    ats = pl.get("NSAppTransportSecurity", {}) or {}
    usage = {k: v for k, v in pl.items() if k.endswith("UsageDescription")}
    return {
        "bundle_id": pl.get("CFBundleIdentifier", ""),
        "version": pl.get("CFBundleShortVersionString", ""),
        "min_os": pl.get("MinimumOSVersion", ""),
        "url_schemes": schemes,                      # deep-link attack surface
        "ats_allows_cleartext": bool(ats.get("NSAllowsArbitraryLoads")),
        "background_modes": pl.get("UIBackgroundModes", []) or [],
        "permission_usages": sorted(usage.keys()),
    }


def _ipa_entitlements(app_dir: Path) -> dict:
    """Entitlements from embedded.mobileprovision (the plist is inside a CMS blob;
    slice it out by the <plist>..</plist> markers — no openssl needed)."""
    p = app_dir / "embedded.mobileprovision"
    if not p.is_file():
        return {}
    try:
        raw = p.read_bytes()
    except OSError:
        return {}
    start, end = raw.find(b"<plist"), raw.find(b"</plist>")
    if start == -1 or end == -1:
        return {}
    try:
        pl = plistlib.loads(raw[start:end + 8])
    except (plistlib.InvalidFileException, ValueError):
        return {}
    ent = pl.get("Entitlements", {}) or {}
    return {
        "get_task_allow": bool(ent.get("get-task-allow")),   # debuggable build
        "aps_environment": ent.get("aps-environment", ""),
        "associated_domains": ent.get("com.apple.developer.associated-domains", []),
        "keychain_groups": ent.get("keychain-access-groups", []),
        "team_id": pl.get("TeamName", ""),
    }


def _macho_secrets(app_dir: Path, cap: int) -> tuple[list[str], list[str]]:
    """Secret/endpoint leads from the app's Mach-O binary + bundled text (bounded)."""
    secrets: list[str] = []
    endpoints: set[str] = set()
    files = 0
    for f in app_dir.rglob("*"):
        if not f.is_file() or files > 4000 or len(secrets) >= cap:
            continue
        if f.suffix.lower() in (".png", ".jpg", ".jpeg", ".car", ".nib", ".ttf", ".otf"):
            continue
        files += 1
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for name, pat in _SECRET_PATTERNS:
            m = pat.search(text)
            if m:
                secrets.append(f"{name}: {f.name}: {m.group(0)[:80]}")
                if len(secrets) >= cap:
                    break
        for m in _ENDPOINT.finditer(text):
            endpoints.add(m.group(0)[:120])
            if len(endpoints) >= 200:
                break
    return secrets, sorted(endpoints)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def mobile_decompile_apk(
        apk_path: str,
        out_dir: str = "",
        max_secret_hits: int = 60,
        timeout: int = 600,
    ) -> str:
        """Decompile an APK with jadx and extract its static attack surface.

        Fills the mobile lane's static gap (Frida/adb are dynamic-only). Runs
        `jadx` to recover Java sources + AndroidManifest, then reports the
        exported-component attack surface, risky manifest flags (debuggable /
        allowBackup / cleartext), declared permissions, and hardcoded
        secret/endpoint leads. For deep SAST run `run_opengrep_source` on the
        `<out>/sources` tree. Local/offline — no target traffic.

        Args:
            apk_path: Path to the .apk (pull one with mobile_pull_file).
            out_dir: Decompile output dir (default: <apk>_jadx beside the apk).
            max_secret_hits: Cap on reported secret leads (default 60).
            timeout: Max seconds for jadx (default 600).
        """
        if not _check_tool("jadx"):
            return (
                "Error: jadx not installed.\n"
                "  apt install jadx  OR  https://github.com/skylot/jadx/releases"
            )
        apk = Path(apk_path).expanduser()
        if not apk.exists():
            return f"Error: apk not found: {apk_path}"
        out = Path(out_dir).expanduser() if out_dir else apk.with_name(apk.stem + "_jadx")

        # jadx: recover sources + resources (manifest). --no-debug-info keeps it lean.
        cmd = ["jadx", "--no-debug-info", "-d", str(out), str(apk)]
        stdout, stderr, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        src_root = out / "sources"
        if not src_root.exists():
            return (
                f"jadx did not produce sources at {src_root} (rc={rc}).\n"
                f"{(stderr or stdout)[:400]}"
            )

        manifest = _parse_manifest(out / "resources" / "AndroidManifest.xml")
        secrets, endpoints = _scan_sources(src_root, max_secret_hits)

        lines = [f"mobile_decompile_apk: {apk.name} -> {out}"]
        if rc != 0:
            lines.append(f"  (jadx exit {rc}; partial decompile — some classes may be missing)")
        if manifest.get("package"):
            lines.append(f"  package: {manifest['package']}")

        flags = manifest.get("flags", {})
        risky = [f"{k}={v}" for k, v in flags.items()
                 if (k in ("debuggable", "usesCleartextTraffic") and v == "true")
                 or (k == "allowBackup" and v == "true")]
        if risky:
            lines.append("  RISKY MANIFEST FLAGS: " + ", ".join(risky))

        exported = manifest.get("exported", [])
        lines.append(f"\n  Exported components ({len(exported)}):")
        for c in exported[:40]:
            perm = f" perm={c['permission']}" if c["permission"] else " (no permission)"
            lines.append(f"    {c['type']}: {c['name']}  [{c['exported_attr']}]{perm}")
        if not exported:
            lines.append("    (none reachable by other apps)")

        perms = manifest.get("permissions", [])
        dangerous = [p for p in perms if any(d in p for d in (
            "READ_SMS", "SEND_SMS", "READ_CONTACTS", "ACCESS_FINE_LOCATION",
            "RECORD_AUDIO", "CAMERA", "READ_EXTERNAL_STORAGE",
            "WRITE_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES"))]
        lines.append(f"\n  Permissions: {len(perms)} declared"
                     + (f"; notable: {', '.join(p.split('.')[-1] for p in dangerous[:12])}"
                        if dangerous else ""))

        lines.append(f"\n  Secret leads ({len(secrets)} — VERIFY, do not assume live):")
        for s in secrets[:max_secret_hits]:
            lines.append(f"    {s}")
        if not secrets:
            lines.append("    (none matched the high-precision patterns)")

        lines.append(f"\n  Endpoints ({len(endpoints)} unique, first 30):")
        for e in endpoints[:30]:
            lines.append(f"    {e}")

        lines.append(f"\n  Next: run_opengrep_source('{src_root}') for full SAST; "
                     "Frida-hook the exported components dynamically.")
        return "\n".join(lines)

    @mcp.tool()
    async def mobile_analyze_ipa(
        ipa_path: str,
        out_dir: str = "",
        max_secret_hits: int = 60,
    ) -> str:
        """Static-analyze an iOS .ipa — the MASVS-CODE/STORAGE half jadx can't do.

        Unzips the IPA (no jailbreak/device needed) and reports the attack
        surface: bundle id, custom URL schemes (deep-link surface), ATS cleartext
        allowance, permission usage strings, entitlements from
        embedded.mobileprovision (get-task-allow = debuggable, associated-domains
        = universal links, keychain groups), and secret/endpoint leads from the
        Mach-O binary + bundled resources.

        Args:
            ipa_path: Path to the .ipa (pull one from the device / App Store).
            out_dir: Unzip dir (default: <ipa>_ipa beside the file).
            max_secret_hits: Cap on reported secret leads (default 60).
        """
        ipa = Path(ipa_path).expanduser()
        if not ipa.exists():
            return f"Error: ipa not found: {ipa_path}"
        out = Path(out_dir).expanduser() if out_dir else ipa.with_name(ipa.stem + "_ipa")
        try:
            with zipfile.ZipFile(ipa) as z:
                # zip-slip guard: refuse entries that escape the output dir.
                for n in z.namelist():
                    if n.startswith("/") or ".." in Path(n).parts:
                        return f"Error: unsafe path in IPA: {n!r}"
                z.extractall(out)
        except (zipfile.BadZipFile, OSError) as exc:
            return f"Error: not a valid IPA/zip: {exc}"
        apps = list((out / "Payload").glob("*.app")) if (out / "Payload").is_dir() else []
        if not apps:
            return f"Error: no Payload/*.app in {out} — not a standard IPA."
        app = apps[0]

        info = _ipa_info(app)
        ent = _ipa_entitlements(app)
        secrets, endpoints = _macho_secrets(app, max_secret_hits)

        lines = [f"mobile_analyze_ipa: {ipa.name} -> {app.name}"]
        if info.get("bundle_id"):
            lines.append(f"  bundle: {info['bundle_id']} v{info.get('version','')} "
                         f"(min iOS {info.get('min_os','?')})")
        risky = []
        if info.get("ats_allows_cleartext"):
            risky.append("ATS NSAllowsArbitraryLoads=true (cleartext allowed)")
        if ent.get("get_task_allow"):
            risky.append("get-task-allow=true (debuggable build)")
        if risky:
            lines.append("  RISKY: " + "; ".join(risky))
        if info.get("url_schemes"):
            lines.append(f"\n  Custom URL schemes (deep-link surface): "
                         f"{', '.join(info['url_schemes'][:20])}")
        if ent.get("associated_domains"):
            lines.append(f"  Universal links: {', '.join(ent['associated_domains'][:12])}")
        if info.get("permission_usages"):
            lines.append(f"  Permissions requested: "
                         f"{', '.join(p.replace('UsageDescription','') for p in info['permission_usages'][:14])}")
        if ent.get("keychain_groups"):
            lines.append(f"  Keychain groups: {', '.join(ent['keychain_groups'][:8])}")

        lines.append(f"\n  Secret leads ({len(secrets)} — VERIFY, do not assume live):")
        for s in secrets[:max_secret_hits]:
            lines.append(f"    {s}")
        if not secrets:
            lines.append("    (none matched the high-precision patterns)")
        lines.append(f"\n  Endpoints ({len(endpoints)} unique, first 30):")
        for e in endpoints[:30]:
            lines.append(f"    {e}")
        lines.append(f"\n  Next: run_opengrep_source('{app}') over the bundle; "
                     "fuzz the URL schemes with mobile_deeplink; Frida-hook at runtime.")
        return "\n".join(lines)
