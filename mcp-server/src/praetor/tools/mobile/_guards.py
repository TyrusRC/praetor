"""HARD safety for the mobile lane: destructive denylist + device allowlist.

Layered on the shared exploit denylist (validate_payload) so filesystem and
system-destruction patterns are caught once, plus mobile-specific irreversible
ops (factory reset, non-target uninstall/clear, reboot to bootloader, SMS/call
abuse). check_device enforces "never on someone else's device" (Rule 8).
"""

from __future__ import annotations

import os
import re

from praetor.tools.exploit._safety import validate_payload

# Mobile-specific irreversible / abusive patterns. Package uninstall/clear are
# data-destroying (Rule 8) — a read-only pentest never needs them. SMS/call
# service calls are cost/abuse (Rule 6/7 analog).
_MOBILE_DESTRUCTIVE: tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"MASTER_CLEAR",
        r"--wipe_data|\bwipe\b",
        r"\bpm\s+uninstall\b",
        r"\bpm\s+clear\b",
        r"\breboot\s+(?:bootloader|recovery|download|edl)\b",
        r"\bfastboot\b",
        r"\bsvc\s+power\s+shutdown\b",
        r"\bservice\s+call\s+isms\b",     # send SMS
        r"\bservice\s+call\s+phone\b",    # place call
        r"content\s+delete",              # provider row deletion
    )
)

# Security-destructive `settings put` / `locksettings` writes (Task 5 preview:
# mobile_setting get/put). Disabling lock screens, package verification, or
# provisioning state removes the device's own security controls — never a
# legitimate pentest action even on the operator's own device.
_MOBILE_SETTING_DENY: tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\blocksettings\b",
        r"settings\s+put\s+secure\s+lock(screen|_pattern|_password|_pin)",
        r"settings\s+put\s+secure\s+lockscreen\.disabled",
        r"settings\s+put\s+(secure|global)\s+package_verifier",
        r"settings\s+put\s+global\s+(verifier_verify_adb_installs|upload_apk_enable)",
        r"settings\s+put\s+(secure|global)\s+install_non_market_apps",
        r"settings\s+put\s+secure\s+(rollback_verifier|user_setup_complete|device_provisioned|managed_provisioning)",
    )
)


def check_command(command: str) -> tuple[bool, str]:
    """Return (ok, reason). ok=False refuses. Runs the shared destructive
    layer first (rm -rf, dd, format, ...), then mobile-specific patterns,
    then the settings/locksettings denylist."""
    ok, why = validate_payload(command, vuln_type="mobile")
    if not ok:
        return False, why
    for pat in _MOBILE_DESTRUCTIVE:
        m = pat.search(command)
        if m:
            return False, (
                f"destructive/abusive mobile op blocked: {m.group(0)!r}. "
                "Mobile pentest proves impact with READ access; drop to "
                "send_raw_request / a manual shell and own the risk if truly required."
            )
    for pat in _MOBILE_SETTING_DENY:
        m = pat.search(command)
        if m:
            return False, (
                f"security-destructive setting write blocked: {m.group(0)!r} — "
                "refuse to disable locks/verification/provisioning"
            )
    return True, ""


def allowed_devices() -> list[str]:
    """Operator-authorized serials/udids from PRAETOR_MOBILE_DEVICES."""
    raw = os.environ.get("PRAETOR_MOBILE_DEVICES", "")
    return [d.strip() for d in raw.split(",") if d.strip()]


def check_device(device_id: str, connected_count: int, strict: bool = False) -> tuple[bool, str]:
    """Enforce the device allowlist (Rule 8). Allowlisted -> ok. No allowlist +
    exactly one device + not strict -> ok (operator convenience). Else refuse."""
    allow = allowed_devices()
    if device_id and device_id in allow:
        return True, ""
    if allow:
        return False, (
            f"device {device_id!r} not in PRAETOR_MOBILE_DEVICES allowlist "
            f"({', '.join(allow)}). Add it only if you are authorized to test it.")
    if strict:
        return False, ("no device allowlist set and strict mode on. Set "
                       "PRAETOR_MOBILE_DEVICES to the serial(s) you are authorized to test.")
    if connected_count == 1:
        return True, ""
    return False, ("no device allowlist set and multiple devices connected — refusing "
                   "to guess. Set PRAETOR_MOBILE_DEVICES to the authorized serial/udid.")
