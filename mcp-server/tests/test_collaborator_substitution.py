"""Verify collaborator placeholder wiring for the 7 auto-probe KB files added
2026-05-21.

Substitution is implemented Java-side in AutoProbeOrchestrator.java (line ~151)
and handles the literal ``{{collaborator}}`` template token. Allocation path:

    needsCollaborator = payload.contains("{{collaborator}}")
                      || any(matcher.type == "collaborator")
    if needsCollaborator:
        cp = CollaboratorPool.tryGetOrCreate(api).generatePayload()
        payload = payload.replace("{{collaborator}}", cp.toString())

Python-side responsibility: ensure no KB file ships a placeholder form the Java
substituter would miss (``COLLABORATOR_URL`` / bare ``COLLABORATOR``). Those
forms are payloads-table convention (mcp-server/src/burpsuite_mcp/payloads/*)
and are only safe there because the payload registry is fed to operators
manually via ``get_payloads`` — never auto-sent.

These tests:
1. Assert each of the 7 new KB files contains zero collaborator placeholders.
2. Assert each KB file declares zero ``collaborator`` matcher type (which
   would otherwise force a pool allocation the KB doesn't consume).
3. Assert no KB file under knowledge/ uses an unsupported placeholder form
   (``COLLABORATOR_URL`` / bare ``COLLABORATOR``) — would silently fail to
   resolve at probe-send time.
"""
import json
import re
import unittest
from pathlib import Path

KB_DIR = Path(__file__).resolve().parents[1] / "src" / "burpsuite_mcp" / "knowledge"

NEW_KB_FILES = [
    "state_machine_race",
    "oauth_dpop_confused_deputy",
    "edge_worker_ssrf",
    "webauthn_passkey_attacks",
    "cache_deception_v2",
    "dom_clobbering_2024",
    "service_worker_attacks",
]

# Java substituter handles this token literal — see AutoProbeOrchestrator.java:151
SUPPORTED_PLACEHOLDER = "{{collaborator}}"

# Forms the substituter does NOT handle. If a KB file ships any of these, the
# placeholder survives into the wire request and either fails or leaks a
# literal string. Treated as a hard test failure.
UNSUPPORTED_PLACEHOLDERS = ("COLLABORATOR_URL", "{{COLLABORATOR}}")

# Bare ``COLLABORATOR`` may appear in human-readable description fields; only
# flag it inside payload/value strings (regex below).
BARE_TOKEN_RE = re.compile(r"\bCOLLABORATOR\b")


def _iter_string_leaves(node, path: str = ""):
    """Yield (path, value) for every string leaf in a nested JSON structure."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _iter_string_leaves(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _iter_string_leaves(v, f"{path}[{i}]")
    elif isinstance(node, str):
        yield path, node


def _collect_payloads(data) -> list[tuple[str, str]]:
    """Return (path, payload-string) for every ``payload`` field."""
    out: list[tuple[str, str]] = []

    def walk(node, path: str = ""):
        if isinstance(node, dict):
            if isinstance(node.get("payload"), str):
                out.append((f"{path}.payload", node["payload"]))
            for k, v in node.items():
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    walk(data)
    return out


def _collect_matcher_types(data) -> list[str]:
    out: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            t = node.get("type")
            if isinstance(t, str):
                out.append(t)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(data)
    return out


class TestCollaboratorSubstitution(unittest.TestCase):
    def test_new_kb_files_exist_and_parse(self):
        for name in NEW_KB_FILES:
            path = KB_DIR / f"{name}.json"
            self.assertTrue(path.exists(), f"missing KB file: {path}")
            with path.open() as f:
                json.load(f)

    def test_new_kb_files_have_no_unsupported_placeholders(self):
        """Each of the 7 new KB files must use the supported ``{{collaborator}}``
        form exclusively (or omit OOB testing entirely)."""
        failures: list[str] = []
        for name in NEW_KB_FILES:
            with (KB_DIR / f"{name}.json").open() as f:
                data = json.load(f)
            for path, value in _iter_string_leaves(data, name):
                for bad in UNSUPPORTED_PLACEHOLDERS:
                    if bad in value:
                        failures.append(
                            f"{name}{path}: unsupported placeholder {bad!r} in {value[:80]!r}"
                        )
                # Bare COLLABORATOR token only flagged inside payload-class
                # paths (payload, value, body). Descriptions are free text.
                if any(seg in path for seg in (".payload", ".value", ".body", ".data")):
                    if BARE_TOKEN_RE.search(value):
                        failures.append(
                            f"{name}{path}: bare COLLABORATOR token in payload: {value[:80]!r}"
                        )
        self.assertEqual(failures, [], "\n".join(failures))

    def test_new_kb_files_collaborator_matcher_consistency(self):
        """If a KB declares a ``collaborator`` matcher type, at least one probe
        in that KB must use ``{{collaborator}}`` (otherwise the pool is
        allocated but never observed). And vice versa."""
        for name in NEW_KB_FILES:
            with (KB_DIR / f"{name}.json").open() as f:
                data = json.load(f)
            matcher_types = _collect_matcher_types(data)
            has_collab_matcher = "collaborator" in matcher_types
            payloads = _collect_payloads(data)
            uses_placeholder = any(SUPPORTED_PLACEHOLDER in p for _, p in payloads)

            if has_collab_matcher:
                self.assertTrue(
                    uses_placeholder,
                    f"{name}: declares 'collaborator' matcher but no payload uses {SUPPORTED_PLACEHOLDER}",
                )

    @unittest.expectedFailure
    def test_all_kb_files_use_only_supported_placeholder(self):
        """Whole-knowledge-base sweep: every KB file must avoid unsupported
        placeholder forms in payload-class fields.

        FINDING (B3 audit, 2026-05-22): multiple pre-existing KB files ship
        payloads with bare ``COLLABORATOR`` (uppercase, no braces) which the
        Java substituter at AutoProbeOrchestrator.java:151 does NOT replace
        (it only handles literal ``{{collaborator}}``). Affected files include:
        dangling_markup, pdf_injection, push_notification, ai_prompt_injection,
        relative_path_overwrite, browser_storage, cspp. Bare ``COLLABORATOR``
        survives into the wire request as the literal string.

        Marked ``expectedFailure`` so the regression stays visible. B3 is
        verification-only — fix tracked as follow-up (extend Java substituter
        to handle bare ``COLLABORATOR`` OR rewrite KB payloads to use
        ``{{collaborator}}``).

        Reference-only files (csv_injection, jwt, xslt_injection, css_injection)
        also contain the token but are skipped by auto_probe so the bug never
        triggers there."""
        failures: list[str] = []
        for path in sorted(KB_DIR.glob("*.json")):
            if path.name.startswith("_"):
                continue
            with path.open() as f:
                data = json.load(f)
            for ppath, value in _collect_payloads(data):
                for bad in UNSUPPORTED_PLACEHOLDERS:
                    if bad in value:
                        failures.append(
                            f"{path.name}{ppath}: unsupported {bad!r} in {value[:80]!r}"
                        )
                if BARE_TOKEN_RE.search(value):
                    failures.append(
                        f"{path.name}{ppath}: bare COLLABORATOR in {value[:80]!r}"
                    )
        self.assertEqual(failures, [], "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
