"""Verify collaborator placeholder wiring for the 7 auto-probe KB files added
2026-05-21.

Substitution is implemented Java-side in AutoProbeOrchestrator.java and handles
two payload forms:

    {{collaborator}}   — canonical (preferred for new KBs)
    COLLABORATOR        — bare token (legacy; kept for KBs authored before the
                          canonical form existed)

Allocation path:

    needsCollaborator = payload.contains("{{collaborator}}")
                      || BARE_COLLABORATOR.matcher(payload).find()
                      || any(matcher.type == "collaborator")
    if needsCollaborator:
        cp = CollaboratorPool.tryGetOrCreate(api).generatePayload()
        payload = payload.replace("{{collaborator}}", cp.toString())
        payload = BARE_COLLABORATOR.matcher(payload).replaceAll(cp.toString())

Both forms produce real Collaborator hosts at runtime. ``COLLABORATOR_URL`` is
NOT a supported KB placeholder — it is reserved for ``payloads/*.json`` (an
operator-facing registry fed via ``get_payloads`` and never auto-sent).

These tests:
1. Assert each of the 7 new KB files contains zero unsupported placeholders.
2. Assert ``collaborator`` matcher type implies at least one consumed payload
   placeholder (otherwise the pool is allocated but never observed).
3. Assert no KB file uses ``COLLABORATOR_URL`` (payloads-table convention only).
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

# Java substituter handles both forms — see AutoProbeOrchestrator.java
SUPPORTED_PLACEHOLDERS = ("{{collaborator}}",)
# Bare COLLABORATOR is also supported. Match outside ``{{...}}`` only — same
# rule the Java substituter applies (negative lookbehind/lookahead on braces).
BARE_TOKEN_RE = re.compile(r"(?<!\{)\bCOLLABORATOR\b(?!\})")

# Forms the substituter does NOT handle. ``COLLABORATOR_URL`` belongs to the
# payloads/ registry, not knowledge/. ``{{COLLABORATOR}}`` (uppercase braced)
# is not a defined form.
UNSUPPORTED_PLACEHOLDERS = ("COLLABORATOR_URL", "{{COLLABORATOR}}")


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
        """Each of the 7 new KB files must use supported placeholder forms only.
        Bare ``COLLABORATOR`` is also supported (legacy form)."""
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
        self.assertEqual(failures, [], "\n".join(failures))

    def test_new_kb_files_collaborator_matcher_consistency(self):
        """If a KB declares a ``collaborator`` matcher type, at least one probe
        in that KB must consume a supported placeholder (otherwise the pool is
        allocated but never observed)."""
        for name in NEW_KB_FILES:
            with (KB_DIR / f"{name}.json").open() as f:
                data = json.load(f)
            matcher_types = _collect_matcher_types(data)
            has_collab_matcher = "collaborator" in matcher_types
            payloads = _collect_payloads(data)
            uses_placeholder = any(
                any(ph in p for ph in SUPPORTED_PLACEHOLDERS) or BARE_TOKEN_RE.search(p)
                for _, p in payloads
            )

            if has_collab_matcher:
                self.assertTrue(
                    uses_placeholder,
                    f"{name}: declares 'collaborator' matcher but no payload consumes a placeholder",
                )

    def test_all_kb_files_use_only_supported_placeholders(self):
        """Whole-knowledge-base sweep: no KB file may use ``COLLABORATOR_URL``
        or ``{{COLLABORATOR}}`` in payload-class fields. Bare ``COLLABORATOR``
        IS supported (Java substituter handles it)."""
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
        self.assertEqual(failures, [], "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
