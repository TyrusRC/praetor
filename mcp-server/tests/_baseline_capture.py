"""Snapshot assess_finding outputs for a range of scenarios — used to prove
behavior equivalence pre/post refactor.

Run pre-refactor to write baseline:
    uv run python -m tests._baseline_capture write

Run post-refactor to verify:
    uv run python -m tests._baseline_capture verify
"""

import asyncio
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from burpsuite_mcp import server


SCENARIOS = [
    # (name, kwargs)
    ("self_xss", dict(
        vuln_type="xss",
        endpoint="/profile",
        evidence="payload only triggers when victim pastes JS into devtools — self-XSS",
        domain="example.com",
    )),
    ("self_xss_negated", dict(
        vuln_type="xss",
        endpoint="/profile",
        evidence="alert(1) executed in stored context, not a self-xss because attacker injects via /search",
        domain="example.com",
    )),
    ("idor_strong", dict(
        vuln_type="idor",
        endpoint="/api/users/{id}",
        evidence="user_id is sequential auto-increment; can fuzz id range to enumerate other accounts",
        domain="example.com",
    )),
    ("idor_weak", dict(
        vuln_type="idor",
        endpoint="/api/users/1",
        evidence="changed the id and got a different page",
        domain="example.com",
    )),
    ("sqli_strong", dict(
        vuln_type="sqli",
        endpoint="/search",
        evidence="response time 5.2s with sleep(5), 0.1s baseline, confirmed 3/3 iterations",
        domain="example.com",
    )),
    ("sqli_blind_no_repro", dict(
        vuln_type="sqli_blind",
        endpoint="/search",
        evidence="sleep(5) triggers delay",
        domain="example.com",
    )),
    ("sqli_blind_with_repros", dict(
        vuln_type="sqli_blind",
        endpoint="/search",
        evidence="sleep(5) confirmed 3/3 iterations consistent timing",
        reproductions=[
            {"logger_index": 1, "elapsed_ms": 5100, "status_code": 200},
            {"logger_index": 2, "elapsed_ms": 5050, "status_code": 200},
            {"logger_index": 3, "elapsed_ms": 5200, "status_code": 200},
        ],
        domain="example.com",
    )),
    ("open_redirect_no_chain", dict(
        vuln_type="open_redirect_no_chain",
        endpoint="/redirect",
        evidence="redirects to evil.com via ?next=",
        domain="example.com",
    )),
    ("clickjacking_about", dict(
        vuln_type="clickjacking",
        endpoint="/about",
        evidence="page can be framed; missing X-Frame-Options",
        domain="example.com",
    )),
    ("clickjacking_sensitive_endpoint", dict(
        vuln_type="clickjacking",
        endpoint="/transfer-funds",
        evidence="page can be framed; missing X-Frame-Options on funds transfer",
        domain="example.com",
    )),
    ("rce_strong", dict(
        vuln_type="rce",
        endpoint="/exec",
        evidence="uid=0(root) gid=0(root) command output reflected",
        domain="example.com",
    )),
    ("ssrf_collaborator", dict(
        vuln_type="ssrf",
        endpoint="/fetch",
        parameter="url",
        evidence="collaborator interaction received; oob callback fired",
        domain="example.com",
    )),
    ("xxe_blind_no_repro", dict(
        vuln_type="xxe_blind",
        endpoint="/upload",
        evidence="external entity parsed",
        domain="example.com",
    )),
    ("unknown_vuln_type", dict(
        vuln_type="invented_class",
        endpoint="/foo",
        evidence="something happened",
        domain="example.com",
    )),
    ("human_verified_skips_q5", dict(
        vuln_type="idor",
        endpoint="/api/orders/1",
        parameter="id",
        evidence="changed id; got another user's order",
        human_verified=True,
        domain="example.com",
    )),
    ("override_q5", dict(
        vuln_type="idor",
        endpoint="/api/orders/2",
        parameter="id",
        evidence="lacks the magic words but verified by hand",
        overrides=["q5_evidence:hand-verified in Burp UI"],
        domain="example.com",
    )),
    ("override_q1", dict(
        vuln_type="sqli",
        endpoint="/search",
        evidence="sleep(5) confirmed 3/3 iterations",
        overrides=["q1_scope:operator-confirmed"],
        domain="example.com",
    )),
    ("override_q2", dict(
        vuln_type="sqli",
        endpoint="/search",
        evidence="intermittent sleep timing; could not reproduce reliably; sleep(5) triggers",
        overrides=["q2_repro:flaky-net-not-app"],
        domain="example.com",
    )),
    ("override_q4", dict(
        vuln_type="sqli",
        endpoint="/dup",
        parameter="q",
        evidence="sleep(5) confirmed 3/3 iterations",
        overrides=["q4_dedup:distinct-mechanism"],
        domain="dup-test.com",
    )),
    ("override_q6", dict(
        vuln_type="self_xss",
        endpoint="/profile",
        evidence="self xss chain via clipboard",
        overrides=["q6_never_submit:chain-with-clipboard-api"],
        chain_with=["f001"],
        domain="example.com",
    )),
    ("override_q7", dict(
        vuln_type="open_redirect",
        endpoint="/r",
        evidence="redirects to evil.com via ?u=",
        overrides=["q7_triager:chained-with-oauth"],
        domain="example.com",
    )),
    ("missing_domain", dict(
        vuln_type="sqli",
        endpoint="/search",
        evidence="sleep(5) confirmed 3/3 iterations",
    )),
    ("full_url_endpoint_no_domain", dict(
        vuln_type="sqli",
        endpoint="https://target.example.com/search",
        evidence="sleep(5) confirmed 3/3 iterations",
    )),
    ("chain_with_clickjacking", dict(
        vuln_type="clickjacking",
        endpoint="/about",
        evidence="frameable",
        chain_with=["f100"],
        domain="example.com",
    )),
    ("low_impact_weak_evidence", dict(
        vuln_type="open_redirect",
        endpoint="/r",
        evidence="redirects somewhere",
        domain="example.com",
    )),
    ("low_impact_weak_with_chain", dict(
        vuln_type="open_redirect",
        endpoint="/r",
        evidence="redirects somewhere",
        chain_with=["f200"],
        domain="example.com",
    )),
    ("intermittent_evidence_fails_q2", dict(
        vuln_type="xss",
        endpoint="/x",
        evidence="alert(1) executed once, intermittent, could not reproduce",
        domain="example.com",
    )),
    ("auth_state_dependent_intermittent_exempt", dict(
        vuln_type="idor",
        endpoint="/api/orders/1",
        evidence="changed id once, got other user data, sequential id range",
        domain="example.com",
    )),
    ("stack_trace_only", dict(
        vuln_type="info_disclosure",
        endpoint="/err",
        evidence="stack trace leaked",
        domain="example.com",
    )),
    ("stack_trace_negated", dict(
        vuln_type="sqli",
        endpoint="/search",
        evidence="not a stack trace, but pg_query error with sleep(5) confirmed 3/3 iterations",
        domain="example.com",
    )),
    ("graphql_introspection", dict(
        vuln_type="graphql",
        endpoint="/graphql",
        evidence="__schema introspection enabled; full type tree returned",
        domain="example.com",
    )),
    ("mass_assignment_strong", dict(
        vuln_type="mass_assignment",
        endpoint="/api/user",
        parameter="role",
        evidence="role=admin echoed; privilege escalated, is_admin: true returned",
        domain="example.com",
    )),
    ("user_enum_blocked", dict(
        vuln_type="user_enumeration",
        endpoint="/signup",
        evidence="different response on existing email",
        domain="example.com",
    )),
    ("auth_bypass_strong", dict(
        vuln_type="auth_bypass",
        endpoint="/admin",
        evidence="401 -> 200 transition with x-original-url accepted; auth bypass confirmed",
        domain="example.com",
    )),
    ("dedup_same_endpoint_same_param", dict(
        vuln_type="sqli",
        endpoint="/dup-test",
        parameter="q",
        evidence="sleep(5) confirmed 3/3 iterations",
        domain="dup-existing.com",
    )),  # paired with seeded findings.json below
    ("oauth_state_missing", dict(
        vuln_type="oauth",
        endpoint="/oauth/cb",
        evidence="state missing; pkce missing; redirect_uri bypass via partial match",
        domain="example.com",
    )),
]


async def run_scenario(name, kwargs):
    """Run one scenario, return its output string."""
    fn = server.mcp._tool_manager._tools["assess_finding"].fn

    async def fake_post(path, json=None):
        return {"in_scope": True}
    async def fake_get(path, params=None):
        return {}

    with patch("burpsuite_mcp.client.post", fake_post), \
         patch("burpsuite_mcp.client.get", fake_get):
        return await fn(**kwargs)


async def run_all():
    tmpdir = Path(tempfile.mkdtemp(prefix="burp-baseline-"))
    original_cwd = Path.cwd()
    os.chdir(tmpdir)
    try:
        # Seed a finding for the dedup scenario.
        intel = tmpdir / ".burp-intel" / "dup-existing.com"
        intel.mkdir(parents=True, exist_ok=True)
        (intel / "findings.json").write_text(json.dumps({
            "findings": [
                {"id": "f900", "endpoint": "/dup-test", "vuln_type": "sqli",
                 "parameter": "q", "title": "prior sqli"}
            ]
        }))
        results = {}
        for name, kwargs in SCENARIOS:
            out = await run_scenario(name, kwargs)
            results[name] = out
        return results
    finally:
        os.chdir(original_cwd)
        shutil.rmtree(tmpdir, ignore_errors=True)


BASELINE_PATH = Path(__file__).parent / "_baseline_assess.json"


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "write"
    results = asyncio.run(run_all())
    if mode == "write":
        BASELINE_PATH.write_text(json.dumps(results, indent=2, sort_keys=True))
        print(f"WROTE {len(results)} baselines -> {BASELINE_PATH}")
        return
    if mode == "verify":
        if not BASELINE_PATH.exists():
            print(f"NO BASELINE at {BASELINE_PATH}")
            sys.exit(2)
        baseline = json.loads(BASELINE_PATH.read_text())
        diffs = []
        for name, got in results.items():
            want = baseline.get(name)
            if want != got:
                diffs.append((name, want, got))
        if diffs:
            print(f"DIVERGED: {len(diffs)} scenarios")
            for name, want, got in diffs:
                print(f"\n=== {name} ===")
                print(f"--- baseline ---\n{want}")
                print(f"--- got ---\n{got}")
            sys.exit(1)
        print(f"OK: all {len(results)} scenarios byte-identical")


if __name__ == "__main__":
    main()
