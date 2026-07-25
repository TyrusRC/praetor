# Cloud Pentest / Red-Team + Burp AI / Burp AT Gap Review — 2026-07-25

**Scope:** Can Praetor (a) do cloud-security pentest/red-team work per the 2026
cloud.hacktricks.wiki catalog, and (b) match/beat PortSwigger's Burp AI and
Burp AT? Findings + fixes below. Sources: three parallel research tracks
(cloud.hacktricks 591-page catalog, portswigger.net/burp/ai, portswigger.net/burp/burp-at).

## Verdict

Praetor is **already competitive-to-superior** on both axes. It is not missing a
category; the real gaps are narrow. Fixed the concrete ones this pass.

## Cloud coverage vs cloud.hacktricks.wiki

The catalog splits into (a) CLI/on-host post-exploitation and (b) DAST-reachable
(SSRF, exposed metadata/service, misconfigured storage URL, CI webhook). A
Burp-integrated tool owns (b); (a) is covered via CLI wrappers.

**Already covered:**
- **SSRF → cloud metadata (§7, the core web→cloud pivot):** `test_ssrf` +
  `test_cloud_metadata` + KB `cloud_webapp` / `ssrf` — AWS IMDSv1/v2, GCP/Azure
  header-gated IMDS, DO/Alibaba/Oracle, IMDSv2 PUT-then-GET documented in
  `playbook-cloud-native.md`.
- **Storage misconfig:** `cloud_storage_misconfig` (S3/GCS/Azure/R2/B2/OCI/MinIO
  anonymous list+write, signed-URL leak) + `extract_js_secrets` + `bucket_urls_by_vuln_class`.
- **Serverless / API GW:** `cloud_function_url`, `cloud_api_gateway`.
- **Kubernetes exposed plane:** `kubernetes_exposed` + `anon_cloud_expansion`
  (apiserver anon, kubelet 10250/10255, etcd 2379, dashboards, docker daemon 2375)
  + `run_kube_hunter` / `run_kubeletctl` / `run_kdigger`.
- **CI/CD injection (source-scan):** `ci_actions_injection` (PPE, pwn_request,
  untrusted checkout, self-hosted-runner) + `run_octoscan` / `run_poutine` /
  `scan_claude_code_project_hooks`.
- **Cognito:** JWT abuse + unauth Identity-Pool `GetCredentialsForIdentity`
  (documented manual replay in playbook §3).
- **Cloud CLI/post-ex:** prowler, scout-suite, cloudsploit, pacu, kubescape,
  peirates, checkov, tfsec, terrascan, hadolint.

**Gap found + FIXED:** the header-less AWS **container-credential** endpoints —
ECS/Fargate (`169.254.170.2/v2/credentials/`) and EKS Pod Identity
(`169.254.170.23/v1/credentials`) — were absent from both `test_ssrf._CLOUD_METADATA`
and `test_cloud_metadata`. These are the modern web→cloud cred pivot: plain GETs
with no token/header dance, so they stay reachable from a bare parameter SSRF
even when IMDSv1 is disabled (now the common case). Added both, plus the direct
IAM role-cred path, temp-cred JSON indicators (`Expiration`, `ASIA`, `RoleArn`),
Alibaba/Oracle endpoint fixes, and an `extra_headers` passthrough on
`test_cloud_metadata` for header-forwarding SSRF (GCP/Azure IMDS are header-gated).

**Deliberately NOT built (out of scope / unsafe / redundant):**
- Live CI webhook / `pull_request_target` PPE *triggering* — firing a pipeline is
  state-changing and risks out-of-scope/destructive execution. Detection via
  source-scan (octoscan/poutine) is the correct, safe surface.
- AWS IAM ~49 privesc paths, K8s RBAC/pod-escape, container runtime escapes —
  all class (a) on-host post-ex; covered by pacu/peirates/kube-hunter wrappers,
  not a DAST tool's job.

## Burp AI parity

All Burp AI features are Pro-only, credit-metered, cloud-only (no local model).
Praetor analog for each:

| Burp AI feature | Praetor analog |
|---|---|
| Explainer / "Explain this" | `explain_finding` |
| Explore Issue (agentic per-issue) | `explore_issue` |
| Shadow Repeater (AI fuzz variants) | `shadow_repeater` |
| BAC false-positive reduction | `assess_finding` (7-Q gate) + `debate_triage` |
| AI-recorded logins | `recorded_login` |
| Montoya AI API (BYO extension AI) | N/A — Praetor *is* the external agent |
| PortSwigger MCP server (transport bridge) | Praetor's Java ext + ~369 MCP tools |

**Where Praetor beats Burp AI:** model choice / offline, no 12-month credit
expiry, no metering, FP-reduction beyond just BAC, deeper business-logic +
multi-step-state testing (Explore Issue is single-issue only).

## Burp AT parity

Burp AT = in-tool, human-in-loop agentic assistant (public beta, Pro-only). NOT
unattended autonomy; no advertised exploit-chaining. Praetor matches/beats on 7
of 8 axes: tool-layer scope enforcement + `_audit.log` trail, deterministic Burp
backbone (Rule 26a), evidence bundling with ≥3 replay (stronger than Burp AT's
"human confirms"), cross-session memory, race primitives, FP triage, updatable
KB/skills.

**Gap found + FIXED:** Burp AT's named **Manual/Smart/Autonomous** autonomy dial
(with a few always-approval high-impact actions even in Autonomous) had no named
equivalent — Praetor had `--paranoid/--normal/--aggressive` but no risk-tiered
action gate spelled out. Added an "Autonomy Modes" section to `autopilot.md`
mapping the three modes to the flags + an explicit ALWAYS-APPROVAL high-impact
action list, enforced at the tool layer (HARD Rules 1–10), architecturally
separate from the model.

**Residual (refinements, not missing primitives):** selective KB-matcher
invocation discipline (partly present), clean single-thread unattended activity
log (checkpoints exist), and pushing `find_rre_chains`/`build_api_dag`/
`propose_chains` toward autonomous multi-step escalation (the one axis where
beating the *category*, incl. XBOW, would require deeper chaining automation).

---

# Addendum — False-Positive Reduction Pass (2026-07-25)

Researched FP-reduction mechanisms across Invicti (proof-based scanning),
Acunetix (AcuSensor IAST / AcuMonitor OOB), Burp Scanner (executable-context +
retry consistency + AI BAC dual-crawl), ZAP (confidence/threshold/alert-filters),
Nuclei (matchers-condition + negative + dynamic extractors), Semgrep (sanitizer
awareness), and XBOW (explorer↔deterministic-validator split).

**Already present in Praetor:** AND-composition across matchers + `not_word`
negation (MatcherEngine), baseline+k-of-n replay (Rules 11/10a), OOB via
Collaborator (Rule 9a), deterministic-prover split (`confirm_with_clean_room` /
`debate_triage`). Praetor's FP stack was already mature.

**Real bug found + fixed — reflected-injection false positive (research #6):**
`augment_evidence` marked XSS "executable context" whenever `<script` / `<img` /
`<svg` / `onload=` appeared in the response body. Every HTML page contains its
own `<script>` tags, so this fired regardless of the payload — inflating
confidence on non-findings. Replaced with a **payload-tied reflection-liveness
check** (`tools/advisor/_liveness.py`): only a decisive token (tag-former,
attribute/tag breakout, or template marker) that the REQUEST carried and that
returns UN-encoded counts as executable. A payload reflected only in
HTML/URL/JS-encoded form is classified `sanitized`, and for reflection classes
(xss/ssti/html_injection/csti) the Q5 gate now **suppresses the finding** —
executable context not proven. Bare event handlers (`onerror=`) are excluded
from the "live" decision since they cannot execute without a live host tag.
Mirrors Burp's executable-context model + Semgrep's sanitizer awareness, applied
black-box.

**Also fixed:** 3 unclosed-file handles in `tests/test_w29_commercial_gap_closure.py`
(ResourceWarning) — now context-managed; passes under `-W error::ResourceWarning`.

**Deferred (documented, not built — higher regression risk / lower marginal value):**
- #7 dual-baseline (authed + unauthenticated) auto-suppression for IDOR/BFLA —
  requires reworking `test_auth_matrix`/`compare_auth_states` output contract.
- #1 formal `proof_token` evidence field as a Q5 auto-pass — canaries already
  exist in probes; formalizing the round-trip protocol across all `confirm_*`
  tools is a larger, separate change.
- #5/#4 hard gate-enforcement of OOB-mandatory / k-of-n for blind classes —
  currently Rule-enforced (9a/10a); promoting to a hard assess-gate reject is a
  calibration change touching the 12-method assess suite.

## Changes this pass
- `tools/vuln/test_ssrf.py` — ECS/EKS/IAM-cred endpoints + temp-cred indicators.
- `tools/edge/test_cloud_metadata.py` + `tools/edge/__init__.py` — full provider
  matrix (ECS/EKS/IMDS/GCP/Azure/DO/Alibaba/Oracle) + `extra_headers` passthrough.
- `.claude/skills/autopilot.md` — Autonomy Modes (Burp AT parity) section.
- `.claude/skills/playbook-cloud-native.md` — container-cred pivot documented.
- `tests/test_cloud_ssrf_creds.py` — 5 tests (structural + behavioral). Suite 1419→1424, green.

FP-reduction pass:
- `tools/advisor/_liveness.py` — NEW payload-tied reflection-liveness helper.
- `tools/advisor/_evidence_augment.py` — payload-tied executable-context marker
  (replaces blanket `<script`-in-body FP) + `sanitized` signal.
- `tools/advisor/_context.py` — `reflected_sanitized` flag.
- `tools/advisor_kb/q5_evidence.py` — sanitizer/executable-context suppression
  for reflection-injection classes.
- `tests/test_reflection_liveness.py` — 8 tests (unit + assess-gate integration).
- `tests/test_w29_commercial_gap_closure.py` — unclosed-file ResourceWarning fix.
- Suite 1424→1431, green.
