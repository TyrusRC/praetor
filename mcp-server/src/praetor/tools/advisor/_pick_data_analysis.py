"""Smart request/JS triage + version-delta + CVE-variant pick_tool mappings.

Data slice re-assembled by _pick_data.py — do not import directly.
Entry order is significant (first keyword match wins).
"""


_ANALYSIS = [
    # ----- W30-c: smart request triage — proxy entry → attack plan -----
    # Collapses get_request_detail -> extract_* -> smart_analyze -> reason
    # -> pick LLM loop into ONE call. Operator hands an index, gets a
    # priority-ordered attack_plan with concrete suggested_call lines.
    (["triage request", "triage proxy entry", "analyze proxy index",
      "analyze captured request", "what to do with this request",
      "next step for index", "next action for index",
      "what to do next", "captured request next step",
      "proxy entry attack plan", "request to attack plan",
      "analyze request smart", "what does this response mean"],
     "smart_request_triage",
     "smart_request_triage(index=12345)"),
    # ----- W30-b: smart JS analysis → attack plan synthesis -----
    # Operator gap: extract_js_secrets / extract_api_endpoints dump raw data,
    # operator burns tokens reasoning about payloads. smart_js_analyze ships
    # the synthesised attack plan in one call.
    (["analyze js", "analyse js", "smart js", "js file analyze",
      "js bundle analyze", "javascript bundle analyze",
      "extract js plan", "js attack plan", "js to payload",
      "harvest js", "harvest action ids", "harvest rsc actions",
      "js sinks", "dom sinks in js", "js secrets and endpoints",
      "next bundle harvest", "chunk analyze", "webpack chunk analyze",
      "rsc action id harvest", "find server action ids",
      "synthesise attack plan", "synthesize attack plan",
      "js bundle to attack plan"],
     "smart_js_analyze",
     "smart_js_analyze(url='https://app/_next/static/chunks/main.js', "
     "target_base_url='https://app.example.com', max_targets=10)"),
    # ----- Version-delta reasoning — must win over a plain advisory lookup -----
    # Operator gap: the public PoC targets version A, the target runs version B,
    # the PoC is fired verbatim and fails on a shape change that has nothing to
    # do with the vulnerability. The reflex is to go read another advisory; the
    # correct move is to reason about what changed between A and B. Routed
    # BEFORE the CVE-variant and lookup entries so the reasoning tool wins.
    (["adapt poc", "adapt payload", "poc for different version",
      "poc version mismatch", "different version", "version mismatch",
      "app runs version", "target runs a different version",
      "poc written for", "port poc", "backport poc", "forward-port poc",
      "version delta", "does the poc still apply", "affected range"],
     "adapt_poc_to_version",
     "adapt_poc_to_version(component='<pkg>', poc_version='<A>', "
     "target_version='<B>', fixed_version='<fix>')"),
    # ----- W30-a: CVE-aware variant sweep — wins on CVE-id keywords -----
    # Operator gap (2026-06-11): known CVE on target, public PoC needs payload
    # tweak. probe_cve_with_variants ships a bounded curated variant pack +
    # canary-echo scoring + first-CONFIRMED short-circuit.
    (["cve variant", "cve variants", "cve poc variants", "try cve poc",
      "known cve poc", "known cve payload", "poc variations",
      "poc didn't work", "poc not working", "cve poc tweak",
      "react2shell", "react 2 shell", "next-action header poc",
      "cve-2025-55182", "cve-2025-66478", "cve-2025-68130",
      "cve-2026-40175", "cve-2026-44789", "cve-2026-44790", "cve-2026-44791",
      "bounded cve sweep", "rsc poc variants", "trpc sspp poc"],
     "probe_cve_with_variants",
     "probe_cve_with_variants(cve_id='CVE-2025-55182', "
     "target_url='https://app/api/action', baseline_payload='<public PoC>', "
     "action_id='<bundle-harvested-id>', max_variants=12)"),
]
