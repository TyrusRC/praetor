"""Router / reporting / findings-hub / checkpoint / frontier-probe pick_tool mappings.

Data slice re-assembled by _pick_data.py — do not import directly.
Entry order is significant (first keyword match wins).
"""


_WORKFLOW = [
    # ----- session additions: router / offline / evidence / azure -----
    (["route signals", "auto trigger", "auto-trigger", "signal to tool",
      "which tool for this signal", "auto fire scanner", "reactive scan",
      "what should i fire", "routing plan", "auto route tools"],
     "route_signals",
     "route_signals(domain='app.example.com', "
     "signals=[{'type':'sql_error','value':'id','target':'https://app/api?id=1'}])"),
    (["analyze raw request", "raw request file", "analyze request file",
      "analyze js file", "js file", "js url", "javascript file",
      "analyze javascript file", "offline analysis", "analyze without burp",
      "analyze project folder", "correlate project", "artifact analysis"],
     "analyze_artifact",
     "analyze_artifact(source='./requests/login.txt')  # or a .js file/URL/dir "
     "or a project/ tree; kind auto-detected"),
    (["curate evidence", "save evidence", "record evidence index",
      "annotate finding evidence", "bookmark evidence", "organizer finding",
      "evidence to organizer"],
     "curate_evidence",
     "curate_evidence(finding_id='f001', index=42, domain='app.example.com', color='RED')"),
    (["audit history noise", "burp history bloat", "reduce history noise",
      "proxy history composition", "lean burp project", "clean up history",
      "history audit"],
     "audit_history_noise",
     "audit_history_noise(domain='app.example.com')"),
    (["azurehound", "azure ad collection", "entra id bloodhound",
      "azure bloodhound", "collect azure ad", "azure graph collection"],
     "run_azurehound",
     "run_azurehound(tenant='<guid-or-domain>', refresh_token='<token>')  "
     "# or jwt=, or username+password"),

    # ----- Assurance & reporting: coverage heatmap, dashboard, compliance -----
    (["standards coverage", "coverage heatmap", "what did we not test",
      "owasp coverage", "wstg coverage", "api top 10 coverage",
      "test coverage against standard", "coverage assurance", "untested categories"],
     "standards_coverage",
     "standards_coverage(domain='app.example.com', standard='owasp_top10')  "
     "# or api_top10 / wstg"),
    (["posture dashboard", "executive dashboard", "security posture", "html dashboard",
      "posture report", "generate dashboard", "engagement dashboard",
      "severity overview", "coverage dashboard"],
     "generate_posture_dashboard",
     "generate_posture_dashboard(domain='app.example.com')  "
     "# self-contained offline HTML under reports/"),
    (["compliance report", "pci report", "soc2 report", "hipaa report",
      "gdpr report", "map findings to controls", "compliance mapping report",
      "framework compliance", "regulatory report"],
     "generate_compliance_report",
     "generate_compliance_report(domain='app.example.com', standard='pci_dss_v4')  "
     "# or soc2_t2 / hipaa / gdpr / owasp"),

    # ----- Findings hub: remediation lifecycle + multi-scanner import -----
    (["set remediation", "assign owner", "remediation owner", "set due date",
      "mark resolved", "remediation sla", "track remediation", "close finding",
      "finding owner"],
     "set_remediation",
     "set_remediation(domain='app.example.com', finding_id='f001', owner='team', "
     "remediation_status='in_progress')"),
    (["remediation status", "overdue findings", "mttr", "sla status",
      "remediation rollup", "aging findings", "time to remediate", "sla report"],
     "remediation_status",
     "remediation_status(domain='app.example.com')  # open/resolved, overdue, MTTR"),
    (["import scan results", "import nessus", "import nuclei", "import scanner output",
      "ingest scan", "consolidate scanner findings", "load nessus file",
      "import findings", "merge scanner results"],
     "import_scan_results",
     "import_scan_results(source='./scan.nessus', domain='app.example.com')  "
     "# nuclei JSONL or nessus XML; dedup-merged as suspected"),
    (["screenshot gallery", "visual triage", "contact sheet", "aquatone",
      "screenshot grid", "browse screenshots", "gallery of screenshots",
      "review captured pages"],
     "screenshot_gallery",
     "screenshot_gallery(domain='app.example.com')  # offline HTML grid of captured screenshots"),
    (["nmap html report", "nmap report", "network exposure report", "port scan report",
      "render nmap", "nmap xml to html", "service inventory report"],
     "nmap_report_html",
     "nmap_report_html(xml_path='scan.xml')  # offline HTML: hosts/ports/versions, non-standard ports flagged"),
    (["exposed google api key", "gemini api key", "aiza key", "validate api key",
      "google api key impact", "leaked gemini key", "check google key",
      "api key abuse", "firebase maps key"],
     "audit_google_api_key",
     "audit_google_api_key(key='AIza...', referer='')  "
     "# validates Gemini access + frames impact; safe, no billable generation"),
    (["sqlmap", "sql injection tool", "waf bypass sqli", "tamper script",
      "dump database sqli", "sqli behind waf", "sqlmap tamper"],
     "run_sqlmap",
     "run_sqlmap(target='http://t/?id=1', tamper='space2comment,randomcase', "
     "dbms='mysql', ignore_code='403,500')  # WAF-bypass via tamper (<=3), hex, random-agent"),
    (["ghauri", "adaptive sqli", "sqli cloud waf", "cloudflare sqli", "blind sqli waf",
      "sqlmap alternative", "sqli akamai"],
     "run_ghauri",
     "run_ghauri(target='http://t/?id=1', confirm=True, dbms='mysql', time_sec=10)  "
     "# adaptive SQLi for cloud WAFs; test alongside run_sqlmap"),
    (["exposed secret", "validate leaked key", "leaked token", "aws key found",
      "github token found", "slack token", "stripe key", "what can this key do",
      "secret impact", "classify secret", "leaked credential"],
     "audit_exposed_secret",
     "audit_exposed_secret(secret='<value>')  "
     "# classify + safe read-only validate (github/gitlab/slack/npm/google); "
     "financial keys (stripe/aws/twilio) classified manual-only"),

    # ----- W37: durable checkpoint + completion judge -----
    (["write checkpoint", "save checkpoint", "engagement checkpoint",
      "task ledger", "record task state", "update task tree",
      "save progress state", "checkpoint the engagement", "next action ledger",
      "mark task done", "track engagement tasks"],
     "write_checkpoint",
     "write_checkpoint(domain='app.example.com', phase='scan', round=4, "
     "next_action='dispatch finding-verifier on f-0007', "
     "tasks=[{'id':'T2','status':'done'}])"),
    (["load checkpoint", "restore task state", "resume checkpoint",
      "read engagement state", "restore engagement", "where did i leave off",
      "engagement task state", "resume progress"],
     "load_checkpoint",
     "load_checkpoint(domain='app.example.com')"),
    (["is the engagement complete", "engagement done", "completion check",
      "am i done", "should i report", "judge completion", "is it complete",
      "stop condition", "completion judge", "verify engagement complete",
      "engagement finished"],
     "judge_completion",
     "judge_completion(domain='app.example.com', objective='broad coverage')"),
    # ----- W36: frontier probes + business-logic gate -----
    (["http3 race", "http/3 race", "quic race", "single datagram race",
      "h3 datagram race", "quic single packet", "http3 datagram race",
      "single udp race", "quic parser race", "ssro race"],
     "probe_race_http3_datagram",
     "probe_race_http3_datagram(target_url='https://app/api/coupon', "
     "method='POST', body='code=SAVE10', concurrent=100)"),
    (["source routes", "inventory routes", "routes from source",
      "api routes from code", "extract routes from source",
      "flask fastapi express routes", "spring routes",
      "source code endpoints", "route inventory",
      "discover api from source"],
     "inventory_source_routes",
     "inventory_source_routes(source_dir='/path/to/repo', domain='app.example.com')"),
    (["record business logic test", "business logic matrix",
      "log business logic test", "business logic coverage",
      "mark invariant tested", "record invariant"],
     "record_business_logic_test",
     "record_business_logic_test(domain='app.example.com', "
     "invariant='price cannot go negative', endpoint='/cart', result='held')"),
]
