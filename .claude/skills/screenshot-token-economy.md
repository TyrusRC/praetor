---
name: screenshot-token-economy
description: Screenshots are EVIDENCE, not a discovery mechanism — never host-Read a saved PNG as vision to find leads during recon. Use when about to look at a screenshot for leads, or when deciding how to inspect a browser/Burp capture.
---

# Screenshot Token Economy

`burp_screenshot` / `browser_screenshot` save a PNG to disk and return a small
dict — no image bytes to the model. The expensive step is a human-style
host-`Read` of that PNG, which the harness bills as ~1.5k+ vision tokens per
tile. Most recon leads (forms, endpoints, error strings, auth markers) are
TEXT that never needed a picture.

## Rule

**Finding leads → TEXT tools, always.** A screenshot is for the report
(baseline/attack/result evidence, Rule 18/Workflow E in `evidence-and-tabs.md`),
not for discovering what's on the page.

| Need | Use (cheap, text) | Not this (vision) |
|---|---|---|
| Page structure, forms, links | `browser_get_page_info`, `analyze_dom`, `extract_links` | Read the PNG |
| Endpoints / API routes called by the page | `discover_attack_surface`, `get_request_detail` | Read the PNG |
| JS secrets, hidden endpoints in bundles | `extract_js_secrets`, `smart_js_analyze` | Read the PNG |
| "What does this request/response actually say" | `get_request_detail`, `extract_regex`/`extract_json_path` | Read the PNG |

## When a screenshot genuinely must be interpreted

Layout, a graphic, a QR code, a CAPTCHA, or text OCR can't reach (image-only
error banner) — in that order of preference:

1. `read_screenshot_text(path=... | domain=..., filename=...)` — OCR the saved
   PNG to plain text (tesseract, off-thread). Costs a few hundred text tokens.
   If the extracted text answers the question, stop there.
2. If OCR text is empty/insufficient, dispatch the `screenshot-triage` agent
   (haiku, 1 screenshot per call) — it OCRs first, falls back to a visual read
   ONLY inside its own isolated context, and returns a compact lead list. This
   keeps the vision tokens out of the MAIN agent's context even when a visual
   read is unavoidable.
3. Host-`Read`-ing the PNG directly in the main agent's context is the LAST
   resort — only when the lead is worth the token cost and neither OCR nor a
   dispatched triage agent applies (e.g. you're personally verifying a single
   report screenshot before shipping it).

## Anti-patterns

- Crawling a target and `Read`-ing every captured screenshot to "see what's
  there" — that's what `browser_get_page_info` / `discover_attack_surface` are for.
- Reading a screenshot to find a form field name or a visible URL — OCR text
  has it.
- Batching N screenshots into one `screenshot-triage` dispatch — one shot per
  call keeps each triage cheap and parallelizable; fan out instead.

## Cross-references

- `read_screenshot_text` — `mcp-server/src/praetor/tools/ocr_read.py`
- `screenshot-triage` agent — `.claude/agents/screenshot-triage.md`
- Screenshot-as-evidence workflow (capture discipline, redaction, naming): `evidence-and-tabs.md` Workflow E
