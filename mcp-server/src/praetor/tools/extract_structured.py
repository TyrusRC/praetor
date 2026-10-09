"""LLM structured extraction + markdownify over a CAPTURED Burp response.

ScrapeGraphAI-style "describe what you want, get JSON" extraction — but on a
response Burp ALREADY captured, so the proxy_history_index evidence model holds
(Rule 26a: never a non-proxied scraper). The LLM is an OPTIONAL enhancer through
`_llm` (PRAETOR_LLM_* or a provider native key); with none configured,
`extract_structured` degrades with a hint and the deterministic extractors
(extract_css_selector / extract_json_path / extract_regex) still cover the
keyless core. `markdownify` needs NO key — it is a deterministic HTML->Markdown
reducer (bs4, already a dependency) that cuts tokens when the agent reads a page.
"""

from __future__ import annotations

import json
import re

import httpx
from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools import _llm


async def _body_for_index(index: int) -> tuple[str, str]:
    """Fetch a captured response body by proxy-history index. Returns (body, error)."""
    entry = await client.get(f"/api/proxy/history/{int(index)}")
    if not isinstance(entry, dict):
        return "", f"no captured entry at index {index}"
    if "error" in entry:
        return "", entry["error"]
    return (entry.get("response_body") or ""), ""


def _html_to_markdown(html: str) -> str:
    """Reduce HTML to readable Markdown (headings, links, list items). Lossy by
    design — the point is a small, LLM-friendly view, not a faithful round-trip."""
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html or "", "html.parser")
    for dead in soup(["script", "style", "noscript", "svg", "head", "template"]):
        dead.decompose()
    for h in soup.find_all(re.compile(r"^h[1-6]$")):
        h.insert_before("\n" + "#" * int(h.name[1]) + " ")
        h.insert_after("\n")
    for a in soup.find_all("a"):
        href = a.get("href") or ""
        txt = a.get_text(strip=True)
        if txt and href:
            a.replace_with(f"[{txt}]({href})")
    for li in soup.find_all("li"):
        li.insert_before("\n- ")
    for br in soup.find_all("br"):
        br.replace_with("\n")
    for block in soup.find_all(["p", "div", "tr", "section", "article", "ul", "ol"]):
        block.insert_after("\n")
    text = soup.get_text()
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _parse_json(raw: str):
    """(obj, True) if `raw` is JSON (optionally inside a ```json fence), else (None, False)."""
    s = (raw or "").strip()
    m = re.search(r"```(?:json)?\s*(.+?)```", s, re.DOTALL)
    if m:
        s = m.group(1).strip()
    try:
        return json.loads(s), True
    except ValueError:
        return None, False


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def markdownify(index: int = -1, max_chars: int = 20000) -> dict:
        """Convert a captured response (its proxy_history_index) HTML -> clean Markdown.

        A keyless, deterministic reducer — use it before reading a big page so the
        agent spends a few hundred tokens on structure instead of thousands on raw
        HTML. Also the pre-step for extract_structured on HTML pages.

        Args:
            index: proxy_history_index of a captured response.
            max_chars: cap the returned Markdown (full length still reported).
        """
        if index < 0:
            return {"error": "pass index (a proxy_history_index of a captured response)"}
        body, err = await _body_for_index(index)
        if err:
            return {"error": err}
        md = _html_to_markdown(body)
        return {"index": index, "markdown": md[:max_chars], "chars": len(md),
                "truncated": len(md) > max_chars}

    @mcp.tool()
    async def extract_structured(index: int = -1, prompt: str = "", schema: str = "",
                                 max_chars: int = 16000) -> dict:
        """Extract structured JSON from a captured response with an LLM (optional enhancer).

        Describe the data in `prompt` ("list every user and their role") and/or give a
        `schema` (a JSON shape to fill). Runs on a response Burp already captured — cite
        the SAME index as evidence; nothing is fetched outside Burp. Needs an LLM
        (PRAETOR_LLM_PROVIDER + key, or a provider native key); with none configured it
        returns a hint — the deterministic extractors (extract_css_selector /
        extract_json_path / extract_regex) remain the keyless path. For a key-free reduce
        use markdownify.

        Args:
            index: proxy_history_index of the captured response to extract from.
            prompt: natural-language description of what to extract.
            schema: optional JSON schema/shape the output must match.
            max_chars: cap the content fed to the model (tokens/cost).
        """
        if index < 0:
            return {"error": "pass index (a proxy_history_index of a captured response)"}
        if not prompt.strip() and not schema.strip():
            return {"error": "pass a prompt (what to extract) and/or a schema (JSON shape)"}
        cfg = _llm.resolve_llm()
        if not cfg.ok:
            return {"error": cfg.reason,
                    "hint": "extract_structured is an optional LLM enhancer — set "
                            "PRAETOR_LLM_PROVIDER + a key (or a provider native key). "
                            "Keyless extractors still work: extract_css_selector / "
                            "extract_json_path / extract_regex."}
        body, err = await _body_for_index(index)
        if err:
            return {"error": err}
        content = (_html_to_markdown(body) if "<" in body[:2000] else body)[:max_chars]
        parts = ["Extract data from the CONTENT below."]
        if prompt.strip():
            parts.append("Instruction: " + prompt.strip())
        if schema.strip():
            parts.append("Return JSON that matches this schema exactly:\n" + schema.strip())
        parts.append("\nCONTENT:\n" + content)
        system = ("You extract structured data from web content. "
                  "Return ONLY valid JSON — no prose, no code fence.")
        try:
            raw = await _llm.complete("\n".join(parts), system=system, max_tokens=1500)
        except (httpx.HTTPError, RuntimeError, KeyError, ValueError) as e:
            return {"error": f"LLM call failed: {e}"}
        data, parsed = _parse_json(raw)
        res = {"index": index, "provider": cfg.provider, "model": cfg.model}
        if parsed:
            res["data"] = data
        else:
            res["raw"] = raw
            res["note"] = "model did not return valid JSON — see raw"
        return res
