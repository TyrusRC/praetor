"""Minimal Markdown -> self-contained HTML for the report exporter.

No external dependency (python-markdown/pandoc not required). Covers exactly the
constructs `generate_report` emits: headings, bold/italic/inline-code, fenced
code, ```mermaid fences (rendered by mermaid.js), tables, ordered/unordered
lists, blockquotes, hr, links, paragraphs. Finding evidence is HTML-escaped so a
payload like `<script>` shows as text, never executes in the report.
"""

from __future__ import annotations

import html
import re

_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_TABLE_ROW = re.compile(r"^\s*\|.*\|\s*$")
_TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{2,}.*$")
_ULI = re.compile(r"^\s*[-*]\s+(.*)$")
_OLI = re.compile(r"^\s*\d+\.\s+(.*)$")


def _inline(text: str) -> str:
    t = html.escape(text, quote=False)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"(?<![\*\w])\*([^*\n]+)\*(?!\*)", r"<em>\1</em>", t)
    t = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)", r'<a href="\2">\1</a>', t)
    return t


def markdown_to_html(md: str) -> str:
    lines = md.split("\n")
    out: list[str] = []
    i, n = 0, len(lines)

    def close_para(buf: list[str]) -> None:
        if buf:
            out.append("<p>" + _inline(" ".join(buf)) + "</p>")
            buf.clear()

    para: list[str] = []
    while i < n:
        line = lines[i]

        # fenced code / mermaid
        if line.lstrip().startswith("```"):
            close_para(para)
            lang = line.lstrip()[3:].strip().lower()
            body: list[str] = []
            i += 1
            while i < n and not lines[i].lstrip().startswith("```"):
                body.append(lines[i]); i += 1
            i += 1  # skip closing fence
            if lang == "mermaid":
                out.append('<div class="mermaid">\n' + "\n".join(body) + "\n</div>")
            else:
                out.append("<pre><code>" + html.escape("\n".join(body)) + "</code></pre>")
            continue

        # table (row + separator)
        if _TABLE_ROW.match(line) and i + 1 < n and _TABLE_SEP.match(lines[i + 1]):
            close_para(para)
            rows: list[str] = []
            while i < n and _TABLE_ROW.match(lines[i]):
                rows.append(lines[i]); i += 1
            out.append(_table(rows))
            continue

        heading = _HEADING.match(line)
        if heading:
            close_para(para)
            lvl = len(heading.group(1))
            out.append(f"<h{lvl}>{_inline(heading.group(2))}</h{lvl}>")
            i += 1
            continue

        if re.match(r"^\s*(-{3,}|\*{3,})\s*$", line):
            close_para(para); out.append("<hr>"); i += 1; continue

        if _ULI.match(line) or _OLI.match(line):
            close_para(para)
            ordered = bool(_OLI.match(line))
            tag = "ol" if ordered else "ul"
            items: list[str] = []
            while i < n and (_OLI.match(lines[i]) if ordered else _ULI.match(lines[i])):
                m = (_OLI if ordered else _ULI).match(lines[i])
                items.append("<li>" + _inline(m.group(1)) + "</li>")
                i += 1
            out.append(f"<{tag}>" + "".join(items) + f"</{tag}>")
            continue

        if line.startswith(">"):
            close_para(para)
            out.append("<blockquote>" + _inline(line.lstrip("> ").rstrip()) + "</blockquote>")
            i += 1
            continue

        if line.strip() == "":
            close_para(para); i += 1; continue

        para.append(line.strip()); i += 1

    close_para(para)
    return "\n".join(out)


def _table(rows: list[str]) -> str:
    def cells(r: str) -> list[str]:
        return [c.strip() for c in r.strip().strip("|").split("|")]
    header = cells(rows[0])
    body = rows[2:]  # rows[1] is the separator
    out = ["<table><thead><tr>"]
    out += [f"<th>{_inline(h)}</th>" for h in header]
    out.append("</tr></thead><tbody>")
    for r in body:
        out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells(r)) + "</tr>")
    out.append("</tbody></table>")
    return "".join(out)


_CSS = """
:root{--fg:#1a1a1a;--muted:#666;--line:#e2e2e2;--crit:#cc3333;--accent:#4472c4}
*{box-sizing:border-box}
body{font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
  color:var(--fg);margin:0;background:#fafafa}
.report{max-width:900px;margin:0 auto;padding:32px 24px;background:#fff}
h1{font-size:1.8em;border-bottom:2px solid var(--accent);padding-bottom:.2em}
h2{font-size:1.4em;margin-top:1.6em;border-bottom:1px solid var(--line);padding-bottom:.2em}
h3{font-size:1.15em;margin-top:1.2em}
code{background:#f2f2f2;padding:1px 5px;border-radius:3px;font-size:.9em}
pre{background:#f6f8fa;border:1px solid var(--line);border-radius:6px;padding:12px;overflow:auto}
pre code{background:none;padding:0}
table{border-collapse:collapse;width:100%;margin:1em 0;font-size:.93em}
th,td{border:1px solid var(--line);padding:6px 10px;text-align:left;vertical-align:top}
th{background:#f4f6f8}
blockquote{border-left:3px solid var(--accent);margin:1em 0;padding:.2em 1em;color:var(--muted)}
hr{border:0;border-top:1px solid var(--line);margin:1.6em 0}
.mermaid{background:#fff;border:1px solid var(--line);border-radius:6px;padding:16px;margin:1em 0;text-align:center;overflow:auto}
.mermaid svg{width:100%!important;height:auto!important;max-width:100%!important;min-height:420px}
a{color:var(--accent)}
"""


# Dark "security-graph" theme (Wiz-style) for the engagement / attack-path view:
# near-black canvas, neon edges, crown-jewel objectives in red, findings in cyan.
_CSS_DARK = """
:root{--fg:#e6edf3;--muted:#8b98a5;--line:#26303b;--crit:#ff5c6c;--accent:#4aa3ff}
*{box-sizing:border-box}
body{font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
  color:var(--fg);margin:0;background:#0b0f14}
.report{max-width:1100px;margin:0 auto;padding:32px 24px;background:#0d1117}
h1{font-size:1.8em;border-bottom:2px solid var(--accent);padding-bottom:.2em}
h2{font-size:1.35em;margin-top:1.6em;color:#cdd9e5;border-bottom:1px solid var(--line);padding-bottom:.2em}
h3{font-size:1.12em;margin-top:1.2em;color:#cdd9e5}
code{background:#161b22;color:#79c0ff;padding:1px 5px;border-radius:3px;font-size:.9em}
pre{background:#0d1117;border:1px solid var(--line);border-radius:6px;padding:12px;overflow:auto}
pre code{background:none;color:#c9d1d9}
table{border-collapse:collapse;width:100%;margin:1em 0;font-size:.93em}
th,td{border:1px solid var(--line);padding:6px 10px;text-align:left;vertical-align:top}
th{background:#161b22;color:#cdd9e5}
blockquote{border-left:3px solid var(--accent);margin:1em 0;padding:.2em 1em;color:var(--muted)}
hr{border:0;border-top:1px solid var(--line);margin:1.6em 0}
.mermaid{background:#0b0f14;border:1px solid var(--line);border-radius:8px;padding:18px;margin:1em 0;text-align:center;overflow:auto}
.mermaid svg{width:100%!important;height:auto!important;max-width:100%!important;min-height:480px}
a{color:var(--accent)}
"""

# useMaxWidth:false + width:100% CSS = the SVG scales to fill the wide container
# crisply on 2K/4K (vector, no pixelation); larger font + spacing = legible.
_FLOW = "flowchart:{useMaxWidth:false,htmlLabels:true,nodeSpacing:55,rankSpacing:70,padding:12},fontSize:17"

_MERMAID_DARK_INIT = (
    "{startOnLoad:true,securityLevel:'strict',theme:'dark'," + _FLOW + ","
    "themeVariables:{background:'#0b0f14',primaryColor:'#161b22',"
    "primaryBorderColor:'#4aa3ff',primaryTextColor:'#e6edf3',"
    "lineColor:'#4aa3ff',fontSize:'17px',fontFamily:'Segoe UI,Roboto,sans-serif'}}"
)
_MERMAID_LIGHT_INIT = "{startOnLoad:true,securityLevel:'strict'," + _FLOW + "}"


def wrap_html(title: str, body_html: str, dark: bool = False) -> str:
    css = _CSS_DARK if dark else _CSS
    init = _MERMAID_DARK_INIT if dark else _MERMAID_LIGHT_INIT
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
        f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>{html.escape(title)}</title>\n<style>{css}</style>\n"
        "<script src=\"https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js\"></script>\n"
        "<script>document.addEventListener('DOMContentLoaded',function(){"
        f"if(window.mermaid){{mermaid.initialize({init});}}}});</script>\n"
        f"</head>\n<body><div class=\"report\">\n{body_html}\n</div></body></html>\n"
    )
