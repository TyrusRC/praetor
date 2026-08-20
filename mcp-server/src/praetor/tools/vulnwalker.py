"""vulnwalker_audit — call-chain walker over Python source.

Walks a source tree, extracts call chains from any function/class declared
in the project, and emits dataflow scaffolds keyed to dangerous sinks
(eval, exec, subprocess, render_template_string, os.system, etc.).
Structured output Claude reasons over (no LLM call from server).

Inspired by Vulnhuntr's call-chain-walk approach; uses AST only, no
LLM round-trip — operator decides whether to deep-dive each scaffold.
"""

from __future__ import annotations

import ast
import pathlib

from mcp.server.fastmcp import FastMCP


_SINKS = {
    "eval": "RCE",
    "exec": "RCE",
    "compile": "RCE",
    "system": "command-injection",
    "popen": "command-injection",
    "call": "command-injection?",
    "check_output": "command-injection?",
    "Popen": "command-injection",
    "shell_exec": "RCE",
    "render_template_string": "SSTI",
    "render_template": "SSTI?",
    "Template": "SSTI?",
    "loads": "deserialization?",
    "load": "deserialization?",
    "pickle.loads": "RCE-deserialization",
    "yaml.load": "RCE-deserialization",
    "marshal.loads": "RCE-deserialization",
    "execute": "SQLi?",
    "executemany": "SQLi?",
    "raw": "SQLi?",
    "format": "format-string?",
    "send_file": "path-traversal?",
    "open": "path-traversal?",
    "redirect": "open-redirect?",
    "urlopen": "SSRF?",
    "requests.get": "SSRF?",
    "requests.post": "SSRF?",
    "httpx.get": "SSRF?",
}

_SOURCES = {
    "request.args",
    "request.form",
    "request.values",
    "request.json",
    "request.data",
    "request.headers",
    "request.cookies",
    "request.files",
    "request.query_params",
    "request.path_params",
    "self.request",
    "input",
    "sys.argv",
    "os.environ",
}


def _walk_module(path: pathlib.Path) -> list[dict]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return []
    findings: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn_name = _call_name(node)
        if fn_name is None:
            continue
        bare = fn_name.rsplit(".", 1)[-1]
        if fn_name in _SINKS or bare in _SINKS:
            cls = _SINKS.get(fn_name) or _SINKS.get(bare, "?")
            findings.append({
                "line": node.lineno,
                "sink": fn_name,
                "class": cls,
                "tainted_input": _input_taint(node),
            })
    return findings


def _call_name(node: ast.Call) -> str | None:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        parts = []
        cur: ast.expr = f
        while isinstance(cur, ast.Attribute):
            parts.insert(0, cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.insert(0, cur.id)
            return ".".join(parts)
    return None


def _input_taint(node: ast.Call) -> str:
    src = ast.unparse(node) if hasattr(ast, "unparse") else "<call>"
    for s in _SOURCES:
        if s in src:
            return s
    return ""


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def vulnwalker_audit(
        path: str,
        only_tainted: bool = True,
        max_files: int = 2000,
    ) -> str:
        """Walk Python source for dangerous-sink calls with optional taint match.

        Args:
            path: directory root (or single .py file).
            only_tainted: emit only sinks whose arg lexically references a known
                request / env / argv source. Default True.
            max_files: file cap (default 2000).
        """
        root = pathlib.Path(path)
        if not root.exists():
            return f"Error: path not found: {path}"

        targets = [root] if root.is_file() else list(root.rglob("*.py"))[:max_files]
        all_rows: list[dict] = []
        for p in targets:
            rows = _walk_module(p)
            for r in rows:
                r["file"] = str(p.relative_to(root) if root.is_dir() else p)
                all_rows.append(r)

        if only_tainted:
            all_rows = [r for r in all_rows if r["tainted_input"]]

        by_class: dict[str, int] = {}
        for r in all_rows:
            by_class[r["class"]] = by_class.get(r["class"], 0) + 1

        lines = [
            f"# vulnwalker_audit — {path}",
            f"Files scanned: {len(targets)}",
            f"Sink calls: {len(all_rows)} ({'tainted-only' if only_tainted else 'all'})",
            "",
            "By class:",
        ]
        for cls, count in sorted(by_class.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {count:>4}  {cls}")
        lines.append("")
        lines.append("Top sinks (first 60):")
        for r in all_rows[:60]:
            taint = f"  <- {r['tainted_input']}" if r["tainted_input"] else ""
            lines.append(
                f"  {r['file']}:{r['line']}  {r['sink']}  [{r['class']}]{taint}"
            )
        if len(all_rows) > 60:
            lines.append(f"  ... +{len(all_rows) - 60} more")
        lines.append("")
        lines.append("Next: open_grep / opengrep_audit for confirmation; manual review for taint chains.")
        return "\n".join(lines)
