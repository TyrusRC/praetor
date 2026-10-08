"""suggest_finding_owner — attribute a source-code finding to its owner.

codex-security parity: its "suggest owners from source and Git history" is the one
defensive-governance feature Praetor's white-box source lane lacked. Given a file
(and optional line) in a source tree, resolve who owns it — CODEOWNERS path rules
(GitHub-style, last matching rule wins) and the `git blame` author of the line — so
a SAST / source-chain finding (run_mantis, run_vulnhuntr, source_aware,
inventory_source_routes) routes to the right person: attach it to the finding, or
assign the push_finding_to_tracker issue to that owner. Read-only (git blame +
CODEOWNERS file read); never writes.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _run_cmd

_CODEOWNERS_LOCATIONS = (
    "CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS", ".gitlab/CODEOWNERS")


def _find_codeowners(repo: Path) -> Path | None:
    for rel in _CODEOWNERS_LOCATIONS:
        p = repo / rel
        if p.is_file():
            return p
    return None


def _parse_codeowners(text: str) -> list[tuple[str, list[str]]]:
    """(pattern, owners) rules in file order. Owners are @user / @org/team / emails."""
    rules: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        owners = [o for o in parts[1:] if o.startswith("@") or "@" in o]
        if owners:
            rules.append((parts[0], owners))
    return rules


def _match_codeowners(rel_path: str, rules: list[tuple[str, list[str]]]) -> list[str]:
    """GitHub CODEOWNERS semantics (approximation): the LAST matching rule wins."""
    rel = rel_path.lstrip("/")
    matched: list[str] = []
    for pattern, owners in rules:
        pat = pattern.lstrip("/")
        hit = False
        if pat in ("*", "**"):
            hit = True
        elif pat.endswith("/"):                       # directory: everything under it
            hit = rel == pat[:-1] or rel.startswith(pat)
        elif any(c in pat for c in "*?["):            # glob
            hit = fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*")
        else:                                         # literal file or dir prefix, or bare name
            hit = (rel == pat or rel.startswith(pat.rstrip("/") + "/")
                   or fnmatch.fnmatch(rel, "**/" + pat))
        if hit:
            matched = owners
    return matched


def _parse_blame_porcelain(out: str) -> dict:
    """Pull author / email / summary / commit from `git blame --porcelain`."""
    info: dict = {}
    lines = out.splitlines()
    if lines and lines[0]:
        info["commit"] = lines[0].split()[0][:12]
    for ln in lines:
        if ln.startswith("author ") and "author" not in info:
            info["author"] = ln[len("author "):].strip()
        elif ln.startswith("author-mail "):
            info["author_mail"] = ln[len("author-mail "):].strip().strip("<>")
        elif ln.startswith("summary "):
            info["summary"] = ln[len("summary "):].strip()
    return info


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def suggest_finding_owner(repo_path: str, file: str, line: int = 0) -> str:
        """Attribute a source finding to its code owner (CODEOWNERS + git blame).

        Resolves who owns a vulnerable file so a white-box finding routes to the
        right person for remediation. Returns the CODEOWNERS match (team/user) and,
        when a line is given, the git blame author + commit of that line. Read-only.

        Args:
            repo_path: path to the checked-out source repository (its .git root).
            file: path to the file, relative to repo_path (e.g. 'src/app/auth.py').
            line: 1-based line number to blame (0 = skip blame, CODEOWNERS only).
        """
        repo = Path(repo_path).expanduser()
        if not repo.is_dir():
            return f"Error: repo_path '{repo_path}' is not a directory."
        repo_res = repo.resolve()
        rel = file.lstrip("/")
        target = (repo / rel).resolve()
        if repo_res not in target.parents and target != repo_res:
            return f"Error: '{file}' resolves outside the repo (path traversal refused)."

        out_lines = [f"Owner of {rel}" + (f":{line}" if line else "") + ":"]

        # CODEOWNERS
        co_path = _find_codeowners(repo)
        if co_path:
            try:
                rules = _parse_codeowners(co_path.read_text(encoding="utf-8", errors="replace"))
                owners = _match_codeowners(rel, rules)
            except OSError as e:
                owners = []
                out_lines.append(f"  CODEOWNERS: (read error: {e})")
            if owners:
                out_lines.append(f"  CODEOWNERS ({co_path.name}): {', '.join(owners)}")
            else:
                out_lines.append(f"  CODEOWNERS ({co_path.name}): no rule matches this path")
        else:
            out_lines.append("  CODEOWNERS: none found (.github/CODEOWNERS, CODEOWNERS, ...)")

        # git blame (only when a line is given)
        if line and line > 0:
            if not target.is_file():
                out_lines.append(f"  git blame: file not found at {rel}")
            else:
                cmd = ["git", "-C", str(repo), "blame", "-L", f"{line},{line}",
                       "--porcelain", "--", rel]
                blame_out, err, rc = await _run_cmd(cmd, timeout=30, bypass_proxy=True)
                if rc != 0:
                    out_lines.append(f"  git blame: unavailable ({(err or 'rc=' + str(rc)).strip()[:120]})")
                else:
                    info = _parse_blame_porcelain(blame_out)
                    who = info.get("author", "?")
                    mail = f" <{info['author_mail']}>" if info.get("author_mail") else ""
                    commit = f" @ {info['commit']}" if info.get("commit") else ""
                    summ = f'  "{info["summary"]}"' if info.get("summary") else ""
                    out_lines.append(f"  git blame: {who}{mail}{commit}{summ}")

        out_lines.append("  -> attach to the finding, or assign the "
                         "push_finding_to_tracker issue to this owner.")
        return "\n".join(out_lines)
