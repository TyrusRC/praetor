"""MCP tools over the red-team knowledge seed.

  lookup_gtfobins(binary, function=None)  - Unix privesc / breakout
  lookup_lolbas(binary, function=None)    - Windows living-off-the-land
  redteam_tool_guide(tool=None, tier=None) - install + Burp-routing guidance

Knowledge only — no execution. The Burp web lane (Rule 26a) does not apply;
these are references the agent reasons over when it has host/network access.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ._gtfobins import GTFOBINS
from ._lolbas import LOLBAS
from ._tooling import REDTEAM_TOOLS


def _norm(name: str) -> str:
    return (name or "").strip().lower()


def _lookup_binary(dataset: dict, binary: str, function: str | None, label: str) -> str:
    key = _norm(binary)
    # Tolerate a full path or a Windows name without .exe.
    if key not in dataset:
        base = key.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        for cand in (base, base + ".exe"):
            if cand in dataset:
                key = cand
                break
    entry = dataset.get(key)
    if entry is None:
        hits = sorted(k for k in dataset if key and key in k)
        suffix = f" Did you mean: {', '.join(hits[:8])}?" if hits else ""
        return f"No {label} entry for {binary!r}.{suffix} ({len(dataset)} binaries known; extend from upstream.)"

    funcs = {k: v for k, v in entry.items() if k != "note"}
    if function:
        fkey = _norm(function)
        matched = {k: v for k, v in funcs.items() if fkey in k}
        if not matched:
            return (
                f"{label} {key}: no function matching {function!r}. "
                f"Available: {', '.join(sorted(funcs))}."
            )
        funcs = matched

    lines = [f"{label}: {key}"]
    for fname in sorted(funcs):
        lines.append(f"  [{fname}]")
        for cmd in funcs[fname]:
            lines.append(f"    {cmd}")
    if entry.get("note"):
        lines.append("  note: " + " ".join(entry["note"]))
    return "\n".join(lines)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def lookup_gtfobins(binary: str, function: str = "") -> str:
        """GTFOBins lookup — how a Unix binary escalates privilege or breaks out.

        Args:
            binary: binary name or path (e.g. 'find', '/usr/bin/vim', 'python3').
            function: optional filter — 'sudo', 'suid', 'capabilities', 'shell',
                'file-read', 'file-write', 'file-download', 'file-upload'.
                Blank returns every known abuse for the binary.

        Use after host access when a SUID/sudo/capability enumeration
        (e.g. LinPEAS) surfaces an interesting binary. Commands assume /bin/sh;
        SUID variants keep euid via `-p`.
        """
        return _lookup_binary(GTFOBINS, binary, function or None, "GTFOBins")

    @mcp.tool()
    async def lookup_lolbas(binary: str, function: str = "") -> str:
        """LOLBAS lookup — abusing a signed Windows binary off the land.

        Args:
            binary: binary name (e.g. 'certutil', 'rundll32.exe', 'msbuild').
            function: optional filter — 'download', 'execute', 'awl-bypass',
                'upload', 'dump', 'decode'. Blank returns all.

        Use for download/exec, AppLocker/WDAC bypass, and on-host dumping
        (SAM/NTDS) with living-off-the-land binaries. Placeholders: ATTACKER,
        PATH.
        """
        return _lookup_binary(LOLBAS, binary, function or None, "LOLBAS")

    @mcp.tool()
    async def redteam_tool_guide(tool: str = "", tier: str = "") -> str:
        """Install + Burp-routing guidance for red-team external tools.

        Args:
            tool: a specific tool (e.g. 'impacket', 'gobuster'); blank lists all.
            tier: filter by fit — 'A' (web/offline, wraps via _run_cmd),
                'C' (internal/AD/post-ex, Burp-blind, needs a separate evidence
                lane). Blank shows every tier.

        Kali install names come first (apt), with a clone/pipx fallback. Tools
        tagged tier C do NOT route through Burp — their evidence is a session
        log / loot file, not a Burp logger_index.
        """
        want_tier = tool_filter = None
        if tier:
            want_tier = tier.strip().upper()
        if tool:
            tool_filter = _norm(tool)

        rows = []
        for name, meta in REDTEAM_TOOLS.items():
            if tool_filter and tool_filter not in name:
                continue
            if want_tier and meta.get("tier") != want_tier:
                continue
            rows.append((name, meta))

        if not rows:
            return f"No red-team tool matched tool={tool!r} tier={tier!r}."

        if tool_filter and len(rows) == 1:
            name, meta = rows[0]
            inst = meta.get("install", {})
            return (
                f"{name} [tier {meta['tier']}] routes_through_burp={meta['routes_burp']}\n"
                f"  purpose: {meta['purpose']}\n"
                f"  install (kali): {inst.get('kali', 'n/a')}\n"
                f"  install (other): {inst.get('other', 'n/a')}\n"
                f"  note: {meta.get('note', '')}"
            )

        lines = ["Red-team tools (kali apt first; tier C = Burp-blind, needs separate evidence lane):"]
        for name, meta in sorted(rows, key=lambda r: (r[1]["tier"], r[0])):
            burp = "burp" if meta["routes_burp"] else "no-burp"
            lines.append(f"  [{meta['tier']}/{burp}] {name} — {meta['purpose']}")
            lines.append(f"       install: {meta.get('install', {}).get('kali', 'n/a')}")
        lines.append("Detail: redteam_tool_guide(tool='<name>').")
        return "\n".join(lines)
