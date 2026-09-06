"""ProjectDiscovery recon tool bodies (part 1: resolvers / scanners / intel).

Pure async implementations delegated to by the thin @mcp.tool() wrappers in
__init__.py. Helper functions (_not_installed / _parse_jsonl) live in
_shared.py; _check_tool / _run_cmd come from recon._common. Names resolve
against THIS module's globals, so test patches target recon_pd._impl.*.
"""

from __future__ import annotations

from praetor.tools.recon._common import _check_tool, _run_cmd

from ._shared import _not_installed, _parse_jsonl


async def run_dnsx(
    targets: list[str],
    record_type: str = "a",
    bruteforce_wordlist: str = "",
    timeout: int = 120,
) -> str:
    if not _check_tool("dnsx"):
        return _not_installed("dnsx", "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
    if not targets:
        return "Error: targets list empty."
    cmd = ["dnsx", "-silent", "-json", "-resp", "-" + record_type.lower()]
    if bruteforce_wordlist:
        cmd += ["-w", bruteforce_wordlist]
    import tempfile, pathlib
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(targets))
        inp = fh.name
    try:
        cmd += ["-l", inp]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
    finally:
        try: pathlib.Path(inp).unlink()
        except OSError: pass
    rows = _parse_jsonl(out)
    lines = [f"dnsx: {len(rows)} resolved ({record_type.upper()})"]
    for r in rows[:50]:
        lines.append(f"  {r.get('host','?')} -> {','.join(r.get(record_type, []))[:120]}")
    if rc != 0 and not rows:
        lines.append(f"[rc={rc}] {err[:200]}")
    return "\n".join(lines)


async def run_naabu(target: str, ports: str = "top-100", timeout: int = 300) -> str:
    if not _check_tool("naabu"):
        return _not_installed("naabu", "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
    cmd = ["naabu", "-host", target, "-silent", "-json"]
    if ports == "top-100":
        cmd += ["-top-ports", "100"]
    elif ports == "top-1000":
        cmd += ["-top-ports", "1000"]
    elif ports == "full":
        cmd += ["-p", "-"]
    else:
        cmd += ["-p", ports]
    out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
    rows = _parse_jsonl(out)
    lines = [f"naabu: {len(rows)} open ports on {target}"]
    for r in rows[:60]:
        lines.append(f"  {r.get('host','?')}:{r.get('port','?')}")
    if rc != 0 and not rows:
        lines.append(f"[rc={rc}] {err[:200]}")
    return "\n".join(lines)


async def run_tlsx(targets: list[str], timeout: int = 120) -> str:
    if not _check_tool("tlsx"):
        return _not_installed("tlsx", "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest")
    if not targets:
        return "Error: targets list empty."
    import tempfile, pathlib
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(targets))
        inp = fh.name
    try:
        out, err, rc = await _run_cmd(
            ["tlsx", "-l", inp, "-silent", "-json", "-san", "-cn", "-jarm", "-expired"],
            timeout=timeout, bypass_proxy=True,
        )
    finally:
        try: pathlib.Path(inp).unlink()
        except OSError: pass
    rows = _parse_jsonl(out)
    lines = [f"tlsx: {len(rows)} certs"]
    for r in rows[:30]:
        host = r.get("host", "")
        cn = r.get("subject_cn") or r.get("cn") or ""
        jarm = r.get("jarm_hash", "")[:30]
        sans = ",".join((r.get("subject_an") or [])[:5])
        lines.append(f"  {host}  cn={cn}  jarm={jarm}  san={sans}")
    if rc != 0 and not rows:
        lines.append(f"[rc={rc}] {err[:200]}")
    return "\n".join(lines)


async def run_asnmap(target: str, timeout: int = 60) -> str:
    if not _check_tool("asnmap"):
        return _not_installed("asnmap", "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest")
    flag = "-d"
    t = target.strip()
    if t.upper().startswith("AS") and t[2:].isdigit():
        flag = "-a"
    elif t.replace(".", "").isdigit():
        flag = "-i"
    out, err, rc = await _run_cmd(
        ["asnmap", flag, t, "-silent", "-json"], timeout=timeout, bypass_proxy=True,
    )
    rows = _parse_jsonl(out)
    lines = [f"asnmap: {len(rows)} ranges for {target}"]
    for r in rows[:30]:
        cidrs = ",".join(r.get("ranges") or r.get("range") or [])[:120]
        org = r.get("org", "")
        lines.append(f"  AS{r.get('asn','?')} {org}  {cidrs}")
    if rc != 0 and not rows:
        lines.append(f"[rc={rc}] {err[:200]}")
    return "\n".join(lines)


async def run_cdncheck(targets: list[str], timeout: int = 60) -> str:
    if not _check_tool("cdncheck"):
        return _not_installed("cdncheck", "go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest")
    if not targets:
        return "Error: targets list empty."
    import tempfile, pathlib
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(targets))
        inp = fh.name
    try:
        out, err, rc = await _run_cmd(
            ["cdncheck", "-l", inp, "-silent", "-json"],
            timeout=timeout, bypass_proxy=True,
        )
    finally:
        try: pathlib.Path(inp).unlink()
        except OSError: pass
    rows = _parse_jsonl(out)
    lines = [f"cdncheck: {len(rows)} classifications"]
    for r in rows[:40]:
        kinds = []
        for k in ("cdn", "waf", "cloud"):
            v = r.get(k)
            if v:
                kinds.append(f"{k}={v}")
        lines.append(f"  {r.get('host') or r.get('ip','?')}  {' '.join(kinds) or 'none'}")
    if rc != 0 and not rows:
        lines.append(f"[rc={rc}] {err[:200]}")
    return "\n".join(lines)


async def run_uncover(query: str, engine: str = "shodan", limit: int = 50, timeout: int = 60) -> str:
    if not _check_tool("uncover"):
        return _not_installed("uncover", "go install github.com/projectdiscovery/uncover/cmd/uncover@latest")
    out, err, rc = await _run_cmd(
        ["uncover", "-q", query, "-e", engine, "-l", str(limit), "-silent"],
        timeout=timeout, bypass_proxy=True,
    )
    hosts = [ln.strip() for ln in out.splitlines() if ln.strip()]
    lines = [f"uncover [{engine}]: {len(hosts)} hits for {query!r}"]
    for h in hosts[:limit]:
        lines.append(f"  {h}")
    if rc != 0 and not hosts:
        lines.append(f"[rc={rc}] {err[:200]} (API key required for most engines)")
    return "\n".join(lines)


async def run_cloudlist(provider: str = "", timeout: int = 300) -> str:
    if not _check_tool("cloudlist"):
        return _not_installed("cloudlist", "go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest")
    cmd = ["cloudlist", "-silent", "-json"]
    if provider:
        cmd += ["-provider", provider]
    out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
    rows = _parse_jsonl(out)
    lines = [f"cloudlist: {len(rows)} assets" + (f" [{provider}]" if provider else "")]
    for r in rows[:40]:
        lines.append(f"  {r.get('provider','?')} {r.get('host') or r.get('ip') or '?'}")
    if rc != 0 and not rows:
        lines.append(f"[rc={rc}] {err[:200]} (provider config required at ~/.config/cloudlist/config.yaml)")
    return "\n".join(lines)


async def run_graphw00f(target: str, timeout: int = 60) -> str:
    if not _check_tool("graphw00f"):
        return _not_installed(
            "graphw00f",
            "pip install graphw00f  |  https://github.com/dolevf/graphw00f",
        )
    out, err, rc = await _run_cmd(
        ["graphw00f", "-t", target, "-d", "-f"],
        timeout=timeout, bypass_proxy=True,
    )
    lines = ["graphw00f scan:"]
    clipped = out.strip()
    if not clipped:
        return f"graphw00f: no output [rc={rc}] {err[:200]}"
    lines.extend("  " + ln for ln in clipped.splitlines()[:40])
    return "\n".join(lines)
