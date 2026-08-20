"""MCP tools over the red-team operator log + loot store.

  record_redteam_action - append an operator-log entry (any non-Burp action)
  record_loot           - record a captured artifact with chain-of-custody
  get_operator_log      - read the log as a kill-chain timeline or ATT&CK view

These are the evidence a network/AD/post-ex finding cites (oplog id) in place
of a Burp logger_index, and what the kill-chain report renders from.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ._oplog import (
    read_loot,
    read_oplog,
    record_action,
    record_loot,
)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def record_redteam_action(
        domain: str,
        tool: str,
        command: str,
        description: str = "",
        target: str = "",
        source: str = "",
        output: str = "",
        output_path: str = "",
        user_context: str = "",
        operator: str = "",
        tactic: str = "",
        technique: str = "",
        detected: bool = False,
        returncode: int = 0,
    ) -> str:
        """Record one non-Burp red-team action in the operator log (evidence).

        Use for every network/AD/post-ex action Burp can't see — nmap,
        impacket, netexec, responder, mimikatz, manual SSH, a privesc step.
        ATT&CK tactic/technique auto-fill from `tool` when left blank.

        Args:
            domain: engagement key (.burp-intel/<domain>/network/oplog.jsonl).
            tool: tool/binary used (e.g. 'impacket-secretsdump', 'netexec').
            command: the exact command run (verbatim — this is the evidence).
            description: operator intent ("dumped domain hashes via DRSUAPI").
            target: target host/IP/asset. source: operator origin host/IP.
            output: short result; large output -> a file, pass output_path.
            user_context: the account/cred used ('DOMAIN\\svc_sql', 'root').
            operator: who ran it. tactic/technique: ATT&CK override.
            detected: blue-team detected this action (purple-team tracking).
            returncode: process exit code.

        Returns the oplog id (e.g. 'op0007') to cite from a finding.
        """
        op_id = record_action(
            domain, tool, command, description=description, source=source,
            target=target, output=output, output_path=output_path,
            user_context=user_context, operator=operator, tactic=tactic,
            technique=technique, detected=detected, returncode=returncode,
        )
        from ._oplog import attack_for
        t, tech, name = attack_for(tool)
        ttp = f" [{tech} {name}]" if tech and not technique else (f" [{technique}]" if technique else "")
        return f"Logged {op_id}: {tool} -> {target or '(no target)'}{ttp}"

    @mcp.tool()
    async def record_loot(
        domain: str,
        loot_type: str,
        value: str,
        source_host: str = "",
        obtained_via: str = "",
        oplog_id: str = "",
        is_path: bool = False,
    ) -> str:
        """Record a captured artifact (hash/ticket/cred/key/file) with custody.

        The artifact goes to network/loot/<id> (gitignored); the manifest keeps
        type, provenance, sha256 and a REDACTED shape — never the plaintext.

        Args:
            domain: engagement key.
            loot_type: 'ntlm_hash'|'ntlmv2'|'kerberos_tgs'|'plaintext_cred'|
                'ssh_key'|'ntds'|'sam'|'file'|'token'|'session'.
            value: the artifact string, or a filepath when is_path=True.
            source_host: where it was captured from.
            obtained_via: tool/technique ('responder', 'secretsdump').
            oplog_id: the operator-log entry that produced it (chain-of-custody).
            is_path: value is a path to copy into the loot store.
        """
        from ._oplog import record_loot as _rl
        row = _rl(domain, loot_type, value, source_host=source_host,
                  obtained_via=obtained_via, oplog_id=oplog_id, is_path=is_path)
        return (f"Loot {row['id']} [{loot_type}] from {source_host or '?'} "
                f"sha256={row['sha256'][:16]}… preview={row['preview']} "
                f"(via {oplog_id or obtained_via or '?'})")

    @mcp.tool()
    async def get_operator_log(domain: str, view: str = "timeline") -> str:
        """Read the red-team operator log — the report's evidence base.

        Args:
            domain: engagement key.
            view: 'timeline' (chronological kill chain), 'attack' (grouped by
                ATT&CK tactic/technique), or 'loot' (captured artifacts).
        """
        entries = read_oplog(domain)
        if view == "loot":
            loot = read_loot(domain)
            if not loot:
                return f"No loot recorded for {domain!r}."
            lines = [f"Loot for {domain} ({len(loot)} artifacts):"]
            for r in loot:
                lines.append(
                    f"  {r['id']} [{r['type']}] {r['preview']} "
                    f"from {r.get('source_host') or '?'} via {r.get('oplog_id') or r.get('obtained_via') or '?'} "
                    f"sha256={r['sha256'][:16]}…")
            return "\n".join(lines)

        if not entries:
            return f"No operator-log entries for {domain!r}. record_redteam_action / run_nmap first."

        if view == "attack":
            by_ttp: dict[str, list[dict]] = {}
            for e in entries:
                key = f"{e.get('tactic') or 'Unmapped'} / {e.get('technique') or '-'} {e.get('technique_name') or ''}".strip()
                by_ttp.setdefault(key, []).append(e)
            lines = [f"ATT&CK coverage for {domain} ({len(entries)} actions, {len(by_ttp)} techniques):"]
            for key in sorted(by_ttp):
                lines.append(f"  {key}")
                for e in by_ttp[key]:
                    lines.append(f"      {e['id']} {e['tool']} -> {e.get('target') or '-'}")
            return "\n".join(lines)

        # timeline (default)
        lines = [f"Operator log for {domain} ({len(entries)} actions):"]
        for e in entries:
            ttp = f" [{e['technique']}]" if e.get("technique") else ""
            det = " DETECTED" if e.get("detected") else ""
            uc = f" as {e['user_context']}" if e.get("user_context") else ""
            lines.append(f"  {e['id']} {e['start'][:19]} {e['tool']} -> {e.get('target') or '-'}{uc}{ttp}{det}")
            if e.get("description"):
                lines.append(f"       {e['description']}")
            lines.append(f"       $ {e['command']}")
        return "\n".join(lines)
