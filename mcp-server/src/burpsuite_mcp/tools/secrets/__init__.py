"""Secret-detection + .git-exposure subsystem (Praetor v1.0).

Tools:
    run_gitleaks       — wrap gitleaks against repo URL / local path / staged diff
    run_trufflehog     — wrap trufflehog with --verify (credentials confirmed-live = HIGH floor)
    dump_exposed_git   — wrap git-dumper to reconstruct .git/ from exposed dir-listing or
                          predictable /.git/HEAD endpoints, auto-chain into gitleaks/trufflehog

Operator chain: discover_common_files finds /.git/HEAD -> ORANGE annotation ->
dump_exposed_git -> run_gitleaks + run_trufflehog on the dump -> save_finding with
chain_with=[parent_id], severity=CRITICAL if any trufflehog finding is verified=true.
"""

from mcp.server.fastmcp import FastMCP

from . import git_dumper, gitleaks, trufflehog


def register(mcp: FastMCP) -> None:
    gitleaks.register(mcp)
    trufflehog.register(mcp)
    git_dumper.register(mcp)
