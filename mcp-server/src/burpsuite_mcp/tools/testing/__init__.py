"""Advanced testing tools — fuzz, auth-state diff, comparer, auth-matrix,
race-condition harness, HTTP parameter pollution.

Split from a single 572-line testing.py into one module per tool family so
each focused submodule stays under ~120 lines and the smart-payload map +
formatter helpers can be reused without re-import dance.
"""

from mcp.server.fastmcp import FastMCP

from . import (
    auth_compare,
    auth_matrix,
    comparer,
    fuzz,
    hpp,
    race,
)


def register(mcp: FastMCP) -> None:
    fuzz.register(mcp)
    auth_compare.register(mcp)
    comparer.register(mcp)
    auth_matrix.register(mcp)
    race.register(mcp)
    hpp.register(mcp)
