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
    cross_transport,
    fuzz,
    fuzz_evolutionary,
    fuzz_feedback,
    hpp,
    id_monotonic,
    race,
    race_lastbyte,
    race_singlepacket,
    rate_limit,
    timeless_timing,
)


def register(mcp: FastMCP) -> None:
    fuzz.register(mcp)
    fuzz_feedback.register(mcp)
    fuzz_evolutionary.register(mcp)
    auth_compare.register(mcp)
    comparer.register(mcp)
    auth_matrix.register(mcp)
    race.register(mcp)
    hpp.register(mcp)
    id_monotonic.register(mcp)
    cross_transport.register(mcp)
    race_lastbyte.register(mcp)
    race_singlepacket.register(mcp)
    rate_limit.register(mcp)
    timeless_timing.register(mcp)
