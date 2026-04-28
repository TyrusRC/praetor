"""Advanced testing tools — submodular package.

Submodules (one tool each):
  - api_schema       : parse_api_schema (OpenAPI/Swagger)
  - graphql_deep     : test_graphql_deep
  - business_logic   : test_business_logic
  - host_header      : test_host_header
  - crlf             : test_crlf_injection
  - smuggling        : test_request_smuggling
  - mass_assignment  : test_mass_assignment
  - cache_poisoning  : test_cache_poisoning

Shared helpers in `_helpers.py`. Tool-specific constants live in their own files.
"""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.testing_extended import (
    api_schema,
    business_logic,
    cache_poisoning,
    crlf,
    graphql_deep,
    host_header,
    mass_assignment,
    smuggling,
)


def register(mcp: FastMCP):
    api_schema.register(mcp)
    graphql_deep.register(mcp)
    business_logic.register(mcp)
    host_header.register(mcp)
    crlf.register(mcp)
    smuggling.register(mcp)
    mass_assignment.register(mcp)
    cache_poisoning.register(mcp)
