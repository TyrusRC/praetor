"""Advanced testing tools — submodular package.

Submodules (one tool each):
  - api_schema           : parse_api_schema (OpenAPI/Swagger)
  - business_logic       : test_business_logic
  - host_header          : test_host_header
  - crlf                 : test_crlf_injection
  - smuggling            : test_request_smuggling
  - mass_assignment      : test_mass_assignment
  - cache_poisoning      : test_cache_poisoning
  - idempotency_key      : probe_idempotency_key      (Strix P0)
  - workflow_reorder     : probe_workflow_reorder     (Strix P0)
  - internal_headers     : probe_internal_headers     (Strix P0)
  - role_cleanup         : probe_role_state_cleanup   (Strix P0)
  - quota_window         : probe_quota_window_edge    (Strix P1)
  - content_type_switch  : probe_content_type_switch  (Strix P1)
  - line_item_mutation   : probe_line_item_mutation   (Strix P1)
  - decimal_rounding     : probe_float_decimal_rounding (Strix P1)
  - cron_backfill        : probe_cron_backfill        (Strix P1)

GraphQL deep testing merged into `edge/test_graphql.py` — call `test_graphql(..., depth='deep')`.

Shared helpers in `_helpers.py`. Tool-specific constants live in their own files.
"""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.testing_extended import (
    api_schema,
    business_logic,
    cache_poisoning,
    content_type_switch,
    cron_backfill,
    crlf,
    decimal_rounding,
    host_header,
    idempotency_key,
    internal_headers,
    line_item_mutation,
    mass_assignment,
    quota_window,
    role_cleanup,
    smuggling,
    workflow_reorder,
)


def register(mcp: FastMCP):
    api_schema.register(mcp)
    business_logic.register(mcp)
    host_header.register(mcp)
    crlf.register(mcp)
    smuggling.register(mcp)
    mass_assignment.register(mcp)
    cache_poisoning.register(mcp)
    idempotency_key.register(mcp)
    workflow_reorder.register(mcp)
    internal_headers.register(mcp)
    role_cleanup.register(mcp)
    quota_window.register(mcp)
    content_type_switch.register(mcp)
    line_item_mutation.register(mcp)
    decimal_rounding.register(mcp)
    cron_backfill.register(mcp)
