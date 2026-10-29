"""Edge-case security testing tools — JWT, CORS, GraphQL, LFI, file upload, redirect, cloud metadata."""

from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from praetor.tools._coverage import record_exploit_coverage
from praetor.tools.edge.test_cors import test_cors_impl
from praetor.tools.edge.test_jwt import test_jwt_impl
from praetor.tools.edge.test_graphql import test_graphql_impl
from praetor.tools.edge.test_cloud_metadata import test_cloud_metadata_impl
from praetor.tools.edge.discover_common_files import discover_common_files_impl
from praetor.tools.edge.test_open_redirect import test_open_redirect_impl
from praetor.tools.edge.test_lfi import test_lfi_impl
from praetor.tools.edge.test_file_upload import test_file_upload_impl
from praetor.tools.edge.test_clickjacking import test_clickjacking_impl
from praetor.tools.edge.probe_baas_rls import probe_baas_rls_impl


def _record(endpoint: str, param: str, vuln_class: str, tool: str, result: dict) -> None:
    v = result.get("verdict", "") if isinstance(result, dict) else ""
    if v in ("CONFIRMED", "FAILED"):
        try:
            domain = urlparse(endpoint).hostname or ""
        except Exception:
            domain = ""
        record_exploit_coverage(domain, endpoint, param, vuln_class,
                                verdict=v, tool_name=tool)


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_cors(
        session: str,
        path: str = "/",
        test_origins: list[str] | None = None,
    ) -> dict:
        """Test CORS configuration for origin reflection and credential misconfigs.

        VIGIL-FIRST: vigil's cors detector covers this class. Run run_vigil()
        first — use this tool only for targeted re-probe of a specific finding,
        or when vigil is not installed.

        Args:
            session: Session name
            path: Endpoint path to test
            test_origins: Custom origins to test
        """
        r = await test_cors_impl(session=session, path=path, test_origins=test_origins)
        _record(path, "", "cors", "test_cors", r)
        return r

    @mcp.tool()
    async def test_jwt(
        token: str,
    ) -> str:
        """Analyze a JWT token for vulnerabilities and attack vectors.

        VIGIL-FIRST: vigil's jwt + jwtadvanced + jkuabuse detectors cover this
        class. Run run_vigil() first — use this tool only for targeted re-probe
        of a specific finding, or when vigil is not installed.

        Args:
            token: JWT token string
        """
        r = await test_jwt_impl(token=token)
        _record("", "", "jwt", "test_jwt", r)
        return r

    @mcp.tool()
    async def test_graphql(
        session: str,
        path: str = "/graphql",
        depth: str = "quick",
    ) -> dict:
        """Test GraphQL endpoint for introspection, field suggestions, batch, GET CSRF, and (deep) alias-DoS + depth limits.

        VIGIL-FIRST: vigil's graphql + graphqladvanced + graphqldos detectors
        cover this class. Run run_vigil() first — use this tool only for
        targeted re-probe of a specific finding, or when vigil is not installed.

        Args:
            session: Session name
            path: GraphQL endpoint path (default /graphql)
            depth: 'quick' (4 tests) or 'deep' (6 tests including alias-DoS + depth limit)
        """
        r = await test_graphql_impl(session=session, path=path, depth=depth)
        _record(path, "", "graphql", "test_graphql", r)
        return r

    @mcp.tool()
    async def test_cloud_metadata(
        session: str,
        parameter: str = "url",
        path: str = "/",
        injection_point: str = "query",
        extra_headers: dict | None = None,
        imdsv2: bool = False,
    ) -> dict:
        """Test SSRF to cloud metadata + container creds (AWS ECS/EKS/IMDS, GCP, Azure, DO, Alibaba, Oracle).

        VIGIL-FIRST: vigil's cloud detector covers this class. Run run_vigil()
        first — use this tool only for targeted re-probe of a specific finding,
        or when vigil is not installed.

        Args:
            session: Session name
            parameter: Parameter to inject SSRF payload into
            path: Endpoint path
            injection_point: Where to inject: 'query' or 'body'
            extra_headers: Outer-request headers (e.g. {"Metadata-Flavor": "Google"})
                for header-forwarding SSRF only — GCP/Azure IMDS are header-gated.
            imdsv2: Also attempt the AWS IMDSv2 two-step (PUT token → GET creds
                with the token header) — the default on modern EC2. Needs a
                method/header-forwarding SSRF (gopher / full-request); set True
                only when the SSRF is known to forward the PUT + token header.
        """
        r = await test_cloud_metadata_impl(session=session, parameter=parameter, path=path, injection_point=injection_point, extra_headers=extra_headers, imdsv2=imdsv2)
        _record(path, parameter, "cloud_metadata", "test_cloud_metadata", r)
        return r

    @mcp.tool()
    async def discover_common_files(
        session: str,
        tech_specific: bool = True,
    ) -> str:
        """Probe for common sensitive files and paths (.git, .env, actuator, etc).

        Args:
            session: Session name
            tech_specific: Add tech-specific paths based on detected stack
        """
        return await discover_common_files_impl(session=session, tech_specific=tech_specific)

    @mcp.tool()
    async def test_open_redirect(
        session: str,
        path: str,
        parameter: str,
        poll_seconds: int = 5,
        follow_redirects: bool = False,
    ) -> dict:
        """Test open redirect with Collaborator-verified DNS/HTTP confirmation.

        VIGIL-FIRST: vigil's redirect detector covers this class. Run run_vigil()
        first — use this tool only for targeted re-probe of a specific finding,
        or when vigil is not installed.

        Args:
            session: Session name
            path: Endpoint path
            parameter: Redirect parameter name
            poll_seconds: Seconds to wait before polling (max 15)
            follow_redirects: Follow redirects to test client-side behavior
        """
        r = await test_open_redirect_impl(session=session, path=path, parameter=parameter, poll_seconds=poll_seconds, follow_redirects=follow_redirects)
        _record(path, parameter, "open_redirect", "test_open_redirect", r)
        return r

    @mcp.tool()
    async def test_lfi(
        session: str,
        path: str,
        parameter: str,
        os_type: str = "auto",
        test_wrappers: bool = True,
        depth: int = 6,
    ) -> dict:
        """Test for LFI/path traversal with encoding bypasses and PHP wrappers.

        VIGIL-FIRST: vigil's lfi detector covers this class. Run run_vigil()
        first — use this tool only for targeted re-probe of a specific finding,
        or when vigil is not installed.

        Args:
            session: Session name
            path: Endpoint path
            parameter: File parameter name
            os_type: 'linux', 'windows', or 'auto'
            test_wrappers: Test PHP stream wrappers
            depth: Traversal depth
        """
        r = await test_lfi_impl(session=session, path=path, parameter=parameter, os_type=os_type, test_wrappers=test_wrappers, depth=depth)
        _record(path, parameter, "lfi", "test_lfi", r)
        return r

    @mcp.tool()
    async def test_file_upload(
        session: str,
        path: str,
        parameter: str = "file",
        test_types: list[str] | None = None,
        content_type_bypass: bool = True,
    ) -> dict:
        """Test file upload for bypass vulnerabilities with extension and content-type evasion.

        VIGIL-FIRST: vigil's fileupload detector covers this class. Run run_vigil()
        first — use this tool only for targeted re-probe of a specific finding,
        or when vigil is not installed.

        Args:
            session: Session name
            path: Upload endpoint path
            parameter: Form field name for file upload
            test_types: Types to test: php, jsp, aspx, svg_xss, html, polyglot
            content_type_bypass: Test with mismatched Content-Type headers
        """
        r = await test_file_upload_impl(session=session, path=path, parameter=parameter, test_types=test_types, content_type_bypass=content_type_bypass)
        _record(path, parameter, "file_upload", "test_file_upload", r)
        return r

    @mcp.tool()
    async def test_clickjacking(
        session: str,
        path: str = "/",
        multistep: bool = True,
        target_url: str = "",
    ) -> dict:
        """Verdict a page's frameability (clickjacking) and emit an attack PoC when frameable.

        VIGIL-FIRST: vigil's xfs (X-Frame/clickjacking) detector covers this
        class. Run run_vigil() first — use this tool only for targeted re-probe
        of a specific finding, or when vigil is not installed.

        Combines X-Frame-Options and CSP frame-ancestors the way a browser does
        (frame-ancestors authoritative; legacy XFO ALLOW-FROM ignored). When
        frameable, returns a ready-to-store overlay PoC for the exploit server.

        Args:
            session: Session name (fetch the target page authenticated if needed).
            path: Endpoint path to test (e.g. /my-account).
            multistep: Two-decoy overlay (for confirm-dialog flows) vs single decoy.
            target_url: Full iframe URL for the PoC; defaults to the fetched URL / path.
        """
        r = await test_clickjacking_impl(session=session, path=path, multistep=multistep, target_url=target_url)
        _record(path, "", "clickjacking", "test_clickjacking", r)
        return r

    @mcp.tool()
    async def probe_supabase_rls(
        supabase_url: str = "",
        anon_key: str = "",
        proxy_history_index: int = -1,
        tables: list[str] | None = None,
    ) -> dict:
        """Probe a Supabase backend for missing Row Level Security (RLS).

        Accepts either explicit supabase_url + anon_key, or a
        proxy_history_index pointing at the JS bundle (auto-extracts
        the Supabase URL and anon key via extract_js_secrets).

        Probes 25 common table names for unauthenticated SELECT access.
        Reports exposed tables, column names, and PII column flags.
        Rule 7 compliant: reads column structure only, never data values.

        Args:
            supabase_url: Supabase project URL (e.g. https://xyz.supabase.co)
            anon_key: Supabase anon/public key (JWT from the JS bundle)
            proxy_history_index: Proxy index of the JS bundle to auto-extract from
            tables: Custom table names to probe (default: 25 common names)
        """
        r = await probe_baas_rls_impl(
            supabase_url=supabase_url, anon_key=anon_key,
            proxy_history_index=proxy_history_index, tables=tables,
        )
        endpoint = r.get("supabase_url", supabase_url) or "unknown"
        _record(endpoint, "anon_key", "idor", "probe_supabase_rls", r)
        return r
