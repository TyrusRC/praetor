"""Edge-case security testing tools — JWT, CORS, GraphQL, LFI, file upload, redirect, cloud metadata."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.edge.test_cors import test_cors_impl
from burpsuite_mcp.tools.edge.test_jwt import test_jwt_impl
from burpsuite_mcp.tools.edge.test_graphql import test_graphql_impl
from burpsuite_mcp.tools.edge.test_cloud_metadata import test_cloud_metadata_impl
from burpsuite_mcp.tools.edge.discover_common_files import discover_common_files_impl
from burpsuite_mcp.tools.edge.test_open_redirect import test_open_redirect_impl
from burpsuite_mcp.tools.edge.test_lfi import test_lfi_impl
from burpsuite_mcp.tools.edge.test_file_upload import test_file_upload_impl


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_cors(
        session: str,
        path: str = "/",
        test_origins: list[str] | None = None,
    ) -> str:
        """Test CORS configuration for origin reflection and credential misconfigs.

        Args:
            session: Session name
            path: Endpoint path to test
            test_origins: Custom origins to test
        """
        return await test_cors_impl(session=session, path=path, test_origins=test_origins)

    @mcp.tool()
    async def test_jwt(
        token: str,
    ) -> str:
        """Analyze a JWT token for vulnerabilities and attack vectors.

        Args:
            token: JWT token string
        """
        return await test_jwt_impl(token=token)

    @mcp.tool()
    async def test_graphql(
        session: str,
        path: str = "/graphql",
    ) -> str:
        """Test GraphQL endpoint for introspection, field suggestions, batch queries, and GET CSRF.

        Args:
            session: Session name
            path: GraphQL endpoint path
        """
        return await test_graphql_impl(session=session, path=path)

    @mcp.tool()
    async def test_cloud_metadata(
        session: str,
        parameter: str = "url",
        path: str = "/",
        injection_point: str = "query",
    ) -> str:
        """Test SSRF to cloud metadata services (AWS, GCP, Azure, DigitalOcean).

        Args:
            session: Session name
            parameter: Parameter to inject SSRF payload into
            path: Endpoint path
            injection_point: Where to inject: 'query' or 'body'
        """
        return await test_cloud_metadata_impl(session=session, parameter=parameter, path=path, injection_point=injection_point)

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
    ) -> str:
        """Test open redirect with Collaborator-verified DNS/HTTP confirmation.

        Args:
            session: Session name
            path: Endpoint path
            parameter: Redirect parameter name
            poll_seconds: Seconds to wait before polling (max 15)
            follow_redirects: Follow redirects to test client-side behavior
        """
        return await test_open_redirect_impl(session=session, path=path, parameter=parameter, poll_seconds=poll_seconds, follow_redirects=follow_redirects)

    @mcp.tool()
    async def test_lfi(
        session: str,
        path: str,
        parameter: str,
        os_type: str = "auto",
        test_wrappers: bool = True,
        depth: int = 6,
    ) -> str:
        """Test for LFI/path traversal with encoding bypasses and PHP wrappers.

        Args:
            session: Session name
            path: Endpoint path
            parameter: File parameter name
            os_type: 'linux', 'windows', or 'auto'
            test_wrappers: Test PHP stream wrappers
            depth: Traversal depth
        """
        return await test_lfi_impl(session=session, path=path, parameter=parameter, os_type=os_type, test_wrappers=test_wrappers, depth=depth)

    @mcp.tool()
    async def test_file_upload(
        session: str,
        path: str,
        parameter: str = "file",
        test_types: list[str] | None = None,
        content_type_bypass: bool = True,
    ) -> str:
        """Test file upload for bypass vulnerabilities with extension and content-type evasion.

        Args:
            session: Session name
            path: Upload endpoint path
            parameter: Form field name for file upload
            test_types: Types to test: php, jsp, aspx, svg_xss, html, polyglot
            content_type_bypass: Test with mismatched Content-Type headers
        """
        return await test_file_upload_impl(session=session, path=path, parameter=parameter, test_types=test_types, content_type_bypass=content_type_bypass)
