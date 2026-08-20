"""Shared helpers for edge-case tests."""

import uuid


def build_multipart(field_name: str, filename: str, content: str, content_type: str) -> tuple[str, str]:
    """Build a multipart/form-data body. Returns (body, boundary)."""
    boundary = f"----WebKitFormBoundary{uuid.uuid4().hex[:16]}"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
        f"{content}\r\n"
        f"--{boundary}--\r\n"
    )
    return body, boundary
