"""Field-formatting helpers for platform finding submissions."""

_MISSING = "_NOT SUPPLIED — fill from the actual request/response before submitting._"


def _list_or_str(value, joiner="\n", item_prefix="") -> str:
    """Render a list field or pass through a string."""
    if isinstance(value, list):
        return joiner.join(f"{item_prefix}{v}" for v in value)
    return str(value or "")


def _numbered(value) -> str:
    """Render a list as a numbered list, or pass through a string."""
    if isinstance(value, list):
        return "\n".join(f"{i}. {s}" for i, s in enumerate(value, 1))
    return str(value or "")


def _evidence_str(evidence) -> str:
    """Evidence lines for a platform submission.

    A bug-bounty triager cannot resolve `logger_index: 412` — it is a pointer
    into someone else's Burp session. Pasting it makes the report look
    machine-generated and gives the triager nothing to verify, so operator
    bookkeeping keys are dropped here unconditionally.
    """
    if isinstance(evidence, dict):
        from praetor.tools.report.builders import _is_internal_evidence
        return "\n".join(
            f"- {k}: {v}" for k, v in evidence.items()
            if not _is_internal_evidence(k, v)
        )
    if isinstance(evidence, str):
        return evidence
    return ""


def _poc_steps(poc, endpoint, domain) -> str:
    """Build a Markdown HTTP block + observation line from a poc_request dict/string."""
    if isinstance(poc, dict):
        method = poc.get("method", "GET")
        path = poc.get("path", endpoint)
        headers = poc.get("headers", {})
        body = poc.get("body", "")
        out = f"1. Send the following request:\n```http\n{method} {path} HTTP/1.1\nHost: {domain}\n"
        for k, v in headers.items():
            out += f"{k}: {v}\n"
        if body:
            out += f"\n{body}\n"
        out += "```\n"
        expected = poc.get("expected_behavior", "")
        if expected:
            out += f"2. Observe: {expected}\n"
        return out
    return str(poc) if poc else ""


