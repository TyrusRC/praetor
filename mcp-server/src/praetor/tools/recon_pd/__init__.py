"""recon_pd — ProjectDiscovery recon tool wrappers.

Thin register() + @mcp.tool() wrappers delegating to the tool bodies in
_impl.py / _gen.py; shared helpers (_not_installed / _parse_jsonl) in _shared.py.
"""

from mcp.server.fastmcp import FastMCP

from . import _gen, _impl


def register(mcp: FastMCP):
    @mcp.tool()
    async def run_dnsx(
        targets: list[str],
        record_type: str = "a",
        bruteforce_wordlist: str = "",
        timeout: int = 120,
    ) -> str:
        """Resolve / brute-force DNS records.

        Args:
            targets: list of domains.
            record_type: a|aaaa|cname|mx|txt|ns|soa|ptr.
            bruteforce_wordlist: optional path to wordlist for subdomain brute.
            timeout: seconds.
        """
        return await _impl.run_dnsx(targets, record_type, bruteforce_wordlist, timeout)

    @mcp.tool()
    async def run_naabu(target: str, ports: str = "top-100", timeout: int = 300) -> str:
        """Port scan via naabu.

        Args:
            target: host / IP / CIDR.
            ports: 'top-100' | 'top-1000' | 'full' | '80,443,8080'.
            timeout: seconds.
        """
        return await _impl.run_naabu(target, ports, timeout)

    @mcp.tool()
    async def run_tlsx(targets: list[str], timeout: int = 120) -> str:
        """Grab TLS metadata (SAN, JARM, cipher, expiry) via tlsx.

        Args:
            targets: list of host:port (default 443).
            timeout: seconds.
        """
        return await _impl.run_tlsx(targets, timeout)

    @mcp.tool()
    async def run_asnmap(target: str, timeout: int = 60) -> str:
        """Expand ASN / org / IP / domain to CIDR ranges.

        Args:
            target: 'AS13335' | 'cloudflare' | '1.1.1.1' | 'example.com'.
            timeout: seconds.
        """
        return await _impl.run_asnmap(target, timeout)

    @mcp.tool()
    async def run_uncover(query: str, engine: str = "shodan", limit: int = 50, timeout: int = 60) -> str:
        """Query Shodan / Censys / Fofa / Quake / Hunter / Netlas / CriminalIP via uncover.

        Args:
            query: search query (engine-specific syntax).
            engine: shodan | censys | fofa | quake | hunter | netlas | criminalip | zoomeye.
            limit: max results.
            timeout: seconds.
        """
        return await _impl.run_uncover(query, engine, limit, timeout)

    @mcp.tool()
    async def run_cloudlist(provider: str = "", timeout: int = 300) -> str:
        """Inventory cloud assets via cloudlist.

        Args:
            provider: '' (all configured) | aws | azure | gcp | digitalocean | scaleway | linode | hetzner | namecheap | terraform.
            timeout: seconds.
        """
        return await _impl.run_cloudlist(provider, timeout)

    @mcp.tool()
    async def run_notify(message: str, provider: str = "", timeout: int = 30) -> str:
        """Pipe a message to Slack / Discord / Teams / Telegram / Pushover / email via notify.

        Args:
            message: text body.
            provider: '' (all configured) | slack | discord | teams | telegram | pushover | smtp.
            timeout: seconds.
        """
        return await _gen.run_notify(message, provider, timeout)

    @mcp.tool()
    async def run_mapcves(query: str = "", year: str = "", severity: str = "", timeout: int = 60) -> str:
        """Query mapcves (CVE -> exploit / nuclei template).

        Args:
            query: free-text query (e.g. 'log4j', 'apache').
            year: filter by CVE year (e.g. '2024').
            severity: low|medium|high|critical.
            timeout: seconds.
        """
        return await _gen.run_mapcves(query, year, severity, timeout)

    @mcp.tool()
    async def run_cdncheck(targets: list[str], timeout: int = 60) -> str:
        """Classify CDN / WAF / cloud IP via cdncheck.

        Args:
            targets: list of hosts/IPs.
            timeout: seconds.
        """
        return await _impl.run_cdncheck(targets, timeout)

    @mcp.tool()
    async def run_alterx(roots: list[str], pattern: str = "", timeout: int = 60) -> str:
        """Generate subdomain permutations via alterx.

        Args:
            roots: seed subdomains (e.g. ['api.example.com', 'dev.example.com']).
            pattern: optional alterx pattern DSL ('{{word}}-{{number}}.{{root}}').
            timeout: seconds.
        """
        return await _gen.run_alterx(roots, pattern, timeout)

    @mcp.tool()
    async def run_chaos(
        domain: str,
        timeout: int = 60,
    ) -> str:
        """PD Chaos subdomain dataset (requires CHAOS_KEY env var).

        Args:
            domain: target apex (e.g. example.com).
            timeout: seconds.
        """
        return await _gen.run_chaos(domain, timeout)

    @mcp.tool()
    async def run_dnsgen(
        wordlist_path: str,
        max_outputs: int = 5000,
        timeout: int = 120,
    ) -> str:
        """Permute subdomain wordlist via dnsgen.

        Args:
            wordlist_path: path to seed list (one host per line).
            max_outputs: max permutations returned.
            timeout: seconds.
        """
        return await _gen.run_dnsgen(wordlist_path, max_outputs, timeout)

    @mcp.tool()
    async def run_shuffledns(
        wordlist_path: str,
        domain: str = "",
        resolvers_path: str = "",
        mode: str = "bruteforce",
        timeout: int = 600,
    ) -> str:
        """Mass DNS resolve / bruteforce via shuffledns (PD).

        Args:
            wordlist_path: file of subdomains (resolve) or wordlist (bruteforce).
            domain: required for bruteforce mode.
            resolvers_path: path to resolvers list (one IP per line).
            mode: bruteforce | resolve.
            timeout: seconds.
        """
        return await _gen.run_shuffledns(wordlist_path, domain, resolvers_path, mode, timeout)

    @mcp.tool()
    async def run_graphw00f(target: str, timeout: int = 60) -> str:
        """Fingerprint a GraphQL endpoint engine via graphw00f.

        Args:
            target: GraphQL endpoint URL (e.g. https://example.com/graphql).
            timeout: seconds.
        """
        return await _impl.run_graphw00f(target, timeout)


# Re-export only the public helpers the package exposes. _check_tool / _run_cmd
# are deliberately NOT re-exported here: the tool bodies live in _impl / _gen and
# resolve those names against THOSE modules, so patch them at
# recon_pd._impl._check_tool / recon_pd._gen._check_tool — a package-level alias
# would patch silently with no effect.
from ._shared import _not_installed, _parse_jsonl  # noqa: F401,E402
