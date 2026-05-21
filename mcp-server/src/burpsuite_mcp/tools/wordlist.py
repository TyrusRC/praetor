"""Smart wordlist generator: tech-filtered SecLists slices + recon-derived priors."""
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.recon.scanning import detect_seclists

# tech-stack token (lower-cased) -> list of SecLists slice paths under <root>/Discovery/Web-Content/
_TECH_TO_SLICES: dict[str, list[str]] = {
    "php": ["PHP.fuzz.txt"],
    "wordpress": ["CMS/wordpress.fuzz.txt", "CMS/wp-plugins.fuzz.txt"],
    "java": ["Java.fuzz.txt"],
    "spring": ["Java.fuzz.txt", "spring-boot.txt"],
    "tomcat": ["Java.fuzz.txt", "tomcat.txt"],
    "node": ["nodejs.txt"],
    "nodejs": ["nodejs.txt"],
    "express": ["nodejs.txt"],
    "iis": ["IIS.fuzz.txt"],
    "asp.net": ["IIS.fuzz.txt", "ASP-aspx.txt"],
    "django": ["django.txt"],
    "rails": ["rails.txt"],
    "flask": ["python.txt"],
}

_GENERIC_BASE = "common.txt"
_GENERIC_MEDIUM = "directory-list-2.3-small.txt"
_GENERIC_DEEP = "directory-list-2.3-medium.txt"

_TIER_LIMITS = {
    "shallow": {"tech": 500, "generic": 200, "recon": 200},
    "medium":  {"tech": 2000, "generic": 5000, "recon": 500},
    "deep":    {"tech": 10000, "generic": 50000, "recon": 1000},
}


def _cwd() -> Path:
    return Path.cwd()


def _load_lines(p: Path, limit: int) -> list[str]:
    if not p.exists():
        return []
    out: list[str] = []
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
        if len(out) >= limit:
            break
    return out


def _recon_segments(domain_intel: Path, limit: int) -> list[str]:
    """Extract path segments from endpoints.json + sitemap.json + wayback URLs."""
    segs: list[str] = []
    seen: set[str] = set()

    def _add_path(url: str):
        try:
            from urllib.parse import urlparse
            path = urlparse(url).path
        except Exception:
            return
        for raw in path.split("/"):
            raw = raw.strip()
            if not raw or raw in seen:
                continue
            seen.add(raw)
            segs.append(raw)
            if len(segs) >= limit:
                return

    endpoints_f = domain_intel / "endpoints.json"
    if endpoints_f.exists():
        try:
            data = json.loads(endpoints_f.read_text())
            for e in data.get("endpoints", []):
                if isinstance(e, str):
                    _add_path(e)
                elif isinstance(e, dict) and "url" in e:
                    _add_path(e["url"])
                if len(segs) >= limit:
                    break
        except (json.JSONDecodeError, OSError):
            pass

    return segs[:limit]


def _tech_slices(seclists_root: Path, tech_list: list[str]) -> list[Path]:
    """Map detected tech tokens to SecLists slice paths."""
    base = seclists_root / "Discovery" / "Web-Content"
    out: list[Path] = []
    seen: set[Path] = set()
    for tech in tech_list:
        key = tech.strip().lower()
        for slice_name in _TECH_TO_SLICES.get(key, []):
            p = base / slice_name
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


def register(mcp: FastMCP):

    @mcp.tool()
    async def generate_smart_wordlist(
        domain: str,
        tier: str = "medium",
        extensions: list[str] | None = None,
    ) -> dict:
        """Build a tech-aware fuzz wordlist for a target.

        Args:
            domain: Target domain (must have .burp-intel/<domain>/ populated)
            tier: 'shallow' (~500), 'medium' (~5k), 'deep' (~50k)
            extensions: Optional file extensions to append to every entry (e.g. ['.php','.bak'])

        Returns:
            {path, total, breakdown: {recon, tech, generic}} or {error}
        """
        if tier not in _TIER_LIMITS:
            return {"error": f"tier must be one of {sorted(_TIER_LIMITS)}, got {tier!r}"}

        seclists = detect_seclists()
        if not seclists:
            return {"error": "SecLists not found. Install: git clone https://github.com/danielmiessler/SecLists /opt/SecLists && export SECLISTS_PATH=/opt/SecLists"}

        seclists_root = Path(seclists)
        intel = _cwd() / ".burp-intel" / domain
        if not intel.exists():
            return {"error": f"No intel for domain {domain}. Run discover_attack_surface or full_recon first."}

        limits = _TIER_LIMITS[tier]
        out_dir = intel / "_wordlists"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"fuzz-{tier}.txt"

        # Load sources
        fingerprint = intel / "fingerprint.json"
        tech_list: list[str] = []
        if fingerprint.exists():
            try:
                fp = json.loads(fingerprint.read_text())
                tech_list = fp.get("tech_stack") or fp.get("tech") or []
            except (json.JSONDecodeError, OSError):
                pass

        recon = _recon_segments(intel, limits["recon"])

        tech_lines: list[str] = []
        for slice_path in _tech_slices(seclists_root, tech_list):
            tech_lines.extend(_load_lines(slice_path, limits["tech"] - len(tech_lines)))
            if len(tech_lines) >= limits["tech"]:
                break

        generic_files = [seclists_root / "Discovery" / "Web-Content" / _GENERIC_BASE]
        if tier in ("medium", "deep"):
            generic_files.append(seclists_root / "Discovery" / "Web-Content" / _GENERIC_MEDIUM)
        if tier == "deep":
            generic_files.append(seclists_root / "Discovery" / "Web-Content" / _GENERIC_DEEP)

        generic_lines: list[str] = []
        for gf in generic_files:
            generic_lines.extend(_load_lines(gf, limits["generic"] - len(generic_lines)))
            if len(generic_lines) >= limits["generic"]:
                break

        # Dedupe, order: recon -> tech -> generic
        seen: set[str] = set()
        ordered: list[str] = []
        recon_n = tech_n = generic_n = 0
        for src, bucket in (("recon", recon), ("tech", tech_lines), ("generic", generic_lines)):
            for entry in bucket:
                if entry in seen:
                    continue
                seen.add(entry)
                ordered.append(entry)
                if src == "recon":
                    recon_n += 1
                elif src == "tech":
                    tech_n += 1
                else:
                    generic_n += 1

        # Extension permutations
        if extensions:
            permuted: list[str] = []
            for entry in ordered:
                permuted.append(entry)
                for ext in extensions:
                    e = ext if ext.startswith(".") else f".{ext}"
                    permuted.append(entry + e)
            ordered = permuted

        out_path.write_text("\n".join(ordered) + "\n")

        return {
            "path": str(out_path),
            "total": len(ordered),
            "breakdown": {"recon": recon_n, "tech": tech_n, "generic": generic_n},
            "tier": tier,
            "tech_detected": tech_list,
        }
