"""Tech-stack → known-vulnerability matching (offline knowledge base)."""

import json
import re
from functools import lru_cache
from pathlib import Path


KNOWLEDGE_DIR = Path(__file__).parent.parent.parent / "knowledge"


@lru_cache(maxsize=1)
def _load_tech_vulns() -> dict:
    """Load tech-specific vulnerability data from knowledge base."""
    path = KNOWLEDGE_DIR / "tech_vulns.json"
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


_VERSION_RE = re.compile(r"[\d]+(?:\.[\d]+)*")


def _extract_version(tech_string: str) -> str:
    """Extract version number from tech string like 'Apache/2.4.49' or 'PHP 8.1.2'."""
    m = _VERSION_RE.search(tech_string)
    return m.group(0) if m else ""


def _version_tuple(v: str) -> tuple:
    """Convert version string to tuple of ints for correct numeric comparison."""
    return tuple(int(x) for x in v.split(".") if x.isdigit())


def _version_in_range(version: str, range_key: str) -> bool:
    """Check if version matches a range key like '2.4.49', '8.5.0-8.5.80', or 'any'.

    Exact-segment match: `range_key='8.1'` matches `version='8.1'`, `'8.1.3'`,
    and `'8.1.99'`, but NOT `'8.10'` or `'8.100'`. Prior implementation used a
    bidirectional prefix-tuple match which treated `8.1` and `8.10` as equal.
    """
    if range_key == "any":
        return True
    if not version:
        return False
    try:
        ver = _version_tuple(version)
        if "-" in range_key:
            low, high = range_key.split("-", 1)
            return _version_tuple(low) <= ver <= _version_tuple(high)
        range_ver = _version_tuple(range_key)
        # Prefix match only — range_key segments must exactly equal the
        # corresponding prefix of `version`. Unequal segment count alone is
        # fine (8.1 matches 8.1.3) but per-segment numbers must be equal.
        if len(ver) < len(range_ver):
            return False
        return ver[:len(range_ver)] == range_ver
    except (ValueError, TypeError):
        # Fall back to string comparison if version format is unexpected.
        # Avoid the bidirectional prefix trap here too: only check the
        # documented range prefix matches the observed version.
        if "-" in range_key:
            low, high = range_key.split("-", 1)
            return low <= version <= high
        return version.startswith(range_key + ".") or version == range_key


def _match_tech_to_vulns(tech_items: list[str], tech_vulns: dict) -> list[dict]:
    """Match detected tech stack items against known vulnerability patterns."""
    matches = []
    technologies = tech_vulns.get("technologies", {})

    for tech in tech_items:
        tech_lower = tech.lower().strip()
        version = _extract_version(tech)

        for tech_name, tech_data in technologies.items():
            if tech_name.lower() not in tech_lower:
                continue

            # Match version-specific CVEs
            for ver_range, ver_data in tech_data.get("versions", {}).items():
                if _version_in_range(version, ver_range):
                    for cve in ver_data.get("cves", []):
                        tests = ver_data.get("tests", [])
                        matches.append({
                            "tech": tech,
                            "category": tech_name,
                            "vulnerability": cve,
                            "description": "; ".join(tests),
                            "severity": ver_data.get("severity", "MEDIUM").upper(),
                            "cve": cve,
                            "test_with": "; ".join(tests),
                            "search_query": f"{tech_name} {ver_range}",
                        })
                    # Also include tests without CVEs (like default cred checks)
                    if not ver_data.get("cves"):
                        tests = ver_data.get("tests", [])
                        for test in tests:
                            matches.append({
                                "tech": tech,
                                "category": tech_name,
                                "vulnerability": test,
                                "description": test,
                                "severity": ver_data.get("severity", "MEDIUM").upper(),
                                "cve": "",
                                "test_with": test,
                                "search_query": f"{tech_name} {ver_range}",
                            })

            # Include common issues (version-independent)
            for issue in tech_data.get("common_issues", []):
                matches.append({
                    "tech": tech,
                    "category": tech_name,
                    "vulnerability": issue,
                    "description": issue,
                    "severity": "MEDIUM",
                    "cve": "",
                    "test_with": "",
                    "search_query": f"{tech_name} {issue.split()[0]}",
                })

            # Include default paths as low-severity checks
            for path in tech_data.get("default_paths", []):
                matches.append({
                    "tech": tech,
                    "category": tech_name,
                    "vulnerability": f"Check path: {path}",
                    "description": f"Default/sensitive path for {tech_name}",
                    "severity": "LOW",
                    "cve": "",
                    "test_with": f"curl_request(url='https://TARGET{path}')",
                    "search_query": "",
                })

    return matches
