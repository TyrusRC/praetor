"""CVE matching + lookups — shim re-exports for backwards compat.

Old path `burpsuite_mcp.tools.cve` still exposes every previously
public/private symbol so existing imports keep working. New code SHOULD
import from the per-backend submodules directly.
"""

from .match import (
    KNOWLEDGE_DIR,
    _extract_version,
    _load_tech_vulns,
    _match_tech_to_vulns,
    _VERSION_RE,
    _version_in_range,
    _version_tuple,
)
from .nvd import _NVD_API_URL, _nvd_lookup
from .register import register
from .shodan import (
    _SHODAN_CPE_URL,
    _SHODAN_CPES_URL,
    _SHODAN_CVE_URL,
    _SHODAN_CVES_URL,
    _shodan_cpe_dict,
    _shodan_cpe_lookup,
    _shodan_cve_lookup,
    _shodan_cves_query,
)
from ._common import _BROWSER_UA

__all__ = [
    "_BROWSER_UA",
    "KNOWLEDGE_DIR",
    "_VERSION_RE",
    "_load_tech_vulns",
    "_extract_version",
    "_version_tuple",
    "_version_in_range",
    "_match_tech_to_vulns",
    "_SHODAN_CVE_URL",
    "_SHODAN_CVES_URL",
    "_SHODAN_CPES_URL",
    "_SHODAN_CPE_URL",
    "_shodan_cve_lookup",
    "_shodan_cves_query",
    "_shodan_cpe_lookup",
    "_shodan_cpe_dict",
    "_NVD_API_URL",
    "_nvd_lookup",
    "register",
]
