"""Research backends — shim re-exports for backwards compat.

Old path `burpsuite_mcp.tools.research` still exposes every previously
public/private symbol so existing imports keep working. New code SHOULD
import from the per-backend submodules directly.
"""

from ._common import _METHODOLOGY_LINKS, _VECTOR_KB
from .attackerkb import _attackerkb_search
from .exploitdb import _exploitdb_search
from .github_advisory import _github_advisory_search
from .github_code import _github_code_search
from .osv import _osv_search
from .register import register
from .snyk import _snyk_db_search

__all__ = [
    "_VECTOR_KB",
    "_METHODOLOGY_LINKS",
    "_exploitdb_search",
    "_osv_search",
    "_github_advisory_search",
    "_snyk_db_search",
    "_attackerkb_search",
    "_github_code_search",
    "register",
]
