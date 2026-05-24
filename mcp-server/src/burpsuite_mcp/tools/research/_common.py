"""Back-compat re-export shim — data tables live in dedicated submodules.

`_VECTOR_KB`         -> `_vector_kb.py`
`_METHODOLOGY_LINKS` -> `_methodology_links.py`
"""

from __future__ import annotations

from ._methodology_links import _METHODOLOGY_LINKS
from ._vector_kb import _VECTOR_KB

__all__ = ["_VECTOR_KB", "_METHODOLOGY_LINKS"]
