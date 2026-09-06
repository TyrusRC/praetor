"""ATT&CK/WSTG/CWE/OWASP framework lookup table (data only).

Consumed by _framework_map/__init__.py — import framework_tags/attack_tag_list
from praetor.tools._framework_map, not from here. The table itself is split
across topical _data_*.py slices and re-assembled below.
"""

from __future__ import annotations

from typing import Any

from ._data_aliases import _ALIASES, _STRIP_SUFFIXES
from ._data_authz import _AUTHZ
from ._data_injection import _INJECTION
from ._data_misc import _MISC
from ._row_builder import _DEFAULT_ROW

__all__ = ["FRAMEWORK_MAP", "_ALIASES", "_DEFAULT_ROW", "_STRIP_SUFFIXES"]

# The lookup table. ~40 core classes, re-assembled from topical slices.
FRAMEWORK_MAP: dict[str, dict[str, Any]] = {**_INJECTION, **_AUTHZ, **_MISC}
