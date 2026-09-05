"""Shared helpers for the notes/ package (facade).

Split by responsibility into _findings_io (paths / file I/O / lock) and
_findings_dedupe (dedup / id-remap / proof formatting). Every public name is
re-exported here so every `notes._helpers` import path is unchanged.
"""

from . import _findings_io as _io
from . import _findings_dedupe as _de

_g = globals()
for _mod in (_io, _de):
    for _name in dir(_mod):
        if not _name.startswith("__"):
            _g[_name] = getattr(_mod, _name)
del _g, _mod, _name
