"""Class-specific deep-dive prompts.

Each entry: deep_dive (open-ended exploration questions), obscure
(vectors operators commonly miss), chain (what the bug enables).

The table is split across topical _vector_kb_*.py slices and re-assembled here.
"""

from __future__ import annotations

from ._vector_kb_injection import _INJECTION
from ._vector_kb_logic import _LOGIC
from ._vector_kb_protocol import _PROTOCOL

_VECTOR_KB: dict[str, dict[str, list[str]]] = {**_INJECTION, **_PROTOCOL, **_LOGIC}
