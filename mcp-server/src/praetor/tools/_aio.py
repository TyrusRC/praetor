"""Async file I/O helpers for MCP tool functions.

Wraps the blocking Path.read_text / json.loads / json.dump / Path.write_text
operations in asyncio.to_thread so async tool handlers don't stall the MCP
event loop on disk I/O. Used in the heaviest paths (findings.json, coverage.json,
endpoints.json) where files routinely exceed 100 KB.
"""
import asyncio
import json
import os
import tempfile
from pathlib import Path
from typing import Any


async def read_json(path: Path) -> Any:
    """Read and parse a JSON file without blocking the event loop."""
    def _read() -> Any:
        return json.loads(path.read_text(encoding="utf-8"))
    return await asyncio.to_thread(_read)


async def read_json_safe(path: Path, default: Any = None) -> Any:
    """Read JSON, returning *default* on missing file or parse error."""
    def _read() -> Any:
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default
    return await asyncio.to_thread(_read)


async def write_json_atomic(path: Path, data: Any) -> None:
    """Atomically write JSON without blocking the event loop.

    Mirrors _internals._atomic_write_json but runs the entire
    temp-file-then-replace dance inside a worker thread.
    """
    def _write() -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            os.replace(tmp, path)
        except Exception:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
    await asyncio.to_thread(_write)


async def read_text(path: Path, encoding: str = "utf-8") -> str:
    """Read a text file without blocking the event loop."""
    return await asyncio.to_thread(path.read_text, encoding)


async def write_text(path: Path, content: str, encoding: str = "utf-8") -> None:
    """Write a text file without blocking the event loop."""
    def _write() -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding=encoding)
    await asyncio.to_thread(_write)
