#!/usr/bin/env python3
"""Prune stale auto-memory entries.

Auto-memory in `~/.claude/projects/<slug>/memory/` accumulates feedback and
project notes that decay in usefulness over time. This script flags entries
older than N days and optionally deletes them.

Default: list-only (dry run). Pass --delete to actually remove.

Usage:
    uv run python scripts/prune_stale_memory.py
    uv run python scripts/prune_stale_memory.py --days 30
    uv run python scripts/prune_stale_memory.py --days 30 --delete
"""

from __future__ import annotations

import argparse
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_SLUG = "-home-tyrus-Github-burpsuite-swiss-knife-mcp"
MEMORY_DIR = Path.home() / ".claude" / "projects" / PROJECT_SLUG / "memory"

# Memory types in order of decay risk (most-likely-stale first).
TYPE_DECAY_DAYS = {
    "project": 30,    # in-progress work decays fastest
    "feedback": 90,   # behavioral guidance lasts longer
    "reference": 180, # external system pointers usually stable
    "user": 365,      # user role rarely changes
}

DATE_RE = re.compile(r"\b(20\d{2})-(\d{2})-(\d{2})\b")


def parse_frontmatter(text: str) -> dict:
    if not text.startswith("---"):
        return {}
    end = text.find("---", 3)
    if end < 0:
        return {}
    out: dict = {}
    for line in text[3:end].splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        out[k.strip()] = v.strip()
    return out


def latest_date_in_text(text: str) -> datetime | None:
    matches = DATE_RE.findall(text)
    if not matches:
        return None
    dates = [datetime(int(y), int(m), int(d), tzinfo=timezone.utc)
             for y, m, d in matches]
    return max(dates)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=0,
                    help="Override default per-type decay window")
    ap.add_argument("--delete", action="store_true",
                    help="Actually remove stale entries (default: list only)")
    args = ap.parse_args()

    if not MEMORY_DIR.exists():
        print(f"No memory at {MEMORY_DIR}")
        return

    now = datetime.now(timezone.utc)
    stale: list[tuple[Path, str, int]] = []

    for f in sorted(MEMORY_DIR.glob("*.md")):
        if f.name == "MEMORY.md":
            continue
        text = f.read_text()
        fm = parse_frontmatter(text)
        mtype = fm.get("type", "unknown")
        decay = args.days or TYPE_DECAY_DAYS.get(mtype, 90)

        # Prefer date inside content; fall back to file mtime
        latest = latest_date_in_text(text)
        if latest is None:
            latest = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)

        age_days = (now - latest).days
        if age_days > decay:
            stale.append((f, mtype, age_days))

    if not stale:
        print("No stale memory entries.")
        return

    print(f"{'STALE' if args.delete else 'WOULD PRUNE'} ({len(stale)} entries):\n")
    for f, mtype, age in stale:
        print(f"  [{mtype:9s}] age={age:>4d}d  {f.name}")

    if args.delete:
        for f, _, _ in stale:
            f.unlink()
        # Best-effort: rebuild MEMORY.md by stripping refs to deleted files
        index = MEMORY_DIR / "MEMORY.md"
        if index.exists():
            keep = []
            removed = {f.name for f, _, _ in stale}
            for line in index.read_text().splitlines():
                if not any(name in line for name in removed):
                    keep.append(line)
            index.write_text("\n".join(keep) + "\n")
        print(f"\nDeleted {len(stale)} entries. MEMORY.md cleaned.")
    else:
        print(f"\nDry run. Pass --delete to remove.")


if __name__ == "__main__":
    main()
