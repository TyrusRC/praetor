"""Dependency typosquat / slopsquat check (pure Python, no new deps)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from mcp.server.fastmcp import FastMCP


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance, O(len(a)*len(b)), fine for package-name lengths."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


# Small, deliberately short reference lists — the 60-80 most-depended-on
# packages per ecosystem (not a full registry mirror). A name within
# max_distance of one of these AND not an exact match is the signal: real
# typosquats target exactly this high-traffic tail (e.g. 'reqeusts',
# 'python3-dateutil', 'colourama').
_TOP_NPM = {
    "react", "react-dom", "lodash", "express", "axios", "chalk", "commander",
    "moment", "request", "async", "underscore", "jquery", "vue", "webpack",
    "babel-core", "eslint", "typescript", "next", "redux", "classnames",
    "uuid", "yargs", "debug", "glob", "minimist", "semver", "mkdirp",
    "rimraf", "colors", "dotenv", "cors", "body-parser", "mongoose",
    "socket.io", "jsonwebtoken", "bcrypt", "nodemon", "pm2", "prettier",
    "jest", "mocha", "chai", "sinon", "winston", "morgan", "helmet",
    "passport", "multer", "sharp", "node-fetch", "formik", "styled-components",
    "tailwindcss", "vite", "rollup", "esbuild", "zod", "date-fns", "rxjs",
}
_TOP_PYPI = {
    "requests", "numpy", "pandas", "flask", "django", "boto3", "urllib3",
    "setuptools", "pip", "wheel", "pyyaml", "cryptography", "certifi",
    "idna", "charset-normalizer", "click", "jinja2", "six", "python-dateutil",
    "pytz", "attrs", "packaging", "typing-extensions", "colorama", "pytest",
    "sqlalchemy", "pillow", "scipy", "matplotlib", "scikit-learn", "torch",
    "tensorflow", "fastapi", "uvicorn", "pydantic", "aiohttp", "httpx",
    "beautifulsoup4", "lxml", "selenium", "paramiko", "redis", "celery",
    "gunicorn", "psycopg2", "pymysql", "pyjwt", "bcrypt", "cffi", "protobuf",
    "grpcio", "markdown", "pygments", "rich", "tqdm", "loguru",
}


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def check_dependency_typosquat(
        manifest_path: str,
        ecosystem: str = "npm",
        max_distance: int = 2,
    ) -> str:
        """Flag dependency names close to a popular package but not exact —
        typosquat / slopsquat candidates CVE scanners miss by design.

        Closes CICD-DEP-003/007-class gaps — osv-scanner/trivy/grype match
        known-vulnerable *exact* package names; a typosquat is a *new*,
        unlisted name deliberately close to a real one, so no CVE-driven
        scanner flags it.

        Args:
            manifest_path: package.json / requirements.txt / Pipfile.lock-
                style file — one dependency name per recognizable line.
            ecosystem: 'npm' or 'pypi' (selects the reference top-package list).
            max_distance: flag names within this edit distance (not equal)
                of a popular package name (default 2).
        """
        p = Path(manifest_path)
        if not p.is_file():
            return f"Error: not a file: {manifest_path}"
        text = p.read_text(encoding="utf-8", errors="replace")

        names: set[str] = set()
        if p.suffix == ".json":
            try:
                data = json.loads(text)
                for key in ("dependencies", "devDependencies", "peerDependencies"):
                    names.update((data.get(key) or {}).keys())
            except json.JSONDecodeError:
                pass
        else:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "//")):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-@/]+)", line)
                if m:
                    names.add(m.group(1).lower())

        ref = _TOP_NPM if ecosystem == "npm" else _TOP_PYPI
        hits: list[str] = []
        for name in sorted(names):
            if name in ref:
                continue
            for popular in ref:
                if abs(len(name) - len(popular)) > max_distance:
                    continue
                dist = _edit_distance(name, popular)
                if 0 < dist <= max_distance:
                    hits.append(f"{name}  (distance {dist} from {popular!r})")
                    break
        if not hits:
            return (f"check_dependency_typosquat {manifest_path} [{ecosystem}]: "
                     f"{len(names)} dependencies checked, 0 typosquat candidates "
                     f"against the {len(ref)}-package reference list.")
        lines = [f"check_dependency_typosquat {manifest_path} [{ecosystem}]: "
                 f"{len(hits)} candidate(s) of {len(names)} dependencies checked"]
        for h in hits:
            lines.append(f"  {h}")
        lines.append("\nA candidate here is a LEAD, not a finding: verify the package is "
                      "actually unofficial/malicious before reporting (Rule 13b).")
        return "\n".join(lines)
