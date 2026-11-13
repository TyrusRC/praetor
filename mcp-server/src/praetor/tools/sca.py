"""Software-composition analysis wrappers — osv-scanner, trivy, grype.

All three are MIT/Apache OSS scanners. Each falls back to install-hint when
binary absent. SBOM-driven (syft optional upstream).

Also: scan_model_artifacts (pure-stdlib pickle opcode scan, no new deps),
check_binary_hardening (checksec wrap for native-binary hardening flags),
and check_dependency_typosquat (pure-Python name-distance check for
typosquat/slopsquat dependencies).
"""

from __future__ import annotations

import json
import pickletools
import zipfile
from difflib import SequenceMatcher
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _check_tool, _run_cmd


def _hint(tool: str, hint: str) -> str:
    return f"Error: {tool} not installed.\nInstall: {hint}"


# ── Pickle/model-file safety scan (stdlib pickletools, no execution) ──────
# Pickle's RCE surface is GLOBAL (module, name) opcodes that resolve to an
# arbitrary callable, invoked by REDUCE at load time. Disassembling with
# pickletools.genops never calls __reduce__/__setstate__ — it only reads the
# opcode stream, so this is safe to run on an untrusted file.
# Modules with no legitimate reason to appear in a data-only pickle stream —
# flagged on module alone. `builtins`/`__builtin__` is NOT here: it also
# carries harmless, extremely common REDUCE targets (list/dict/set/tuple/...)
# used by ordinary object serialization, so it is name-gated below instead.
_DANGEROUS_MODULES = {
    "os", "nt", "posix", "subprocess", "sys", "socket", "shutil", "pty",
    "runpy", "code", "ctypes", "platform", "importlib", "multiprocessing",
    "webbrowser", "pdb", "antigravity",
}
# Names that are dangerous regardless of which module they resolve through
# (mainly builtins/__builtin__, but matched module-independently so an
# aliased import doesn't slip past).
_DANGEROUS_NAMES = {
    "eval", "exec", "system", "popen", "Popen", "call", "check_call",
    "check_output", "execfile", "compile", "__import__", "getattr",
    "setattr", "open",
}


_STRING_PUSH_OPS = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING",
}


def _scan_pickle_bytes(data: bytes) -> list[str]:
    """Disassemble (not unpickle) a pickle byte stream; return dangerous
    module.name references found, deduped, in appearance order.

    Protocol 0's GLOBAL opcode carries 'module\\nname' directly in `arg`.
    Protocol >=4's STACK_GLOBAL is stack-based instead: the module and name
    are pushed as two preceding string opcodes and STACK_GLOBAL itself
    carries no arg — so this tracks the last two string pushes and resolves
    STACK_GLOBAL from them, which is how every modern (protocol 2+) pickle
    stream — including every default `pickle.dumps()` / `torch.save()`
    output — actually encodes a REDUCE callable.
    """
    hits: list[str] = []
    last_strings: list[str] = []
    try:
        for opcode, arg, _pos in pickletools.genops(data):
            if opcode.name in _STRING_PUSH_OPS:
                last_strings.append(str(arg))
                last_strings = last_strings[-2:]
                continue
            if opcode.name == "GLOBAL" and arg is not None:
                # pickletools' GLOBAL arg reader joins "module name" with a
                # single space (not the on-wire '\n' — genops already
                # decoded that), so split on the first space.
                module, _, name = str(arg).partition(" ")
            elif opcode.name in ("STACK_GLOBAL", "INST", "OBJ") and len(last_strings) == 2:
                module, name = last_strings[0], last_strings[1]
            else:
                continue
            ref = f"{module}.{name}"
            if module in _DANGEROUS_MODULES or name in _DANGEROUS_NAMES:
                if ref not in hits:
                    hits.append(ref)
    except Exception as e:  # malformed/truncated stream — report, don't crash
        hits.append(f"<scan error: {e}>")
    return hits


def _classify_file(path: Path) -> tuple[str, list[bytes]]:
    """Return (kind, [pickle byte blobs to scan]).

    kind: 'pytorch-zip' (new-format .pt/.pth, a zip with data.pkl inside),
    'raw-pickle' (old-format .pt/.pkl/.joblib, a bare pickle stream),
    'safetensors' (header-only JSON, no scan needed — safe by format), or
    'unknown'.
    """
    head = path.read_bytes()[:16]
    if head[:4] == b"PK\x03\x04":
        blobs = []
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.endswith((".pkl", "data.pkl")) or "/data.pkl" in name:
                    blobs.append(zf.read(name))
        return "pytorch-zip", blobs
    if path.suffix == ".safetensors":
        return "safetensors", []
    return "raw-pickle", [path.read_bytes()]


# ── Dependency typosquat / slopsquat check (pure Python, no new deps) ────
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


def _fmt_retire(data) -> str:
    """Format retire.js JSON (v2/v3 list or v4 {data:[...]}) into vuln findings."""
    items = data.get("data", []) if isinstance(data, dict) else data
    if not isinstance(items, list) or not items:
        return "retire.js: no vulnerable client-side libraries found."
    lines: list[str] = []
    total = 0
    for entry in items:
        if not isinstance(entry, dict):
            continue
        fname = entry.get("file", "?")
        for res in entry.get("results", []) or []:
            comp = res.get("component", "?")
            ver = res.get("version", "?")
            for v in res.get("vulnerabilities", []) or []:
                total += 1
                sev = str(v.get("severity") or "?").upper()
                ids = v.get("identifiers", {}) or {}
                cves = ", ".join(ids.get("CVE", []) or [])
                label = cves or ids.get("summary", "") or "advisory"
                lines.append(f"  [{sev}] {comp}@{ver} — {label}  ({fname})")
    if not lines:
        return "retire.js: no vulnerable client-side libraries found."
    return (f"retire.js: {total} vulnerable client-side library finding(s):\n"
            + "\n".join(lines))


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_osv_scanner(path: str, timeout: int = 600) -> str:
        """Scan a path (lockfile / dir / SBOM) against OSV.dev via osv-scanner.

        Args:
            path: lockfile, directory, container image, or SBOM file.
            timeout: seconds.
        """
        if not _check_tool("osv-scanner"):
            return _hint("osv-scanner",
                         "go install github.com/google/osv-scanner/cmd/osv-scanner@v2")
        out, err, rc = await _run_cmd(
            ["osv-scanner", "--format", "json", path],
            timeout=timeout, bypass_proxy=True,
        )
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        vulns: list[dict] = []
        for r in data.get("results", []):
            src = r.get("source", {}).get("path", path)
            for pkg in r.get("packages", []):
                name = pkg.get("package", {}).get("name", "?")
                version = pkg.get("package", {}).get("version", "?")
                for v in pkg.get("vulnerabilities", []):
                    vulns.append({
                        "id": v.get("id", "?"),
                        "summary": (v.get("summary") or "")[:120],
                        "package": f"{name}@{version}",
                        "source": src,
                    })
        lines = [f"osv-scanner: {len(vulns)} vulns in {path}"]
        for v in vulns[:50]:
            lines.append(f"  [{v['id']}] {v['package']} -- {v['summary']}")
        if rc != 0 and not vulns:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_trivy(
        target: str,
        mode: str = "fs",
        severity: str = "HIGH,CRITICAL",
        timeout: int = 600,
    ) -> str:
        """Scan a target via trivy (Aqua).

        Args:
            target: path | image | git-url | k8s-cluster.
            mode: fs | image | repo | k8s | sbom | config (IaC).
            severity: comma list (LOW,MEDIUM,HIGH,CRITICAL,UNKNOWN).
            timeout: seconds.
        """
        if not _check_tool("trivy"):
            return _hint("trivy",
                         "brew install aquasecurity/trivy/trivy  |  "
                         "https://github.com/aquasecurity/trivy/releases")
        if mode not in {"fs", "image", "repo", "k8s", "sbom", "config"}:
            return f"Error: mode must be fs|image|repo|k8s|sbom|config (got {mode!r})."
        cmd = ["trivy", mode, "--severity", severity, "--format", "json", "--quiet", target]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        rows: list[dict] = []
        for r in data.get("Results", []) or []:
            for v in r.get("Vulnerabilities", []) or []:
                rows.append({
                    "id": v.get("VulnerabilityID", "?"),
                    "sev": v.get("Severity", "?"),
                    "pkg": f"{v.get('PkgName','?')}@{v.get('InstalledVersion','?')}",
                    "title": (v.get("Title") or v.get("Description") or "")[:120],
                })
        lines = [f"trivy [{mode}]: {len(rows)} findings in {target} (severity={severity})"]
        for r in rows[:50]:
            lines.append(f"  [{r['sev']:<8}] {r['id']}  {r['pkg']} -- {r['title']}")
        if rc != 0 and not rows:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_grype(target: str, timeout: int = 600) -> str:
        """Scan an image / dir / SBOM via grype (Anchore).

        Args:
            target: image:tag | dir:./path | sbom:./bom.json.
            timeout: seconds.
        """
        if not _check_tool("grype"):
            return _hint("grype",
                         "brew install grype  |  https://github.com/anchore/grype#installation")
        out, err, rc = await _run_cmd(
            ["grype", target, "-o", "json", "-q"],
            timeout=timeout, bypass_proxy=True,
        )
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        rows: list[dict] = []
        for m in data.get("matches", []) or []:
            v = m.get("vulnerability", {})
            a = m.get("artifact", {})
            rows.append({
                "id": v.get("id", "?"),
                "sev": v.get("severity", "?"),
                "pkg": f"{a.get('name','?')}@{a.get('version','?')}",
            })
        lines = [f"grype: {len(rows)} findings in {target}"]
        for r in rows[:50]:
            lines.append(f"  [{r['sev']:<8}] {r['id']}  {r['pkg']}")
        if rc != 0 and not rows:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_syft(
        target: str,
        output_format: str = "cyclonedx-json",
        timeout: int = 600,
    ) -> str:
        """Generate SBOM via syft (Anchore).

        Args:
            target: image:tag | dir:./path | file:./binary.
            output_format: cyclonedx-json | spdx-json | syft-json | table.
            timeout: seconds.
        """
        if not _check_tool("syft"):
            return _hint("syft",
                         "brew install syft  |  https://github.com/anchore/syft#installation")
        out, err, rc = await _run_cmd(
            ["syft", target, "-o", output_format, "-q"],
            timeout=timeout, bypass_proxy=True,
        )
        if output_format.endswith("json") and out.strip():
            try:
                data = json.loads(out)
                comps = data.get("components") or data.get("artifacts") or []
                lines = [f"syft: {len(comps)} components in {target} ({output_format})"]
                for c in comps[:40]:
                    name = c.get("name") or "?"
                    ver = c.get("version") or "?"
                    typ = c.get("type") or "?"
                    lines.append(f"  {typ:<12} {name}@{ver}")
                lines.append("")
                lines.append("Full SBOM in stdout above; pipe to file with --output-file.")
                if rc != 0 and not comps:
                    lines.append(f"[rc={rc}] {err[:200]}")
                return "\n".join(lines)
            except json.JSONDecodeError:
                pass
        tail = "\n".join(out.splitlines()[:60])
        lines = [f"syft [{output_format}] rc={rc}", tail]
        if rc != 0:
            lines.append(f"[stderr] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_cosign_verify(
        image: str,
        public_key: str = "",
        certificate_identity: str = "",
        certificate_issuer: str = "",
        timeout: int = 120,
    ) -> str:
        """Verify a container signature via cosign (Sigstore).

        Args:
            image: image:tag or image@sha256:...
            public_key: path to public key (--key); empty -> keyless via Fulcio.
            certificate_identity: required for keyless mode (Fulcio cert SAN).
            certificate_issuer: required for keyless mode (Fulcio OIDC issuer).
            timeout: seconds.
        """
        if not _check_tool("cosign"):
            return _hint("cosign",
                         "brew install cosign  |  https://github.com/sigstore/cosign/releases")
        cmd = ["cosign", "verify", image]
        if public_key:
            cmd += ["--key", public_key]
        else:
            if not (certificate_identity and certificate_issuer):
                return ("Error: keyless mode needs --certificate-identity and "
                        "--certificate-issuer. Provide both or supply public_key.")
            cmd += ["--certificate-identity", certificate_identity,
                    "--certificate-oidc-issuer", certificate_issuer]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        status = "VERIFIED" if rc == 0 else "FAILED"
        lines = [f"cosign verify [{image}]: {status}"]
        if rc == 0:
            lines.append(out.strip()[:600])
        else:
            lines.append(f"[rc={rc}] {(err or out)[:600]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_retirejs(path: str, timeout: int = 300) -> str:
        """Client-side SCA — scan JS for known-vulnerable library versions (retire.js).

        PTK-style client-library SCA: maps each detected front-end library@version
        to its known CVEs/advisories. Point it at JavaScript pulled FROM the target
        — e.g. saved by fetch_resource / fetch_page_resources under
        .burp-intel/<domain>/material, or a checked-out front-end bundle. retire.js
        exits non-zero when it finds vulns — that is a HIT, not an error.

        Args:
            path: directory or .js file to scan.
            timeout: seconds.
        """
        if not _check_tool("retire"):
            return _hint("retire", "npm install -g retire   (or run: npx retire)")
        out, err, rc = await _run_cmd(
            ["retire", "--path", path, "--outputformat", "json"],
            timeout=timeout, bypass_proxy=True,
        )
        if not out.strip() and err.strip() and "vulnerab" not in err.lower():
            return f"retire.js error [rc={rc}]: {err[:600]}"
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            return f"retire.js ran but output was not JSON:\n{(out or err)[:800]}"
        return _fmt_retire(data)

    @mcp.tool()
    async def scan_model_artifacts(path: str) -> str:
        """Scan a model file for unsafe pickle deserialization (no execution).

        Closes LLM-SUPPLY-001/002 (Critical) — loading a pickled model can run
        arbitrary code via `__reduce__`; no model-file scanner existed in
        Praetor. Disassembles the pickle opcode stream with stdlib
        `pickletools` (never calls `pickle.load`, so the file is never
        executed) and flags GLOBAL/STACK_GLOBAL references into
        exec-capable modules (os, subprocess, sys, builtins, ...).

        Args:
            path: local file — .pt/.pth/.bin/.pkl/.joblib/.ckpt (PyTorch zip
                or raw pickle) or .safetensors (format has no exec surface;
                reported safe without a scan).

        A hit here is a real finding (Critical, RCE-on-load) — not a lead to
        escalate. Use `confirm_rce`-style evidence only if you then prove the
        file is actually served/loaded by the target; the scan itself is
        conclusive about the file's content.
        """
        p = Path(path)
        if not p.is_file():
            return f"Error: not a file: {path}"
        try:
            kind, blobs = _classify_file(p)
        except (OSError, zipfile.BadZipFile) as e:
            return f"Error reading {path}: {e}"

        if kind == "safetensors":
            # Header is JSON-only by spec (tensor names/shapes/dtypes/offsets);
            # there is no opcode stream and so no RCE-on-load surface. Confirm
            # the header actually parses as JSON — a mislabeled pickle with a
            # .safetensors extension would fail this and should be re-scanned
            # under its real format.
            try:
                n = int.from_bytes(p.read_bytes()[:8], "little")
                json.loads(p.read_bytes()[8:8 + n])
                return f"scan_model_artifacts {path} [safetensors]: SAFE — header is valid JSON, no exec surface."
            except Exception as e:
                return (f"scan_model_artifacts {path} [safetensors]: HEADER DID NOT PARSE "
                        f"as JSON ({e}) — this file may be mislabeled; re-check its real format.")

        if not blobs:
            return f"scan_model_artifacts {path} [{kind}]: no pickle stream found to scan."

        all_hits: list[str] = []
        for blob in blobs:
            all_hits.extend(_scan_pickle_bytes(blob))
        if not all_hits:
            return f"scan_model_artifacts {path} [{kind}]: no dangerous GLOBAL references found."
        lines = [f"scan_model_artifacts {path} [{kind}]: {len(all_hits)} dangerous reference(s) — UNSAFE DESERIALIZATION"]
        for h in all_hits[:30]:
            lines.append(f"  GLOBAL {h}")
        lines.append("\nImpact: loading this file (torch.load / pickle.load) can execute "
                      "arbitrary code via __reduce__. Severity: Critical (RCE on load).")
        return "\n".join(lines)

    @mcp.tool()
    async def check_binary_hardening(path: str, timeout: int = 30) -> str:
        """Check a native binary's compile-time hardening flags (checksec).

        Closes MOB-CODE-005 / DESK-CODE-004 / IOT native-binary-class tests —
        wraps the already-installed `checksec` tool (no new dependency).

        Args:
            path: local path to the binary (ELF or PE).
            timeout: seconds.

        Reports NX, PIE, RELRO (full/partial/none), stack canary, Fortify —
        the exact fields those checklist tests ask for. Does not assert
        pass/fail (Rule 13b): a missing mitigation is Low-Medium severity on
        its own and matters most as a prerequisite for another finding
        (chain_with), not as a standalone report.
        """
        if not Path(path).is_file():
            return f"Error: not a file: {path}"
        if not _check_tool("checksec"):
            return _hint("checksec",
                         "apt install checksec  |  https://github.com/slimm609/checksec.sh")
        # Two incompatible tools share the name `checksec` in the wild:
        # classic checksec.sh (--file=<path> --format json) and pwntools'
        # `pwn checksec` (--file <path>, plain-text only, no --format flag —
        # passing it errors out). Try the universal `--file <path>` form,
        # then parse whichever shape comes back: JSON if it is, else the
        # plain-text "Key:    Value" lines both tools print.
        out, err, rc = await _run_cmd(
            ["checksec", "--file", path],
            timeout=timeout, bypass_proxy=True,
        )
        combined = out or err
        try:
            data = json.loads(combined)
            row = next(iter(data.values()), {}) if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            row = {}
            import re
            for line in combined.splitlines():
                m = re.match(r"^\s*([A-Za-z][A-Za-z \-]{1,20}):\s+(.+?)\s*$", line)
                if m:
                    row[m.group(1).strip()] = m.group(2).strip()
        if not row:
            tail = "\n".join(combined.splitlines()[:20])
            return f"checksec [{path}]: no parseable result (rc={rc}):\n{tail}"
        lines = [f"checksec {path}:"]
        for k, v in row.items():
            lines.append(f"  {k}: {v}")
        return "\n".join(lines)

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
            import re
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
