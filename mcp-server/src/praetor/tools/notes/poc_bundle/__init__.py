"""poc_bundle — export_poc_bundle / export_proof_capsule (impl in _impl.py)."""

from mcp.server.fastmcp import FastMCP

from praetor import client

from .._proxy_entry import _normalize_entry
from ._impl import (
    _CAPSULE_SCHEMA_VERSION,
    _curl_for_request,
    _oracle_spec,
    _raw_request,
    _raw_response,
    _readme,
    _verify_py,
)


def register(mcp: FastMCP):

    @mcp.tool()
    async def export_poc_bundle(
        domain: str,
        finding_id: str,
        output_dir: str = "",
    ) -> dict:
        """Build a reproducible PoC bundle (.tar.gz) for a saved finding.

        Bundle includes raw request + response, repro.sh, verify.py, README,
        and the finding.json record. Drops to
        `.burp-intel/<domain>/artifacts/poc/poc-<finding_id>.tar.gz` unless output_dir given.

        Args:
            domain: target domain (used for .burp-intel path resolution)
            finding_id: saved-finding ID
            output_dir: optional output directory (default .burp-intel/<domain>/artifacts/poc/)
        """
        path = _safe_findings_path(domain)
        if not path.exists():
            return {"error": f"no findings.json at {path}", "finding_id": finding_id}

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            return {"error": f"failed to read findings.json: {exc}"}
        items = data if isinstance(data, list) else data.get("findings", [])
        target = next(
            (f for f in items if (f.get("id") or f.get("finding_id")) == finding_id),
            None,
        )
        if not target:
            return {"error": f"finding {finding_id!r} not found in {path}"}

        evidence = target.get("evidence") or {}
        idx = evidence.get("logger_index") if isinstance(evidence, dict) else None
        if idx is None and isinstance(evidence, dict):
            idx = evidence.get("proxy_history_index")
        if idx is None or int(idx) < 0:
            return {"error": "no logger_index / proxy_history_index in evidence"}

        detail = await client.get(f"/api/proxy/history/{int(idx)}", params={"include_body": "true"})
        if "error" in detail:
            return {"error": f"fetch proxy entry {idx}: {detail['error']}"}
        req = _normalize_entry(detail)
        resp = req.get("response") or {}

        if output_dir:
            out_root = Path(output_dir)
        else:
            new_root = _intel_dir() / _sanitized(domain) / "artifacts" / "poc"
            legacy = _intel_dir() / _sanitized(domain) / "_poc"
            out_root = legacy if (legacy.exists() and not new_root.exists()) else new_root
        out_root.mkdir(parents=True, exist_ok=True)
        tar_path = out_root / f"poc-{finding_id}.tar.gz"

        readme = _readme(target, req)
        verify = _verify_py(target, req)
        repro = "#!/usr/bin/env bash\nset -eo pipefail\n" \
                'export HTTPS_PROXY="${HTTPS_PROXY:-http://127.0.0.1:8080}"\n' \
                'export HTTP_PROXY="${HTTP_PROXY:-http://127.0.0.1:8080}"\n\n' \
                + _curl_for_request(req) + "\n"
        finding_blob = json.dumps(target, indent=2, default=str)
        req_bytes = _raw_request(req)
        resp_bytes = _raw_response(resp)

        prefix = f"poc-{finding_id}"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            def add(name: str, content: bytes, mode: int = 0o644):
                info = tarfile.TarInfo(name=f"{prefix}/{name}")
                info.size = len(content)
                info.mode = mode
                info.mtime = int(time.time())
                tar.addfile(info, io.BytesIO(content))

            add("README.md", readme.encode("utf-8"))
            add("request.http", req_bytes)
            add("response.http", resp_bytes)
            add("repro.sh", repro.encode("utf-8"), mode=0o755)
            add("verify.py", verify.encode("utf-8"), mode=0o755)
            add("finding.json", finding_blob.encode("utf-8"))

        tar_path.write_bytes(buf.getvalue())
        return {
            "ok": True,
            "finding_id": finding_id,
            "bundle_path": str(tar_path),
            "size_bytes": tar_path.stat().st_size,
            "files": ["README.md", "request.http", "response.http", "repro.sh", "verify.py", "finding.json"],
        }

    @mcp.tool()
    async def export_proof_capsule(
        finding_id: str,
        domain: str,
        output_dir: str = "",
    ) -> dict:
        """Emit a self-contained, one-command-replayable proof capsule for a
        single confirmed finding.

        Unlike export_poc_bundle (a .tar.gz for triager handoff), the capsule is
        an unpacked directory carrying the confirming request/response, the
        machine-checkable oracle (what makes it a true positive), and a replay
        script that re-fires the request and exits 0 only if the oracle still
        holds. This is EVIDENCE packaging, not a benchmark.

        Layout: `.burp-intel/<domain>/artifacts/poc/<finding_id>/capsule/`
            manifest.json   — finding id, class, endpoint, oracle spec, schema version
            oracle.json     — the standalone oracle spec (also embedded in manifest)
            request.http    — confirming request bytes (CRLF normalised)
            response.http   — confirming response bytes (first 64 KB)
            replay.py       — re-fire + oracle assertion (exit 0 = still reproduces)
            repro.sh        — curl-through-Burp replay (reuses generate_repro_script)
            finding.json    — full saved-finding record

        Replay in one command:  `python replay.py`  (exit 0 = confirmed).

        Args:
            finding_id: saved-finding ID
            domain: target domain (used for .burp-intel path resolution)
            output_dir: optional override for the capsule directory root

        Returns a clear error if the finding or its evidence index is unresolvable.
        """
        path = _safe_findings_path(domain)
        if not path.exists():
            return {"error": f"no findings.json at {path}", "finding_id": finding_id}

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            return {"error": f"failed to read findings.json: {exc}"}
        items = data if isinstance(data, list) else data.get("findings", [])
        target = next(
            (f for f in items if (f.get("id") or f.get("finding_id")) == finding_id),
            None,
        )
        if not target:
            return {"error": f"finding {finding_id!r} not found in {path}"}

        evidence = target.get("evidence") or {}
        idx = evidence.get("logger_index") if isinstance(evidence, dict) else None
        if idx is None and isinstance(evidence, dict):
            idx = evidence.get("proxy_history_index")
        if idx is None or int(idx) < 0:
            return {
                "error": (
                    f"finding {finding_id!r} has no logger_index / proxy_history_index "
                    "in evidence — cannot resolve the confirming request"
                )
            }

        detail = await client.get(f"/api/proxy/history/{int(idx)}", params={"include_body": "true"})
        if "error" in detail:
            return {"error": f"fetch proxy entry {idx}: {detail['error']}"}
        req = _normalize_entry(detail)
        resp = req.get("response") or {}

        if output_dir:
            capsule_dir = Path(output_dir)
        else:
            capsule_dir = (
                _intel_dir() / _sanitized(domain) / "artifacts" / "poc"
                / _sanitized(str(finding_id)) / "capsule"
            )
        capsule_dir.mkdir(parents=True, exist_ok=True)

        oracle = _oracle_spec(target, req)
        manifest = {
            "capsule_schema_version": _CAPSULE_SCHEMA_VERSION,
            "finding_id": finding_id,
            "vuln_class": oracle["vuln_class"],
            "severity": str(target.get("severity") or "INFO").upper(),
            "title": target.get("title") or target.get("vuln_type") or "",
            "endpoint": oracle["endpoint"],
            "parameter": target.get("parameter") or "",
            "evidence_index": int(idx),
            "oracle": oracle,
            "replay_cmd": "python replay.py",
            "files": [
                "manifest.json", "oracle.json", "request.http",
                "response.http", "replay.py", "repro.sh", "finding.json",
            ],
        }

        writes: dict[str, bytes] = {
            "manifest.json": json.dumps(manifest, indent=2, default=str).encode("utf-8"),
            "oracle.json": json.dumps(oracle, indent=2, default=str).encode("utf-8"),
            "request.http": _raw_request(req),
            "response.http": _raw_response(resp),
            "replay.py": _verify_py(target, req).encode("utf-8"),
            "repro.sh": _render_repro(target, req).encode("utf-8"),
            "finding.json": json.dumps(target, indent=2, default=str).encode("utf-8"),
        }
        for name, content in writes.items():
            fpath = capsule_dir / name
            fpath.write_bytes(content)
            if name in ("replay.py", "repro.sh"):
                fpath.chmod(0o755)

        return {
            "ok": True,
            "finding_id": finding_id,
            "capsule_dir": str(capsule_dir),
            "capsule_schema_version": _CAPSULE_SCHEMA_VERSION,
            "oracle_kind": oracle["verdict_kind"],
            "replay_cmd": "python replay.py",
            "files": manifest["files"],
        }


# Re-export _impl's module surface so tests and callers that reach these on the
# package path (e.g. <module>.client, <module>._scan_secrets, <module>._VERIFY_HINTS)
# keep resolving after the impl split. register() above is defined here, not in
# _impl, so it is never shadowed.
from . import _impl as _impl  # noqa: E402
globals().update({_k: getattr(_impl, _k) for _k in dir(_impl) if not _k.startswith("__")})
