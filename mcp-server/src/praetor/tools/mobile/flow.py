# tools/mobile/flow.py
"""Locate-by-label + a scripted multi-step UI flow runner.

Closes two device-control gaps: tapping an element by its VISIBLE TEXT/label
(accessibility-tree first, OCR fallback for Compose/Flutter/Canvas screens where
the tree is empty) and running a VERIFIED multi-step UI journey for authenticated
mobile business-logic testing. Deterministic — the host model composes the steps,
these tools execute + verify and record an operator-log trace. No LLM, no key.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from ._device import DeviceError, backend_for, resolve_device
from ._store import artifact_dir, log_action
from .control import parse_ui


def _match_in_tree(els: list[dict], needle: str) -> list[dict]:
    """Elements whose text / resource_id / class contains `needle`, best first
    (clickable + shortest label = most specific)."""
    nl = needle.lower()
    hits = [e for e in els
            if e.get("center")
            and nl in " ".join(str(e.get(k, "")) for k in ("text", "resource_id", "class")).lower()]
    hits.sort(key=lambda e: (not e.get("clickable"), len(e.get("text") or "")))
    return hits


def _ocr_boxes(png_path) -> list[dict] | None:
    """tesseract TSV -> [{text, conf, center:[x,y], bbox}]. None when tesseract is
    missing (so the caller can distinguish "unavailable" from "no match"); [] on
    any OCR failure."""
    if not shutil.which("tesseract"):
        return None
    try:
        proc = subprocess.run(["tesseract", str(png_path), "stdout", "--psm", "11", "tsv"],
                              capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.SubprocessError):
        return []
    out: list[dict] = []
    for line in proc.stdout.splitlines()[1:]:
        c = line.split("\t")
        if len(c) < 12 or not c[11].strip():
            continue
        try:
            left, top, w, h, conf = int(c[6]), int(c[7]), int(c[8]), int(c[9]), float(c[10])
        except ValueError:
            continue
        out.append({"text": c[11].strip(), "conf": conf,
                    "center": [left + w // 2, top + h // 2], "bbox": [left, top, w, h]})
    return out


async def _locate_element(dev, text: str, domain: str) -> tuple[str, list[dict], str]:
    """Return (method, hits, error). method = 'tree' | 'ocr'. hits best-first with a
    `center`. error is non-empty only on a hard blocker (OCR needed but absent)."""
    try:
        raw = await backend_for(dev).ui_dump_raw(dev)
        els = parse_ui(raw, dev.platform)
    except DeviceError:
        els = []
    hits = _match_in_tree(els, text)
    if hits:
        return "tree", hits, ""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    out = artifact_dir(domain) / f"locate-{dev.id}-{ts}.png"
    try:
        await backend_for(dev).screenshot(dev, out)
    except DeviceError as e:
        return "ocr", [], str(e)
    boxes = await asyncio.to_thread(_ocr_boxes, out)
    if boxes is None:
        return "ocr", [], ("no accessibility-tree match and tesseract not installed — "
                           "install tesseract-ocr for the OCR fallback (setup.sh), or pass "
                           "coords / element_index to mobile_tap")
    nl = text.lower()
    obj = sorted((b for b in boxes if nl in b["text"].lower()), key=lambda b: -b["conf"])
    hits = [{"text": b["text"], "center": b["center"], "bounds": b["bbox"],
             "conf": b["conf"], "clickable": None} for b in obj]
    return "ocr", hits, ""


async def _screen_has_text(dev, needle: str, domain: str) -> bool:
    """True if `needle` is on screen now — accessibility tree OR OCR."""
    nl = needle.lower()
    try:
        raw = await backend_for(dev).ui_dump_raw(dev)
        if nl in " ".join(e.get("text", "") for e in parse_ui(raw, dev.platform)).lower():
            return True
    except DeviceError:
        pass
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    out = artifact_dir(domain) / f"assert-{dev.id}-{ts}.png"
    try:
        await backend_for(dev).screenshot(dev, out)
    except DeviceError:
        return False
    boxes = await asyncio.to_thread(_ocr_boxes, out)
    return bool(boxes) and nl in " ".join(b["text"] for b in boxes).lower()


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def mobile_locate(text: str = "", device: str = "", tap: bool = False,
                            domain: str = "") -> dict:
        """Find an on-screen element by its VISIBLE text/label and return tap coords.

        Accessibility-tree first (exact), OCR fallback for Compose / Flutter / Canvas
        / game screens where the tree is empty (needs tesseract). `tap=True` taps the
        best match. Use instead of hand-reading a ui_dump when you know the label.

        Args:
            text: the visible label to find (e.g. "Log in", "Continue"). Single-word
                labels match most reliably in the OCR fallback.
            device: adb serial / ios udid. Empty = the only connected device.
            tap: tap the best match's center.
            domain: engagement domain for artifact + oplog storage.
        """
        if not text.strip():
            return {"error": "pass the visible text/label to locate"}
        try:
            dev = await resolve_device(device)
        except DeviceError as e:
            return {"error": str(e)}
        method, hits, err = await _locate_element(dev, text, domain)
        if err:
            return {"found": False, "method": method, "text": text, "error": err}
        if not hits:
            return {"found": False, "method": method, "text": text,
                    "hint": "no element/label matched — mobile_ui_dump to inspect the tree, "
                            "or mobile_screenshot + read_screenshot_text"}
        best = hits[0]
        cx, cy = best["center"]
        res = {"found": True, "method": method, "text": text, "center": [cx, cy],
               "candidates": hits[:5], "device": dev.id}
        if tap:
            try:
                await backend_for(dev).tap(dev, cx, cy)
            except DeviceError as e:
                return {**res, "tapped": False, "error": str(e)}
            res["tapped"] = True
            res["oplog_id"] = log_action(domain, dev.id,
                                         f"tap '{text}' @ {cx},{cy} ({method})",
                                         description="locate+tap")
        return res

    @mcp.tool()
    async def mobile_run_flow(steps: list | None = None, device: str = "", domain: str = "",
                              stop_on_error: bool = True) -> dict:
        """Run a scripted multi-step UI journey and verify it — the on-device analog
        of run_flow, for authenticated mobile business-logic testing.

        Deterministic: the host model composes `steps`; this executes each and records
        an operator-log trace. Supported step dicts (`action` + args):
          {"action": "tap", "text": "Login"}            tap by visible label (locate)
          {"action": "tap", "element_index": 7}          tap a ui_dump element
          {"action": "tap", "x": 540, "y": 1200}         tap a coordinate
          {"action": "input", "text": "wiener"}          type into the focused field
          {"action": "swipe", "x1":.., "y1":.., "x2":.., "y2":.., "duration_ms": 300}
          {"action": "key", "key": "KEYCODE_BACK"}
          {"action": "deeplink", "uri": "app://...", "package": "..."}
          {"action": "wait", "ms": 800}
          {"action": "screenshot"}
          {"action": "assert_text", "text": "Welcome"}   verify text is on screen (tree+OCR)

        Args:
            steps: ordered list of step dicts (above).
            device: adb serial / ios udid. Empty = the only connected device.
            domain: engagement domain for artifact + oplog storage.
            stop_on_error: stop at the first failed/unverified step (default True).
        """
        if not isinstance(steps, list) or not steps:
            return {"error": "steps must be a non-empty list of {action, ...} dicts"}
        try:
            dev = await resolve_device(device)
        except DeviceError as e:
            return {"error": str(e)}
        be = backend_for(dev)
        trace: list[dict] = []
        ok_all = True
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                trace.append({"step": i, "ok": False, "error": "step is not a dict"})
                ok_all = False
                if stop_on_error:
                    break
                continue
            action = (step.get("action") or "").lower()
            rec: dict = {"step": i, "action": action}
            try:
                if action == "tap":
                    if step.get("text"):
                        _m, hits, err = await _locate_element(dev, step["text"], domain)
                        if err or not hits:
                            raise DeviceError(err or f"could not locate '{step['text']}'")
                        cx, cy = hits[0]["center"]
                        await be.tap(dev, cx, cy)
                        rec["target"] = [cx, cy]
                    elif step.get("element_index") is not None:
                        raw = await be.ui_dump_raw(dev)
                        m = next((e for e in parse_ui(raw, dev.platform)
                                  if e["index"] == step["element_index"]), None)
                        if not m or not m["center"]:
                            raise DeviceError(f"element_index {step['element_index']} not found")
                        await be.tap(dev, m["center"][0], m["center"][1])
                        rec["target"] = m["center"]
                    else:
                        await be.tap(dev, int(step["x"]), int(step["y"]))
                        rec["target"] = [int(step["x"]), int(step["y"])]
                elif action == "input":
                    await be.input_text(dev, step.get("text", ""))
                elif action == "swipe":
                    await be.swipe(dev, int(step["x1"]), int(step["y1"]),
                                   int(step["x2"]), int(step["y2"]), int(step.get("duration_ms", 300)))
                elif action == "key":
                    await be.key(dev, step.get("key", ""))
                elif action == "deeplink":
                    await be.deeplink(dev, step.get("uri", ""), step.get("package", ""))
                elif action == "wait":
                    await asyncio.sleep(min(10.0, max(0, int(step.get("ms", 500))) / 1000.0))
                elif action == "screenshot":
                    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
                    out = artifact_dir(domain) / f"flow-{dev.id}-{i}-{ts}.png"
                    await be.screenshot(dev, out)
                    rec["path"] = str(out)
                elif action == "assert_text":
                    needle = step.get("text", "")
                    present = await _screen_has_text(dev, needle, domain)
                    rec["present"] = present
                    if not present:
                        raise DeviceError(f"assert_text '{needle}' not found on screen")
                else:
                    raise DeviceError(f"unknown action {action!r}")
                rec["ok"] = True
            except (DeviceError, KeyError, ValueError, TypeError) as e:
                rec["ok"] = False
                rec["error"] = str(e)
                ok_all = False
            trace.append(rec)
            if not rec["ok"] and stop_on_error:
                break
        oid = log_action(domain, dev.id, f"run_flow {len(steps)} steps",
                         description="mobile UI flow", output=f"ok={ok_all}")
        return {"ok": ok_all, "steps_run": len(trace), "trace": trace,
                "oplog_id": oid, "device": dev.id}
