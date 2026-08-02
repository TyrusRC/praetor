"""Every make_verdict / error_verdict call site must match the real signature.

These helpers are keyword-heavy and are called from ~100 probe modules. A wrong
keyword (`human_summary=` instead of `summary=`) or an extra positional is a
TypeError raised only when that branch executes at runtime — against a live
target, mid-engagement. Nine modules shipped in exactly that state.

Static check, so a probe with no unit test is still covered.
"""

import ast
import inspect
import unittest
from pathlib import Path

from burpsuite_mcp.tools.testing import _verdict

SRC = Path(_verdict.__file__).resolve().parents[3]

CHECKED = {
    "make_verdict": inspect.signature(_verdict.make_verdict),
    "error_verdict": inspect.signature(_verdict.error_verdict),
    "verdict_from_tally": inspect.signature(_verdict.verdict_from_tally),
}


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _violations():
    out = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name == "_verdict.py":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            sig = CHECKED.get(_call_name(node))
            if sig is None:
                continue
            # **kwargs / *args forwarding — can't be checked statically.
            if any(k.arg is None for k in node.keywords) or any(
                isinstance(a, ast.Starred) for a in node.args
            ):
                continue
            # Values are irrelevant — only arity and keyword names are checked.
            args = [None] * len(node.args)
            kwargs = {k.arg: None for k in node.keywords}
            try:
                sig.bind(*args, **kwargs)
            except TypeError as exc:
                rel = path.relative_to(SRC)
                out.append(f"{rel}:{node.lineno} {_call_name(node)}(): {exc}")
    return out


class VerdictCallConformanceTest(unittest.TestCase):
    def test_every_call_site_binds(self):
        bad = _violations()
        self.assertEqual(
            bad, [], "verdict helper called with a signature that raises:\n  "
            + "\n  ".join(bad)
        )


if __name__ == "__main__":
    unittest.main()
