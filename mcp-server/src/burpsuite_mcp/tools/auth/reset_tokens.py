"""analyze_reset_tokens — entropy + sequential + timestamp analysis of N
captured password-reset tokens.

The classic exploit chain: trigger N resets for accounts I control, capture
tokens, observe pattern, predict the victim's token. Currently scattered
across operator notebooks; this tool collapses it to one call.

Three signals, each independent:
- Shannon entropy per token (bits) — < 60 = weak
- Sequential bytes — first/last/middle bytes monotonically incrementing
- Timestamp correlation — token bytes look like time(now) ± seconds

Operator runs N resets out-of-band, collects N tokens, hands them here.
"""

from __future__ import annotations

import math
import re
import time
from collections import Counter

from mcp.server.fastmcp import FastMCP


def _shannon_entropy(s: str) -> float:
    """Per-character Shannon entropy in bits. A 32-hex token of true random
    bytes scores ~4.0 bits/char (16 symbols * 2 bits each gives log2(16)=4)."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _total_entropy_bits(s: str) -> float:
    """Approximate total entropy of the string in bits."""
    return _shannon_entropy(s) * len(s)


def _looks_hex(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))


def _looks_b64(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_\-+/=]+", s)) and len(s) >= 8


def _detect_sequential(tokens: list[str]) -> tuple[bool, str]:
    """Compare consecutive tokens — same length? same prefix? incrementing
    integer slice? Returns (is_sequential, reason)."""
    if len(tokens) < 2:
        return False, "need >=2 tokens"

    # Same length is a precondition for most pattern detection.
    if len(set(len(t) for t in tokens)) > 1:
        return False, "tokens have differing lengths"

    n = len(tokens[0])

    # Find any common prefix.
    prefix_len = 0
    for i in range(n):
        chars = {t[i] for t in tokens}
        if len(chars) == 1:
            prefix_len = i + 1
        else:
            break

    # Try to interpret the differing suffix as an integer (decimal or hex).
    suffixes = [t[prefix_len:] for t in tokens]
    nums: list[int] = []
    for suf in suffixes:
        try:
            if _looks_hex(suf):
                nums.append(int(suf, 16))
            elif suf.isdigit():
                nums.append(int(suf, 10))
            else:
                break
        except ValueError:
            break

    if len(nums) == len(tokens) and len(nums) >= 2:
        deltas = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
        if all(d > 0 for d in deltas):
            avg = sum(deltas) / len(deltas)
            # Allow up to ~50% jitter around the mean delta. `<=` and a
            # ceiling-style bound keep small averages from forcing exact-match
            # (avg=1.33 -> bound=1, jitter of 1 is acceptable).
            spread = max(deltas) - min(deltas)
            bound = max(1, math.ceil(avg * 0.5))
            if spread <= bound:
                return True, (f"common prefix {tokens[0][:prefix_len]!r}, "
                              f"numeric suffix with mean delta {avg:.1f}")
    return False, ""


def _detect_timestamp(tokens: list[str], capture_times: list[float] | None,
                      ) -> tuple[bool, str]:
    """If we have capture timestamps + hex-shaped tokens, check whether the
    first N bytes correlate with unix time."""
    if not capture_times or len(capture_times) != len(tokens):
        return False, ""
    # Try slicing common Unix-epoch byte widths (4-byte sec, 5-byte sec+small)
    for hex_len in (8, 10, 12):
        try:
            ints = [int(t[:hex_len], 16) for t in tokens
                    if _looks_hex(t[:hex_len])]
        except ValueError:
            continue
        if len(ints) != len(tokens):
            continue
        # Compare to capture times — check correlation by ranking.
        # Both ints and times should be in roughly the same order.
        order_ints = sorted(range(len(ints)), key=lambda i: ints[i])
        order_times = sorted(range(len(capture_times)),
                             key=lambda i: capture_times[i])
        if order_ints == order_times:
            # Strong signal — but also check the absolute value is plausible.
            now = time.time()
            if all(abs(i - now) < 86400 * 365 * 10 for i in ints):
                return True, (f"first {hex_len} hex chars correlate with "
                              f"capture time")
    return False, ""


def register(mcp: FastMCP):

    @mcp.tool()
    async def analyze_reset_tokens(  # cost: zero (pure compute)
        tokens: list[str],
        capture_times: list[float] | None = None,
    ) -> str:
        """Analyze N captured reset/OTP tokens for predictability.

        Operator triggers N password resets out-of-band (for accounts the
        operator controls), captures the tokens, then passes them here.
        2+ tokens minimum; 5+ recommended for confident verdicts.

        Args:
            tokens: List of captured token strings (URL-decoded if needed)
            capture_times: Optional list of capture timestamps (unix seconds,
                same order as tokens). Enables timestamp-correlation check.
        """
        if not tokens or len(tokens) < 2:
            return "Error: provide >=2 tokens for comparison."
        if capture_times and len(capture_times) != len(tokens):
            return ("Error: capture_times length must match tokens length "
                    "(one timestamp per token).")

        lines = [f"analyze_reset_tokens ({len(tokens)} samples):\n"]

        # ── Length / shape ──
        lengths = set(len(t) for t in tokens)
        lines.append(f"  Length: {sorted(lengths)}")
        shape = "mixed"
        if all(_looks_hex(t) for t in tokens):
            shape = "hex"
        elif all(_looks_b64(t) for t in tokens):
            shape = "base64-ish"
        elif all(t.isdigit() for t in tokens):
            shape = "numeric"
        lines.append(f"  Shape: {shape}")
        lines.append("")

        # ── Entropy ──
        ents = [_total_entropy_bits(t) for t in tokens]
        mean_ent = sum(ents) / len(ents)
        lines.append(f"  Mean Shannon entropy: {mean_ent:.1f} bits "
                     f"(per token, ~total — not symbol space).")
        if mean_ent < 60:
            lines.append("    [!] LOW — guessable in <2^60 attempts. "
                         "Strong predictability candidate.")
        elif mean_ent < 80:
            lines.append("    [?] BORDERLINE — still cracking-feasible "
                         "for targeted brute on specific accounts.")
        else:
            lines.append("    [OK] High entropy — unlikely to brute.")
        lines.append("")

        # ── Sequential / prefix ──
        is_seq, seq_reason = _detect_sequential(tokens)
        if is_seq:
            lines.append(f"  *** SEQUENTIAL DETECTED *** — {seq_reason}")
            lines.append("    Predict the next token by extrapolating the "
                         "numeric suffix. CRITICAL when this is a reset token "
                         "for the victim account.")
        else:
            lines.append("  Sequential: no.")
        lines.append("")

        # ── Timestamp correlation ──
        is_ts, ts_reason = _detect_timestamp(tokens, capture_times)
        if is_ts:
            lines.append(f"  *** TIMESTAMP CORRELATION *** — {ts_reason}")
            lines.append("    Reduces effective entropy massively: attacker "
                         "predicts time-of-issue ± few seconds and brute-forces "
                         "the remaining bytes only.")
        elif capture_times:
            lines.append("  Timestamp correlation: no significant match.")
        lines.append("")

        # ── Common prefix / suffix (independent of sequential check) ──
        prefix_len = 0
        for i in range(min(len(t) for t in tokens)):
            chars = {t[i] for t in tokens}
            if len(chars) == 1:
                prefix_len = i + 1
            else:
                break
        if prefix_len >= 4:
            lines.append(f"  Common prefix ({prefix_len} chars): "
                         f"{tokens[0][:prefix_len]!r}")
            lines.append("    Reduces effective entropy by 8*prefix_len bits.")

        # ── Verdict ──
        signals = sum([is_seq, is_ts, mean_ent < 60])
        lines.append("")
        if signals >= 2:
            lines.append("VERDICT: weak token generation — multi-signal hit. "
                         "Worth a full PoC: predict the next-issued token for "
                         "an account you don't control.")
        elif signals == 1:
            lines.append("VERDICT: one weak signal — collect more samples "
                         "(target 10-20) to confirm.")
        else:
            lines.append("VERDICT: no weakness detected. Token generation "
                         "appears cryptographically sound at this sample size.")

        return "\n".join(lines)
