"""Pure match/rank engine over ROUTING_TABLE. No side effects, no execution."""

import json

from ._rules import ALWAYS_ASK_TOOLS, HARD_DENY, IMPACT_WEIGHT, ROUTING_TABLE


def _denied(args: dict) -> str | None:
    blob = json.dumps(args).lower()
    for tok in HARD_DENY:
        if tok.lower() in blob:
            return tok
    return None


def match(signals: list[dict]) -> dict:
    auto, ask, dropped, seen = [], [], [], set()
    for rule in ROUTING_TABLE:
        for sig in rule["when"](signals):
            for tmpl in rule["fire"](sig):
                args = tmpl.get("args", {})
                key = (tmpl["tool"], json.dumps(args, sort_keys=True))
                if key in seen:
                    continue
                seen.add(key)
                deny = _denied(args)
                if deny:
                    dropped.append({"tool": tmpl["tool"],
                                    "reason": f"HARD-denylist: {deny}"})
                    continue
                policy = "ask" if tmpl["tool"] in ALWAYS_ASK_TOOLS else rule["policy"]
                action = {"tool": tmpl["tool"], "args": args, "policy": policy,
                          "rationale": rule["rationale"], "signal": sig}
                (auto if policy == "auto" else ask).append(action)
    auto.sort(key=lambda a: -IMPACT_WEIGHT.get(a["tool"], 1))
    ask.sort(key=lambda a: -IMPACT_WEIGHT.get(a["tool"], 1))
    return {"auto": auto, "ask": ask, "dropped": dropped}
