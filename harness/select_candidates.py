#!/usr/bin/env python3
"""Tripwire Phase-1 candidate selection (host-side, SAFE — no untrusted code run).

Reads `results/hub_index.jsonl` and emits ~60 envs LIKELY to be pure-Python
`binary` verifiers — the cheap, offline-scorable majority to lead the audit with
(spec §2/§4). Selection is by TAG only (metadata, never code): prefer
math/gsm8k/reasoning/single-turn/multiple-choice/rlvr; exclude
sandbox/llm-judge/tool-use/multimodal/game/multi-turn; skip never-published envs
(latest_version null). The verifier type is confirmed later in-container by
`score_env.py --classify`; this is only a prior to cut the frontier.

Writes `results/phase1_candidates.txt` (one `owner/name` per line) and prints it.
"""
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HUB_INDEX = os.path.join(REPO, "results", "hub_index.jsonl")
OUT_PATH = os.path.join(REPO, "results", "phase1_candidates.txt")
TARGET_N = 60

# tags that make an env a good binary pure-Python candidate (weighted)
PREFER = {
    "math": 3, "gsm8k": 3, "rlvr": 3, "multiple-choice": 3,
    "reasoning": 2, "single-turn": 2,
    # secondary signals of a deterministic answer-match verifier (tie-breakers)
    "boxed-answer": 2, "boxed-letter": 2, "ifeval": 2, "logic": 1,
    "mcqa": 1, "qa": 1, "instruction-following": 1, "verifiers": 1,
}
# tags that route an env OUT of the pure-Python binary lane
EXCLUDE = {
    "sandbox", "llm-judge", "llm-as-judge", "tool-use", "tools", "multimodal",
    "vision", "game", "games", "multi-turn", "multiturn", "browser", "agent",
    "multi-agent", "code", "coding", "swe", "rlm", "computer-use",
    "math-python", "code-execution", "python-exec",  # spec §4: run code remotely
}


def main():
    if not os.path.exists(HUB_INDEX):
        print(f"[!] {HUB_INDEX} not found — run enumerate_hub.py first", file=sys.stderr)
        return 2

    scored = []
    total = published = 0
    for line in open(HUB_INDEX):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        total += 1
        if not d.get("latest_version"):      # never-published -> skip
            continue
        published += 1
        tags = set(t.lower() for t in (d.get("tags") or []))
        if tags & EXCLUDE:
            continue
        score = sum(w for t, w in PREFER.items() if t in tags)
        if score <= 0:                        # no positive binary signal
            continue
        owner = (d.get("owner") or {}).get("name")
        name = d.get("name")
        if not owner or not name:
            continue
        stars = d.get("stars") or 0
        scored.append((score, stars, f"{owner}/{name}", sorted(tags)))

    # rank: prefer-score desc, then stars desc, then name for determinism
    scored.sort(key=lambda x: (-x[0], -x[1], x[2]))
    picks = scored[:TARGET_N]

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w") as f:
        for _s, _st, env_id, _tags in picks:
            f.write(env_id + "\n")

    print(f"# Tripwire Phase-1 candidates: {len(picks)} of {published} published "
          f"({total} total) — pure-Python binary priors")
    print(f"# written to {OUT_PATH}\n")
    for score, stars, env_id, tags in picks:
        print(f"{env_id:45s}  score={score} stars={stars}  {tags}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
