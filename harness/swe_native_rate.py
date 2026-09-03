#!/usr/bin/env python3
"""SWE-bench-500 native-hackable rate, derived from the committed attack records.

Recomputes the three quantities the confirmed-rate estimator takes as inputs --
``total_tasks``, ``native_hackable`` and ``queue_size`` -- directly from the
per-task attack records in ``results/raw_swe_500/``. Reads only committed files:
no Docker, no network, no API key.

    python harness/swe_native_rate.py          # prints the derivation, exits 0
    python harness/swe_native_rate.py --json   # the record, as JSON

Definitions, as registered in ``docs/preregistration.md`` and used by
``harness/code_attack.py`` when it wrote these records:

    native_hackable   a task with >= 1 candidate patch the SHIPPED test suite
                      resolved (``candidate.native_resolved``). This is the
                      verifier-verdict-alone numerator: the published 51.0%.

    queue_size        a task that is native_hackable AND has >= 1 such candidate
                      the differ marked ``behaviorally_distinct`` from gold.
                      Candidates identical in behaviour to gold are legitimate
                      alternative fixes and are excluded before the dual gate,
                      which is why the confirmed rate is a lower bound.

The dual gate itself (oracle = WRONG) is applied downstream in
``harness/swe_confirm.py``; nothing here decides whether a patch is wrong.
"""
from __future__ import annotations

import argparse
import glob
import json
import os

HARNESS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HARNESS)
RAW_DIR = os.path.join(REPO, "results", "raw_swe_500")


def load_records(raw_dir: str = RAW_DIR) -> list[dict]:
    """Every per-task attack record, ordered by filename for determinism."""
    paths = sorted(glob.glob(os.path.join(raw_dir, "*.json")))
    if not paths:
        raise FileNotFoundError(f"no attack records under {raw_dir}")
    return [json.load(open(p)) for p in paths]


def derive(records: list[dict]) -> dict:
    """The three declared inputs, recomputed from the records. Pure."""
    total = len(records)
    native = 0
    queue = 0
    for r in records:
        cands = r.get("candidates") or []
        resolved = [c for c in cands if c.get("native_resolved")]
        if resolved:
            native += 1
            if any(c.get("behaviorally_distinct") for c in resolved):
                queue += 1
    return {
        "total_tasks": total,
        "native_hackable": native,
        "native_rate": (native / total) if total else 0.0,
        "queue_size": queue,
        "queue_rate": (queue / total) if total else 0.0,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--raw-dir", default=RAW_DIR)
    ap.add_argument("--json", action="store_true", help="emit the record as JSON")
    a = ap.parse_args(argv)

    d = derive(load_records(a.raw_dir))
    if a.json:
        print(json.dumps(d, indent=2, sort_keys=True))
        return 0
    print(f"tasks attacked                       {d['total_tasks']}")
    print(f"native-hackable (verifier alone)     {d['native_hackable']}"
          f"  = {d['native_rate']:.1%}")
    print(f"dual-gate confirm queue              {d['queue_size']}"
          f"  = {d['queue_rate']:.1%}   (behaviorally distinct from gold)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
