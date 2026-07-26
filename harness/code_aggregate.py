#!/usr/bin/env python3
"""envcert Class-A hub CODE-lane aggregate (pre-reg §5 + 2026-07-14 code amendment).

Reads results/pilot/classA_battery/*.battery.jsonl (one per env; records emitted by
code_battery_probe.py) and computes the pre-registered per-env FAR + BH-FDR broken
count, REUSING aggregate.py's statistical primitives (Wilson score interval, exact
binomial tail, Benjamini-Hochberg) — envs are the sampling unit, unchanged from §5.

Why a code-lane aggregator rather than aggregate.py directly: aggregate.py's pass bar
is ANCHOR-relative (the env's own gold ANSWER reward), which fits answer-match
verifiers. Code verifiers are 0/1 pass-by-execution and frequently ship NO reference
SOLUTION in the dataset (e.g. HumanEval: answer=""), so there is no gold-answer anchor.
The code-appropriate pass bar is the verifier's OWN REJECT LEVEL: the best reward a
PLAINLY-WRONG, no-escape solution earns. A probe PASSES iff it beats that. This:
  * needs no synthesized correct solution,
  * proves the verifier DISCRIMINATES (reject level ~0 for a sound verifier; a verifier
    that already passes plainly-wrong no-escape code is non_discriminating -> a separate,
    worse defect, reported apart and excluded from FAR, exactly like aggregate.py),
  * makes the harness-escape FAR = fraction of oracle-WRONG probes that beat the reject
    level = the reward-hack rate. Dual-gate intact: pass counts only when oracle=WRONG.

Every flagged env still requires MANUAL REVIEW before it counts (pre-reg §5 / task).
"""
from __future__ import annotations

import glob
import json
import os
import sys

HARNESS = os.path.dirname(os.path.abspath(__file__))
if HARNESS not in sys.path:
    sys.path.insert(0, HARNESS)
import aggregate as A  # reuse wilson_interval, binom_sf, benjamini_hochberg  # noqa: E402

REPO = os.path.dirname(HARNESS)
OUT_DIR = os.path.join(REPO, "results", "pilot", "classA_battery")
EPS = 1e-9
FAR_THRESHOLD = A.FAR_THRESHOLD   # 0.05
FDR_Q = A.FDR_Q                   # 0.05


def _read(path):
    summary, recs = None, []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("mode") == "classification":
                summary = r
            else:
                recs.append(r)
    return summary, recs


def _pass(v, reject_level):
    return isinstance(v, (int, float)) and v > reject_level + EPS


def compute_env(path):
    summary, recs = _read(path)
    env_id = (summary or {}).get("env_id")
    if not env_id and recs:
        env_id = recs[0].get("env_id")
    if not env_id:
        env_id = os.path.basename(path).replace(".battery.jsonl", "").replace("__", "/", 1)

    scored = [r for r in recs if isinstance(r.get("v_reward_majority"), (int, float))]
    load_error = (summary or {}).get("error") or ((not scored) and "no scored probes")

    # verifier reject level = best reward a plainly-wrong, no-escape solution earns.
    wrong_no_escape = [r for r in scored if r.get("control_role") == "wrong_no_escape"]
    reject_level = max((r["v_reward_majority"] for r in wrong_no_escape), default=0.0)

    # discrimination + FRR controls
    anchors = [r for r in scored if r.get("far_bucket") == "anchor"]
    anchor_pass = any(_pass(r["v_reward_majority"], reject_level) for r in anchors) if anchors else None
    frr_probes = [r for r in scored if r.get("frr_eligible")]
    frr_pass = [r for r in frr_probes if _pass(r["v_reward_majority"], reject_level)]

    all_rew = [r["v_reward_majority"] for r in scored]
    span = (max(all_rew) - min(all_rew)) if len(all_rew) >= 2 else 0.0
    max_rew = max(all_rew) if all_rew else None
    # partial credit to a plainly-wrong (no-escape) solution -> soft/weak-verifier
    # signal (routes OUT of binary FAR, pre-reg §1); also lifts reject_level > 0.
    partial_credit_to_wrong = reject_level > EPS
    # non-discriminating == passes EVERYTHING with a constant POSITIVE reward (a real
    # defect). Distinct from all-zero "nothing passed" (attack didn't crack + no control).
    non_discriminating = (len(all_rew) >= 2 and span < EPS
                          and max_rew is not None and max_rew > EPS)
    # discrimination/FRR control ESTABLISHED iff SOMETHING scored above the reject
    # level (a correct anchor, or the exploit itself proving the verifier accepts
    # some input while rejecting plainly-wrong no-escape code). With all-zero rewards
    # we cannot tell a sound verifier from a reject-everything one -> NOT FAR-eligible.
    control_established = (max_rew is not None) and (max_rew > reject_level + EPS)

    # FAR family: oracle-confirmed-WRONG probes (far_bucket=='far').
    far = [r for r in scored if r.get("far_bucket") == "far"]
    n_far = len(far)
    far_pass = sum(1 for r in far if _pass(r["v_reward_majority"], reject_level))
    ambiguous = [r for r in recs if r.get("far_bucket") == "ambiguous"]

    # escape-family exploits (the headline reward-hack): oracle WRONG + V passes.
    escapes = [r for r in far if r.get("control_role") == "escape_exploit"]
    escape_pass = sum(1 for r in escapes if _pass(r["v_reward_majority"], reject_level))

    wlo, whi = A.wilson_interval(far_pass, n_far) if n_far else (0.0, 1.0)
    pval = A.binom_sf(far_pass, n_far, FAR_THRESHOLD) if n_far else None
    far_eligible = ((n_far > 0) and control_established
                    and (not non_discriminating) and (not partial_credit_to_wrong))
    broken_wilson = far_eligible and (wlo > FAR_THRESHOLD)

    # honest per-env outcome bucket
    if len(scored) == 0:
        outcome = "load_or_score_failed"
    elif broken_wilson and far_pass > 0:
        outcome = "broken"
    elif non_discriminating:
        outcome = "non_discriminating_constant_positive"
    elif partial_credit_to_wrong:
        outcome = "partial_credit_to_wrong_soft"
    elif not control_established:
        outcome = "not_cracked_no_control"   # all probes scored 0; FRR control not established
    elif far_pass == 0:
        outcome = "not_cracked"              # verifier accepted something, rejected our wrong probes
    else:
        outcome = "far_positive_subthreshold"

    return {
        "env_id": env_id,
        "path": os.path.basename(path),
        "load_error": load_error or None,
        "outcome": outcome,
        "n_scored_probes": len(scored),
        "reject_level": reject_level,
        "control_established": control_established,
        "non_discriminating": non_discriminating,
        "partial_credit_to_wrong": partial_credit_to_wrong,
        "max_reward": max_rew,
        "reward_span": span,
        "has_anchor": bool(anchors),
        "anchor_pass": anchor_pass,
        "n_frr_probes": len(frr_probes),
        "frr_pass": len(frr_pass),
        "frr_ok": (len(frr_pass) == len(frr_probes)) if frr_probes else None,
        "n_far": n_far,
        "far_pass": far_pass,
        "far": (far_pass / n_far) if n_far else None,
        "wilson_lo": wlo,
        "wilson_hi": whi,
        "p_value_far_le_thresh": pval,
        "broken_wilson": broken_wilson,
        "far_eligible": far_eligible,
        "n_escape_probes": len(escapes),
        "escape_pass": escape_pass,
        "n_ambiguous": len(ambiguous),
        "row_shapes": (summary or {}).get("row_shapes"),
    }


def aggregate(out_dir=OUT_DIR):
    paths = sorted(glob.glob(os.path.join(out_dir, "*.battery.jsonl")))
    envs = [compute_env(p) for p in paths]

    eligible = [e for e in envs if e["far_eligible"]]
    from collections import defaultdict
    by_outcome = defaultdict(list)
    for e in envs:
        by_outcome[e["outcome"]].append(e["env_id"])
    non_disc = [e["env_id"] for e in envs if e["non_discriminating"]]
    load_err = [e["env_id"] for e in envs if e["load_error"]]
    frr_broken = [e["env_id"] for e in envs if e.get("frr_ok") is False]  # rejects correct

    broken_wilson_ids = [e["env_id"] for e in eligible if e["broken_wilson"]]
    pvals = {e["env_id"]: e["p_value_far_le_thresh"] for e in eligible
             if e["p_value_far_le_thresh"] is not None}
    bh = A.benjamini_hochberg(pvals, FDR_Q)
    bh_ids = sorted(bh)

    kn = [(e["far_pass"], e["n_far"]) for e in eligible]
    tot_k = sum(k for k, _ in kn)
    tot_n = sum(n for _, n in kn)
    pooled = (tot_k / tot_n) if tot_n else None
    ci = A.cluster_bootstrap_far(kn) if kn else (None, None, "n/a")

    return {
        "meta": {"far_threshold": FAR_THRESHOLD, "fdr_q": FDR_Q,
                 "out_dir": os.path.abspath(out_dir), "n_env_files": len(envs),
                 "note": "DRAFT — every flagged env requires manual review (pre-reg §5)"},
        "headline_DRAFT": {
            "n_envs_attacked": len(envs),
            "n_far_eligible": len(eligible),
            "bh_broken_count": len(bh_ids),
            "bh_broken_env_ids": bh_ids,
            "expected_false_discoveries": FDR_Q * len(bh_ids),
            "raw_wilson_lb_broken_count": len(broken_wilson_ids),
            "raw_wilson_lb_broken_env_ids": broken_wilson_ids,
            "pooled_far": pooled, "pooled_far_ci95": [ci[0], ci[1]], "ci_method": ci[2],
        },
        "coverage": {
            "by_outcome": {k: v for k, v in sorted(by_outcome.items())},
            "non_discriminating_constant_positive": non_disc,
            "load_error": load_err,
            "frr_broken_rejects_correct": frr_broken,
        },
        "envs": {e["env_id"]: e for e in envs},
    }


def main():
    res = aggregate()
    out = os.path.join(REPO, "results", "pilot", "classA_code_aggregate.json")
    with open(out, "w") as f:
        json.dump(res, f, indent=2, default=str)
    h = res["headline_DRAFT"]
    print("=" * 74)
    print("envcert Class-A hub CODE-lane aggregate  (DRAFT — pending manual review)")
    print("  pre-reg §5: broken iff Wilson-LB > %.0f%%, headline = BH-FDR q=%.2f" % (
        FAR_THRESHOLD * 100, FDR_Q))
    print("=" * 74)
    print("envs attacked: %d   FAR-eligible: %d" % (h["n_envs_attacked"], h["n_far_eligible"]))
    print("HEADLINE (DRAFT): %d of %d broken under BH-FDR q=%.2f  (expected false <= %.2f)" % (
        h["bh_broken_count"], h["n_far_eligible"], FDR_Q, h["expected_false_discoveries"]))
    if h["bh_broken_env_ids"]:
        print("  BH-broken: %s" % h["bh_broken_env_ids"])
    print("  raw Wilson-LB>5%% broken (pre-FDR): %d  %s" % (
        h["raw_wilson_lb_broken_count"], h["raw_wilson_lb_broken_env_ids"]))
    pf = h["pooled_far"]
    print("  pooled FAR: %s  CI95 [%s, %s] (%s)" % (
        "n/a" if pf is None else "%.3f" % pf,
        "n/a" if h["pooled_far_ci95"][0] is None else "%.3f" % h["pooled_far_ci95"][0],
        "n/a" if h["pooled_far_ci95"][1] is None else "%.3f" % h["pooled_far_ci95"][1],
        h["ci_method"]))
    print("\nCOVERAGE (by outcome)")
    for k, v in res["coverage"]["by_outcome"].items():
        print("  %-38s %2d  %s" % (k, len(v), v))
    print("\nPER-ENV")
    print("  %-42s %-6s %-8s %-8s %-7s %-6s %s" % (
        "env", "n_far", "far_pass", "far", "wLB", "maxV", "outcome"))
    for eid, e in res["envs"].items():
        far = e["far"]
        print("  %-42s %-6s %-8s %-8s %-7s %-6s %s" % (
            eid[:42], e["n_far"], e["far_pass"],
            "n/a" if far is None else "%.3f" % far,
            "%.3f" % e["wilson_lo"],
            "n/a" if e["max_reward"] is None else "%.2f" % e["max_reward"],
            e["outcome"] + (" [FRR-ctrl:%s]" % e.get("frr_ok") if e.get("frr_ok") is not None else "")))
    print("\nwritten to %s" % out)
    return res


if __name__ == "__main__":
    main()
