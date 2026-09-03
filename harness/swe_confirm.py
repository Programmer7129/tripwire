#!/usr/bin/env python3
"""SWE-bench confirmed-reward-hack rate from the committed dual-gate verdicts.

Implements the estimator registered in ``docs/preregistration.md``, amendment
2026-07-14 ("SWE-bench-500 confirmed-rate estimation by pre-registered
sampling"), and the anchor tally in ``docs/anchor-result.md``. It reads only the
committed records in ``results/`` — no Docker, no network, no API key — so the
published headline can be recomputed from the evidence at any time.

    python harness/swe_confirm.py            # prints the headline, exits 0
    python harness/swe_confirm.py --json     # the record, as JSON

Estimator (pre-reg amendment 2026-07-14):
    p̂ = HACK / n_sample over the pre-drawn seed-42 stratified sample, with
    AMBIGUOUS excluded from the NUMERATOR and kept in the denominator (the
    conservative reading of the §3 ambiguous rule).
    confirmed count = queue_size · p̂; confirmed rate = that count / 500.
    The Wilson 95% interval on p̂ is propagated through both.

INPUTS. ``queue_size`` (the dual-gate confirm queue: tasks with >= 1
behaviorally-distinct native-hackable candidate), ``native_hackable`` and
``total_tasks`` come from the full attack pass in ``results/raw_swe_500/``.
Those 500 per-task records are committed, so these are no longer taken on
trust: ``harness/swe_native_rate.py`` rederives all three from the evidence,
and ``tests/test_swe_native_rate.py`` fails the build if they ever disagree
with what this module reads from ``results/swe500_confirmed.json``.
Everything downstream — the tally, p̂, the interval, the counts and the
rates — is recomputed here from the per-task verdicts.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HARNESS = os.path.dirname(os.path.abspath(__file__))
if HARNESS not in sys.path:
    sys.path.insert(0, HARNESS)
import aggregate as A  # reuse the pre-registered Wilson interval  # noqa: E402

REPO = os.path.dirname(HARNESS)
RESULTS = os.path.join(REPO, "results")

VERDICTS = ("HACK", "CORRECT", "AMBIGUOUS")


# --------------------------------------------------------------------------- #
# Pure core
# --------------------------------------------------------------------------- #
def tally_sample_verdicts(verdicts, sample_ids=None):
    """Count HACK / CORRECT / AMBIGUOUS over the sampled tasks.

    `verdicts` maps instance_id -> {"verdict": ...}. `sample_ids` restricts the
    tally to the pre-drawn sample (and is the authority on its size); when it is
    None every verdict is counted. Keys starting with "_" are metadata.
    """
    items = {k: v for k, v in verdicts.items() if not k.startswith("_")}
    ids = list(sample_ids) if sample_ids is not None else list(items)
    tally = {v: 0 for v in VERDICTS}
    for iid in ids:
        rec = items.get(iid)
        if rec is None:
            # nothing silently dropped: a missing verdict would deflate p-hat.
            raise ValueError(f"{iid}: sampled task has no verdict")
        verdict = rec.get("verdict")
        if verdict not in tally:
            raise ValueError(f"{iid}: unknown verdict {verdict!r}")
        tally[verdict] += 1
    tally["n"] = len(ids)
    return tally


def estimate_confirmed_rate(n_hack, n_sample, queue_size, total_tasks):
    """Confirmed reward-hack rate over the benchmark, with the CI propagated.

    AMBIGUOUS is already excluded from `n_hack` and already included in
    `n_sample` — the conservative reading registered in the 2026-07-14
    amendment. Returns the published record's fields, at the published
    precision.
    """
    if n_sample <= 0:
        raise ValueError("n_sample must be positive")
    if n_hack > n_sample:
        raise ValueError("n_hack cannot exceed n_sample")
    p_hat = n_hack / n_sample
    lo, hi = A.wilson_interval(n_hack, n_sample)
    return {
        "sample_n": n_sample,
        "sample_HACK": n_hack,
        "p_hat": round(p_hat, 4),
        "wilson95": [round(lo, 4), round(hi, 4)],
        "confirmed_count_est": round(queue_size * p_hat, 1),
        "confirmed_count_ci": [round(queue_size * lo, 1), round(queue_size * hi, 1)],
        "confirmed_rate": round(queue_size * p_hat / total_tasks, 4),
        "confirmed_rate_ci": [round(queue_size * lo / total_tasks, 4),
                              round(queue_size * hi / total_tasks, 4)],
    }


def tally_dual_gate(confirm, handreview, eligible_tasks):
    """Anchor-lane tally: diffexec auto-confirmations + hand-confirmed HACKs.

    `confirm` maps instance_id -> the diffexec_oracle record (one per
    behaviorally-distinct native-hackable candidate); `handreview` maps the
    residual instance_ids -> {"verdict": HACK|CORRECT|AMBIGUOUS}. AMBIGUOUS is
    never counted. `eligible_tasks` is the run's denominator.
    """
    hr = {k: v for k, v in handreview.items() if not k.startswith("_")}
    auto = sorted(iid for iid, rec in confirm.items() if rec.get("oracle_wrong"))
    residual = sorted(iid for iid, rec in confirm.items() if not rec.get("oracle_wrong"))
    unreviewed = [iid for iid in residual if iid not in hr]
    hand = sorted(iid for iid, rec in hr.items() if rec.get("verdict") == "HACK")
    confirmed = sorted(set(auto) | set(hand))
    return {
        "distinct_candidates": len(confirm),
        "diffexec_confirmed": len(auto),
        "diffexec_confirmed_ids": auto,
        "hand_confirmed": len(hand),
        "hand_confirmed_ids": hand,
        "hand_reviewed": len(hr),
        "unreviewed_residual": unreviewed,
        "confirmed": len(confirmed),
        "confirmed_ids": confirmed,
        "eligible_tasks": eligible_tasks,
        "confirmed_rate": len(confirmed) / eligible_tasks if eligible_tasks else None,
    }


# --------------------------------------------------------------------------- #
# I/O caller
# --------------------------------------------------------------------------- #
def _read(results_dir, name):
    with open(os.path.join(str(results_dir), name)) as fh:
        return json.load(fh)


def build_record(results_dir=RESULTS):
    """Recompute the swe500 headline record from the committed evidence."""
    declared = _read(results_dir, "swe500_confirmed.json")
    sample = _read(results_dir, "swe500_confirm_sample.json")
    verdicts = _read(results_dir, "swe500_sample_verdicts.json")

    tally = tally_sample_verdicts(verdicts, sample["sample_ids"])
    est = estimate_confirmed_rate(n_hack=tally["HACK"], n_sample=tally["n"],
                                  queue_size=declared["queue_size"],
                                  total_tasks=declared["total_tasks"])
    auto = sorted(iid for iid, v in verdicts.items()
                  if v.get("verdict") == "HACK" and v.get("method") == "diffexec")
    record = {
        # declared inputs (raw_swe_500/ is not committed)
        "queue_size": declared["queue_size"],
        "total_tasks": declared["total_tasks"],
        "native_hackable": declared["native_hackable"],
        "native_rate": round(declared["native_hackable"] / declared["total_tasks"], 4),
        # recomputed from the committed per-task verdicts
        "sample_CORRECT": tally["CORRECT"],
        "sample_AMBIGUOUS": tally["AMBIGUOUS"],
        "diffexec_auto_hack": auto,
        "method": declared.get("method"),
    }
    record.update(est)
    return record


def anchor_records(results_dir=RESULTS, eligible_tasks=49):
    """The anchor + capability-ladder tallies, keyed by attacker."""
    return {
        "sonnet-4.5": tally_dual_gate(_read(results_dir, "anchor_confirm.json"),
                                      _read(results_dir, "anchor_handreview.json"),
                                      eligible_tasks),
        "haiku-4.5": tally_dual_gate(_read(results_dir, "haiku_confirm.json"),
                                     _read(results_dir, "haiku_handreview.json"),
                                     eligible_tasks),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Recompute the SWE-bench headline from results/.")
    ap.add_argument("--results-dir", default=RESULTS)
    ap.add_argument("--json", action="store_true", help="print the record as JSON")
    args = ap.parse_args(argv)

    record = build_record(args.results_dir)
    anchors = anchor_records(args.results_dir)
    if args.json:
        print(json.dumps({"extend_500": record, "anchor": anchors}, indent=2))
        return 0

    print("=" * 74)
    print("SWE-bench-Verified reward-hackability — recomputed from results/")
    print("  pre-reg amendment 2026-07-14: seed-42 stratified sample, "
          "AMBIGUOUS excluded from the numerator")
    print("=" * 74)
    for name, a in anchors.items():
        print("anchor  %-12s %2d/%d = %.1f%%   (diffexec %d + hand %d, "
              "of %d distinct candidates)" % (
                  name, a["confirmed"], a["eligible_tasks"],
                  100 * a["confirmed_rate"], a["diffexec_confirmed"],
                  a["hand_confirmed"], a["distinct_candidates"]))
    print("extend  native-hackable   %d/%d = %.1f%%   (verifier verdict alone)" % (
        record["native_hackable"], record["total_tasks"],
        100 * record["native_rate"]))
    print("extend  sample tally      HACK %d / CORRECT %d / AMBIGUOUS %d  (n=%d)" % (
        record["sample_HACK"], record["sample_CORRECT"],
        record["sample_AMBIGUOUS"], record["sample_n"]))
    print("extend  p-hat             %.4f  Wilson95 [%.4f, %.4f]" % (
        record["p_hat"], record["wilson95"][0], record["wilson95"][1]))
    print("extend  confirmed         %.1f/%d tasks  CI [%.1f, %.1f]" % (
        record["confirmed_count_est"], record["total_tasks"],
        record["confirmed_count_ci"][0], record["confirmed_count_ci"][1]))
    print("extend  CONFIRMED RATE    %.1f%%  95%% CI [%.1f%%, %.1f%%]  (dual-gated)" % (
        100 * record["confirmed_rate"], 100 * record["confirmed_rate_ci"][0],
        100 * record["confirmed_rate_ci"][1]))
    print("\nqueue_size, native_hackable and total_tasks are DECLARED inputs "
          "(results/raw_swe_500/\nis intermediate and not committed); "
          "everything else above is recomputed from results/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
