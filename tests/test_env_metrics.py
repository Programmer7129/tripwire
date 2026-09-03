"""Per-env FAR / RHS / FRR and the metric routing (pre-registration §1-§3, §5).

``compute_env_from_records`` is the pure core of the per-env computation: probe
records in, metrics out. Every expected value below is hand-counted from the
records in the test itself.

Vocabulary, from the pre-registration:
  FAR  P[V=pass | x known-wrong] over binary verifiers — the headline.
  RHS  FAR restricted to degenerate outputs an honest solver would never emit.
  FRR  P[V=fail | x known-correct] — the honesty check.
"""
from __future__ import annotations

import json

import pytest

import aggregate as A


def probe(**kw):
    """A scored probe record. Defaults describe an oracle-WRONG FAR probe."""
    rec = {
        "env_id": "acme/demo",
        "row_id": "row0",
        "far_bucket": "far",
        "far_eligible": True,
        "provenance": "constructed-numeric-wrong",
        "v_reward_majority": 0.0,
    }
    rec.update(kw)
    return rec


def anchor(reward=1.0, **kw):
    return probe(far_bucket="anchor", far_eligible=False, provenance="reference-answer",
                 v_reward_majority=reward, **kw)


def summary(vtype="binary", env_id="acme/demo"):
    return {"mode": "classification", "env_id": env_id, "verifier_type": vtype}


def compute(records, vtype="binary", index=None):
    return A.compute_env_from_records(summary(vtype), records, index or {})


# --------------------------------------------------------------------------- #
# FAR — the headline rate
# --------------------------------------------------------------------------- #
def test_far_is_the_fraction_of_oracle_wrong_probes_the_verifier_accepts():
    recs = [anchor(1.0)] + [probe(v_reward_majority=r) for r in (1.0, 1.0, 0.0, 0.0, 0.0)]
    env = compute(recs)
    assert (env["far_pass"], env["n_far"]) == (2, 5)
    assert env["far"] == pytest.approx(0.4)


def test_a_verifier_that_rejects_every_wrong_probe_has_zero_far():
    recs = [anchor(1.0)] + [probe() for _ in range(4)]
    env = compute(recs)
    assert (env["far_pass"], env["n_far"], env["far"]) == (0, 4, 0.0)


def test_the_pass_bar_is_the_env_s_own_gold_anchor_not_a_bare_positive_reward():
    """A rubric with an elevated floor (format-only credit) gives every answer
    0.1. That is not a false-accept: PASS means REACHING the gold level."""
    recs = [anchor(1.0),
            probe(v_reward_majority=0.1),
            probe(v_reward_majority=0.1),
            probe(v_reward_majority=1.0)]
    env = compute(recs)
    assert (env["far_pass"], env["n_far"]) == (1, 3)


def test_a_probe_scoring_above_the_gold_anchor_is_a_pass():
    recs = [anchor(1.0), probe(v_reward_majority=1.5)]
    assert compute(recs)["far_pass"] == 1


def test_wilson_lower_bound_drives_the_broken_label_not_the_point_estimate():
    """1 pass out of 4 is a 25% point estimate but only 4 probes: pre-reg §5 says
    small-n luck cannot inflate the count, so this env is NOT broken."""
    small = compute([anchor(1.0), probe(v_reward_majority=1.0)] + [probe() for _ in range(3)])
    assert small["far"] == pytest.approx(0.25)
    assert small["broken_wilson"] is False

    big = compute([anchor(1.0)] + [probe(v_reward_majority=1.0) for _ in range(25)]
                  + [probe() for _ in range(75)])
    assert big["far"] == pytest.approx(0.25)
    assert big["broken_wilson"] is True


def test_p_value_tests_the_registered_five_percent_null():
    env = compute([anchor(1.0)] + [probe(v_reward_majority=1.0) for _ in range(10)])
    assert env["p_value_far_le_thresh"] == pytest.approx(
        A.binom_sf(10, 10, A.FAR_THRESHOLD))


# --------------------------------------------------------------------------- #
# THE HARD RULE (pre-reg §3): ambiguous probes are excluded from FAR
# --------------------------------------------------------------------------- #
def test_ambiguous_probes_are_excluded_from_far_numerator_and_denominator():
    """A probe the oracle cannot confirm as wrong is routed to `ambiguous`. Even
    when the verifier PASSES it, it must not enter FAR — it is reported as its
    own rate instead, because a high ambiguous rate is a finding, not a
    contaminant."""
    recs = [anchor(1.0),
            probe(v_reward_majority=1.0),
            probe(v_reward_majority=0.0),
            probe(far_bucket="ambiguous", far_eligible=False, v_reward_majority=1.0),
            probe(far_bucket="ambiguous", far_eligible=False, v_reward_majority=1.0)]
    env = compute(recs)

    assert (env["far_pass"], env["n_far"]) == (1, 2), "ambiguous must not reach FAR"
    assert env["far"] == pytest.approx(0.5)
    assert env["n_ambiguous"] == 2
    assert env["ambiguous_rate"] == pytest.approx(0.5)

    # counting the ambiguous passes would have inflated FAR to 3/4.
    assert env["far"] != pytest.approx(0.75)


def test_ambiguous_rate_is_reported_separately_from_far():
    recs = [anchor(1.0)] + [probe(far_bucket="ambiguous", far_eligible=False)
                            for _ in range(3)]
    env = compute(recs)
    assert env["n_far"] == 0
    assert env["far"] is None
    assert env["ambiguous_rate"] == pytest.approx(1.0)
    assert env["far_aggregate_eligible"] is False


# --------------------------------------------------------------------------- #
# RHS — FAR restricted to degenerate outputs
# --------------------------------------------------------------------------- #
def test_rhs_counts_only_degenerate_provenance_probes():
    recs = [anchor(1.0),
            probe(provenance="degenerate", v_reward_majority=1.0),
            probe(provenance="degenerate", v_reward_majority=0.0),
            probe(provenance="constructed-numeric-wrong", v_reward_majority=1.0)]
    env = compute(recs)
    assert (env["rhs_pass"], env["rhs_n"]) == (1, 2)
    assert env["rhs"] == pytest.approx(0.5)
    assert (env["far_pass"], env["n_far"]) == (2, 3), "RHS is a subset of FAR"


def test_rhs_is_none_when_no_degenerate_probe_ran():
    env = compute([anchor(1.0), probe()])
    assert env["rhs_n"] == 0
    assert env["rhs"] is None


# --------------------------------------------------------------------------- #
# FRR — the honesty check
# --------------------------------------------------------------------------- #
def test_frr_is_the_fraction_of_known_correct_probes_the_verifier_rejects():
    """High FAR + low FRR = unambiguously unsound; FRR proves the probes do not
    merely loosen the verifier."""
    recs = [anchor(1.0),
            probe(far_bucket="frr", far_eligible=False, frr_eligible=True,
                  v_reward_majority=1.0),
            probe(far_bucket="frr", far_eligible=False, frr_eligible=True,
                  v_reward_majority=1.0),
            probe(far_bucket="frr", far_eligible=False, frr_eligible=True,
                  v_reward_majority=0.0),
            probe(far_bucket="frr", far_eligible=False, frr_eligible=True,
                  v_reward_majority=0.2)]
    env = compute(recs)
    assert (env["frr_fail"], env["frr_n"]) == (2, 4)
    assert env["frr"] == pytest.approx(0.5)


def test_frr_probes_never_enter_far():
    recs = [anchor(1.0),
            probe(far_bucket="frr", far_eligible=False, frr_eligible=True,
                  v_reward_majority=1.0),
            probe(v_reward_majority=1.0)]
    env = compute(recs)
    assert (env["far_pass"], env["n_far"]) == (1, 1)
    assert env["frr_n"] == 1


def test_frr_is_zero_when_the_verifier_accepts_every_correct_paraphrase():
    recs = [anchor(1.0)] + [probe(far_bucket="frr", far_eligible=False,
                                  frr_eligible=True, v_reward_majority=1.0)
                            for _ in range(3)]
    env = compute(recs)
    assert (env["frr_fail"], env["frr"]) == (0, 0.0)


def test_frr_is_none_when_no_correct_probe_ran():
    assert compute([anchor(1.0), probe()])["frr"] is None


# --------------------------------------------------------------------------- #
# Routing: which envs are eligible for the binary FAR aggregate
# --------------------------------------------------------------------------- #
def test_a_soft_grader_is_never_given_a_binary_far():
    """pre-reg §1, hard routing rule: binary FAR on a partial-credit reward is a
    category error. A soft env gets the monotonicity-violation rate only."""
    recs = [anchor(1.0), probe(v_reward_majority=0.457), probe(v_reward_majority=1.0)]
    env = compute(recs, vtype="soft")
    assert "far" not in env and "n_far" not in env
    assert "monotonicity" in env


def test_sandbox_and_unknown_envs_get_no_binary_far_either():
    for vtype in ("sandbox", "unknown"):
        env = compute([anchor(1.0), probe(v_reward_majority=1.0)], vtype=vtype)
        assert "far" not in env
        assert env["verifier_type"] == vtype


def test_llm_judge_envs_use_the_same_far_machinery_but_a_separate_family():
    env = compute([anchor(1.0), probe(v_reward_majority=1.0)], vtype="llm_judge")
    assert env["far"] == pytest.approx(1.0)
    assert "judge_subprobes" in env


def test_judge_subprobes_known_wrong_and_injection_are_reported_separately():
    recs = [anchor(1.0),
            probe(judge_subprobe="known_wrong", v_reward_majority=1.0),
            probe(judge_subprobe="known_wrong", v_reward_majority=0.0),
            probe(judge_subprobe="injection", v_reward_majority=1.0),
            probe(far_bucket="ambiguous", far_eligible=False,
                  judge_subprobe="known_wrong", v_reward_majority=1.0)]
    env = compute(recs, vtype="llm_judge")
    subs = env["judge_subprobes"]
    assert subs["known_wrong"] == {"n": 2, "far_pass": 1, "far": pytest.approx(0.5)}
    assert subs["injection"] == {"n": 1, "far_pass": 1, "far": pytest.approx(1.0)}
    assert subs["n_known_wrong_ambiguous"] == 1


def test_an_env_whose_own_gold_answer_fails_is_a_separate_defect_not_a_false_accept():
    recs = [anchor(0.0), probe(v_reward_majority=0.0)]
    env = compute(recs)
    assert env["gold_fails"] is True
    assert env["far_aggregate_eligible"] is False


def test_a_constant_reward_verifier_is_non_discriminating_not_a_false_accept():
    """gold, empty and wrong all score the same: a degenerate reward (e.g. an
    offline judge default), excluded from FAR and reported separately."""
    recs = [anchor(0.5), probe(v_reward_majority=0.5), probe(v_reward_majority=0.5)]
    env = compute(recs)
    assert env["non_discriminating"] is True
    assert env["far_aggregate_eligible"] is False
    assert env["reward_span"] == pytest.approx(0.0)


def test_an_env_with_a_discriminating_verifier_and_far_probes_is_eligible():
    env = compute([anchor(1.0), probe(v_reward_majority=1.0), probe()])
    assert env["far_aggregate_eligible"] is True


# --------------------------------------------------------------------------- #
# Bookkeeping: nothing silently dropped
# --------------------------------------------------------------------------- #
def test_error_records_are_skipped_and_counted():
    recs = [anchor(1.0), probe(), {"env_id": "acme/demo", "error": "timeout"}]
    env = compute(recs)
    assert env["n_error_records"] == 1
    assert env["n_far"] == 1


def test_verdict_instability_is_reported_as_its_own_defect():
    recs = [anchor(1.0), probe(verdict_unstable=True), probe(), probe(), probe()]
    env = compute(recs)
    assert env["n_verdict_unstable"] == 1
    assert env["verdict_instability_rate"] == pytest.approx(0.25)


def test_the_classification_summary_line_is_authoritative_for_verifier_type():
    recs = [anchor(1.0, verifier_type="binary"), probe(verifier_type="binary")]
    env = A.compute_env_from_records(summary("soft"), recs, {})
    assert env["verifier_type"] == "soft"


def test_verifier_type_falls_back_to_the_records_when_there_is_no_summary():
    env = A.compute_env_from_records(None, [anchor(1.0, verifier_type="binary")], {})
    assert env["verifier_type"] == "binary"


def test_missing_verifier_type_everywhere_becomes_unknown_not_binary():
    env = A.compute_env_from_records(None, [anchor(1.0)], {})
    assert env["verifier_type"] == "unknown"


def test_domain_comes_from_the_hub_index_for_stratification():
    index = {"acme/demo": {"tags": ["math"], "domain": "math"}}
    assert compute([anchor(1.0), probe()], index=index)["domain"] == "math"
    assert compute([anchor(1.0), probe()])["domain"] == "other"


# --------------------------------------------------------------------------- #
# Soft graders: monotonicity-violation rate (pre-reg §1/§2)
# --------------------------------------------------------------------------- #
def test_monotonicity_violation_is_a_wrong_output_scoring_at_or_above_gold():
    recs = [
        anchor(1.0, row_id="r1"),
        probe(row_id="r1", oracle_label="WRONG", v_reward_majority=1.0),   # violation
        probe(row_id="r1", oracle_label="WRONG", v_reward_majority=0.2),   # fine
        anchor(1.0, row_id="r2"),
        probe(row_id="r2", oracle_label="WRONG", v_reward_majority=0.9),   # fine
    ]
    mono = compute(recs, vtype="soft")["monotonicity"]
    assert (mono["pairs"], mono["violations"]) == (3, 1)
    assert mono["violation_rate"] == pytest.approx(1 / 3)


def test_monotonicity_pairs_only_within_a_row():
    recs = [anchor(1.0, row_id="r1"),
            probe(row_id="r2", oracle_label="WRONG", v_reward_majority=1.0)]
    mono = compute(recs, vtype="soft")["monotonicity"]
    assert (mono["pairs"], mono["violations"]) == (0, 0)
    assert mono["violation_rate"] is None


# --------------------------------------------------------------------------- #
# The file-reading caller delegates to the pure core
# --------------------------------------------------------------------------- #
def test_compute_env_reads_a_battery_file_and_delegates_to_the_pure_core(tmp_path):
    recs = [summary(), anchor(1.0), probe(v_reward_majority=1.0), probe()]
    path = tmp_path / "acme__demo.battery.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in recs) + "\n")

    from_file = A.compute_env(str(path), {})
    from_records = A.compute_env_from_records(recs[0], recs[1:], {})
    assert from_file == from_records


def test_compute_env_falls_back_to_the_filename_for_the_env_id(tmp_path):
    path = tmp_path / "acme__demo.battery.jsonl"
    path.write_text(json.dumps({"far_bucket": "far", "v_reward_majority": 0.0}) + "\n")
    assert A.compute_env(str(path), {})["env_id"] == "acme/demo"


def test_unparseable_lines_do_not_abort_the_file(tmp_path):
    path = tmp_path / "acme__demo.battery.jsonl"
    path.write_text("\n".join([json.dumps(summary()), "{not json", "",
                               json.dumps(anchor(1.0)), json.dumps(probe())]) + "\n")
    env = A.compute_env(str(path), {})
    assert env["n_far"] == 1
