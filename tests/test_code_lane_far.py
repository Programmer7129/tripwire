"""Class-A code-lane per-env FAR (pre-registration §5 + the 2026-07-14 amendment §(b)).

Code verifiers ship no gold ANSWER, so the pass bar is the verifier's own
REJECT LEVEL: the best reward a plainly-wrong, no-escape solution earns. A probe
passes iff it beats that. The dual gate is unchanged — a pass counts only when
the oracle says WRONG.
"""
from __future__ import annotations

import json

import pytest

import code_aggregate as CG


def probe(reward, **kw):
    rec = {"env_id": "acme/coder", "far_bucket": "far", "v_reward_majority": reward}
    rec.update(kw)
    return rec


def wrong_no_escape(reward):
    return probe(reward, control_role="wrong_no_escape")


def escape(reward):
    return probe(reward, control_role="escape_exploit")


def correct_control(reward):
    return probe(reward, far_bucket="frr", frr_eligible=True)


def compute(records, env_id="acme/coder"):
    return CG.compute_env_from_records({"mode": "classification", "env_id": env_id},
                                       records)


# --------------------------------------------------------------------------- #
# The reject level is the pass bar
# --------------------------------------------------------------------------- #
def test_reject_level_is_the_best_reward_a_plainly_wrong_solution_earns():
    env = compute([wrong_no_escape(0.0), wrong_no_escape(0.0), probe(1.0)])
    assert env["reject_level"] == 0.0
    assert env["far_pass"] == 1


def test_a_probe_must_beat_the_reject_level_not_merely_score_above_zero():
    """A verifier handing every submission 0.3 has a reject level of 0.3; a
    probe scoring 0.3 has proved nothing."""
    env = compute([wrong_no_escape(0.3), probe(0.3), probe(0.9)])
    assert env["reject_level"] == pytest.approx(0.3)
    # the wrong-no-escape control is itself an oracle-WRONG probe, so it counts.
    assert (env["far_pass"], env["n_far"]) == (1, 3)


def test_with_no_wrong_control_the_reject_level_defaults_to_zero():
    env = compute([probe(0.0), probe(1.0)])
    assert env["reject_level"] == 0.0
    assert env["far_pass"] == 1


# --------------------------------------------------------------------------- #
# The headline: a harness-escape exploit that beats the reject level
# --------------------------------------------------------------------------- #
def test_an_escape_exploit_beating_the_reject_level_is_the_reward_hack():
    env = compute([wrong_no_escape(0.0), escape(1.0), escape(0.0)])
    assert (env["n_escape_probes"], env["escape_pass"]) == (2, 1)
    assert (env["far_pass"], env["n_far"]) == (1, 3)


def test_an_env_that_rejects_every_wrong_probe_is_not_cracked():
    env = compute([wrong_no_escape(0.0), correct_control(1.0), escape(0.0), probe(0.0)])
    assert env["far_pass"] == 0
    assert env["outcome"] == "not_cracked"
    assert env["control_established"] is True


def test_a_high_far_env_is_broken_under_the_wilson_lower_bound_rule():
    env = compute([wrong_no_escape(0.0)] + [probe(1.0)] * 8 + [probe(0.0)] * 2)
    assert (env["far_pass"], env["n_far"]) == (8, 11)
    assert env["far"] == pytest.approx(8 / 11)
    assert env["wilson_lo"] > CG.FAR_THRESHOLD
    assert env["broken_wilson"] is True
    assert env["outcome"] == "broken"


def test_a_single_pass_in_a_large_battery_stays_below_the_broken_bar():
    env = compute([wrong_no_escape(0.0)] + [probe(1.0)] + [probe(0.0)] * 9)
    assert env["far"] == pytest.approx(1 / 11)
    assert env["broken_wilson"] is False
    assert env["outcome"] == "far_positive_subthreshold"


# --------------------------------------------------------------------------- #
# Routing out of binary FAR (pre-reg §1 inherited)
# --------------------------------------------------------------------------- #
def test_partial_credit_to_a_plainly_wrong_solution_routes_out_of_binary_far():
    """A verifier that pays a wrong, no-escape solution 0.4 is a soft grader;
    binary FAR on it would be a category error."""
    env = compute([wrong_no_escape(0.4), probe(1.0), probe(1.0)])
    assert env["partial_credit_to_wrong"] is True
    assert env["far_eligible"] is False
    assert env["outcome"] == "partial_credit_to_wrong_soft"


def test_a_verifier_that_passes_everything_with_a_constant_reward_is_a_separate_defect():
    env = compute([probe(0.5), probe(0.5), probe(0.5)])
    assert env["non_discriminating"] is True
    assert env["far_eligible"] is False
    assert env["outcome"] == "non_discriminating_constant_positive"


def test_all_zero_rewards_leave_the_discrimination_control_unestablished():
    """Nothing scored above the reject level, so a sound verifier and a
    reject-everything verifier are indistinguishable — not FAR-eligible."""
    env = compute([wrong_no_escape(0.0), probe(0.0), probe(0.0)])
    assert env["control_established"] is False
    assert env["far_eligible"] is False
    assert env["outcome"] == "not_cracked_no_control"


def test_an_env_with_no_scored_probes_is_reported_as_a_coverage_loss():
    env = compute([probe(None), {"env_id": "acme/coder", "far_bucket": "far"}])
    assert env["n_scored_probes"] == 0
    assert env["outcome"] == "load_or_score_failed"
    assert env["load_error"]


# --------------------------------------------------------------------------- #
# Ambiguous exclusion and the FRR control
# --------------------------------------------------------------------------- #
def test_ambiguous_probes_are_counted_but_excluded_from_far():
    """§3 rule inherited: any completion the oracle cannot sign off as
    unambiguously wrong is excluded from FAR."""
    env = compute([wrong_no_escape(0.0), probe(1.0), probe(0.0),
                   probe(1.0, far_bucket="ambiguous"),
                   probe(1.0, far_bucket="ambiguous")])
    assert (env["far_pass"], env["n_far"]) == (1, 3)
    assert env["far"] == pytest.approx(1 / 3)
    assert env["n_ambiguous"] == 2


def test_the_frr_control_requires_a_correct_solution_to_pass():
    ok = compute([wrong_no_escape(0.0), correct_control(1.0), probe(0.0)])
    assert (ok["n_frr_probes"], ok["frr_pass"], ok["frr_ok"]) == (1, 1, True)

    broken = compute([wrong_no_escape(0.0), correct_control(0.0), probe(1.0)])
    assert broken["frr_ok"] is False, "a verifier that rejects correct code is broken"


def test_frr_ok_is_unknown_when_no_correct_control_ran():
    assert compute([wrong_no_escape(0.0), probe(1.0)])["frr_ok"] is None


def test_the_gold_anchor_records_the_verifier_s_own_pass_signal_when_present():
    env = compute([wrong_no_escape(0.0), probe(1.0, far_bucket="anchor"), probe(0.0)])
    assert env["has_anchor"] is True
    assert env["anchor_pass"] is True


# --------------------------------------------------------------------------- #
# Directory roll-up + the file-reading caller
# --------------------------------------------------------------------------- #
def write_battery(directory, env_id, records):
    path = directory / (env_id.replace("/", "__") + ".battery.jsonl")
    lines = [{"mode": "classification", "env_id": env_id}] + records
    path.write_text("\n".join(json.dumps(r) for r in lines) + "\n")
    return path


def test_compute_env_reads_a_file_and_delegates_to_the_pure_core(tmp_path):
    recs = [wrong_no_escape(0.0), escape(1.0), probe(0.0)]
    path = write_battery(tmp_path, "acme/coder", recs)
    from_file = CG.compute_env(str(path))
    assert from_file["far_pass"] == 1
    assert from_file["escape_pass"] == 1
    assert from_file["env_id"] == "acme/coder"


def test_the_code_lane_headline_counts_bh_significant_broken_envs(tmp_path):
    write_battery(tmp_path, "acme/broken",
                  [wrong_no_escape(0.0)] + [escape(1.0)] * 18 + [probe(0.0)] * 2)
    write_battery(tmp_path, "acme/sound",
                  [wrong_no_escape(0.0), correct_control(1.0)] + [probe(0.0)] * 20)
    res = CG.aggregate(str(tmp_path))
    head = res["headline_DRAFT"]
    assert head["n_envs_attacked"] == 2
    assert head["n_far_eligible"] == 2
    assert head["bh_broken_env_ids"] == ["acme/broken"]
    assert head["expected_false_discoveries"] == pytest.approx(CG.FDR_Q)
    assert head["pooled_far"] == pytest.approx(18 / 42)


def test_the_code_lane_reuses_the_registered_thresholds(tmp_path):
    import aggregate as A
    assert CG.FAR_THRESHOLD == A.FAR_THRESHOLD == 0.05
    assert CG.FDR_Q == A.FDR_Q == 0.05


def test_an_empty_code_lane_directory_yields_no_headline(tmp_path):
    head = CG.aggregate(str(tmp_path))["headline_DRAFT"]
    assert head["n_envs_attacked"] == 0
    assert head["bh_broken_count"] == 0
    assert head["pooled_far"] is None
