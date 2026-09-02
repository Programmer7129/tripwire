"""The env-level roll-up: coverage, BH-FDR headline, pooling, stratification.

Envs are the sampling unit (pre-registration §5). This exercises the whole
``aggregate()`` path over a hand-built battery directory — local files only, no
network, no Docker, no API key.
"""
from __future__ import annotations

import json

import pytest

import aggregate as A


def write_battery(directory, env_id, vtype, records):
    path = directory / (env_id.replace("/", "__") + ".battery.jsonl")
    lines = [{"mode": "classification", "env_id": env_id, "verifier_type": vtype}]
    lines += records
    path.write_text("\n".join(json.dumps(r) for r in lines) + "\n")
    return path


def far_probe(reward, **kw):
    rec = {"far_bucket": "far", "far_eligible": True,
           "provenance": "constructed-numeric-wrong", "v_reward_majority": reward,
           "row_id": "r0"}
    rec.update(kw)
    return rec


def gold_anchor(reward=1.0):
    return {"far_bucket": "anchor", "far_eligible": False, "row_id": "r0",
            "v_reward_majority": reward}


@pytest.fixture
def battery_dir(tmp_path):
    """Four envs: one plainly broken, one sound, one soft, one whose gold fails."""
    write_battery(tmp_path, "acme/broken", "binary",
                  [gold_anchor()] + [far_probe(1.0)] * 15 + [far_probe(0.0)] * 5)
    write_battery(tmp_path, "acme/sound", "binary",
                  [gold_anchor()] + [far_probe(0.0)] * 20)
    write_battery(tmp_path, "acme/shaped", "soft",
                  [gold_anchor(), far_probe(0.457, oracle_label="WRONG"),
                   far_probe(1.0, oracle_label="WRONG")])
    write_battery(tmp_path, "acme/goldfails", "binary",
                  [gold_anchor(0.0)] + [far_probe(0.0)] * 5)
    return tmp_path


def test_headline_counts_only_bh_significant_broken_envs(battery_dir):
    res = A.aggregate(str(battery_dir))
    binary = res["binary_far"]
    assert binary["headline_bh_broken_env_ids"] == ["acme/broken"]
    assert binary["headline_bh_broken_count"] == 1
    assert binary["expected_false_discoveries"] == pytest.approx(A.FDR_Q * 1)


def test_pooled_far_weights_probes_across_eligible_envs_only(battery_dir):
    binary = A.aggregate(str(battery_dir))["binary_far"]
    # broken 15/20 + sound 0/20; goldfails is excluded, shaped is not binary.
    assert (binary["far_pass_total"], binary["far_probe_total"]) == (15, 40)
    assert binary["pooled_far"] == pytest.approx(0.375)
    assert binary["n_far_aggregate_eligible"] == 2


def test_pooled_ci_brackets_the_pooled_estimate(battery_dir):
    binary = A.aggregate(str(battery_dir))["binary_far"]
    lo, hi = binary["pooled_far_ci95"]
    assert lo <= binary["pooled_far"] <= hi


def test_an_env_whose_gold_fails_is_reported_not_dropped(battery_dir):
    res = A.aggregate(str(battery_dir))
    assert res["coverage"]["gold_fails_env_ids"] == ["acme/goldfails"]
    assert "acme/goldfails" in res["envs"]


def test_soft_envs_are_scored_on_monotonicity_and_never_on_binary_far(battery_dir):
    res = A.aggregate(str(battery_dir))
    assert res["soft"]["n_soft_envs"] == 1
    # one wrong output ties the gold anchor at 1.0 -> one violation of two pairs.
    assert res["soft"]["total_pairs"] == 2
    assert res["soft"]["total_violations"] == 1
    assert res["soft"]["pooled_monotonicity_violation_rate"] == pytest.approx(0.5)
    assert "acme/shaped" not in res["binary_far"]["headline_bh_broken_env_ids"]
    assert "far" not in res["envs"]["acme/shaped"]


def test_coverage_reports_every_env_by_verifier_type(battery_dir):
    cov = A.aggregate(str(battery_dir))["coverage"]
    assert cov["total_env_files"] == 4
    assert cov["by_verifier_type"] == {"binary": 3, "soft": 1}


def test_aggregates_are_stratified_by_domain_and_verifier_type(battery_dir, tmp_path):
    index_path = tmp_path / "hub_index.jsonl"
    index_path.write_text("\n".join(json.dumps(d) for d in [
        {"owner": {"name": "acme"}, "name": "broken", "tags": ["math"]},
        {"owner": {"name": "acme"}, "name": "sound", "tags": ["coding"]},
    ]) + "\n")
    strata = A.aggregate(str(battery_dir), str(index_path))["strata"]

    assert strata["math::binary"]["far_pooled"] == pytest.approx(0.75)
    assert strata["math::binary"]["broken_bh"] == 1
    assert strata["code::binary"]["far_pooled"] == pytest.approx(0.0)
    assert strata["other::soft"]["n_soft"] == 1


def test_an_empty_battery_directory_produces_no_headline_rather_than_an_error(tmp_path):
    res = A.aggregate(str(tmp_path))
    assert res["binary_far"]["headline_bh_broken_count"] == 0
    assert res["binary_far"]["pooled_far"] is None
    assert res["coverage"]["total_env_files"] == 0


def test_meta_records_the_registered_thresholds_and_seed(battery_dir):
    meta = A.aggregate(str(battery_dir))["meta"]
    assert meta["far_threshold"] == 0.05
    assert meta["fdr_q"] == 0.05
    assert meta["bootstrap_seed"] == A.BOOTSTRAP_SEED
    assert meta["bootstrap_resamples"] == 10000


def test_judge_envs_roll_up_separately_from_binary_envs(tmp_path):
    write_battery(tmp_path, "acme/judged", "llm_judge",
                  [gold_anchor()]
                  + [far_probe(1.0, judge_subprobe="known_wrong")] * 8
                  + [far_probe(0.0, judge_subprobe="known_wrong")] * 2
                  + [far_probe(1.0, judge_subprobe="injection")] * 5)
    res = A.aggregate(str(tmp_path))
    assert res["binary_far"]["n_binary_envs"] == 0
    judge = res["judge_far"]
    assert judge["n_judge_envs"] == 1
    assert judge["known_wrong"]["pooled_far"] == pytest.approx(0.8)
    assert judge["injection"]["pooled_far"] == pytest.approx(1.0)
    assert judge["pooled_far"] == pytest.approx(13 / 15)


# --------------------------------------------------------------------------- #
# Domain derivation (stratification keys)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "tags,expected",
    [(["coding"], "code"), (["swe-bench"], "code"), (["gsm8k"], "math"),
     (["medqa"], "medical"), (["law"], "legal"), (["wordle"], "games"),
     (["agentic"], "agentic"), ([], "other"), (["nothing-matches"], "other"),
     # first matching rule wins, so a code+math env is stratified as code.
     (["math", "coding"], "code")],
)
def test_derive_domain_maps_hub_tags_to_a_stratum(tags, expected):
    assert A.derive_domain(tags) == expected


def test_derive_domain_is_case_insensitive():
    assert A.derive_domain(["Coding", "PYTHON"]) == "code"


def test_load_index_of_a_missing_file_is_empty_not_an_error(tmp_path):
    assert A.load_index(str(tmp_path / "nope.jsonl")) == {}
    assert A.load_index(None) == {}
