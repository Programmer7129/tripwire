"""Every published verdict must agree with the per-task record behind it.

This is the join the suite was missing. The other tests check the published
files against each other, which is why a `method: "diffexec"` label could stand
on 17 tasks whose own records say the oracle never ran, and why a task the
oracle marked WRONG could be published CORRECT. Both defects turn red here.

`results/raw_swe_500/` is the ground truth: it is what the attacker and the
oracle actually wrote, one file per task, committed.
"""
from __future__ import annotations

import json

import pytest

from conftest import REPO, read_result

RAW = REPO / "results" / "raw_swe_500"


def _oracle(raw: dict) -> dict | None:
    """The differential-execution result for a task, or None if it never ran."""
    for cand in raw.get("candidates", []):
        de = cand.get("diffexec_result") or {}
        if (cand.get("confirmation_method") or de.get("method")) == "differential-execution":
            return de
    return None


@pytest.fixture(scope="module")
def verdicts():
    return {k: v for k, v in read_result("swe500_sample_verdicts.json").items()
            if not k.startswith("_")}


@pytest.fixture(scope="module")
def oracles():
    """instance_id -> oracle result, for every sampled task that ran the oracle."""
    out = {}
    for path in RAW.glob("*.json"):
        rec = _oracle(json.loads(path.read_text()))
        if rec:
            out[path.stem] = rec
    return out


def test_every_sampled_task_has_a_committed_raw_record(verdicts):
    missing = [iid for iid in verdicts if not (RAW / f"{iid}.json").exists()]
    assert not missing, f"published verdicts with no evidence file: {missing}"


def test_a_diffexec_label_means_the_oracle_actually_ran(verdicts, oracles):
    """The defect that let 17 labels claim an execution that never happened."""
    claimed = {iid for iid, v in verdicts.items() if v.get("method") == "diffexec"}
    unbacked = sorted(claimed - set(oracles))
    assert not unbacked, f"method=diffexec with no differential-execution record: {unbacked}"


def test_every_oracle_run_is_labelled_diffexec(verdicts, oracles):
    """The mirror defect: a real execution published under a hand-review label."""
    sampled_with_oracle = set(oracles) & set(verdicts)
    mislabelled = sorted(iid for iid in sampled_with_oracle
                         if verdicts[iid].get("method") != "diffexec")
    assert not mislabelled, f"oracle ran but verdict says hand-review: {mislabelled}"


def test_no_published_verdict_contradicts_its_oracle(verdicts, oracles):
    """astropy-7671 was published CORRECT against its own oracle_wrong: true."""
    for iid, oracle in oracles.items():
        if iid not in verdicts:
            continue
        expected = "HACK" if oracle.get("oracle_wrong") else "CORRECT"
        assert verdicts[iid]["verdict"] == expected, (
            f"{iid}: oracle_wrong={oracle.get('oracle_wrong')} implies {expected}, "
            f"published {verdicts[iid]['verdict']}")


def test_diffexec_evidence_is_copied_from_the_record_not_retyped(verdicts, oracles):
    """The published divergent input must be the one the oracle wrote."""
    for iid, v in verdicts.items():
        if v.get("method") != "diffexec":
            continue
        for field in ("divergent_input", "gold_output", "exploit_output"):
            assert v.get(field) == oracles[iid].get(field), f"{iid}: {field} drifted"


def test_every_verdict_states_its_evidence(verdicts, oracles):
    """A verdict carries an oracle record, a written rationale, or an explicit
    admission that neither exists. Silence is what the diffexec label was hiding."""
    for iid, v in verdicts.items():
        has = (iid in oracles) or bool(v.get("rationale")) or v.get("evidence") == "none-recorded"
        assert has, f"{iid}: verdict with no oracle record, no rationale, no flag"


def test_the_unevidenced_verdicts_are_counted_and_conservative(verdicts):
    """15 sampled verdicts rest on no recorded evidence. All are CORRECT, so they
    suppress the confirmed rate rather than inflating it. If that ever stops being
    true the headline is being moved by tasks nobody documented."""
    unevidenced = {iid: v["verdict"] for iid, v in verdicts.items()
                   if v.get("evidence") == "none-recorded"}
    assert len(unevidenced) == 15
    assert set(unevidenced.values()) == {"CORRECT"}


def test_no_verdict_ships_a_reproducer_field(verdicts):
    """The reproducer strings named callables that exist nowhere in this repo.
    Execution evidence is the oracle's three fields; nothing else claims to be one."""
    stale = sorted(iid for iid, v in verdicts.items() if "reproducer" in v)
    assert not stale, f"stale reproducer field: {stale}"
