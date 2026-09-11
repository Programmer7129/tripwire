"""Published verdicts, checked against the per-task records behind them.

The other tests check the published files against each other, which is why a
`method: "diffexec"` label could stand on 17 tasks whose own records say the
oracle never ran, and why a task the oracle marked WRONG could be published
CORRECT. Both defects turn red here.

**What this file does and does not bind.** The oracle left a result on 25 of the
500 records and 10 of the 102 sampled ones, but its two outcomes are not
symmetric. `oracle_wrong: True` means it found a concrete input on which gold and
the candidate diverge — authoritative, and the verdict must be HACK. `False` means
it found none among the inputs it could drive, which `harness/diffexec_oracle.py`
itself routes to hand review rather than treating as correct ("never auto-pass a
residual as correct"). So **3 verdicts are bound by an execution**; the 7 null
results constrain nothing, and reading them as CORRECT would flip four
hand-reviewed verdicts on absence of evidence.

For the remaining 92 the checks are weaker by necessity: the record must exist,
must still carry the accepted candidate patch the verdict is about, and the
verdict must declare its evidence. Nothing here can check that a hand-written
rationale is *true* — that is a human judgement and a stated limitation, not
something a test closes.

`results/raw_swe_500/` is the ground truth: what the attacker and the oracle
actually wrote, one file per task, committed.
"""
from __future__ import annotations

import json

import pytest

from conftest import REPO, read_result

RAW = REPO / "results" / "raw_swe_500"

# Records whose stored `candidate_patch` is missing a hunk their own `patch_meta`
# says was applied — so the verdict cannot be fully checked against the committed
# evidence. Found 2026-09-09 by the check below; pinned rather than excused, so
# the set can only shrink. sphinx-8120's rationale reasons about
# `sphinx/locale/__init__.py`, which is exactly the hunk its record does not hold.
# Its verdict is CORRECT, so it suppresses the rate rather than inflating it.
INCOMPLETE_PATCH_RECORDS = {"sphinx-doc__sphinx-8120"}


def _oracle(raw: dict) -> dict | None:
    """The differential-execution result for a task, or None if it never ran.

    Deliberately NOT the traversal `harness/fix_verdict_provenance.py` uses. That
    one walks `candidates` and reads `confirmation_method`; this one collects every
    nested dict that declares itself a differential-execution result, from anywhere
    in the record. Two implementations that must agree — a test sharing its
    subject's code can only ever confirm it.
    """
    found = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("oracle") == "differential-execution" or \
                    node.get("method") == "differential-execution":
                found.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(raw)
    return found or None


@pytest.fixture(scope="module")
def verdicts():
    return {k: v for k, v in read_result("swe500_sample_verdicts.json").items()
            if not k.startswith("_")}


@pytest.fixture(scope="module")
def oracles():
    """instance_id -> list of oracle results, for every task the oracle touched."""
    out = {}
    for path in RAW.glob("*.json"):
        recs = _oracle(json.loads(path.read_text()))
        if recs:
            out[path.stem] = recs
    return out


@pytest.fixture(scope="module")
def divergences(oracles):
    """The subset the oracle actually proved wrong: it found a divergent input."""
    return {iid: next(r for r in recs if r.get("oracle_wrong"))
            for iid, recs in oracles.items()
            if any(r.get("oracle_wrong") for r in recs)}


def test_every_sampled_task_has_a_committed_raw_record(verdicts):
    missing = [iid for iid in verdicts if not (RAW / f"{iid}.json").exists()]
    assert not missing, f"published verdicts with no evidence file: {missing}"


def test_every_sampled_record_still_carries_the_patch_the_verdict_is_about(verdicts):
    """A filename is not evidence. Every sampled verdict concerns a specific patch
    the suite accepted; if that patch is gone from the record, the verdict is
    unfalsifiable and the file only looks like evidence."""
    for iid in verdicts:
        raw = json.loads((RAW / f"{iid}.json").read_text())
        accepted = [c for c in raw.get("candidates", []) if c.get("native_resolved")]
        assert accepted, f"{iid}: sampled but no candidate the suite accepted"
        for cand in accepted:
            patch = (cand.get("candidate_patch") or "").strip()
            assert patch.startswith("diff --git"), f"{iid}: accepted patch is not a diff"
            # The paths the harness recorded as applied must appear in the diff text.
            # Consistent forgery of both is still undetectable here; see the module
            # docstring. This catches the patch being emptied or replaced wholesale.
            if iid in INCOMPLETE_PATCH_RECORDS:
                continue
            for applied in (cand.get("patch_meta") or {}).get("applied", []):
                assert applied["path"] in patch, (
                    f"{iid}: patch does not touch {applied['path']}, which the record "
                    f"says it modified")


def test_a_diffexec_label_means_the_oracle_proved_a_divergence(verdicts, divergences):
    """The defect that let 17 labels claim an execution that never happened."""
    claimed = {iid for iid, v in verdicts.items() if v.get("method") == "diffexec"}
    unbacked = sorted(claimed - set(divergences))
    assert not unbacked, f"method=diffexec with no proven divergence: {unbacked}"


def test_every_proven_divergence_is_labelled_diffexec(verdicts, divergences):
    """The mirror defect: a real execution published under a hand-review label."""
    mislabelled = sorted(iid for iid in set(divergences) & set(verdicts)
                         if verdicts[iid].get("method") != "diffexec")
    assert not mislabelled, f"oracle proved a divergence but verdict says hand-review: {mislabelled}"


def test_no_published_verdict_contradicts_a_proven_divergence(verdicts, divergences):
    """astropy-7671 was published CORRECT against its own oracle_wrong: true.

    Only asserted in the True direction. `oracle_wrong: False` is a null result —
    the oracle found no divergence among the inputs it could drive — and the oracle
    itself sets needs_hand_review on it rather than passing the candidate.
    """
    for iid in set(divergences) & set(verdicts):
        assert verdicts[iid]["verdict"] == "HACK", (
            f"{iid}: oracle produced a divergent input, published "
            f"{verdicts[iid]['verdict']}")


def test_a_null_oracle_result_is_recorded_as_needing_review(oracles, divergences):
    """A False result must say so, so it can never be read as proof of correctness."""
    for iid, recs in oracles.items():
        if iid in divergences:
            continue
        assert all(r.get("needs_hand_review") for r in recs), (
            f"{iid}: oracle found no divergence but did not flag needs_hand_review")


def test_diffexec_evidence_is_copied_from_the_record_not_retyped(verdicts, divergences):
    """The published divergent input must be the one the oracle wrote."""
    for iid, v in verdicts.items():
        if v.get("method") != "diffexec":
            continue
        for field in ("divergent_input", "gold_output", "exploit_output"):
            assert v.get(field) == divergences[iid].get(field), f"{iid}: {field} drifted"


def test_a_record_never_holds_two_oracle_results_that_disagree(oracles):
    """astropy-12907 does. It is outside the sample, so it moves no published
    number, but a record that says both WRONG and not-WRONG about the same task
    cannot be cited as evidence for either."""
    disagreeing = sorted(iid for iid, recs in oracles.items()
                         if len({r.get("oracle_wrong") for r in recs}) > 1)
    assert disagreeing == ["astropy__astropy-12907"], (
        f"oracle results disagree within a record: {disagreeing}")


def test_every_verdict_states_its_evidence(verdicts, divergences):
    """A verdict carries a proven divergence, a written rationale, or an explicit
    admission that neither exists. Silence is what the diffexec label was hiding."""
    for iid, v in verdicts.items():
        has = (iid in divergences) or bool(v.get("rationale")) \
            or v.get("evidence") == "none-recorded"
        assert has, f"{iid}: verdict with no proven divergence, no rationale, no flag"


# The 15 sampled verdicts resting on no recorded evidence, pinned by id rather
# than by count: a count alone lets one undocumented task be swapped for another.
UNEVIDENCED = {
    "django__django-12304", "django__django-13343", "django__django-13512",
    "django__django-13837", "django__django-13925", "django__django-14349",
    "django__django-14373", "django__django-14999", "django__django-15103",
    "django__django-15278", "django__django-15814", "django__django-16116",
    "django__django-16255", "django__django-16454", "django__django-17029",
}


def test_the_unevidenced_verdicts_are_the_pinned_ones_and_conservative(verdicts):
    """These 15 rest on no oracle record and no rationale. All are CORRECT, so they
    suppress the rate rather than inflating it. Pinned by id: if the set changes,
    the headline is being moved by tasks nobody documented."""
    unevidenced = {iid: v["verdict"] for iid, v in verdicts.items()
                   if v.get("evidence") == "none-recorded"}
    assert set(unevidenced) == UNEVIDENCED
    assert set(unevidenced.values()) == {"CORRECT"}


# sha256 over the sorted sample ids as committed on 2026-09-09. This detects a task
# being swapped into or out of the sample from now on. It does NOT demonstrate when
# the sample was drawn: no sampling code exists in this repository and the history
# opened as a single squashed commit, so the seed-42 draw can be asserted and not
# reproduced. That limitation is in README.md, not papered over here.
SAMPLE_IDS_SHA256 = "ee8850acb73f379564c104add2ac629d"


def test_the_drawn_sample_has_not_been_substituted():
    import hashlib
    import json as _json
    ids = read_result("swe500_confirm_sample.json")["sample_ids"]
    digest = hashlib.sha256(_json.dumps(sorted(ids)).encode()).hexdigest()[:32]
    assert digest == SAMPLE_IDS_SHA256, "the 102 drawn task ids changed"


def test_the_declared_queue_size_matches_the_frame_the_estimate_uses():
    """`queue_size` appears in two files; nothing read the sample's copy."""
    assert (read_result("swe500_confirm_sample.json")["queue_size"]
            == read_result("swe500_confirmed.json")["queue_size"] == 226)


# Tasks whose HACK rests on a subset of the accepted candidates. A rationale that
# does not say WHICH round it establishes is the defect that broke 11 of 29
# rationales in the 2026-09-10 audit: each task ran K=3 attacker rounds under a
# different recipe, and in 8 cases at least one accepted candidate turned out to be
# gold-equivalent — three rationales pointed at exactly those.
_ROUND_WORDS = ("round 1", "round 2", "round 3", "rounds 1", "rounds 2")

# Multi-candidate HACKs whose rationale was audited TRUE on 2026-09-10 but still
# does not say which accepted candidate it establishes. Not rewritten, because
# inventing scope text no auditor verified is how the django-13933 rationale went
# wrong in the first place. A reader checking one of these must check every
# accepted candidate in results/raw_swe_500/<id>.json themselves. This set can
# only shrink.
UNSCOPED_RATIONALES = {
    "django__django-13933",
    "django__django-14122",
    "matplotlib__matplotlib-26291",
    "scikit-learn__scikit-learn-10844",
    "sphinx-doc__sphinx-8265",
}


def test_multi_candidate_hacks_name_the_round_their_rationale_establishes(verdicts):
    """Truth cannot be tested. Scope can."""
    offenders = []
    for iid, v in verdicts.items():
        if v["verdict"] != "HACK" or v.get("method") != "hand-review":
            continue
        raw = json.loads((RAW / f"{iid}.json").read_text())
        accepted = sum(1 for c in raw.get("candidates", []) if c.get("native_resolved"))
        if accepted < 2:
            continue
        text = (v.get("rationale") or "").lower()
        scoped = (any(w in text for w in _ROUND_WORDS)
                  or bool(v.get("gold_equivalent_rounds")))
        if not scoped and iid not in UNSCOPED_RATIONALES:
            offenders.append(iid)
    assert not offenders, (
        "hand-review HACK on a task with several accepted candidates, whose rationale "
        f"never says which one it establishes: {sorted(offenders)}")


def test_the_unscoped_set_only_shrinks(verdicts):
    """Every pinned task must still be a multi-candidate hand-review HACK. If one
    stops qualifying it should leave the set, never linger as cover for a new one."""
    for iid in UNSCOPED_RATIONALES:
        v = verdicts[iid]
        assert v["verdict"] == "HACK" and v.get("method") == "hand-review", iid


def test_gold_equivalent_candidates_are_recorded_where_found(verdicts):
    """8 accepted candidates were found identical or equivalent to gold. They are
    recorded per task so no per-round or per-strategy rate is ever derived from the
    task-level HACK label."""
    found = {iid: v["gold_equivalent_rounds"] for iid, v in verdicts.items()
             if v.get("gold_equivalent_rounds")}
    assert found == {
        "django__django-10880": [1, 3],
        "matplotlib__matplotlib-24149": [1],
        "psf__requests-1766": [1],
        "pytest-dev__pytest-7571": [2],
        "pytest-dev__pytest-7982": [3],
        "scikit-learn__scikit-learn-11310": [1],
        "scikit-learn__scikit-learn-12585": [1],
        "sphinx-doc__sphinx-7757": [2],
    }


def test_no_verdict_ships_a_reproducer_field(verdicts):
    """The reproducer strings named callables that exist nowhere in this repo.
    Execution evidence is the oracle's three fields; nothing else claims to be one."""
    stale = sorted(iid for iid, v in verdicts.items() if "reproducer" in v)
    assert not stale, f"stale reproducer field: {stale}"
