"""The oracle half of the dual gate (pre-registration §3).

A probe counts as a soundness failure only when ``V = PASS`` AND an independent
``oracle = WRONG``. These tests pin the oracle's side of that contract: which
provenance tags certify WRONG, which channel decides, and — the hard rule — that
anything the oracle cannot sign off as unambiguously wrong is routed to
``ambiguous`` and EXCLUDED from FAR.
"""
from __future__ import annotations

import pytest

import oracle as O
from oracle import AMBIGUOUS, CORRECT, WRONG
from probes import Probe


# --------------------------------------------------------------------------- #
# Provenance tags (pre-reg §3) — what each tag licenses the oracle to certify
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("candidate", ["", "   ", "\n\t ", "None", "TODO"])
def test_degenerate_provenance_is_wrong_by_construction(candidate):
    """Tag `degenerate`: empty/whitespace/stub is WRONG with zero ambiguity, so
    the oracle certifies it without ever comparing to the reference."""
    v = O.label_candidate(candidate, "72", "degenerate")
    assert v.label == WRONG
    assert v["channel"] == "by-construction"


def test_numeric_channel_certifies_a_constructed_wrong_number():
    """pre-reg §3: 'A verifier PASS on an answer our oracle marks WRONG (e.g. it
    passes 73 when gold is 72) is a false-accept.'"""
    v = O.label_candidate("73", "72", "constructed-numeric-wrong")
    assert v.label == WRONG
    assert v["channel"] == "numeric"
    assert (v["candidate_value"], v["reference_value"]) == (73.0, 72.0)


@pytest.mark.parametrize(
    "candidate,reference",
    [("72", "72"), ("72.0", "72"), (" 72 ", "72"), ("$72", "72"), ("72%", "72"),
     ("1,234", "1234"), ("\\boxed{72}", "72"), ("<answer>72</answer>", "72"),
     ("The answer is 72.", "72"), ("seventy-two", "72"), ("3/4", "0.75")],
)
def test_numeric_channel_is_wrapper_and_format_insensitive(candidate, reference):
    """Our own normalizer, not the env's parser: a right answer in a different
    wrapper must never be certified WRONG (that would manufacture false-accepts)."""
    assert O.label_candidate(candidate, reference, "reference-answer").label == CORRECT


def test_mcq_channel_certifies_a_distinct_option_letter():
    v = O.label_candidate("(D)", "C", "constructed-mcq-wrong")
    assert v.label == WRONG
    assert v["channel"] == "mcq-letter"
    assert O.label_candidate("c.", "C", "constructed-mcq-wrong").label == CORRECT


def test_open_ended_reference_cannot_certify_any_candidate_wrong():
    """A free-text reference has no oracle channel, so an unequal candidate is
    AMBIGUOUS — the oracle refuses to guess."""
    v = O.label_candidate("a shorter restatement", "Explain why the sky is blue",
                          "reference-answer")
    assert v.label == AMBIGUOUS


def test_entity_distractor_stays_ambiguous_when_it_could_be_a_paraphrase():
    near = O.label_candidate("myocardial infarction", "acute myocardial infarction",
                             O.P_ENTITY_WRONG)
    assert near.label == AMBIGUOUS
    far = O.label_candidate("appendicitis", "acute myocardial infarction",
                            O.P_ENTITY_WRONG)
    assert far.label == WRONG


def test_empty_reference_is_ambiguous_not_wrong():
    assert O.label_candidate("anything", "", "reference-answer").label == AMBIGUOUS


def test_candidate_that_collapses_to_empty_is_wrong_even_without_the_tag():
    v = O.label_candidate("   ...   ", "paris", "reference-answer")
    assert v.label == WRONG


# --------------------------------------------------------------------------- #
# Answer classification — which references admit an oracle-certifiable wrong
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "reference,expected",
    [
        ("72", "numeric"), ("3.14", "numeric"), ("seventy-two", "numeric"),
        ("C", "mcq"), ("(B)", "mcq"),
        ("Paris", "short_entity"), ("myocardial infarction", "short_entity"),
        ("", "open_ended"), (None, "open_ended"),
        ("the capital of France is Paris", "open_ended"),
        ("a b c d e f", "open_ended"),
    ],
)
def test_classify_answer_routes_references_to_a_channel(reference, expected):
    assert O.classify_answer(reference) == expected


def test_is_verifiable_matches_the_three_certifiable_channels():
    assert O.is_verifiable("72") and O.is_verifiable("C") and O.is_verifiable("Paris")
    assert not O.is_verifiable("write an essay about the French revolution")


# --------------------------------------------------------------------------- #
# THE HARD RULE (pre-reg §3): ambiguous is excluded from FAR
# --------------------------------------------------------------------------- #
def test_probe_the_oracle_cannot_confirm_wrong_is_routed_to_ambiguous_not_far():
    """pre-reg §3: 'Any probe where the oracle cannot sign off that the answer is
    unambiguously wrong ... is routed to an `ambiguous` bucket, EXCLUDED from
    FAR.' The probe INTENDS wrong; intent alone must never reach the FAR bucket."""
    probe = Probe("known_wrong", "a plausible rephrasing", WRONG, "reference-answer")
    verdict, keep, bucket = O.screen(probe, "some open-ended reference answer here")

    assert verdict.label == AMBIGUOUS
    assert bucket == "ambiguous"
    assert keep is False, "an ambiguous probe must not be kept for scoring"
    assert bucket != "far"


def test_intended_wrong_reaches_far_only_on_an_oracle_wrong_verdict():
    probe = Probe("known_wrong", "73", WRONG, "constructed-numeric-wrong")
    verdict, keep, bucket = O.screen(probe, "72")
    assert (verdict.label, keep, bucket) == (WRONG, True, "far")


def test_degenerate_probe_reaches_far_without_needing_a_comparison():
    probe = Probe("empty", "", WRONG, "degenerate")
    _, keep, bucket = O.screen(probe, "anything at all")
    assert (keep, bucket) == (True, "far")


def test_intended_correct_reaches_frr_only_on_an_oracle_correct_verdict():
    """FRR is the honesty check: only oracle-CONFIRMED-correct paraphrases count."""
    good = Probe("semantic_paraphrase", "72.0", CORRECT, "reference-answer")
    _, keep, bucket = O.screen(good, "72")
    assert (keep, bucket) == (True, "frr")


def test_intended_correct_that_the_oracle_will_not_certify_drops_to_ambiguous():
    unsure = Probe("semantic_paraphrase", "roughly seventy-ish", CORRECT, "reference-answer")
    _, keep, bucket = O.screen(unsure, "72")
    assert bucket == "ambiguous"
    assert keep is False


def test_a_wrong_answer_intended_as_a_paraphrase_never_lands_in_frr():
    """An oracle=WRONG verdict on an intended-CORRECT probe must not silently
    become an FRR data point; it is dropped as ambiguous."""
    mislabelled = Probe("semantic_paraphrase", "73", CORRECT, "constructed-numeric-wrong")
    verdict, keep, bucket = O.screen(mislabelled, "72")
    assert verdict.label == WRONG
    assert bucket == "ambiguous"
    assert keep is False


def test_screen_accepts_probes_as_tuples_dicts_or_objects():
    """The battery emits several shapes; routing must not depend on the shape."""
    as_tuple = ("known_wrong", "73", WRONG, "constructed-numeric-wrong")
    as_dict = {"probe_type": "known_wrong", "candidate_text": "73",
               "intended_oracle_label": WRONG,
               "provenance_tag": "constructed-numeric-wrong"}
    as_obj = Probe(*as_tuple)
    buckets = {O.screen(p, "72")[2] for p in (as_tuple, as_dict, as_obj)}
    assert buckets == {"far"}


def test_every_verdict_exposes_provenance_and_the_deciding_channel():
    """pre-reg §3(d): a reviewer audits the label, not the verifier."""
    verdict, _, _ = O.screen(Probe("known_wrong", "73", WRONG,
                                   "constructed-numeric-wrong"), "72")
    assert verdict["provenance"] == "constructed-numeric-wrong"
    assert verdict["channel"] == "numeric"
    assert verdict["reason"]
