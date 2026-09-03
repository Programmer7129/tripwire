"""The published 51.0% must derive from the committed attack records.

Pins the three inputs ``swe_confirm`` declares, against the evidence now
committed under ``results/raw_swe_500/``. If these drift, the README headline
and the repository disagree, which is the failure this test exists to catch.
"""
from __future__ import annotations

import json
import os

import pytest

import swe_native_rate as N

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DECLARED = os.path.join(REPO, "results", "swe500_confirmed.json")


@pytest.fixture(scope="module")
def derived() -> dict:
    return N.derive(N.load_records())


def test_five_hundred_tasks_were_attacked(derived):
    assert derived["total_tasks"] == 500


def test_native_hackable_is_the_published_255(derived):
    assert derived["native_hackable"] == 255


def test_native_rate_is_the_published_51_percent(derived):
    assert derived["native_rate"] == pytest.approx(0.510, abs=5e-4)


def test_confirm_queue_is_the_published_226(derived):
    assert derived["queue_size"] == 226


def test_derived_inputs_match_what_the_estimator_declares(derived):
    """swe_confirm.py reads these as constants; they must equal the evidence."""
    declared = json.load(open(DECLARED))
    for key in ("total_tasks", "native_hackable", "queue_size"):
        assert derived[key] == declared[key], f"{key} disagrees with the evidence"


def test_queue_is_a_subset_of_native_hackable(derived):
    """Behavioural distinctness only ever removes tasks, never adds them."""
    assert derived["queue_size"] <= derived["native_hackable"] <= derived["total_tasks"]


def test_derive_is_pure_on_a_synthetic_corpus():
    """Two tasks: one resolved-and-distinct, one resolved-but-identical to gold."""
    records = [
        {"candidates": [{"native_resolved": True, "behaviorally_distinct": True}]},
        {"candidates": [{"native_resolved": True, "behaviorally_distinct": False}]},
        {"candidates": [{"native_resolved": False, "behaviorally_distinct": True}]},
    ]
    d = N.derive(records)
    assert (d["total_tasks"], d["native_hackable"], d["queue_size"]) == (3, 2, 1)
