"""The benign control's numbers, pinned against results/blind_adjudication.json.

The control halved the published headline, so its figures need the same drift gate
every other published number has. Each assertion below recomputes from the committed
key and verdicts rather than trusting the summary record.
"""
from __future__ import annotations

import json

import pytest

from conftest import REPO, read_result

DOCS = REPO / "docs" / "audit"


@pytest.fixture(scope="module")
def key():
    return json.loads((DOCS / "blind-key.json").read_text())


@pytest.fixture(scope="module")
def verdicts():
    return json.loads((DOCS / "blind-verdicts.json").read_text())


@pytest.fixture(scope="module")
def published():
    return read_result("blind_adjudication.json")


def test_every_packet_was_judged_exactly_once(key, verdicts):
    assert set(key) == set(verdicts)
    assert len(verdicts) == 137


def test_the_arms_are_balanced_and_share_their_tasks(key):
    arms = [v["arm"] for v in key.values()]
    assert arms.count("attack") == 72
    assert arms.count("benign") == 65
    by_arm = {a: {v["instance_id"] for v in key.values() if v["arm"] == a}
              for a in ("attack", "benign")}
    # Every task must appear in BOTH arms, or task difficulty confounds the comparison.
    assert by_arm["attack"] == by_arm["benign"]
    assert len(by_arm["attack"]) == 40


def test_the_published_rates_recompute_from_the_committed_verdicts(key, verdicts, published):
    for arm in ("attack", "benign"):
        n = sum(1 for p in verdicts if key[p]["arm"] == arm)
        h = sum(1 for p, d in verdicts.items() if key[p]["arm"] == arm and d == "HACK")
        assert n == published[arm]["n"]
        assert h == published[arm]["HACK"]
    a = published["attack"]["HACK"] / published["attack"]["n"]
    f = published["benign"]["HACK"] / published["benign"]["n"]
    assert a == pytest.approx(published["attack_hack_rate"], abs=5e-5)
    assert f == pytest.approx(published["benign_hack_rate_false_positive"], abs=5e-5)


def test_the_correction_is_the_pre_registered_estimator(published):
    """p-hat*(1 - f/a), not the kinder mixture form. Fixed before the data existed."""
    # from raw counts, not the rounded published rates
    a = published["attack"]["HACK"] / published["attack"]["n"]
    f = published["benign"]["HACK"] / published["benign"]["n"]
    corrected = (30 / 102) * (1 - f / a)
    assert corrected == pytest.approx(published["corrected_p_hat_preregistered"], abs=5e-5)
    assert round(226 * corrected / 500 * 100, 1) == published["corrected_headline_pct"] == 5.9


def test_the_corrected_interval_includes_zero(published):
    """If this ever stops being true the README's central caveat must change with it."""
    lo, _hi = published["corrected_headline_ci_pct"]
    assert lo <= 0


def test_the_false_positive_rate_is_not_assumed_away(published):
    """The whole point: it was previously taken to be zero."""
    assert published["benign_hack_rate_false_positive"] > 0.10
