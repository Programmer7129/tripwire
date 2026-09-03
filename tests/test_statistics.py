"""Rate arithmetic and confidence intervals (pre-registration §5).

These primitives turn per-probe counts into the published headline, so every
expected value below comes from an independent source: a closed form, a
defining property of the interval, a hand-computed binomial tail, or the
worked example in the Benjamini-Hochberg paper. None of them re-runs the
implementation's own algebra.
"""
from __future__ import annotations

import math

import pytest

import aggregate as A

Z = A.WILSON_Z


# --------------------------------------------------------------------------- #
# Wilson score interval — the per-env "broken" label and the published CI
# --------------------------------------------------------------------------- #
def score_statistic(p_hat: float, p: float, n: int) -> float:
    """|p_hat - p| / sqrt(p(1-p)/n) — the statistic the Wilson interval inverts.

    Independent of the implementation: the Wilson interval is DEFINED as the set
    of p for which this stays <= z, so at each endpoint it must equal z exactly.
    """
    return abs(p_hat - p) / math.sqrt(p * (1 - p) / n)


@pytest.mark.parametrize("k,n", [(1, 10), (5, 50), (31, 102), (13, 20), (99, 100)])
def test_wilson_endpoints_solve_the_score_equation(k, n):
    lo, hi = A.wilson_interval(k, n)
    assert score_statistic(k / n, lo, n) == pytest.approx(Z, abs=1e-9)
    assert score_statistic(k / n, hi, n) == pytest.approx(Z, abs=1e-9)


@pytest.mark.parametrize(
    "k,n,lo,hi",
    [
        # k=0: the score equation collapses to hi = z^2 / (n + z^2), lo = 0.
        (0, 10, 0.0, Z * Z / (10 + Z * Z)),
        # k=n: mirror image — lo = n / (n + z^2), hi = 1.
        (10, 10, 10 / (10 + Z * Z), 1.0),
        (1, 1, 1 / (1 + Z * Z), 1.0),
    ],
)
def test_wilson_degenerate_cases_match_closed_form(k, n, lo, hi):
    assert A.wilson_interval(k, n) == pytest.approx((lo, hi), abs=1e-12)


def test_wilson_of_zero_probes_is_maximally_uninformative():
    # n == 0 must not divide by zero and must not claim to have measured anything.
    assert A.wilson_interval(0, 0) == (0.0, 1.0)


def test_wilson_interval_contains_the_point_estimate_and_stays_in_unit_range():
    # tol absorbs float noise: at k == 0 the lower bound lands on ~5e-17, not 0.0.
    tol = 1e-12
    for k, n in [(0, 7), (1, 7), (3, 7), (7, 7), (31, 102), (255, 500)]:
        lo, hi = A.wilson_interval(k, n)
        assert -tol <= lo <= k / n + tol
        assert k / n - tol <= hi <= 1.0 + tol


def test_wilson_lower_bound_is_the_broken_label_not_the_point_estimate():
    """pre-reg §5: broken iff the Wilson LOWER BOUND exceeds 5%, so small-n luck
    cannot inflate the count. 1/5 = 20% point estimate must NOT clear the bar."""
    lo_small, _ = A.wilson_interval(1, 5)
    assert 1 / 5 > A.FAR_THRESHOLD
    assert lo_small <= A.FAR_THRESHOLD
    # the same 20% rate over 100 probes is real signal and does clear it.
    lo_big, _ = A.wilson_interval(20, 100)
    assert lo_big > A.FAR_THRESHOLD


# --------------------------------------------------------------------------- #
# Exact binomial tail — the per-env one-sided p-value for H0: FAR <= 5%
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "k,n,p,expected",
    [
        # P[X >= 1] = 1 - (1-p)^n
        (1, 20, 0.05, 1 - 0.95 ** 20),
        (1, 3, 0.5, 1 - 0.5 ** 3),
        # P[X >= n] = p^n
        (3, 3, 0.5, 0.5 ** 3),
        (2, 2, 0.05, 0.05 ** 2),
        # P[X >= 2] = 1 - (1-p)^5 - 5p(1-p)^4
        (2, 5, 0.05, 1 - 0.95 ** 5 - 5 * 0.05 * 0.95 ** 4),
    ],
)
def test_binom_sf_matches_hand_computed_tails(k, n, p, expected):
    assert A.binom_sf(k, n, p) == pytest.approx(expected, abs=1e-12)


def test_binom_sf_of_zero_passes_is_certain():
    """Observing 0 false-accepts can never be evidence against H0: FAR <= 5%."""
    assert A.binom_sf(0, 40, A.FAR_THRESHOLD) == 1.0


def test_binom_sf_is_monotone_decreasing_in_observed_passes():
    tails = [A.binom_sf(k, 20, A.FAR_THRESHOLD) for k in range(0, 21)]
    assert tails == sorted(tails, reverse=True)


# --------------------------------------------------------------------------- #
# Benjamini-Hochberg — the headline "broken env count" is BH-significant only
# --------------------------------------------------------------------------- #
# The worked example from Benjamini & Hochberg (1995), the Needleman p-values.
# At q = 0.05 the paper rejects the four smallest hypotheses.
BH_1995_PVALS = [0.0001, 0.0004, 0.0019, 0.0095, 0.0201, 0.0278, 0.0298,
                 0.0344, 0.0459, 0.3240, 0.4262, 0.5719, 0.6528, 0.7590, 1.000]


def test_benjamini_hochberg_reproduces_the_1995_worked_example():
    pvals = {f"env{i}": p for i, p in enumerate(BH_1995_PVALS)}
    rejected = A.benjamini_hochberg(pvals, q=0.05)
    assert rejected == {"env0", "env1", "env2", "env3"}


def test_benjamini_hochberg_is_step_up_not_per_test_thresholding():
    """A p-value ABOVE its own BH line is still rejected when a larger-rank one
    passes. env_b fails its rank-2 line (0.040 > 2/3 * 0.05 = 0.0333) but the
    rank-3 line (0.05) admits env_c, so the step-up sweeps env_b back in.
    Per-test thresholding would drop it."""
    pvals = {"env_a": 0.001, "env_b": 0.040, "env_c": 0.045}
    assert pvals["env_b"] > (2 / 3) * 0.05      # fails its own line
    assert pvals["env_c"] <= (3 / 3) * 0.05     # the largest rank passes
    assert A.benjamini_hochberg(pvals, q=0.05) == {"env_a", "env_b", "env_c"}


def test_benjamini_hochberg_rejects_nothing_when_no_p_value_clears_its_line():
    pvals = {"env_a": 0.30, "env_b": 0.40, "env_c": 0.90}
    assert A.benjamini_hochberg(pvals, q=0.05) == set()


def test_benjamini_hochberg_on_empty_input_is_empty():
    assert A.benjamini_hochberg({}, q=0.05) == set()


def test_benjamini_hochberg_is_more_conservative_than_uncorrected_testing():
    """One env at p = 0.01 among 19 nulls. Uncorrected testing flags it; BH's
    rank-1 line is q/m = 0.0025, so the multiplicity correction holds it back."""
    pvals = {"env_flagged": 0.01}
    pvals.update({f"env_null{i}": 0.90 for i in range(19)})
    assert pvals["env_flagged"] < 0.05          # uncorrected would reject
    assert A.benjamini_hochberg(pvals, q=0.05) == set()


def test_benjamini_hochberg_rejects_everything_only_when_the_largest_p_clears_q():
    """The rank-m line IS q, so a uniformly marginal slate is rejected wholesale.
    This is BH working as specified, not a leak — it is why the pre-registration
    also reports the expected false-discovery count alongside the broken count."""
    pvals = {f"env{i}": 0.04 for i in range(20)}
    assert A.benjamini_hochberg(pvals, q=0.05) == set(pvals)
    # nudge one above q: it drops out, the 19 below its rank-19 line (0.0475) stay.
    pvals["env19"] = 0.051
    assert A.benjamini_hochberg(pvals, q=0.05) == set(pvals) - {"env19"}


# --------------------------------------------------------------------------- #
# Pooling — envs are the sampling unit; never average per-env point estimates
# --------------------------------------------------------------------------- #
def test_beta_binomial_pool_weights_by_probe_count_not_by_env():
    """pre-reg §5: 'Never average per-env point estimates.' One env with 1/100
    and one with 1/1 must pool to 2/101, not to the 0.505 mean of the rates."""
    pooled = A.beta_binomial_pool([(1, 100), (1, 1)])
    assert pooled["mean"] == pytest.approx(2 / 101)
    naive_mean_of_rates = (1 / 100 + 1 / 1) / 2
    assert pooled["mean"] != pytest.approx(naive_mean_of_rates)


def test_beta_binomial_pool_reports_no_dispersion_for_a_single_env():
    pooled = A.beta_binomial_pool([(3, 10)])
    assert pooled["mean"] == pytest.approx(0.3)
    assert pooled["n_envs"] == 1
    assert pooled["rho"] is None


def test_beta_binomial_pool_detects_overdispersion_across_envs():
    """Envs that disagree wildly (all-pass vs all-fail) are overdispersed; envs
    that agree are not. rho is the intra-cluster correlation."""
    split = A.beta_binomial_pool([(10, 10), (0, 10), (10, 10), (0, 10)])
    agree = A.beta_binomial_pool([(5, 10), (5, 10), (5, 10), (5, 10)])
    assert split["rho"] == pytest.approx(1.0, abs=1e-3)
    assert agree["rho"] == 0.0


def test_beta_binomial_pool_ignores_envs_with_no_probes():
    assert A.beta_binomial_pool([(2, 10), (0, 0)])["n_envs"] == 1


# --------------------------------------------------------------------------- #
# Cluster bootstrap over envs (the published CI method)
# --------------------------------------------------------------------------- #
def test_cluster_bootstrap_is_deterministic_under_the_registered_seed():
    kn = [(2, 10), (0, 10), (5, 10), (1, 10), (3, 10)]
    first = A.cluster_bootstrap_far(kn, resamples=500)
    second = A.cluster_bootstrap_far(kn, resamples=500)
    assert first == second


def test_cluster_bootstrap_brackets_the_pooled_point_estimate():
    kn = [(2, 10), (0, 10), (5, 10), (1, 10), (3, 10)]
    lo, hi, method = A.cluster_bootstrap_far(kn, resamples=2000)
    pooled = sum(k for k, _ in kn) / sum(n for _, n in kn)
    assert lo <= pooled <= hi
    assert method in ("BCa", "percentile")


def test_cluster_bootstrap_on_identical_envs_has_no_between_env_spread():
    """Resampling ENVS (not probes) is the point: identical envs resample to the
    identical pooled rate, so the interval collapses."""
    lo, hi, _ = A.cluster_bootstrap_far([(3, 10)] * 6, resamples=300)
    assert lo == pytest.approx(0.3)
    assert hi == pytest.approx(0.3)


def test_cluster_bootstrap_with_no_probes_is_degenerate_not_an_error():
    assert A.cluster_bootstrap_far([]) == (0.0, 0.0, "degenerate")
    assert A.cluster_bootstrap_far([(0, 0)]) == (0.0, 0.0, "degenerate")


# --------------------------------------------------------------------------- #
# Percentile / normal helpers used by the bootstrap
# --------------------------------------------------------------------------- #
def test_percentile_interpolates_between_neighbours():
    vals = [0.0, 1.0, 2.0, 3.0, 4.0]
    assert A._percentile(vals, 0) == 0.0
    assert A._percentile(vals, 100) == 4.0
    assert A._percentile(vals, 50) == 2.0
    assert A._percentile(vals, 25) == 1.0
    assert A._percentile(vals, 12.5) == pytest.approx(0.5)


def test_norm_ppf_inverts_norm_cdf_at_the_wilson_quantile():
    assert A._norm_ppf(0.975) == pytest.approx(Z, abs=1e-6)
    assert A._norm_cdf(Z) == pytest.approx(0.975, abs=1e-9)
    for p in (0.001, 0.01, 0.2, 0.5, 0.8, 0.99, 0.999):
        assert A._norm_cdf(A._norm_ppf(p)) == pytest.approx(p, abs=1e-6)
