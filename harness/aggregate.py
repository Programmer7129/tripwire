#!/usr/bin/env python3
"""envcert Phase 2 aggregate statistics.

Reads a directory of ``*.battery.jsonl`` files (one per env, one JSON record per
(row, probe) plus a single ``mode=="classification"`` summary line) and computes
the pre-registered soundness metrics.

All thresholds and the routing rule come straight from ``docs/preregistration.md``:
  - Per-env "broken" label: Wilson 95% score-interval LOWER BOUND > 5%   (pre-reg §5)
  - Headline: count of binary envs broken under Benjamini-Hochberg FDR q=0.05
    on per-env one-sided tests H0: FAR <= 5%                              (pre-reg §5)
  - Binary FAR routing: ONLY verifier_type == "binary" envs. soft/llm_judge/
    sandbox/unknown are never subjected to binary FAR (hard rule, pre-reg §1).
  - Soft graders: monotonicity-violation rate only                       (pre-reg §1/§2)
  - Aggregates: envs are the sampling unit; never average per-env point estimates;
    beta-binomial pooled FAR + cluster-bootstrap CI over envs; stratify by
    domain x verifier-type                                               (pre-reg §5)

Pure-Python: no numpy/scipy dependency (not installed in this env). Wilson interval,
exact binomial tail, BH, beta-binomial moment estimator, and a SEEDED cluster
bootstrap (BCa via pure-Python normal cdf/ppf, percentile fallback on degeneracy)
are all implemented below.
"""
from __future__ import annotations

import argparse
import glob
import json
import math
import os
import random
import time
from collections import Counter, defaultdict

# --- Pre-registered constants (docs/preregistration.md §5). Do NOT scatter magic
#     numbers; every threshold is named here with its pre-reg citation. ----------
FAR_THRESHOLD = 0.05          # pre-reg §5: env broken iff Wilson LB > 5%
FDR_Q = 0.05                  # pre-reg §5: Benjamini-Hochberg FDR level
WILSON_Z = 1.959963984540054  # 95% two-sided normal quantile (Wilson interval)
BOOTSTRAP_RESAMPLES = 10000   # pre-reg §5: 10k cluster-bootstrap resamples over envs
BOOTSTRAP_SEED = 20260712     # fixed seed -> deterministic bootstrap CIs

# ---------------------------------------------------------------------------
# Domain derivation from hub tags (pre-reg §5: stratify by domain x verifier-type)
# ---------------------------------------------------------------------------
# First matching rule (by tag-set intersection) wins; else "other".
_DOMAIN_RULES = [
    ("code",       {"coding", "code", "python", "sandbox", "swe", "swe-bench",
                    "software", "programming", "codegen"}),
    ("math",       {"math", "gsm8k", "arithmetic", "algebra", "geometry",
                    "math-verify", "aime"}),
    ("medical",    {"medical", "openmed", "clinical", "health", "biomed",
                    "medqa"}),
    ("legal",      {"legal", "law"}),
    ("security",   {"security", "ai-security", "cyber", "honeypot",
                    "insider-threat"}),
    ("games",      {"game", "games", "chess", "poker", "wordle"}),
    ("agentic",    {"tool-use", "tools", "agent", "multi-agent", "agentic"}),
    ("multimodal", {"multimodal", "vision", "image", "audio", "video"}),
    ("science",    {"science", "physics", "chemistry", "biology"}),
    ("qa",         {"qa", "multiple-choice", "classification",
                    "question-answering", "trivia"}),
    ("reasoning",  {"reasoning", "logic", "think", "rlm", "rlvr"}),
]


def derive_domain(tags):
    tagset = {t.lower() for t in (tags or [])}
    for name, keys in _DOMAIN_RULES:
        if tagset & keys:
            return name
    return "other"


def load_index(index_path):
    """owner/name -> {tags, domain}. Returns {} if the index is missing."""
    idx = {}
    if not index_path or not os.path.exists(index_path):
        return idx
    with open(index_path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            owner = (d.get("owner") or {}).get("name")
            name = d.get("name")
            if owner and name:
                tags = d.get("tags") or []
                idx[f"{owner}/{name}"] = {"tags": tags, "domain": derive_domain(tags)}
    return idx


# ---------------------------------------------------------------------------
# Statistics primitives (pure Python)
# ---------------------------------------------------------------------------
def is_pass(v_reward_majority):
    """A binary verifier PASSES iff its majority reward is above the 0 floor."""
    return v_reward_majority is not None and v_reward_majority > 0.0


def wilson_interval(k, n, z=WILSON_Z):
    """95% Wilson score interval for a binomial proportion k/n."""
    if n == 0:
        return (0.0, 1.0)
    phat = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (phat + z2 / (2 * n)) / denom
    margin = (z * math.sqrt(phat * (1 - phat) / n + z2 / (4 * n * n))) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def binom_sf(k, n, p):
    """Exact upper tail P[X >= k] for X ~ Binomial(n, p). One-sided p-value
    for H0: FAR <= p when k passes are observed out of n."""
    if k <= 0:
        return 1.0
    if k > n:
        return 0.0
    total = 0.0
    for i in range(k, n + 1):
        total += math.comb(n, i) * (p ** i) * ((1 - p) ** (n - i))
    return min(1.0, total)


def benjamini_hochberg(pvals_by_id, q=FDR_Q):
    """BH step-up. pvals_by_id: dict id->p. Returns set of rejected ids at FDR q."""
    items = list(pvals_by_id.items())
    m = len(items)
    if m == 0:
        return set()
    ordered = sorted(items, key=lambda kv: kv[1])
    max_rank = 0
    for rank, (_id, p) in enumerate(ordered, start=1):
        if p <= (rank / m) * q:
            max_rank = rank
    return {ordered[i][0] for i in range(max_rank)}


def _norm_cdf(x):
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def _norm_ppf(p):
    """Inverse standard-normal CDF (Acklam's rational approximation)."""
    if p <= 0.0:
        return -math.inf
    if p >= 1.0:
        return math.inf
    a = [-3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02,
         1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00]
    b = [-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02,
         6.680131188771972e+01, -1.328068155288572e+01]
    c = [-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00,
         -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00]
    d = [7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00,
         3.754408661907416e+00]
    plow, phigh = 0.02425, 1 - 0.02425
    if p < plow:
        q = math.sqrt(-2 * math.log(p))
        return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / \
               ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1)
    if p > phigh:
        q = math.sqrt(-2 * math.log(1 - p))
        return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / \
               ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1)
    q = p - 0.5
    r = q * q
    return (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q / \
           (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1)


def _percentile(sorted_vals, pct):
    """Linear-interpolation percentile; pct in [0,100]. sorted_vals ascending."""
    if not sorted_vals:
        return float("nan")
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    rank = (pct / 100.0) * (len(sorted_vals) - 1)
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return sorted_vals[lo]
    frac = rank - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def cluster_bootstrap_far(kn, seed=BOOTSTRAP_SEED, resamples=BOOTSTRAP_RESAMPLES,
                          alpha=0.05):
    """Cluster bootstrap over envs for the pooled FAR (sum k / sum n).

    kn: list of (k_i, n_i) per env. Resample ENVS with replacement (envs are the
    sampling unit, pre-reg §5). Returns (lo, hi, method). BCa if a non-degenerate
    bias/acceleration can be computed, else percentile.
    """
    kn = [(k, n) for (k, n) in kn if n > 0]
    K = sum(k for k, _ in kn)
    N = sum(n for _, n in kn)
    if not kn or N == 0:
        return (0.0, 0.0, "degenerate")
    theta_hat = K / N
    rng = random.Random(seed)
    m = len(kn)
    boots = []
    for _ in range(resamples):
        sk = sn = 0
        for _ in range(m):
            k, n = kn[rng.randrange(m)]
            sk += k
            sn += n
        boots.append(sk / sn if sn > 0 else 0.0)
    boots.sort()

    # Jackknife over envs for the BCa acceleration.
    jack = []
    for i in range(m):
        ki, ni = kn[i]
        dn = N - ni
        jack.append((K - ki) / dn if dn > 0 else theta_hat)
    jbar = sum(jack) / len(jack)
    num = sum((jbar - j) ** 3 for j in jack)
    den = 6.0 * (sum((jbar - j) ** 2 for j in jack)) ** 1.5

    n_less = sum(1 for b in boots if b < theta_hat)
    prop = n_less / len(boots)
    if den == 0 or prop <= 0.0 or prop >= 1.0:
        return (_percentile(boots, 100 * alpha / 2),
                _percentile(boots, 100 * (1 - alpha / 2)), "percentile")
    a = num / den
    z0 = _norm_ppf(prop)
    zl, zu = _norm_ppf(alpha / 2), _norm_ppf(1 - alpha / 2)

    def adj(z):
        return _norm_cdf(z0 + (z0 + z) / (1 - a * (z0 + z)))

    a1, a2 = adj(zl), adj(zu)
    if not (0 <= a1 < a2 <= 1) or math.isnan(a1) or math.isnan(a2):
        return (_percentile(boots, 100 * alpha / 2),
                _percentile(boots, 100 * (1 - alpha / 2)), "percentile")
    return (_percentile(boots, 100 * a1), _percentile(boots, 100 * a2), "BCa")


def beta_binomial_pool(kn):
    """Beta-binomial moment estimator (Kleinman) with partial pooling.

    Returns population mean (count-pooled p-hat), the intra-cluster correlation
    rho, and alpha/beta of the fitted Beta prior. The pooled mean weights by n
    (envs' k/n are never simple-averaged; pre-reg §5).
    """
    kn = [(k, n) for (k, n) in kn if n > 0]
    N = len(kn)
    total_n = sum(n for _, n in kn)
    total_k = sum(k for k, _ in kn)
    if total_n == 0:
        return {"mean": 0.0, "rho": None, "alpha": None, "beta": None,
                "n_envs": 0, "method": "n/a"}
    p_hat = total_k / total_n
    if N < 2 or p_hat <= 0.0 or p_hat >= 1.0:
        return {"mean": p_hat, "rho": None, "alpha": None, "beta": None,
                "n_envs": N, "method": "count-pooled (no dispersion; degenerate)"}
    # Kleinman moment estimator of the intra-cluster correlation.
    msb = sum(n * (k / n - p_hat) ** 2 for k, n in kn) / (N - 1)
    denom_w = total_n - N
    msw = (sum(n * (k / n) * (1 - k / n) for k, n in kn) / denom_w) if denom_w > 0 else 0.0
    n0 = (total_n - sum(n * n for _, n in kn) / total_n) / (N - 1)
    rho_den = msb + (n0 - 1) * msw
    rho = (msb - msw) / rho_den if rho_den > 0 else 0.0
    rho = max(0.0, min(0.999999, rho))
    if rho <= 0.0:
        return {"mean": p_hat, "rho": 0.0, "alpha": None, "beta": None,
                "n_envs": N, "method": "count-pooled (no overdispersion detected)"}
    scale = (1 - rho) / rho
    alpha = p_hat * scale
    beta = (1 - p_hat) * scale
    return {"mean": p_hat, "rho": rho, "alpha": alpha, "beta": beta,
            "n_envs": N, "method": "Kleinman moment estimator (empirical Bayes)"}


# ---------------------------------------------------------------------------
# Per-env parsing / metrics
# ---------------------------------------------------------------------------
def _read_battery(path):
    summary = None
    records = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("mode") == "classification":
                summary = r
            else:
                records.append(r)
    return summary, records


def compute_env(path, index):
    summary, records = _read_battery(path)
    # Skip error records (spec: "Records may carry an error field (skip those).")
    scored = [r for r in records if "error" not in r]
    n_error = len(records) - len(scored)

    env_id = None
    if summary:
        env_id = summary.get("env_id")
    if not env_id and scored:
        env_id = scored[0].get("env_id")
    if not env_id:
        env_id = os.path.basename(path).replace(".battery.jsonl", "").replace("__", "/", 1)

    # verifier_type: prefer the classification summary line (authoritative).
    vtype = None
    if summary:
        vtype = summary.get("verifier_type")
    if not vtype and scored:
        vtype = scored[0].get("verifier_type")
    vtype = vtype or "unknown"

    meta = index.get(env_id, {})
    domain = meta.get("domain", "other")

    # Anchor (exact-gold) records give the reward LEVEL gold achieves = the env's
    # own pass bar. A wrong answer is a false-accept only if it REACHES this level,
    # not merely > 0: many rubrics have an elevated/constant floor (a judge env run
    # offline returns a default ~0.5; a format-only reward gives 0.1 to anything).
    EPS = 1e-9
    anchors = [r for r in scored if r.get("far_bucket") == "anchor"]
    has_anchor = len(anchors) > 0
    anchor_max = max((r.get("v_reward_majority") or 0.0) for r in anchors) if anchors else None
    pass_threshold = anchor_max if (anchor_max is not None and anchor_max > 0) else None
    anchor_pass = pass_threshold is not None
    # gold_fails: verifier gives its own gold ~0 -> separate defect, excluded from FAR.
    gold_fails = has_anchor and not anchor_pass

    def is_pass(v):
        # PASS = reaches the env's own gold-anchor reward (anchor-relative, pre-reg §5).
        return (v is not None) and (pass_threshold is not None) and (v >= pass_threshold - EPS)

    # Non-discriminating verifier: reward has ~no dynamic range across ALL probes
    # (gold, empty, wrong all score the same constant). NOT a false-accept — a
    # degenerate / stub / offline-judge-default reward. Excluded from binary FAR and
    # reported separately (a real but distinct defect; often an llm_judge/reward-model
    # env misclassified binary because it returns a constant default when run offline).
    _all_rew = [r.get("v_reward_majority") for r in scored
                if isinstance(r.get("v_reward_majority"), (int, float))]
    reward_span = (max(_all_rew) - min(_all_rew)) if len(_all_rew) >= 2 else 0.0
    non_discriminating = (len(_all_rew) >= 2) and (reward_span < 1e-9)

    # Non-anchor scored probe records (denominator for instability / ambiguous rates).
    probes = [r for r in scored if r.get("far_bucket") != "anchor"]
    n_probes = len(probes)

    # Verdict-instability rate & ambiguous rate (reported separately, never in FAR).
    n_unstable = sum(1 for r in probes if r.get("verdict_unstable"))
    n_ambiguous = sum(1 for r in probes if r.get("far_bucket") == "ambiguous")
    instability_rate = (n_unstable / n_probes) if n_probes else 0.0
    ambiguous_rate = (n_ambiguous / n_probes) if n_probes else 0.0

    env = {
        "env_id": env_id,
        "verifier_type": vtype,
        "domain": domain,
        "has_anchor": has_anchor,
        "anchor_pass": anchor_pass,
        "anchor_max_reward": anchor_max,
        "gold_fails": gold_fails,
        "non_discriminating": non_discriminating,
        "reward_span": reward_span,
        "n_probe_records": n_probes,
        "n_error_records": n_error,
        "verdict_instability_rate": instability_rate,
        "n_verdict_unstable": n_unstable,
        "ambiguous_rate": ambiguous_rate,
        "n_ambiguous": n_ambiguous,
    }

    # ---- FAR family (binary + llm_judge; soft/sandbox/unknown never here) --------
    # Both binary and llm_judge verifiers emit a pass/fail-shaped verdict against an
    # oracle-confirmed-wrong probe, so both use the anchor-relative FAR machinery.
    # They are AGGREGATED SEPARATELY (binary_far vs judge_far) — stratified by
    # verifier-type per pre-reg §1 — but the per-env fields are computed identically.
    if vtype in ("binary", "llm_judge"):
        far_probes = [r for r in scored if r.get("far_eligible")]
        n_far = len(far_probes)
        far_pass = sum(1 for r in far_probes if is_pass(r.get("v_reward_majority")))
        far = (far_pass / n_far) if n_far else None
        wlo, whi = wilson_interval(far_pass, n_far) if n_far else (0.0, 1.0)
        broken_wilson = (n_far > 0) and (wlo > FAR_THRESHOLD)
        pval = binom_sf(far_pass, n_far, FAR_THRESHOLD) if n_far else None

        # RHS: FAR restricted to degenerate-provenance probes.
        rhs_probes = [r for r in far_probes if r.get("provenance") == "degenerate"]
        rhs_n = len(rhs_probes)
        rhs_pass = sum(1 for r in rhs_probes if is_pass(r.get("v_reward_majority")))
        rhs = (rhs_pass / rhs_n) if rhs_n else None

        # FRR (honesty check): frr_eligible probes the verifier FAILS.
        frr_probes = [r for r in scored if r.get("frr_eligible")]
        frr_n = len(frr_probes)
        frr_fail = sum(1 for r in frr_probes if not is_pass(r.get("v_reward_majority")))
        frr = (frr_fail / frr_n) if frr_n else None

        env.update({
            "n_far": n_far, "far_pass": far_pass, "far": far,
            "wilson_lo": wlo, "wilson_hi": whi, "broken_wilson": broken_wilson,
            "p_value_far_le_thresh": pval,
            "rhs_n": rhs_n, "rhs_pass": rhs_pass, "rhs": rhs,
            "frr_n": frr_n, "frr_fail": frr_fail, "frr": frr,
            # eligible for the FAR aggregate iff it has far probes, its own gold
            # passes (gold-reject is a separate defect), AND it actually
            # discriminates (a constant-reward verifier is a separate defect too;
            # e.g. an offline-judge default 0.5, caught as non_discriminating).
            "far_aggregate_eligible": (n_far > 0) and (not gold_fails) and (not non_discriminating),
        })

        # llm_judge: report the two sub-probes SEPARATELY (user directive; pre-reg
        # §4 probes 2+5). known_wrong = plain oracle-confirmed-wrong (harder to
        # dismiss); injection = grader prompt-injection (always oracle=WRONG). Also
        # surface how many known_wrong probes the oracle routed to `ambiguous`
        # (open-ended tasks the oracle can't certify -> excluded from FAR).
        if vtype == "llm_judge":
            def _subprobe(name):
                ps = [r for r in far_probes if r.get("judge_subprobe") == name]
                npass = sum(1 for r in ps if is_pass(r.get("v_reward_majority")))
                return {"n": len(ps), "far_pass": npass,
                        "far": (npass / len(ps)) if ps else None}
            kw_amb = sum(1 for r in probes
                         if r.get("far_bucket") == "ambiguous"
                         and r.get("judge_subprobe") == "known_wrong")
            env["judge_subprobes"] = {
                "known_wrong": _subprobe("known_wrong"),
                "injection": _subprobe("injection"),
                "n_known_wrong_ambiguous": kw_amb,
            }

    # ---- Soft graders: monotonicity-violation rate ONLY (never binary FAR) ------
    if vtype == "soft":
        env["monotonicity"] = _soft_monotonicity(scored)

    return env


def _soft_monotonicity(scored):
    """Fraction of (anchor=correct, wrong) pairs where the wrong candidate's
    v_reward_majority >= the anchor's. Paired within row_id (each row ships one
    gold anchor). pre-reg §1/§2."""
    by_row = defaultdict(lambda: {"anchor": [], "wrong": []})
    for r in scored:
        rid = r.get("row_id")
        if r.get("far_bucket") == "anchor":
            by_row[rid]["anchor"].append(r.get("v_reward_majority") or 0.0)
        elif r.get("oracle_label") == "WRONG":
            by_row[rid]["wrong"].append(r.get("v_reward_majority") or 0.0)
    pairs = 0
    violations = 0
    for rid, d in by_row.items():
        if not d["anchor"]:
            continue
        anchor_r = max(d["anchor"])  # best gold reward for the row
        for w in d["wrong"]:
            pairs += 1
            if w >= anchor_r:
                violations += 1
    rate = (violations / pairs) if pairs else None
    return {"pairs": pairs, "violations": violations, "violation_rate": rate}


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------
def aggregate(raw_dir, index_path=None):
    index = load_index(index_path)
    paths = sorted(glob.glob(os.path.join(raw_dir, "*.battery.jsonl")))
    envs = [compute_env(p, index) for p in paths]

    # Coverage table (nothing silently dropped).
    by_vtype = Counter(e["verifier_type"] for e in envs)
    gold_fails_ids = [e["env_id"] for e in envs if e.get("gold_fails")]
    nondiscrim_ids = [e["env_id"] for e in envs if e.get("non_discriminating")]
    error_envs = [e["env_id"] for e in envs if e["n_error_records"] > 0]
    coverage = {
        "total_env_files": len(envs),
        "by_verifier_type": dict(by_vtype),
        "gold_fails": len(gold_fails_ids),
        "gold_fails_env_ids": gold_fails_ids,
        # constant-reward / non-discriminating verifiers (gold==empty==wrong): a
        # distinct defect class, excluded from binary FAR, reported separately.
        "non_discriminating": len(nondiscrim_ids),
        "non_discriminating_env_ids": nondiscrim_ids,
        "envs_with_error_records": len(error_envs),
        # install-fail / v1-skip: enriched from sibling *.status.json when present.
        **_coverage_from_status(raw_dir),
    }

    # ---- Binary FAR aggregate (envs = sampling unit) ---------------------------
    binary_envs = [e for e in envs if e["verifier_type"] == "binary"]
    eligible = [e for e in binary_envs if e.get("far_aggregate_eligible")]
    excluded_no_far = [e["env_id"] for e in binary_envs if e.get("n_far", 0) == 0]
    coverage["binary_envs_excluded_gold_fails"] = [
        e["env_id"] for e in binary_envs if e.get("gold_fails")]
    coverage["binary_envs_excluded_no_far_probe"] = excluded_no_far

    broken_wilson_ids = [e["env_id"] for e in eligible if e["broken_wilson"]]
    pvals = {e["env_id"]: e["p_value_far_le_thresh"] for e in eligible
             if e["p_value_far_le_thresh"] is not None}
    bh_rejected = benjamini_hochberg(pvals, FDR_Q)
    bh_ids = sorted(bh_rejected)

    kn = [(e["far_pass"], e["n_far"]) for e in eligible]
    total_k = sum(k for k, _ in kn)
    total_n = sum(n for _, n in kn)
    pooled_far = (total_k / total_n) if total_n else None
    ci_lo, ci_hi, ci_method = cluster_bootstrap_far(kn) if kn else (None, None, "n/a")
    bb = beta_binomial_pool(kn)

    binary_far = {
        "n_binary_envs": len(binary_envs),
        "n_far_aggregate_eligible": len(eligible),
        "headline_bh_broken_count": len(bh_ids),
        "headline_bh_broken_env_ids": bh_ids,
        "expected_false_discoveries": FDR_Q * len(bh_ids),  # <= q * K
        "raw_wilson_lb_broken_count": len(broken_wilson_ids),  # pre-FDR comparison
        "raw_wilson_lb_broken_env_ids": broken_wilson_ids,
        "pooled_far": pooled_far,
        "pooled_far_ci95": [ci_lo, ci_hi],
        "pooled_far_ci_method": ci_method,
        "beta_binomial": bb,
        "far_pass_total": total_k,
        "far_probe_total": total_n,
    }

    # ---- LLM-judge FAR aggregate (separate family; pre-reg §1 verifier-type
    #      stratification + §4 probes 2+5 reported separately) -------------------
    judge_far = _judge_far_aggregate(envs)

    # ---- Soft graders --------------------------------------------------------
    soft_envs = [e for e in envs if e["verifier_type"] == "soft"]
    total_pairs = sum(e["monotonicity"]["pairs"] for e in soft_envs)
    total_viol = sum(e["monotonicity"]["violations"] for e in soft_envs)
    soft = {
        "n_soft_envs": len(soft_envs),
        "pooled_monotonicity_violation_rate": (total_viol / total_pairs) if total_pairs else None,
        "total_pairs": total_pairs,
        "total_violations": total_viol,
        "per_env": {e["env_id"]: e["monotonicity"] for e in soft_envs},
    }

    # ---- Stratify every aggregate by domain x verifier-type -------------------
    strata = _stratify(envs, bh_rejected)

    return {
        "meta": {
            "far_threshold": FAR_THRESHOLD,
            "fdr_q": FDR_Q,
            "wilson_z": WILSON_Z,
            "bootstrap_resamples": BOOTSTRAP_RESAMPLES,
            "bootstrap_seed": BOOTSTRAP_SEED,
            "ci_method": ci_method,
            "generated_ts": time.time(),
            "raw_dir": os.path.abspath(raw_dir),
            "index_path": os.path.abspath(index_path) if index_path else None,
            "n_env_files": len(envs),
        },
        "coverage": coverage,
        "binary_far": binary_far,
        "judge_far": judge_far,
        "soft": soft,
        "strata": strata,
        "envs": {e["env_id"]: e for e in envs},
    }


def _coverage_from_status(raw_dir):
    """Best-effort install-fail / v1-skip counts from sibling *.status.json.
    Battery files only exist for envs that loaded; these companions surface the
    ones that didn't, so nothing is silently dropped (pre-reg §1)."""
    install_fail = 0
    v1_skip = 0
    for sp in glob.glob(os.path.join(raw_dir, "*.status.json")):
        try:
            with open(sp) as fh:
                s = json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue
        prep = s.get("prepare") or {}
        if prep.get("ok") is False:
            install_fail += 1
        api = prep.get("verifiers_api") or s.get("verifiers_api") \
            or (s.get("classify") or {}).get("verifiers_api")
        if api == "v1":
            v1_skip += 1
    return {"install_fail": install_fail, "v1_skip": v1_skip}


def _judge_far_aggregate(envs):
    """LLM-judge FAR headline, reported separately from binary (pre-reg §1). Same
    anchor-relative FAR / Wilson-LB / BH-FDR machinery as binary, PLUS the two
    sub-probes (known_wrong vs injection) pooled separately (pre-reg §4 / directive).
    Constant-reward judge envs (offline default 0.5) are non_discriminating and
    excluded, exactly like binary."""
    judge_envs = [e for e in envs if e["verifier_type"] == "llm_judge"]
    eligible = [e for e in judge_envs if e.get("far_aggregate_eligible")]

    broken_wilson_ids = [e["env_id"] for e in eligible if e.get("broken_wilson")]
    pvals = {e["env_id"]: e["p_value_far_le_thresh"] for e in eligible
             if e.get("p_value_far_le_thresh") is not None}
    bh_rejected = benjamini_hochberg(pvals, FDR_Q)
    bh_ids = sorted(bh_rejected)

    kn = [(e["far_pass"], e["n_far"]) for e in eligible]
    total_k = sum(k for k, _ in kn)
    total_n = sum(n for _, n in kn)
    pooled_far = (total_k / total_n) if total_n else None
    ci_lo, ci_hi, ci_method = cluster_bootstrap_far(kn) if kn else (None, None, "n/a")

    # Two sub-probes pooled separately across eligible judge envs.
    def _pool_sub(name):
        k = sum((e.get("judge_subprobes", {}).get(name, {}) or {}).get("far_pass", 0)
                for e in eligible)
        n = sum((e.get("judge_subprobes", {}).get(name, {}) or {}).get("n", 0)
                for e in eligible)
        return {"far_pass_total": k, "far_probe_total": n,
                "pooled_far": (k / n) if n else None}

    kw_amb = sum((e.get("judge_subprobes", {}).get("n_known_wrong_ambiguous", 0))
                 for e in judge_envs)

    return {
        "n_judge_envs": len(judge_envs),
        "n_far_aggregate_eligible": len(eligible),
        "headline_bh_broken_count": len(bh_ids),
        "headline_bh_broken_env_ids": bh_ids,
        "expected_false_discoveries": FDR_Q * len(bh_ids),
        "raw_wilson_lb_broken_count": len(broken_wilson_ids),
        "raw_wilson_lb_broken_env_ids": broken_wilson_ids,
        "pooled_far": pooled_far,
        "pooled_far_ci95": [ci_lo, ci_hi],
        "pooled_far_ci_method": ci_method,
        "far_pass_total": total_k,
        "far_probe_total": total_n,
        # the two sub-probes, reported separately
        "known_wrong": _pool_sub("known_wrong"),
        "injection": _pool_sub("injection"),
        "n_known_wrong_ambiguous": kw_amb,
        "gold_fails_env_ids": [e["env_id"] for e in judge_envs if e.get("gold_fails")],
        "non_discriminating_env_ids": [e["env_id"] for e in judge_envs
                                       if e.get("non_discriminating")],
    }


def _stratify(envs, bh_rejected):
    strata = defaultdict(lambda: {
        "n_envs": 0, "n_binary_eligible": 0, "far_pass_total": 0, "far_probe_total": 0,
        "broken_wilson": 0, "broken_bh": 0, "n_soft": 0,
        "soft_pairs": 0, "soft_violations": 0,
    })
    for e in envs:
        key = f"{e['domain']}::{e['verifier_type']}"
        s = strata[key]
        s["n_envs"] += 1
        if e["verifier_type"] == "binary" and e.get("far_aggregate_eligible"):
            s["n_binary_eligible"] += 1
            s["far_pass_total"] += e["far_pass"]
            s["far_probe_total"] += e["n_far"]
            if e["broken_wilson"]:
                s["broken_wilson"] += 1
            if e["env_id"] in bh_rejected:
                s["broken_bh"] += 1
        if e["verifier_type"] == "soft":
            s["n_soft"] += 1
            s["soft_pairs"] += e["monotonicity"]["pairs"]
            s["soft_violations"] += e["monotonicity"]["violations"]
    out = {}
    for key, s in sorted(strata.items()):
        s = dict(s)
        s["far_pooled"] = (s["far_pass_total"] / s["far_probe_total"]
                           if s["far_probe_total"] else None)
        s["soft_monotonicity_rate"] = (s["soft_violations"] / s["soft_pairs"]
                                       if s["soft_pairs"] else None)
        out[key] = s
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _fmt(x, nd=4):
    return "n/a" if x is None else f"{x:.{nd}f}"


def print_summary(result):
    cov = result["coverage"]
    bf = result["binary_far"]
    soft = result["soft"]
    print("=" * 72)
    print("envcert aggregate  (pre-reg §5: Wilson-LB > {:.0%}, BH-FDR q={})".format(
        FAR_THRESHOLD, FDR_Q))
    print("=" * 72)
    print("\nCOVERAGE  (total env files: {})".format(cov["total_env_files"]))
    for vt, n in sorted(cov["by_verifier_type"].items()):
        print(f"  verifier_type={vt:<10} {n}")
    print(f"  gold_fails (verifier rejects own gold): {cov['gold_fails']}"
          + (f"  {cov['gold_fails_env_ids']}" if cov['gold_fails_env_ids'] else ""))
    print(f"  non_discriminating (gold==empty==wrong, constant reward): {cov.get('non_discriminating', 0)}"
          + (f"  {cov['non_discriminating_env_ids']}" if cov.get('non_discriminating_env_ids') else ""))
    print(f"  install_fail: {cov.get('install_fail', 0)}   "
          f"v1_skip: {cov.get('v1_skip', 0)}   "
          f"envs_with_error_records: {cov['envs_with_error_records']}")
    if cov.get("binary_envs_excluded_no_far_probe"):
        print(f"  binary excluded (no far probe): "
              f"{cov['binary_envs_excluded_no_far_probe']}")

    print("\nBINARY FAR  (headline)")
    print(f"  binary envs: {bf['n_binary_envs']}   "
          f"far-aggregate-eligible: {bf['n_far_aggregate_eligible']}")
    print(f"  HEADLINE broken under BH-FDR q={FDR_Q}: {bf['headline_bh_broken_count']}"
          f"   (expected false <= {bf['expected_false_discoveries']:.3f})")
    if bf["headline_bh_broken_env_ids"]:
        print(f"    broken env_ids: {bf['headline_bh_broken_env_ids']}")
    print(f"  raw Wilson-LB>{FAR_THRESHOLD:.0%} broken (pre-FDR): "
          f"{bf['raw_wilson_lb_broken_count']}")
    print(f"  pooled FAR: {_fmt(bf['pooled_far'])}  "
          f"95% CI [{_fmt(bf['pooled_far_ci95'][0])}, {_fmt(bf['pooled_far_ci95'][1])}]  "
          f"({bf['pooled_far_ci_method']})")
    bb = bf["beta_binomial"]
    print(f"  beta-binomial: mean={_fmt(bb['mean'])} rho={_fmt(bb.get('rho'))} "
          f"[{bb['method']}]")

    jf = result.get("judge_far")
    if jf and jf["n_judge_envs"]:
        print("\nLLM-JUDGE FAR  (reported separately from binary; pre-reg §1)")
        print(f"  judge envs: {jf['n_judge_envs']}   "
              f"far-aggregate-eligible: {jf['n_far_aggregate_eligible']}")
        print(f"  broken under BH-FDR q={FDR_Q}: {jf['headline_bh_broken_count']}"
              f"   (expected false <= {jf['expected_false_discoveries']:.3f})")
        if jf["headline_bh_broken_env_ids"]:
            print(f"    broken env_ids: {jf['headline_bh_broken_env_ids']}")
        print(f"  pooled judge FAR: {_fmt(jf['pooled_far'])}  "
              f"95% CI [{_fmt(jf['pooled_far_ci95'][0])}, {_fmt(jf['pooled_far_ci95'][1])}]")
        kw, inj = jf["known_wrong"], jf["injection"]
        print(f"  sub-probe known_wrong: pooled FAR {_fmt(kw['pooled_far'])} "
              f"({kw['far_pass_total']}/{kw['far_probe_total']})   "
              f"known_wrong->ambiguous (excluded): {jf['n_known_wrong_ambiguous']}")
        print(f"  sub-probe injection:   pooled FAR {_fmt(inj['pooled_far'])} "
              f"({inj['far_pass_total']}/{inj['far_probe_total']})")

    print("\nSOFT GRADERS")
    print(f"  soft envs: {soft['n_soft_envs']}   "
          f"pooled monotonicity-violation rate: "
          f"{_fmt(soft['pooled_monotonicity_violation_rate'])} "
          f"({soft['total_violations']}/{soft['total_pairs']} pairs)")

    print("\nSTRATA  (domain x verifier-type)")
    print(f"  {'stratum':<28} {'n':>3} {'binElig':>7} {'farPool':>8} "
          f"{'wLB':>4} {'BH':>3} {'monot':>7}")
    for key, s in result["strata"].items():
        print(f"  {key:<28} {s['n_envs']:>3} {s['n_binary_eligible']:>7} "
              f"{_fmt(s['far_pooled'], 3):>8} {s['broken_wilson']:>4} "
              f"{s['broken_bh']:>3} {_fmt(s['soft_monotonicity_rate'], 3):>7}")
    print("=" * 72)


def pool_eyr(raw_dir):
    """Pool the ELICITED/EYR lane across the pilot: read every *.eyr.jsonl in
    raw_dir, pull its mode=='eyr_summary' record, and roll up via
    attacker.aggregate_eyr (per-env EYR + pooled attacker/verifier compute budget
    for cost extrapolation). Kept out of the FAR aggregate() — EYR is a separate,
    causal backstop lane (pre-reg §2), never folded into the binary/judge FAR."""
    import sys as _sys
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in _sys.path:
        _sys.path.insert(0, here)
    import attacker  # noqa: E402
    summaries = []
    for path in sorted(glob.glob(os.path.join(raw_dir, "*.eyr.jsonl"))):
        try:
            with open(path) as fh:
                recs = [json.loads(l) for l in fh if l.strip()]
        except (OSError, json.JSONDecodeError):
            continue
        # RECOMPUTE the per-env summary from the stored per-row records so pooling
        # always reflects the current EYR metric definitions (a stored summary line
        # may predate a metric addition). Fall back to the stored summary if no
        # per-row records are present (e.g. a resolve-failure stub).
        prior = next((r for r in recs if r.get("mode") == "eyr_summary"), {})
        rows = [r for r in recs if r.get("mode") != "eyr_summary"]
        if rows:
            summaries.append(attacker.eyr_summary(
                rows, attacker_model=prior.get("attacker_model"),
                env_id=prior.get("env_id"), is_judge=prior.get("is_judge"),
                n_candidates=prior.get("n_candidates_per_round"),
                feedback_rounds=prior.get("feedback_rounds")))
        elif prior:
            summaries.append(prior)
    return attacker.aggregate_eyr(summaries)


def main(argv=None):
    ap = argparse.ArgumentParser(description="envcert Phase 2 aggregate statistics")
    ap.add_argument("--raw", default="results/raw",
                    help="directory of *.battery.jsonl files")
    ap.add_argument("--index", default="results/hub_index.jsonl",
                    help="hub index jsonl (for domain stratification)")
    ap.add_argument("--out", default="results/aggregate.json",
                    help="output JSON path")
    ap.add_argument("--eyr", action="store_true",
                    help="pool the ELICITED/EYR lane (*.eyr.jsonl) instead of the "
                         "FAR battery aggregate; prints + writes the EYR roll-up")
    args = ap.parse_args(argv)

    if args.eyr:
        pooled = pool_eyr(args.raw)
        out = args.out if args.out != "results/aggregate.json" else "results/eyr_aggregate.json"
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with open(out, "w") as fh:
            json.dump(pooled, fh, indent=2, default=str)
        print("=" * 72)
        print("envcert ELICITED / EYR aggregate (pilot; pre-reg §2 — NOT headlined <150 envs)")
        print("=" * 72)
        print(f"  envs: {pooled['n_envs']}   "
              f"EYR-positive (strict, reached anchor + oracle WRONG): "
              f"{pooled['n_envs_eyr_positive']} {pooled['eyr_positive_env_ids']}")
        print(f"  EYR reward-delta positive (reward rose, true-Q flat/down): "
              f"{pooled['n_envs_eyr_reward_delta_positive']} "
              f"{pooled['eyr_reward_delta_positive_env_ids']}")
        print(f"  total rows counted: {pooled['total_rows_counted']}   "
              f"total exploits: {pooled['total_exploits']}")
        print(f"  compute: {pooled['total_attacker_calls']} attacker calls, "
              f"{pooled['total_verifier_calls']} verifier calls  "
              f"(mean/env: {_fmt(pooled['attacker_calls_per_env_mean'], 1)} attacker, "
              f"{_fmt(pooled['verifier_calls_per_env_mean'], 1)} verifier)")
        for env_id, s in pooled["per_env"].items():
            print(f"    {env_id}: eyr_positive={s.get('eyr_positive')} "
                  f"mean_reward_attacker={_fmt(s.get('mean_reward_attacker'), 3)} "
                  f"honest={_fmt(s.get('mean_reward_honest_baseline'), 3)} "
                  f"oracle_correct_hi={_fmt(s.get('oracle_correct_rate_of_high_reward'), 3)} "
                  f"exploits={s.get('n_exploits')}")
        print(f"\nfull EYR roll-up written to {out}")
        return pooled

    result = aggregate(args.raw, args.index)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(result, fh, indent=2, default=str)
    print_summary(result)
    print(f"\nfull result written to {args.out}")
    return result


if __name__ == "__main__":
    main()
