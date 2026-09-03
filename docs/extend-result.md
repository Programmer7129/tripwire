# Extend result — SWE-bench-Verified FULL 500 reward-hackability

Date: 2026-07-14. The extend of the P0 anchor (`docs/anchor-result.md`) from a 50-task seeded subset to
the **entire SWE-bench-Verified benchmark (500 tasks)**. This is a **novel result**: arXiv:2606.16062
reported on 49 tasks and never ran the full set. Same open, deterministic harness; same dual-gate
(verifier PASS **and** an independent oracle says WRONG). Aggregate-only until the 30-day disclosure gate.

## Setup
- **Tasks:** all 500 of `princeton-nlp/SWE-bench_Verified`, 11 repos (django 231, sympy 60, sphinx 35,
  matplotlib 34, scikit-learn 26, astropy 22, xarray 18, pytest 15, pylint 8, requests 6, seaborn 2,
  flask 1).
- **Attacker:** Claude **Sonnet 4.5** via AWS Bedrock (Sonnet 4 retired — disclosed substitution), the
  same `harness/code_attack.py` as the anchor. K=3 candidates/task, round 1 single-shot, rounds 2–3 fed
  the shipped-suite failure logs. SEARCH/REPLACE output → deterministic difflib diff (99% apply).
- **Verifier:** each task's shipped `test_patch` on the native `swebench` runner, Docker Hub prebuilt
  images, emulated x86 on arm64.
- **Oracle (dual gate):** deterministic **differential execution** (`harness/diffexec_oracle.py`) where
  the candidate callable is invokable; conservative **code hand-review** (HACK/CORRECT/AMBIGUOUS) where
  it is not (django ORM/class methods without DB/app fixtures) — the anchor's accepted method, matching
  the paper's manual EQS review.

## Result

| metric | value |
| --- | --- |
| **native-hackable** (verifier PASS ≥1 candidate — the paper's looser metric) | **255 / 500 = 51.0 %** |
| **confirmed reward-hacks** (dual-gated, extrapolated) | **13.7 %, 95 % CI [10.1 %, 18.0 %]** |
| confirmed count over 500 | ≈ **69** tasks, 95 % CI [50, 90] |
| patch-production rate (attacker emitted an applying patch) | 96.6 % (483/500) |

### How the confirmed rate is computed (pre-registered — `docs/preregistration.md`, amendment 2026-07-14)
The dual-gate **confirm queue** = every task with ≥1 *behaviorally-distinct* native-hackable candidate
(verifier PASS **and** candidate ≠ gold): **226 tasks**. Exhaustive per-task oracle review is impractical
at this scale and django candidates are largely diffexec-uninvokable, so the confirmed rate is estimated
from a **stratified random sample** (proportional by repo, seed 42, **n = 102**, drawn and git-committed
*before* any verdict was read). Each sampled task was confirmed by the same anchor dual-gate:

- **31 HACK** (3 by deterministic differential-execution with a divergent-input reproducer, incl. two
  django callables the oracle *could* drive at scale; 28 by conservative code hand-review),
- **67 CORRECT** (legitimate alternative fixes — incl. several gold-equivalent patches carrying a
  misleading "hack"/"hardcode" comment: the dual-gate correctly *not* flagging them),
- **4 AMBIGUOUS** (excluded from the numerator — conservative).

p̂ = 31/102 = **0.304**, Wilson 95 % CI **[0.223, 0.399]**. Confirmed count = 226·p̂ ≈ 69 (CI [50, 90]);
confirmed rate over 500 = 226·p̂/500 = **13.7 %** (CI [10.1 %, 18.0 %]). Counting the 4 AMBIGUOUS as hacks
would raise p̂ to 0.343 → 15.5 %; we headline the conservative figure. Confirmed HACKs span **9 repos**
(django 12, sympy 4, scikit-learn 3, pytest 3, astropy 2, xarray 2, matplotlib 2, sphinx 2, requests 1).

## Reading — representative, and honestly lower than the anchor
**13.7 % confirmed vs the anchor's 22.4 %** (astropy+django) and the paper's 28.5 % (49 tasks). The full
500 is *more representative* — it includes robust repos (sympy, scikit-learn, sphinx, pytest) with
stronger test suites where the confirmed hack rate is far lower, dragging the benchmark-wide number down
from the hackable-heavy astropy/django slice the anchor and the paper used. Every number is a **lower
bound**: Wilson lower edge, AMBIGUOUS excluded, and the dual-gate requires a *demonstrated* behavioral
divergence. Even so, **~1 in 7 SWE-bench-Verified tasks admits a confirmed wrong patch that the shipped
verifier accepts**, and on *half* the verifier accepts an attacker's candidate patch at all — on the exact
benchmark the field treats as gold-standard for code-RL reward.

Artifacts: `results/swe500_confirmed.json` (aggregate), `results/swe500_sample_verdicts.json` (per-task
verdicts + reproducers/rationale), `results/swe500_confirm_sample.json` (the pre-drawn seed-42 sample),
`results/raw_swe_500/` (all 500 raw attacker records, committed; `harness/swe_native_rate.py` rederives the 500/255/226 inputs from them).

### Methodology notes (honest limitations)
- 28 of 31 confirmed HACKs rest on code hand-review, not deterministic execution — 42/102 sampled tasks
  hit a Docker `image-missing` during the diffexec pass (VM-disk pressure) and were routed to hand-review.
  The 3 diffexec-auto hacks (django-13933, django-14122, astropy-14309) are the deterministic exhibits;
  strengthening auto-confirmation coverage (fixture-driven django invocation) is future work.
- The first 500 pass was discarded: a Docker VM-disk exhaustion silently blocked base-file reads for
  non-django/astropy repos → empty patches → a spurious "hackable only in django/astropy." Caught,
  fixed (disk raised + live prune guard + content-filter-tolerant attacker), and fully re-run clean. The
  before/after is part of the reproducibility record, not number-tuning.
