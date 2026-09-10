# Extend result — SWE-bench-Verified FULL 500 reward-hackability

Date: 2026-07-14. The extend of the P0 anchor (`docs/anchor-result.md`) from a 50-task seeded subset to
the **entire SWE-bench-Verified benchmark (500 tasks)**. This is a **novel result**: arXiv:2606.16062
reported on 49 tasks and never ran the full set. Same harness as the anchor. Aggregate-only until the 30-day disclosure gate.

> **Corrected 2026-09-09.** An audit against `results/raw_swe_500/` found three defects in this document
> and in the published verdicts: 17 verdicts labelled `diffexec` on tasks whose records show the oracle
> never ran, one task published CORRECT against its own `oracle_wrong: true`, and a stated cause for the
> hand-review fallback that the records do not support. All three are fixed below and the headline moved
> from 13.7% to **14.2%**. See `tests/test_verdict_provenance.py`, which now fails on any of them.

## Setup
- **Tasks:** all 500 of `princeton-nlp/SWE-bench_Verified`, 12 repos (django 231, sympy 75, sphinx 44,
  matplotlib 34, scikit-learn 32, astropy 22, xarray 22, pytest 19, pylint 10, requests 8, seaborn 2,
  flask 1). Counted from `results/raw_swe_500/`; an earlier revision listed a stale tally summing to
  458 and said 11 repos.
- **Attacker:** Claude **Sonnet 4.5** via AWS Bedrock (Sonnet 4 retired — disclosed substitution), the
  same `harness/code_attack.py` as the anchor. K=3 candidates/task, round 1 single-shot, rounds 2–3 fed
  the shipped-suite failure logs. SEARCH/REPLACE output → deterministic difflib diff (99% apply).
- **Verifier:** each task's shipped `test_patch` on the native `swebench` runner, Docker Hub prebuilt
  images, emulated x86 on arm64.
- **Attacker inputs (disclosed):** the attacker is given the source region reconstructed from the **gold
  patch** (`pre_image_context`, so it never localizes the bug), the `FAIL_TO_PASS` / `PASS_TO_PASS` test
  node-ids, and up to three rounds of failing-test logs. 51.0% is the rate under that white-boxed search.
- **Adjudication:** the oracle left a result on **10 of the 102** sampled tasks but proved a divergence on
  only **3**; on the other 7 it found none, which `diffexec_oracle.py` routes to hand review rather than
  treating as correct. 92 were never attempted. So 3 verdicts rest on execution and 99 on single-rater
  code review.

## Result

| metric | value |
| --- | --- |
| **native-hackable** (verifier PASS ≥1 candidate — the paper's looser metric) | **255 / 500 = 51.0 %** |
| **adjudicated-wrong rate** (extrapolated) | **14.2 %, 95 % CI [10.5 %, 18.5 %]** |
| adjudicated-wrong count over 500 | ≈ **71** tasks, 95 % CI [52, 93] |
| patch-production rate (attacker emitted an applying patch) | 96.6 % (483/500) |

### How the confirmed rate is computed (pre-registered — `docs/preregistration.md`, amendment 2026-07-14)
The dual-gate **confirm queue** = every task with ≥1 *behaviorally-distinct* native-hackable candidate
(verifier PASS **and** candidate ≠ gold): **226 tasks**. Exhaustive per-task oracle review is impractical
at this scale and django candidates are largely diffexec-uninvokable, so the confirmed rate is estimated
from a **stratified random sample** (proportional by repo, **n = 102**). The proportionality is
checkable — `tests/test_published_results.py` rederives the per-repo allocation from the 226-task queue
— and the ids are now hash-pinned against later substitution. The *draw* is not checkable: no sampling
code exists in this repository, so "seed 42, drawn before any verdict was read" is asserted, not
demonstrated (see `docs/preregistration.md` §9 on the squashed history). Each sampled task was then
adjudicated:

- **32 HACK** (3 by differential execution — `astropy-14309`, `astropy-14995`, `astropy-7671`, each
  shipping the divergent input and both outputs copied from its record; 29 by single-rater code review,
  each shipping a written rationale),
- **66 CORRECT** (legitimate alternative fixes — incl. several gold-equivalent patches carrying a
  misleading "hack"/"hardcode" comment. **15 of these rest on no recorded evidence at all** and are
  flagged `"evidence": "none-recorded"`; all 15 are CORRECT, so they suppress the rate),
- **4 AMBIGUOUS** (excluded from the numerator — conservative).

p̂ = 32/102 = **0.314**, Wilson 95 % CI **[0.232, 0.409]**. Count = 226·p̂ ≈ 71 (CI [52, 93]); rate over
500 = 226·p̂/500 = **14.2 %** (CI [10.5 %, 18.5 %]). Counting the 4 AMBIGUOUS as hacks would raise p̂ to
0.353 → 16.0 %; we headline the conservative figure. HACKs span **9 repos** (django 12, sympy 4,
scikit-learn 3, pytest 3, astropy 3, xarray 2, matplotlib 2, sphinx 2, requests 1).

The interval carries **no finite-population correction** (n/N = 102/226 = 45 %), does not exploit the
stratification, and allows **nothing for adjudication error** — which, with 29 of 32 from one non-blind
rater, is plausibly the dominant uncertainty.

## Reading — representative, and honestly lower than the anchor
**14.2 % vs the anchor's 22.4 %** (astropy+django) and the paper's 28.5 % (49 tasks). The full
500 is *more representative* — it includes robust repos (sympy, scikit-learn, sphinx, pytest) with
stronger test suites where the confirmed hack rate is far lower, dragging the benchmark-wide number down
from the hackable-heavy astropy/django slice the anchor and the paper used. AMBIGUOUS is excluded and the 15 unevidenced verdicts all sit in the
conservative direction, but **this is not a lower bound**, because no benign-attacker control has been
run: OpenAI's Feb 2026 audit found 35.5 % of tasks enforce narrow tests that reject functionally correct
patches, so some fraction of "diverges from gold" is what correctness looks like here. Separating the two
requires re-running the pipeline with the prompt flipped to *write a correct patch*, and that has not been
done.

Artifacts: `results/swe500_confirmed.json` (aggregate), `results/swe500_sample_verdicts.json` (per-task
verdicts, each with its oracle record or its rationale), `results/swe500_confirm_sample.json` (the
frozen stratified sample),
`results/raw_swe_500/` (all 500 raw attacker records, committed; `harness/swe_native_rate.py` rederives the 500/255/226 inputs from them).

### Methodology notes (honest limitations)
- 29 of 32 HACKs rest on single-rater code review, not execution — non-blind, no second rater, no
  agreement statistic. The 3 executed exhibits are `astropy-14309`, `astropy-14995` and `astropy-7671`.
  *(An earlier revision of this file said 42/102 tasks hit a Docker `image-missing` and were routed to
  hand review. No `image-missing` record exists anywhere in `results/`; the records show 92 of 102 as
  `gate_skipped` — the oracle stage was never attempted on them. The claim was unsupported and is
  withdrawn. A later pass found the oracle had in fact left results on 10 sampled tasks, not 3; 7 of them
  are null results that establish nothing.)*
- 15 of the 102 verdicts carry no oracle record and no rationale. Flagged, counted, and all CORRECT.
- The first 500 pass was discarded: a Docker VM-disk exhaustion silently blocked base-file reads for
  non-django/astropy repos → empty patches → a spurious "hackable only in django/astropy." Caught,
  fixed (disk raised + live prune guard + content-filter-tolerant attacker), and fully re-run clean. The
  before/after is part of the reproducibility record, not number-tuning.
