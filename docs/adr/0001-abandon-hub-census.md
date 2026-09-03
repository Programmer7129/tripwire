# ADR 0001: Abandon the hub census lane

Date: 2026-09-02
Status: Accepted

## Context

Two specs were written for publishing the 512-environment hub census. Both were killed by
adversarial review, and every fatal finding was verified against the raw records before the
decision was taken.

**Attempt 1, the false-accept census.** Headline 3.6% pooled false-accept rate.
- 87% of the probe denominator was degenerate inputs, the exact thing the spec dismissed four
  prior tools for measuring. The non-degenerate arm alone was 2.21%.
- The false-reject control read 74%. Pre-registration §2 requires "high FAR + low FRR" for the
  claim. The precondition was not met and the spec reported the control as passed.
- The strongest finding, LLM-judge injection at 18.2%, was one environment at 9/9. The other
  24 judge environments scored 0 across 139 probes.

**Attempt 2, the brittleness result.** Headline: verifiers reject a correct answer 73.2% of the
time versus accepting a wrong one 2.21%, a 33x asymmetry. Four fatal defects, all verified:
- **60 of 295 counted rejections were harness crashes.** `KeyError('timing')`, `AssertionError`
  and `TypeError` from our own API mismatch with `verifiers` left `v_reward_majority = None`,
  and `None <= 0` scored as a rejection. The same defect in the other arm counted as a
  non-accept, so one bug inflated one arm's numerator and the other arm's denominator at once.
- **19 environments reject their own gold answer** and supplied 155 of 295 rejections, 52.5% of
  the numerator. A verifier that rejects the dataset's own reference says nothing about
  paraphrase handling.
- **The two arms were different populations.** The reject arm was `raw`-only, the accept arm was
  all formats. The spec's own testing section required a test asserting a `raw`-only headline
  population; that test would have failed against the spec's own number.
- **20 of 28 false accepts came from one environment** at 20/20, with 26 of 32 environments
  contributing zero. This is the identical defect the spec cited when killing its predecessor.

Fully corrected: 56.45% [50.2, 62.5] versus 5.21% [3.6, 7.4], a 10.8x ratio over **32**
environments, not 51 or 73.

## Decision

Abandon the hub census lane. Do not write a third spec.

## Rationale

The blocker is not the framing, it is the data. Three independent contaminations were found in
one dataset, every one of them inflating in the flattering direction, and each was found only
because someone went looking. That is a strong prior that more remain.

Making it publishable would require repairing the harness's `verifiers` API mismatch, re-running
the census, resolving whether `discovered_format = "raw"` means "no contract" or merely "no
wrapper scored higher" (it is an argmax with ties resolving to raw, so probably the latter),
and then defending a result about roughly 32 environments drawn from the hub's tutorial tail,
where every environment above five stars had already fallen out of eligibility.

That is weeks of work for a narrow claim about toy environments.

## What is NOT abandoned

The SWE-bench lane. It survived three rounds of independent review, its numbers reproduce from
committed evidence, CI fails on drift, and two published claims were corrected in the process.
That is the artifact. The hub census was upside on it and the upside did not materialise.

## Consequence

`docs/SPEC-census.md` and `docs/SPEC-brittleness.md` are removed from the working tree and
remain in git history at this ADR's parent commits. The raw census records stay where they are,
outside this repository, unpublished.

## The rule this earns

**When a dataset yields three separate contaminations under review, stop measuring and fix the
instrument, or stop.** Do not write a third framing of a number the data cannot support. Each
reframing looks like progress and is actually the same error wearing a different headline.
