# SPEC: publish the hub verifier census (aggregate only)

Status: DRAFT, pending adversarial review
Date: 2026-09-02
Phase: the hub lane of `docs/preregistration.md`, §1-§6. Disclosure governed by §8.

## Problem Statement

Everyone is building RL environments. Nobody independently certifies that their verifiers
work. Tripwire has published that certification for exactly one benchmark, SWE-bench
Verified, while the instrument that can do it across the whole public ecosystem has already
been built and already been run.

512 environments from a 1,367-environment census have been scored, classified by verifier
type, and aggregated. The result sits on one laptop. Until it is published it certifies
nothing for anyone.

Four other tools audited this same hub in the two months to September 2026. Every one of
them stopped at **degenerate probes**: empty strings, echoed prompts, garbage. That measures
Reward-Hack Susceptibility, the easy bucket. None measured a **false-accept rate against an
independent oracle on plausible, non-degenerate wrong answers**, which is the harder and more
useful question, and which this instrument already answers.

## Solution

Publish the aggregate census: pooled false-accept rates by verifier type with confidence
intervals, the false-reject honesty gate that makes them credible, and the monotonicity
violation rate for partial-credit graders. **No environment is named.**

The headline is of the form: *across N public RL environment verifiers, the pooled
false-accept rate against an independent oracle is X% [CI], and separately, LLM-judge
verifiers resist wrong answers at 0% while failing prompt injection at Y%.*

## What is NOT published, and why

`docs/preregistration.md` §8 binds this project to a **30-day author and platform embargo
before naming any broken environment**, to a per-env one-pager with the failing probe and a
fix hint, to re-test-on-fix markers, and to framing authors as collaborators. It further
states Phase 1-2 are private aggregate research with no per-env public naming until Phase 4.

Therefore, by the author's own instruction and consistent with §8:

- **No environment identifier is published**, including the author's own environments. Not in
  the aggregate, not in the per-env rows, not in the writeup.
- Per-env rows are published under a **salted opaque token**. The salt is not published, so
  the mapping is recoverable by the author alone and by nobody else.
- No environment's code, prompts, or dataset rows are reproduced.

This is stricter than §8 requires and is a deliberate choice, not an oversight.

## User Stories

1. As someone training on a public RL environment, I want the pooled false-accept rate of its verifier class, so I know the base rate of my reward signal being wrong.
2. As the same person, I want it split by verifier type, because a binary matcher and an LLM judge fail differently.
3. As the same person, I want the LLM-judge result split by attack type, because resisting wrong answers and resisting injection are different properties.
4. As someone using a partial-credit grader, I want the monotonicity violation rate, because a grader that scores a worse answer higher is broken even when it never fully accepts a wrong one.
5. As a skeptical reader, I want the false-reject rate, so I know the probes did not simply loosen every verifier.
6. As a skeptical reader, I want the count of environments excluded because their own gold answer failed, because that number is a finding about the ecosystem and not a footnote.
7. As a skeptical reader, I want the coverage funnel stated at every stage, because 90 eligible out of 1,367 enumerated is the first thing I will ask about.
8. As a skeptical reader, I want to know the census is a snapshot with a date, and how much the hub has drifted since.
9. As a reproducer, I want every published figure recomputable from committed records by one command.
10. As a reproducer, I want the per-env rows, so I can check the aggregate rather than trust it.
11. As an environment author, I want to know whether I am in the broken set without everyone else knowing, so the author must be able to answer that privately from the withheld salt.
12. As a maintainer, I want the preregistration for this lane committed before any census artifact enters the repository, so the ordering is provable this time.

## Implementation Decisions

### Ordering, which is the point

1. A dated amendment to `docs/preregistration.md` registering this lane's headline, its
   thresholds, and the anonymisation scheme lands as **its own commit, pushed, before any
   census artifact exists in the repository**. The amendment of 2026-09-02 already committed
   this project to exactly that, and this is the first phase that must honour it.
2. Only then do the anonymised artifacts land.

### Anonymisation

- A random 32-byte salt, generated once, stored outside the repository and never committed.
- Every environment identifier becomes `sha256(salt || env_id)`, truncated to 12 hex chars,
  as a stable token. Collisions checked at generation; regenerate the salt if any occur.
- Fields carrying identity are dropped entirely rather than tokenised where they serve no
  analytic purpose: the four `*_env_ids` lists in `binary_far` and `judge_far`, and the two
  in `coverage`. The counts stay; the names go.
- Per-env rows keep every statistic and the `domain` and `verifier_type` labels, since the
  stratification is the analysis. `env_id` is replaced by the token.
- A test asserts no published artifact contains any string from the census index.

### What is published

- The coverage funnel, stated as a single table from 1,367 enumerated down to the eligible
  denominators, with the reason for each drop.
- Per verifier type: pooled false-accept rate, its cluster-bootstrap interval, the
  Benjamini-Hochberg broken count at q = 0.05 with expected false discoveries, and the
  Wilson-lower-bound count alongside it.
- The judge lane split into known-wrong probes and injection probes, reported separately.
  This split is the most interesting result in the census and must not be pooled away.
- The soft lane: monotonicity violations as pairs and rate.
- The stratification by domain and verifier type, as data.
- The gold-fails and non-discriminating counts, as findings.

### Frozen before publication

- No threshold, interval method, or eligibility rule changes. They are already registered in
  §5: Wilson lower bound above 5% for the broken label, Benjamini-Hochberg at q = 0.05,
  cluster bootstrap over environments with 10,000 BCa resamples, and no unweighted means.
- The census is a **snapshot dated 2026-07-12**. It is not re-run to improve a number. Hub
  drift since that date is measured and reported, not corrected for.

### Coverage is a first-class result, not an apology

The funnel from 1,367 enumerated to 90 FAR-eligible binary environments is large, and the
reasons are themselves findings: environments that fail to load, environments whose own gold
answer does not pass, environments whose verifier does not discriminate between a right and
a wrong answer at all. Each is reported with its count and an interpretation. A reader who
concludes the ecosystem is hard to audit has understood the paper correctly.

## Testing Decisions

Tests verify what the analysis returns from committed records, need no network and no
container, and are table-driven where the input is data.

- **Anonymisation**: tokens are stable across runs given the same salt, differ across salts,
  are collision-free on the real census, and no published artifact contains any raw
  identifier. That last one is the test that matters and it runs over every committed file.
- **Every published figure is pinned**: pooled rates, intervals, broken counts, expected
  false discoveries, monotonicity rate, and every number in the coverage funnel, recomputed
  from the anonymised per-env rows and asserted against what the writeup states.
- **The funnel is closed**: each stage's drop plus the next stage's count equals the previous
  stage's count. A funnel that does not add up is the most likely error here.
- **The honesty gate**: an environment whose gold answer fails is excluded from every rate,
  and a test trips it.
- **Drift check** is a script, not a test, since it needs the network.

## Out of Scope

- Naming any environment, including the author's own.
- Publishing environment code, prompts, or dataset rows.
- Re-running the census, extending coverage, or scoring the sandbox bucket.
- The cross-model slate registered in §7. That is a later phase.
- Any recommendation to a specific environment's author.

## Further Notes

- The likeliest hostile question is coverage, not method. Answer it in the abstract.
- The judge injection result is the strongest finding and has its own control arm at 0%.
  Lead with it.
- Four shallower audits of this hub already exist. The claim is not priority over them; it is
  that they measured degenerate-input susceptibility and this measures false accepts against
  an independent oracle. State that distinction plainly and cite them.
