# SPEC: verifier brittleness in public RL environments

Status: DRAFT, pending adversarial review
Date: 2026-09-02
Supersedes: `docs/SPEC-census.md` (the false-accept framing), killed by its own honesty control.
Phase: the hub lane of `docs/preregistration.md`. Disclosure governed by §8.

## Problem Statement

The field's assumption is that RL training verifiers are too **loose**: models learn to game a
weak check, so audits hunt for false accepts. Four public tools audited the same environment
hub in the two months to September 2026 and every one of them probed with degenerate inputs
(empty strings, echoed prompts, garbage), which can only ever find looseness.

This project ran the other arm as well: semantically-correct paraphrases, with an independent
oracle confirming each is numerically equal to the reference answer. On 512 scored
environments from a 1,367 census, the two arms disagree in direction.

| what the verifier does | rate | Wilson 95% | envs |
|---|---|---|---|
| accepts a plausible wrong answer | **2.21%** | [1.53, 3.17] | 73 |
| rejects a numerically-correct answer | **73.20%** | [68.67, 77.29] | 51 |

These verifiers are not loose. They are **brittle**: they implement string equality and call it
correctness. `four` is scored wrong when gold is `4`; so are `seventy-two` for `72` and `18.0`
for `18`. A correct answer is rejected roughly **33 times more often** than a plausible wrong
answer is accepted.

That is the worse failure. A loose verifier occasionally pays for a wrong answer. A brittle one
**systematically punishes correct behaviour**, so the gradient teaches format mimicry instead of
task competence. And it is invisible to every audit published so far, because degenerate probes
cannot detect it.

## How this spec came to exist, which belongs in the paper

The predecessor spec proposed publishing a false-accept census headlined at 3.6%. Adversarial
review killed it on three counts, all verified against the raw records before acceptance:

1. **The headline measured the thing it dismissed others for measuring.** 3.6% pooled across
   probe families that are 87% degenerate. The non-degenerate arm alone is 2.21%.
2. **The honesty control failed and was being reported as passed.** The false-reject rate is
   74%, and §2 of the pre-registration states the claim requires "high FAR + low FRR".
3. **The strongest finding was one environment.** All nine LLM-judge injection accepts came
   from a single environment at 9/9; the other 24 scored 0 across 139 probes.

The instrument found that its own headline did not survive its own control. The paper says so.

## Solution

Publish the brittleness result, with the false-accept arm as its foil rather than its headline.
Aggregate only. **No environment is named**, per §8 and the author's instruction.

## User Stories

1. As someone training on a public RL environment, I want to know how often its verifier rejects a correct answer, because that is a penalty applied to correct behaviour.
2. As the same person, I want both arms side by side, because the ratio is the finding and either number alone misleads.
3. As the same person, I want the result restricted to environments that impose no answer-format contract, so I know the rejections are not my own formatting failure.
4. As a skeptical reader, I want the probes that violated a declared format excluded, and I want to see that excluding them does not change the conclusion.
5. As a skeptical reader, I want the false-accept arm decomposed by probe family, so I can see which prior findings are degenerate-input susceptibility and which are not.
6. As a skeptical reader, I want the coverage funnel from 1,367 enumerated to the eligible denominators, with a reason for every drop.
7. As a skeptical reader, I want to know the environments are not independent, and how much that widens the intervals.
8. As a skeptical reader, I want the population described honestly, including that it skews to the hub's simpler tail.
9. As a reproducer, I want every published figure recomputable from committed records by one command.
10. As an environment author, I want to learn privately whether I am affected, so the author must retain the identity mapping.
11. As a maintainer, I want this lane's pre-registration committed before any artifact of it, so the ordering is provable.

## Implementation Decisions

### Ordering

The dated pre-registration amendment for this lane lands as **its own commit, pushed, before any
brittleness artifact exists in the repository**. The 2026-09-02 amendment already committed the
project to this and this is the first lane that must honour it.

### The headline and its guards

- **Primary population: environments whose discovered answer format is `raw`.** These impose no
  wrapper, so a bare answer cannot violate a format contract. 295/403 rejected across 51
  environments.
- The 160 probes against environments that DID declare a wrapper or parser are reported
  separately, at 76.25%, and are **excluded from the headline**. They are reported because the
  agreement between the two buckets is evidence the effect is not a probe artefact.
- Every counted false reject carries `oracle_label = CORRECT` on the `numeric` channel. The
  verifier's own verdict is never the ground truth for correctness, in either direction.
- The false-accept arm is reported **decomposed by probe family**, never pooled: known-wrong
  2.21%, semantic-substring 16.54%, empty 6.51%, degenerate 6.63%. Pooling these was the
  predecessor's fatal error and it is not repeated.

### Non-independence, which widens everything

Environments on this hub include forks, templates and duplicate uploads of the same underlying
dataset. Before any interval is published, near-duplicate environments are detected by
fingerprinting the per-environment probe counts and outcomes, grouped, and the cluster bootstrap
resamples **groups, not environments**. The effective independent count is reported alongside
the raw count, and if it is materially smaller the intervals widen accordingly. A published
interval computed on the assumption of 90 independent environments when there are 25 is a false
precision, and the pre-registration's §5 clustering rule already requires the environment to be
the sampling unit.

### Frozen before publication

Thresholds, interval method and eligibility rules are unchanged from §5: Wilson intervals,
Benjamini-Hochberg at q = 0.05, cluster bootstrap with 10,000 BCa resamples, no unweighted
means. The census is a snapshot dated 2026-07-12 and is not re-run to improve a number.

### Anonymisation

Identifiers are replaced by a salted hash, salt withheld. Identity-bearing lists are dropped
outright rather than tokenised. **Re-identification must be tested, not assumed**: a published
row still carries domain, verifier type and a dozen statistics, and a reader can enumerate the
same public hub. The test measures how many rows are uniquely determined by their published
fields. If re-identification is easy, fields are dropped until it is not, or the per-row release
is abandoned in favour of the aggregate alone.

## Testing Decisions

No network, no container. Table-driven where the input is data.

- **Every published figure is pinned**, recomputed from committed records and asserted against
  the writeup: both arms, every probe family, both format buckets, the ratio, and every stage
  of the coverage funnel.
- **The funnel closes**: each stage's drop plus the next stage's count equals the previous count.
- **The oracle gate**: a probe whose oracle did not confirm the label is excluded from both
  arms, and a test trips it.
- **Format exclusion**: a probe against an environment declaring a wrapper is excluded from the
  headline, and the test asserts the headline population is `raw`-only.
- **Anonymisation**: tokens stable under a fixed salt, no raw identifier in any committed
  artifact, and the re-identification measurement runs as a test with a declared ceiling.
- **Clustering**: the fingerprint grouping is deterministic and a synthetic corpus with planted
  duplicates recovers the planted group count.

## Out of Scope

- Naming any environment, including the author's own.
- The LLM-judge lane. One environment produced every accept; that is an anecdote and is reported
  as a single observation or not at all.
- Re-running the census, extending coverage, or scoring the sandbox bucket.
- The cross-model slate of §7.
- Any claim about RL environments in general. The claim is about this population.

## Further Notes

- The likeliest hostile question is the population, not the method. 51 environments skewed to
  the hub's simpler tail, where every environment above 5 stars fell out of eligibility. State
  it in the abstract, not the limitations.
- The second likeliest is whether `four` is genuinely a correct answer to a question whose gold
  is `4`. The paper must argue this rather than assume it, and must concede the case where a
  task's contract legitimately demands a digit.
- The false-accept arm is the foil, and it is what makes the brittleness number land. Publishing
  either alone would be weaker than publishing the pair.
