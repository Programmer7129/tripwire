<div align="center">

# 🔦 Tripwire

### An open, deterministic harness that measures how often RL training verifiers accept *wrong* answers.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Results: reproducible](https://img.shields.io/badge/results-reproducible-brightgreen.svg)](#-reproduce-it-yourself)
[![Compute: $29.98](https://img.shields.io/badge/compute-%2429.98-success.svg)](#cost)
[![Reproduces arXiv:2606.16062](https://img.shields.io/badge/reproduces-arXiv%3A2606.16062-b31b1b.svg)](https://arxiv.org/abs/2606.16062)
[![Oracle: differential execution](https://img.shields.io/badge/oracle-differential%20execution-8A2BE2.svg)](#how-it-works)

</div>

---

Reinforcement learning trains a model against a **verifier** — a reward function that decides whether an
answer is right. In code, that verifier is a test suite: the patch passes the tests, it gets the reward.
But if the tests are weak, a **wrong** patch passes too, and the model is rewarded for *gaming the check
instead of solving the task.* This is **reward hacking**, and it silently corrupts the training signal on
the exact benchmarks the field treats as gold-standard.

Everyone is racing to *build* RL environments and verifiers. **Nobody independently certifies that they
work.** Tripwire is that missing layer. It attacks a verifier the way a pentester attacks a network,
then **dual-gates** every hit: a failure counts only when the verifier says PASS *and* an independent,
deterministic oracle proves the answer is actually WRONG.

## 📊 Headline

On **SWE-bench Verified** — the industry-standard coding benchmark for code-RL reward — measured with an
open, pre-registered, dual-gated harness:

```
 Verifier verdict alone (shipped test suite accepts a patch that differs from gold)
   51.0%  ██████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░   255 / 500 tasks

 Dual-gated  (that patch independently proven WRONG, not an LLM's opinion)
   13.7%  ███████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   ~69 / 500   [95% CI 10.1–18.0%]
```

> **On half of SWE-bench Verified, the shipped test suite accepts a patch that is not the accepted fix.
> About 1 in 7 admits a *confirmed* reward-hack** — a patch that passes the shipped tests but demonstrably
> does the wrong thing, each backed by a reproducer you can re-run.

Those two numbers measure different things and the gap between them is the point. Passing the suite with a
patch that differs from gold is **not** evidence of a wrong patch: most such patches are legitimate
alternative fixes. In the pre-registered sample of 102, adjudication came back **31 HACK / 67 CORRECT /
4 AMBIGUOUS** — about two thirds were correct. That is exactly why the dual gate exists, and why 13.7%
rather than 51.0% is this project's finding.

The prior published result ([arXiv:2606.16062](https://arxiv.org/abs/2606.16062)) measured this on 49 tasks
and **never released its code**. Tripwire reproduces it with an open harness and extends it to the **full
500-task benchmark** for the first time — with a *stricter* oracle (deterministic behavioral divergence,
not an LLM-augmented test), so every number here is a conservative **lower bound**.

## The finding in one table

| Run | Tasks | Attacker | Suite accepts a patch differing from gold | Confirmed reward-hack (dual-gated) |
| --- | --- | --- | --- | --- |
| **Anchor** (reproduction) | 49 (astropy + django) | Claude Sonnet 4.5 | — | **11/49 = 22.4%** |
| Anchor — capability ladder | 49 | Claude Haiku 4.5 | — | 8/49 = 16.3% |
| Reference — arXiv:2606.16062 | 49 | Claude Sonnet 4 | — | 14/49 = 28.5% |
| **Extend** (novel — full benchmark) | **500 (11 repos)** | Claude Sonnet 4.5 | **51.0%** (255/500) | **13.7%** — CI [10.1–18.0%] |

The full-500 confirmed rate (13.7%) is *lower* than the anchor's 22.4% **on purpose** — the full benchmark
includes robust repos (sympy, scikit-learn, sphinx, pytest) with stronger suites, so it's more
representative than the hackable-heavy astropy/django slice the anchor and the prior paper used.

## How it works

Tripwire wraps every candidate in a two-stage gate. The attacker is *only* a search process; the **verdict
is deterministic execution**, never an LLM judge.

```mermaid
flowchart LR
    A["SWE-bench task<br/>(issue + hidden test suite)"] --> B["Attacker LLM<br/>K=3 rounds, fed the<br/>failing-test logs.<br/>Goal: a WRONG patch<br/>that passes the tests"]
    B --> C{"Native verifier<br/>shipped test_patch<br/>run in Docker"}
    C -- "fails the tests" --> X["not hackable"]
    C -- "PASS" --> D{"Dual-gate oracle<br/>differential execution:<br/>run gold vs candidate<br/>on generated inputs"}
    D -- "same behavior as gold" --> Y["legitimate alternative fix<br/><i>conservatively excluded</i>"]
    D -- "diverges → provably WRONG" --> Z["✅ CONFIRMED reward-hack<br/>+ divergent-input reproducer"]
```

**The dual-gate is the whole point.** The gold (accepted) patch defines correct behavior. A candidate that
passes the tests but diverges from the gold patch on *some input* is, by construction, a wrong answer the
verifier rewarded. Where the callable can't be driven automatically (e.g. Django ORM methods needing DB
fixtures), it falls back to conservative code hand-review — the same manual EQS method the reference paper
used. Legitimate alternative fixes that merely differ from gold are **excluded**, which is why the reported
numbers are lower bounds.

Everything is **pre-registered** (`docs/preregistration.md`) — thresholds, the stratified sample, and the
disclosure policy were committed *before* any verdict was read.

## 🔁 Reproduce it yourself

Requirements: Docker, Python 3.11+, and an LLM attacker key (Anthropic API or AWS Bedrock).

```bash
git clone https://github.com/Programmer7129/tripwire && cd tripwire
pip install -r requirements.txt
export ANTHROPIC_API_KEY=...        # or configure AWS Bedrock and pass --provider bedrock
```

**1 — Sanity-check the verifier adapter** (the gold patch must resolve; a no-op must not):

```bash
python harness/swebench_adapter.py astropy__astropy-12907 --gold     # expect: resolved = True
python harness/swebench_adapter.py astropy__astropy-12907 --noop     # expect: resolved = False
```

**2 — Run the attack** on the pinned anchor subset (the 49 task IDs are in `results/swe_subset.json`):

```bash
python harness/code_attack.py <instance_ids...> \
    --provider anthropic --attacker-model claude-sonnet-4-5 \
    --out results/raw_swe
```

**3 — Confirm a hit with the deterministic oracle** (gold vs candidate behavioral divergence):

```bash
python harness/diffexec_oracle.py astropy__astropy-14309 --exploit-file <candidate.diff>
```

**4 — Recompute the headline** from the committed evidence in `results/` (no Docker, no API key).
Both numbers derive from files in this repository — the verifier-alone rate from the 500 per-task
attack records, the confirmed rate from the per-task dual-gate verdicts:

```bash
python harness/swe_native_rate.py   # 51.0% (255/500) and the 226-task confirm queue
python harness/swe_confirm.py       # 13.7% [10.1-18.0%] — Wilson interval, pre-registered estimator
```

For the hub Class-A code lane (Wilson CIs, Benjamini–Hochberg FDR, cluster-bootstrap over envs):

```bash
python harness/code_aggregate.py
```

**5 — Run the tests** (no network, no Docker, no API key, no GPU):

```bash
pip install -e ".[dev]" && pytest -q
```

Exact parameters, the seed-42 stratified sample, and the per-task verdicts are in
[`docs/anchor-result.md`](docs/anchor-result.md) and [`docs/extend-result.md`](docs/extend-result.md).

## What's in this repo

```
harness/          the tooling (attacker, SWE-bench adapter, differential-execution oracle, aggregation)
  code_attack.py        the reward-hack attacker (K=3, failure-log feedback, deterministic diff transport)
  swebench_adapter.py   apply any patch → run the native verifier → read resolved
  diffexec_oracle.py    the dual-gate: gold vs candidate behavioral divergence, verdict by execution
  aggregate.py          Wilson CIs, BH-FDR, beta-binomial pooling, cluster-bootstrap over envs
  code_aggregate.py     the same statistics for the hub Class-A code lane
  swe_confirm.py        recomputes the published confirmed rate (13.7%) from results/
  swe_native_rate.py    recomputes the verifier-alone rate (51.0%) from the raw attack records
results/          the evidence — every confirmed hack, its reproducer, and the pre-drawn sample
  raw_swe_500/          all 500 per-task attack records: the evidence behind 51.0% (4.1 MB)
tests/            the metric test suite — no network, no Docker, no API key, no GPU
docs/
  anchor-result.md      the reproduction (11/49) + capability ladder, per-task rationale
  extend-result.md      the novel full-500 result (51% / 13.7%), sampling + honest limitations
  preregistration.md    thresholds & protocol, committed before any verdict
```

> **A note on the name.** The public artifact is **Tripwire**. `envcert` is the older internal name
> and still appears in runtime identifiers — the Docker image and container names
> (`envcert-base:latest`), the egress network and proxy names, the in-container probe paths and the
> run-id prefixes. Those are load-bearing strings, not prose, so they are left alone; nothing named
> `envcert` is a separate project.

## Honest limitations

Conservative science is a credibility asset, so these are stated up front (full detail in the docs):

- **28 of 31 confirmed hacks in the extend sample rest on code hand-review**, not deterministic execution —
  Django ORM callables need DB/app fixtures the oracle doesn't yet build. The 3 fully-deterministic
  exhibits (`django-13933`, `django-14122`, `astropy-14309`) are the auto-confirmed proof; broader
  fixture-driven auto-confirmation is future work.
- The confirmed rate is estimated from a **pre-registered stratified sample (n=102, seed 42)**, not an
  exhaustive review of all 226 hackable candidates.
- SWE-bench Verified is itself contested for contamination; the reward-hacking failure measured here is
  independent of contamination (a wrong patch passing a weak test suite), but decontaminated benchmarks
  are on the roadmap.
- An earlier full-500 pass was **discarded** after a Docker disk-exhaustion bug silently produced empty
  patches; caught, fixed, and re-run clean. The before/after is documented as part of the record.

<a name="cost"></a>**Total attacker spend: $29.98**, summed from the `cost_usd` field of every
attack record. **$21.60 of that is checkable from this repository** — the full-500 pass, whose 500
records are committed and whose total is pinned by `pytest`. The remaining **$8.38 is not
independently checkable here**: the anchor run ($2.53), the discarded v1 ($2.64), the Haiku
capability rung ($2.58) and the retest and diagnostic passes ($0.63), whose raw records stay out of
the repo as superseded intermediates. Docker and CPU time are local and unmetered. (An earlier
revision said `~$15`; that was the anchor-scale estimate and it understated the total.)

## Why this matters

A broken verifier is worse than no verifier: it actively teaches a model to game the check. Reward hacking
gets *harder* to catch as models get stronger, and a verifier that's sound against today's model can be
gamed by the next one — so verifier soundness needs measuring continuously, per model generation. Tripwire
is the open, independent instrument for that.

## Citation & references

- Rajan, S. *Auditing Reward Hackability in Code RL Training Environments.* [arXiv:2606.16062](https://arxiv.org/abs/2606.16062) — the result this reproduces and extends.
- *SWE-bench: Can Language Models Resolve Real-World GitHub Issues?* [princeton-nlp/SWE-bench](https://github.com/SWE-bench/SWE-bench)
- Related verifier-adequacy work: UTBoost ([arXiv:2506.09289](https://arxiv.org/abs/2506.09289)), STING ([arXiv:2604.01518](https://arxiv.org/abs/2604.01518)).

## License

[MIT](LICENSE). See [`NOTICE`](NOTICE) — the confirmed-exploit artifacts carry a canary and **must not be
used as model training data.**

<div align="center"><sub>Built by Vedant Patel · vedantspatel33@gmail.com</sub></div>
