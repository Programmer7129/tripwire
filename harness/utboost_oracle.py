#!/usr/bin/env python3
"""envcert UTBoost oracle (04-code-cert-mvp §3) — the PRIMARY dual-gate oracle.

UTBoost (arXiv:2506.09289, MIT, github.com/uiuc-kang-lab/UTBoost) augments the
weak SWE-bench-Verified test suites with extra tests that a merely-passing patch
must ALSO satisfy. We use those augmented tests as the independent WRONG-oracle in
envcert's dual gate, replacing the LLM-authored differential test as the primary
path (the LLM oracle cannot reliably construct the distinguishing input for subtle
control-flow hacks -> it under-counts; see the 04 §3 UTBoost paragraph).

TWO UTBoost sources are loaded from the pinned repo (third_party/UTBoost):

  1. CONFIRMED  `assets/useful_scripts/augTest.json` — UTBoost's own Docker-confirmed
     augmented tests (36 instances; arXiv v1 quoted more, the repo ships fewer — 04 §8
     flag). Highest trust, used first when it covers the instance.
  2. GENERATED  `assets/useful_scripts/dir_generated_test_cases.zip` (the `verified_*`
     dirs) — UTGenerator's raw candidate augmented tests BEFORE UTBoost's own
     confirmation filter. Much broader instance coverage. We NEVER trust these on
     say-so: every candidate is re-confirmed by OUR OWN Docker gate below.

THE GATE (methodology §1 / 04 §3, load-bearing — identical rigor to the LLM path).
A UTBoost augmented test only flips oracle_wrong=True when, inside swebench's own
Docker,
    (a) it PASSES when the GOLD source patch is applied   (non-defective augmentation;
        guards the paper's 61.9% augmenter-defect rate — a test that fails on gold is
        discarded, never used), AND
    (b) it FAILS when the EXPLOIT candidate patch is applied.
PASS-on-gold AND FAIL-on-exploit => the test pins a real behavioural divergence the
shipped (weak) suite missed => oracle=WRONG, Docker-confirmed. Anything else =>
INCONCLUSIVE for UTBoost (we do NOT claim an exploit; the caller falls back to the
LLM differential gate, then marks inconclusive — never silently PASS).

The augmented test file is injected exactly as swebench's own UTBoost evaluation does:
the candidate test-file diff REPLACES the instance `test_patch`, and the augmented
node ids become FAIL_TO_PASS, so swebench applies (source patch, then augmented test
diff) and runs the augmented node ids inside the disposable per-instance container.
The verdict is read only from swebench's success/failure node lists — never from any
model.

Scope (P0, honest): clean for pytest repos (astropy: swebench runs `pytest <nodeids>`
so a module-level `def test_...` in the augmented file is collected and graded by id).
Django runs via `runtests.py` with dotted `test (module.Class)` ids and does NOT
collect bare module-level functions; UTGenerator's generated django tests are
module-level, so django injection is deferred (reported as covered-but-not-injectable).
"""
from __future__ import annotations

import json
import os
import re
import zipfile
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

import swebench_adapter as A

# --------------------------------------------------------------------------- #
# repo layout (pinned clone, gitignored)
# --------------------------------------------------------------------------- #
_ROOT = Path(__file__).resolve().parent.parent
UTBOOST_ROOT = _ROOT / "third_party" / "UTBoost"
AUGTEST_JSON = UTBOOST_ROOT / "assets" / "useful_scripts" / "augTest.json"
GEN_ZIP = UTBOOST_ROOT / "assets" / "useful_scripts" / "dir_generated_test_cases.zip"

MAX_CANDIDATES = 6   # generated candidates to Docker-check per instance (budget cap)

_TESTFILE_RE = re.compile(r"\+\+\+ b/(\S+)")
_MODFN_RE = re.compile(r"^\+def (test_\w+)", re.MULTILINE)          # module-level
_ANYFN_RE = re.compile(r"^\+\s*def (test_\w+)", re.MULTILINE)       # incl. class methods
_HUNK_CLASS_RE = re.compile(r"^@@.*@@\s*class (\w+)")
_CLASS_RE = re.compile(r"class (\w+)")
_DEF_RE = re.compile(r"def (test_\w+)")


def utboost_available() -> bool:
    return AUGTEST_JSON.exists() or GEN_ZIP.exists()


# --------------------------------------------------------------------------- #
# source loaders (cached)
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def _load_confirmed() -> dict[str, dict]:
    """UTBoost's Docker-confirmed augmented tests: iid -> {aug_test, augFail2Pass}."""
    if not AUGTEST_JSON.exists():
        return {}
    return json.loads(AUGTEST_JSON.read_text())


@lru_cache(maxsize=1)
def _load_generated() -> dict[str, list[str]]:
    """UTGenerator raw candidate test diffs (verified split only): iid -> [unique diffs].

    Read straight from the shipped zip (no extraction side effect). Deduped per
    instance, ordered by number of module-level test functions (desc) so the
    richest candidates are Docker-checked first."""
    out: dict[str, dict[str, int]] = {}
    if not GEN_ZIP.exists():
        return {}
    with zipfile.ZipFile(GEN_ZIP) as zf:
        for name in zf.namelist():
            if "__MACOSX" in name or not name.endswith(".json"):
                continue
            if "verified" not in name.lower():
                continue
            try:
                data = json.loads(zf.read(name))
            except (json.JSONDecodeError, KeyError):
                continue
            if not isinstance(data, dict):
                continue
            for iid, diff in data.items():
                if isinstance(diff, str) and diff.strip():
                    out.setdefault(iid, {}).setdefault(diff, 0)
                    out[iid][diff] += 1
    ranked: dict[str, list[str]] = {}
    for iid, diffs in out.items():
        # keep any candidate with >=1 addable test fn (module-level OR class method);
        # richest first (most parseable node ids)
        scored = [(d, _parse_candidate(d)) for d in diffs]
        scored = [(d, p) for d, p in scored if p and p[1]]
        scored.sort(key=lambda dp: -len(dp[1][1]))
        ranked[iid] = [d for d, _ in scored]
    return ranked


def _parse_candidate(diff: str) -> Optional[tuple[str, list[str]]]:
    """(test_file, [pytest node ids]) from a candidate test-file diff, or None.

    Handles module-level `def test_...` (-> file::fn) and class methods
    (`    def test_...` inside a `class X` -> file::X::fn). The enclosing class is
    tracked from the hunk section heading (`@@ ... @@ class X`) and from any `class X`
    line (added or context) seen within the hunk, keyed by indentation. A method whose
    class can't be resolved is skipped (a bad node id can only miss, never false-confirm:
    it fails the gold-sanity run and the candidate is discarded)."""
    mf = _TESTFILE_RE.search(diff)
    if not mf:
        return None
    tf = mf.group(1)
    seen: set[str] = set()
    nodes: list[str] = []
    cur_class: Optional[str] = None
    class_indent = -1
    for raw in diff.splitlines():
        if raw.startswith("@@"):
            m = _HUNK_CLASS_RE.match(raw)
            cur_class = m.group(1) if m else None
            class_indent = 0 if m else -1
            continue
        if not raw or raw[0] not in "+ ":
            continue
        body = raw[1:]
        stripped = body.lstrip()
        indent = len(body) - len(stripped)
        cm = _CLASS_RE.match(stripped)
        if cm:
            cur_class = cm.group(1)
            class_indent = indent
            continue
        if raw[0] != "+":
            continue  # only ADDED test defs become nodes
        dm = _DEF_RE.match(stripped)
        if not dm:
            continue
        fn = dm.group(1)
        if indent == 0:
            nid = f"{tf}::{fn}"
        elif cur_class is not None and indent > class_indent:
            nid = f"{tf}::{cur_class}::{fn}"
        else:
            continue  # indented def with no resolvable class -> skip
        if nid not in seen:
            seen.add(nid)
            nodes.append(nid)
    return (tf, nodes) if nodes else None


def candidate_suites(instance_id: str) -> list[dict]:
    """Ordered UTBoost augmented-test candidates for an instance. CONFIRMED first,
    then GENERATED (richest first). Each: {source, test_diff, node_ids}."""
    suites: list[dict] = []
    conf = _load_confirmed().get(instance_id)
    if conf and conf.get("aug_test"):
        parsed = _parse_candidate(conf["aug_test"])
        if parsed:
            _, nodes = parsed
            suites.append({"source": "confirmed", "test_diff": conf["aug_test"],
                           "node_ids": nodes})
    for diff in _load_generated().get(instance_id, []):
        parsed = _parse_candidate(diff)
        if parsed:
            _, nodes = parsed
            suites.append({"source": "generated", "test_diff": diff, "node_ids": nodes})
    return suites


def covers(instance_id: str) -> bool:
    return bool(candidate_suites(instance_id))


# --------------------------------------------------------------------------- #
# Docker gate
# --------------------------------------------------------------------------- #
def _run_suite(inst: dict, source_patch: str, test_diff: str, node_ids: list[str],
               run_id: str, timeout: int) -> dict:
    """Apply source_patch, inject the UTBoost augmented test diff as the test_patch,
    run the augmented node ids inside swebench Docker; report per-node pass/fail."""
    aug = dict(inst)
    aug["test_patch"] = test_diff
    aug["FAIL_TO_PASS"] = node_ids
    aug["PASS_TO_PASS"] = []
    res = A.apply_and_run(aug, source_patch, run_id=run_id, timeout=timeout)
    succ = set(res["fail_to_pass_results"]["success"])
    fail = set(res["fail_to_pass_results"]["failure"])
    return {"resolved": res["resolved"], "applied": res["patch_applied"],
            "error": res["error"], "success_nodes": sorted(succ),
            "failure_nodes": sorted(fail),
            "tail": (res["logs"].get("test_output_tail") or "")[-1500:]}


def utboost_gate(inst: dict, exploit_patch: str, *,
                 timeout: int = A.DEFAULT_TIMEOUT,
                 max_candidates: int = MAX_CANDIDATES) -> dict:
    """PRIMARY oracle. oracle_wrong=True ONLY when a UTBoost augmented test is
    Docker-confirmed PASS-on-gold AND FAIL-on-exploit. Returns a verdict dict.

    verdict:
      no_coverage    — UTBoost has no injectable augmented test for this instance
      wrong_confirmed — a UTBoost test pins a gold/exploit divergence (oracle_wrong)
      inconclusive   — has candidates, none discriminated (defective on gold, or the
                       augmented tests pass on BOTH gold and exploit)
    """
    iid = inst["instance_id"]
    repo = inst["repo"]
    is_pytest = repo.startswith("astropy")
    rec: dict[str, Any] = {"oracle": "utboost", "repo": repo, "instance_id": iid,
                           "pytest_injection": is_pytest, "oracle_wrong": False,
                           "verdict": "no_coverage", "attempts": []}
    suites = candidate_suites(iid)
    rec["n_candidates_available"] = len(suites)
    if not suites:
        rec["note"] = "UTBoost has no augmented test for this instance"
        return rec
    if not is_pytest:
        # covered by UTBoost but not injectable via runtests.py (django) — honest scope
        rec["verdict"] = "coverage_not_injectable"
        rec["note"] = ("UTBoost augmented tests exist but repo runs via runtests.py "
                       "(dotted-module ids); module-level generated tests are not "
                       "collected -> pytest-only injection (P1). Not claiming exploit.")
        return rec

    for i, suite in enumerate(suites[:max_candidates]):
        nodes = suite["node_ids"]
        rid = f"utgate-{iid[:20]}-{i}"
        gold = _run_suite(inst, inst["patch"], suite["test_diff"], nodes,
                          rid + "-gold", timeout)
        pass_on_gold = [n for n in nodes if n in gold["success_nodes"]]
        at: dict[str, Any] = {"candidate": i, "source": suite["source"],
                              "node_ids": nodes, "test_diff": suite["test_diff"],
                              "gold": gold, "pass_on_gold_nodes": pass_on_gold}
        if not pass_on_gold:
            at["discard_reason"] = ("augmentation FAILED/errored on gold "
                                    "(defective augmentation, paper §3.3) -> discard")
            rec["attempts"].append(at)
            continue
        # STAGE 2 (differential): the pass-on-gold nodes must FAIL on the exploit.
        expl = _run_suite(inst, exploit_patch, suite["test_diff"], pass_on_gold,
                          rid + "-expl", timeout)
        confirming = [n for n in pass_on_gold if n in expl["failure_nodes"]]
        at["exploit"] = expl
        at["confirming_nodes"] = confirming
        rec["attempts"].append(at)
        if confirming:
            rec["oracle_wrong"] = True
            rec["verdict"] = "wrong_confirmed"
            rec["confirming_source"] = suite["source"]
            rec["confirming_nodes"] = confirming
            rec["aug_test_diff"] = suite["test_diff"]
            rec["aug_test_nodes"] = confirming
            return rec
        at["note"] = ("valid augmentation (pass-on-gold) but the exploit ALSO passes it "
                      "-> no divergence pinned by this UTBoost test")
    rec["verdict"] = "inconclusive"
    rec["note"] = ("UTBoost has augmented tests but none Docker-discriminated gold from "
                   "exploit (they pass on both, or were defective on gold)")
    return rec


# --------------------------------------------------------------------------- #
# CLI (one-off inspection)
# --------------------------------------------------------------------------- #
def _main(argv: Optional[list[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="UTBoost oracle — coverage / one-off gate")
    ap.add_argument("instance_id")
    ap.add_argument("--exploit-file", help="candidate diff to gate; else just report coverage")
    ap.add_argument("--timeout", type=int, default=A.DEFAULT_TIMEOUT)
    ap.add_argument("--max-candidates", type=int, default=MAX_CANDIDATES)
    args = ap.parse_args(argv)
    iid = args.instance_id
    suites = candidate_suites(iid)
    print(json.dumps({"instance_id": iid, "utboost_available": utboost_available(),
                      "n_candidate_suites": len(suites),
                      "sources": [s["source"] for s in suites],
                      "node_ids": [s["node_ids"] for s in suites]}, indent=2))
    if args.exploit_file:
        inst = A.get_instance(iid)
        exploit = Path(args.exploit_file).read_text()
        rec = utboost_gate(inst, exploit, timeout=args.timeout,
                           max_candidates=args.max_candidates)
        slim = {k: rec[k] for k in ("oracle_wrong", "verdict", "confirming_source",
                                    "confirming_nodes", "n_candidates_available")
                if k in rec}
        print(json.dumps(slim, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
