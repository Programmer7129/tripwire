#!/usr/bin/env python3
"""envcert offline rubric-scoring probe — runs INSIDE the disposable container.

Two phases (network is controlled by the host runner, not here):
  --prepare : network ON. import the env, call load_environment() once to warm
              the HF dataset cache and confirm v0-vs-v1. writes a status file.
  --score   : network OFF. re-load the env offline (cache hit), pull a few
              dataset rows, feed a battery of canned probe completions into
              env.rubric.score_rollout(state), emit one JSONL record per
              (row, probe) with the full metrics dict.

NEVER trust the verifier's own verdict as ground truth — this tool only records
(reward, metrics); the dual-gate oracle comparison happens downstream.
"""
import argparse
import asyncio
import hashlib
import importlib
import importlib.metadata as ilmd
import json
import os
import sys
import time
import traceback

# ---------------------------------------------------------------------------
# env resolution
# ---------------------------------------------------------------------------

def _candidate_modules(package, name):
    """Ordered guesses for the importable top-level module of an env dist."""
    seen, out = set(), []

    def add(m):
        if m and m not in seen:
            seen.add(m)
            out.append(m)

    # top_level.txt from installed dist metadata (most reliable)
    for dist_name in (package, name, (name or "").replace("-", "_")):
        if not dist_name:
            continue
        try:
            tl = ilmd.distribution(dist_name).read_text("top_level.txt")
            if tl:
                for line in tl.splitlines():
                    add(line.strip())
        except Exception:
            pass
    # name-derived guesses
    for base in (name, package):
        if base:
            add(base.replace("-", "_"))
            add(base.replace("-", ""))
            add(base)
    return out


def resolve_env(package, name):
    """Return (env_object, module_name, how). Tries verifiers' own resolver
    first, then direct module import. Raises on total failure."""
    errors = []

    # 1) verifiers top-level resolver: load_environment('<name>')
    try:
        import verifiers as vf
        loader = getattr(vf, "load_environment", None)
        if loader is not None:
            for ident in (name, package, (name or "").replace("-", "_")):
                if not ident:
                    continue
                try:
                    env = loader(ident)
                    return env, f"verifiers.load_environment({ident!r})", "vf_resolver"
                except Exception as e:  # noqa: BLE001
                    errors.append(f"vf.load_environment({ident!r}): {e!r}")
    except Exception as e:  # noqa: BLE001
        errors.append(f"import verifiers: {e!r}")

    # 2) direct module import + module.load_environment()
    for mod_name in _candidate_modules(package, name):
        try:
            mod = importlib.import_module(mod_name)
        except Exception as e:  # noqa: BLE001
            errors.append(f"import {mod_name}: {e!r}")
            continue
        fn = getattr(mod, "load_environment", None)
        if fn is None:
            errors.append(f"{mod_name}: no load_environment")
            continue
        env = fn()
        return env, mod_name, "direct_import"

    raise RuntimeError("could not resolve env; tried:\n  " + "\n  ".join(errors))


def detect_api(env):
    """v0 iff the env exposes a rubric with an async score_rollout(state).
    v1 packages score @vf.reward methods against a vf.Trace instead."""
    rubric = getattr(env, "rubric", None)
    if rubric is not None and hasattr(rubric, "score_rollout"):
        return "v0"
    # secondary signal: module path / verifiers.v1
    mod = type(env).__module__ or ""
    if "_v1" in mod or ".v1" in mod:
        return "v1"
    return "v1" if rubric is None else "v0"


# ---------------------------------------------------------------------------
# dataset rows
# ---------------------------------------------------------------------------

def get_dataset(env):
    for attr in ("dataset", "eval_dataset"):
        ds = getattr(env, attr, None)
        if ds is not None and len(ds) > 0:
            return ds
    return None


def row_fields(row):
    """Normalise a dataset row into (question_str, answer, info, task)."""
    question = ""
    if isinstance(row.get("question"), str):
        question = row["question"]
    elif isinstance(row.get("prompt"), list) and row["prompt"]:
        # messages -> take the last user turn's content
        for msg in reversed(row["prompt"]):
            if isinstance(msg, dict) and msg.get("role") == "user":
                question = str(msg.get("content", ""))
                break
        if not question:
            question = str(row["prompt"][-1].get("content", ""))
    elif isinstance(row.get("prompt"), str):
        question = row["prompt"]
    answer = row.get("answer", "")
    info = row.get("info", {}) or {}
    task = row.get("task", "default") or "default"
    return question, answer, info, task


# ---------------------------------------------------------------------------
# probe battery
# ---------------------------------------------------------------------------

def mutate_wrong(answer):
    s = str(answer).strip()
    try:
        val = float(s.replace(",", "").replace("$", "").rstrip("%"))
        return str(int(val) + 1) if val == int(val) else str(val + 1.0)
    except (TypeError, ValueError):
        return "definitely-not-the-answer-xyzzy" if not s else ("wrong-" + s[::-1])


def build_probes(answer):
    """(probe_type, completion_text). Multiple gold/wrong *representations* so a
    record survives whatever parser the env uses (exact / boxed / prose / xml)."""
    a = str(answer)
    wrong = mutate_wrong(answer)
    return [
        ("gold_raw",           a),
        ("gold_boxed",         f"\\boxed{{{a}}}"),
        ("gold_prose",         f"Reasoning aside, the final answer is {a}."),
        ("gold_xml",           f"<answer>{a}</answer>"),
        ("empty",              ""),
        ("known_wrong_raw",    wrong),
        ("known_wrong_boxed",  f"\\boxed{{{wrong}}}"),
    ]


def make_state(question, completion_text, answer, info, task):
    # trajectory/responses/turn are empty defaults so weight-0 monitor reward
    # funcs (e.g. num_turns) don't KeyError on our minimal single-turn state;
    # they don't affect the real verifier's verdict.
    return {
        "prompt":     [{"role": "user", "content": question}],
        "completion": [{"role": "assistant", "content": completion_text}],
        "answer":     answer,
        "info":       info,
        "task":       task,
        "trajectory": [],
        "responses":  [],
        "turn":       1,
    }


def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def score_one(env, state):
    """Run the (async) rubric scorer and normalise the result.

    verifiers 0.2.0's score_rollout returns None and writes reward/metrics INTO
    the state dict; older/other versions return a RolloutScore {reward, metrics}.
    Handle both: prefer an explicit return, fall back to the mutated state."""
    res = asyncio.run(env.rubric.score_rollout(state))
    reward = _get(res, "reward") if res is not None else None
    metrics = (_get(res, "metrics", None) if res is not None else None)
    if reward is None:
        reward = state.get("reward")
    if metrics is None:
        metrics = state.get("metrics", {})
    metrics = metrics or {}
    try:
        reward = float(reward)
    except (TypeError, ValueError):
        pass
    metrics = {k: (float(v) if isinstance(v, (int, float)) else v) for k, v in dict(metrics).items()}
    return reward, metrics


# ---------------------------------------------------------------------------
# phases
# ---------------------------------------------------------------------------

def config_hash(kwargs):
    return hashlib.sha256(json.dumps(kwargs, sort_keys=True, default=str).encode()).hexdigest()[:16]


def phase_prepare(args, status_path):
    status = {"env_id": args.env_id, "phase": "prepare", "ts": time.time()}
    try:
        env, how, mech = resolve_env(args.package, args.name)
        api = detect_api(env)
        ds = get_dataset(env)
        # static (introspection-only, NO scoring) bucket so the host runner can
        # decide judge-mode BEFORE cutting the network — llm_judge envs keep the
        # allowlist egress up for scoring; everything else is scored zero-network.
        static_bucket = None
        try:
            _classify, _p, _o, _f = _load_harness_modules()
            static_bucket = _classify.classify_static(env).get("bucket")
        except Exception as e:  # noqa: BLE001
            status["static_bucket_error"] = repr(e)
        status.update({
            "ok": True,
            "verifiers_api": api,
            "resolved_via": mech,
            "resolver_detail": how,
            "rubric_class": type(getattr(env, "rubric", None)).__name__,
            "static_bucket": static_bucket,
            "dataset_rows": (len(ds) if ds is not None else 0),
            "verifiers_version": _pkg_version("verifiers"),
        })
    except Exception as e:  # noqa: BLE001
        status.update({"ok": False, "error": repr(e), "traceback": traceback.format_exc()})
    _write_json(status_path, status)
    print(f"[prepare] {json.dumps(status)[:400]}")
    return 0 if status.get("ok") else 1


def phase_score(args, out_path):
    ts = time.time()
    kwargs = {}  # declared default config — no custom tolerances
    chash = config_hash(kwargs)
    records = []

    def emit(rec):
        base = {
            "env_id": args.env_id,
            "env_package": args.package,
            "config_hash": chash,
            "ts": time.time(),
        }
        base.update(rec)
        records.append(base)

    try:
        env, how, mech = resolve_env(args.package, args.name)
    except Exception as e:  # noqa: BLE001
        emit({"error": f"resolve_env failed: {e!r}", "traceback": traceback.format_exc()})
        _write_jsonl(out_path, records)
        print(f"[score] FATAL resolve: {e!r}")
        return 1

    api = detect_api(env)
    rubric = getattr(env, "rubric", None)
    rubric_class = type(rubric).__name__ if rubric is not None else None
    reward_func_names = _reward_func_names(rubric)

    if api != "v0":
        emit({
            "verifiers_api": api, "rubric_class": rubric_class,
            "reward_func_names": reward_func_names,
            "skipped": True,
            "note": "v1 package (scores @vf.reward against vf.Trace); Phase 0 targets v0 — skipped gracefully",
        })
        _write_jsonl(out_path, records)
        print(f"[score] {args.env_id} is v1 — skipped (spec §7 item 3)")
        return 0

    ds = get_dataset(env)
    if ds is None:
        emit({"verifiers_api": api, "rubric_class": rubric_class, "error": "no dataset rows available"})
        _write_jsonl(out_path, records)
        return 1

    observed_funcs = set()
    n = min(args.rows, len(ds))
    for i in range(n):
        try:
            row = ds[i]
            question, answer, info, task = row_fields(row)
        except Exception as e:  # noqa: BLE001
            emit({"row_id": i, "error": f"row read failed: {e!r}"})
            continue
        for probe_type, completion_text in build_probes(answer):
            rec = {
                "verifiers_api": api,
                "row_id": i,
                "probe_type": probe_type,
                "candidate_preview": completion_text[:120],
                "rubric_class": rubric_class,
                "reward_func_names": reward_func_names,
            }
            try:
                state = make_state(question, completion_text, answer, info, task)
                reward, metrics = score_one(env, state)
                rec["reward"] = reward
                rec["metrics"] = metrics
                observed_funcs.update(metrics.keys())
            except Exception as e:  # noqa: BLE001
                rec["error"] = repr(e)
                rec["traceback"] = traceback.format_exc()[:2000]
            emit(rec)

    # If rubric introspection came up empty, the metrics keys directly name the
    # reward funcs that fired — backfill so the attribution field is populated.
    if not reward_func_names and observed_funcs:
        rfn = sorted(observed_funcs)
        for r in records:
            if not r.get("reward_func_names"):
                r["reward_func_names"] = rfn

    _write_jsonl(out_path, records)
    ok = sum(1 for r in records if "reward" in r)
    print(f"[score] {args.env_id}: {ok}/{len(records)} scored, api={api}, rubric={rubric_class}, funcs={reward_func_names}")
    return 0


# ---------------------------------------------------------------------------
# dual-gated battery + classification (Phase 1) — pre-reg §1/§3/§4
# ---------------------------------------------------------------------------

def _load_harness_modules():
    """Import the sibling classify/probes/oracle modules. They live next to this
    file; add its dir to sys.path so this works whether we're run as
    /app/score_env.py in-container or from the repo. Lazy on purpose: the legacy
    --prepare/--score paths must keep working even if these modules aren't
    mounted."""
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    import classify as _classify
    import probes as _probes
    import oracle as _oracle
    import formatting as _formatting
    return _classify, _probes, _oracle, _formatting


def _majority_reward(rewards):
    """Modal reward across k repeats + instability flag. Rewards rounded to 6dp
    for the modal count; instability = >1 distinct rounded value (judge/flaky
    non-determinism, pre-reg §4)."""
    vals = [r for r in rewards if isinstance(r, (int, float))]
    if not vals:
        return None, False
    rounded = [round(float(v), 6) for v in vals]
    from collections import Counter
    modal, _ = Counter(rounded).most_common(1)[0]
    unstable = len(set(rounded)) > 1
    return modal, unstable


def phase_classify(args, out_path):
    """Emit the verifier-type classification record (pre-reg §1). Static
    introspection, then (if a dataset is available) a tiny gold/known-wrong probe
    to observe the reward range and finalize binary-vs-soft empirically."""
    _classify, _probes, _oracle, _formatting = _load_harness_modules()
    rec = {"env_id": args.env_id, "env_package": args.package,
           "mode": "classify", "ts": time.time(),
           "verifiers_version": _pkg_version("verifiers")}
    try:
        env, how, mech = resolve_env(args.package, args.name)
    except Exception as e:  # noqa: BLE001
        rec.update(ok=False, error=f"resolve_env failed: {e!r}",
                   traceback=traceback.format_exc())
        _write_json(out_path, rec)
        print(f"[classify] FATAL resolve: {e!r}")
        return 1

    api = detect_api(env)
    rec["verifiers_api"] = api
    try:
        cls = _classify.classify_static(env)
    except Exception as e:  # noqa: BLE001
        rec.update(ok=False, error=f"classify_static failed: {e!r}",
                   traceback=traceback.format_exc())
        _write_json(out_path, rec)
        print(f"[classify] introspection failed: {e!r}")
        return 1
    rec.update(cls)

    # empirical binary-vs-soft finalization (only when applicable + v0 + dataset)
    observed = []
    if api == "v0" and cls["bucket"] in ("binary", "soft"):
        ds = get_dataset(env)
        if ds is not None:
            n = min(getattr(args, "rows", 5) or 5, len(ds))
            for i in range(n):
                try:
                    q, ans, info, task = row_fields(ds[i])
                except Exception:
                    continue
                for _pt, cand, _lbl, _prov in [
                    ("gold", str(ans), None, None),
                    ("wrong", _probes.gen_known_wrong(ans)[0].candidate_text
                        if _probes.gen_known_wrong(ans) else None, None, None),
                ]:
                    if cand is None:
                        continue
                    try:
                        state = make_state(q, cand, ans, info, task)
                        r, _m = score_one(env, state)
                        if isinstance(r, (int, float)):
                            observed.append(float(r))
                    except Exception:
                        continue
        final, detail = _classify.finalize_binary_soft(cls["bucket"], observed)
        rec["bucket"] = final
        rec["binary_soft_detail"] = detail
        rec["observed_rewards"] = observed
    rec["ok"] = True
    _write_json(out_path, rec)
    print(f"[classify] {args.env_id}: bucket={rec['bucket']} api={api} "
          f"rubric={cls['rubric_class']} env={cls['env_class']} "
          f"funcs={cls['reward_func_names']}")
    return 0


def phase_battery(args, out_path):
    """Dual-gated per-probe battery (pre-reg §3/§4). For each of N rows, build the
    probe battery, screen every candidate through the INDEPENDENT oracle, run each
    KEPT candidate through score_rollout k>=5 times, and emit one JSONL record per
    (row, probe). FAR/aggregates are NOT computed here (Phase 2)."""
    _classify, _probes, _oracle, _formatting = _load_harness_modules()
    ts = time.time()
    chash = config_hash({})  # env's own declared default config
    records = []

    def emit(rec):
        base = {"env_id": args.env_id, "env_package": args.package,
                "config_hash": chash, "ts": time.time()}
        base.update(rec)
        records.append(base)

    try:
        env, how, mech = resolve_env(args.package, args.name)
    except Exception as e:  # noqa: BLE001
        emit({"error": f"resolve_env failed: {e!r}", "traceback": traceback.format_exc()})
        _write_jsonl(out_path, records)
        print(f"[battery] FATAL resolve: {e!r}")
        return 1

    api = detect_api(env)
    rubric = getattr(env, "rubric", None)
    rubric_class = type(rubric).__name__ if rubric is not None else None
    reward_func_names = _reward_func_names(rubric)

    try:
        cls = _classify.classify_static(env)
        static_bucket = cls["bucket"]
    except Exception as e:  # noqa: BLE001
        cls, static_bucket = {"bucket": "unknown", "error": repr(e)}, "unknown"

    if api != "v0":
        emit({"verifiers_api": api, "rubric_class": rubric_class,
              "reward_func_names": reward_func_names, "verifier_type": static_bucket,
              "skipped": True,
              "note": "v1 package — Phase 1 battery targets v0; skipped gracefully"})
        _write_jsonl(out_path, records)
        print(f"[battery] {args.env_id} is v1 — skipped")
        return 0

    ds = get_dataset(env)
    if ds is None:
        emit({"verifiers_api": api, "rubric_class": rubric_class,
              "verifier_type": static_bucket, "error": "no dataset rows available"})
        _write_jsonl(out_path, records)
        return 1

    k = max(1, getattr(args, "k", 5) or 5)
    n = min(args.rows, len(ds))
    observed_rewards = []       # only from far/frr scored probes -> binary/soft
    observed_funcs = set()

    # ---- auto-format discovery + applicability gating (Phase 2 validity fix) ----
    # Find the first readable row to (a) decide answer-substitutability and (b)
    # discover the passing completion FORMAT from the env's OWN parser + reward.
    # The discovered format is cached and reused for the anchor + every probe.
    disc_row = None
    for j in range(n):
        try:
            disc_row = row_fields(ds[j])
            break
        except Exception:
            continue

    discovered = None
    applicability = "substitutable"
    applic_reason = "no readable row for applicability check"
    if disc_row is not None:
        dq, da, dinfo, dtask = disc_row
        applicability, applic_reason = _formatting.classify_applicability(da, dinfo)
        if applicability == "substitutable":
            def _score_completion(text, _q=dq, _a=da, _i=dinfo, _t=dtask):
                state = make_state(_q, text, _a, _i, _t)
                r, _m = score_one(env, state)
                return r
            try:
                discovered = _formatting.discover_format(env, da, _score_completion)
            except Exception as e:  # noqa: BLE001
                emit({"mode": "format_discovery", "error": f"discover_format failed: {e!r}",
                      "traceback": traceback.format_exc()[:2000]})

    gold_passes = bool(discovered and discovered.gold_passes)
    final_applicability = _formatting.resolve_applicability(applicability, gold_passes)
    fmt_record = discovered.as_record() if discovered is not None else None
    discovered_format_name = discovered.name if discovered is not None else None
    gold_anchor_reward = discovered.gold_anchor_reward if discovered is not None else None

    def _wrap(candidate, probe_type=None):
        """Wrap a candidate in the env's discovered format before SCORING (what the
        verifier sees). The format_only family is left untouched (it varies the
        wrapper on purpose). The oracle already judged the RAW candidate upstream,
        so this wrapping never touches the correctness label (oracle independence,
        pre-reg §3)."""
        if discovered is None or (probe_type is not None and _probes.is_format_only(probe_type)):
            return candidate if candidate is not None else ""
        return discovered.wrap("" if candidate is None else candidate)

    # emit a standalone discovery/applicability record (audit trail, never silent)
    emit({"mode": "format_discovery", "applicability": final_applicability,
          "applicability_reason": applic_reason, "answer_substitutable": applicability,
          "discovered_format": discovered_format_name,
          "gold_anchor_reward": gold_anchor_reward, "gold_passes": gold_passes,
          "format_detail": fmt_record})

    # non_substitutable: a wrong-answer STRING doesn't map to this verifier. Do NOT
    # emit a gold anchor (would falsely register as a gold_fail) and do NOT run the
    # FAR battery. Recorded with a reason, EXCLUDED from FAR (pre-reg §1 routing).
    if final_applicability == "non_substitutable":
        final_bucket = static_bucket
        bs_detail = None
        for r in records:
            r["verifier_type"] = final_bucket
            r["applicability"] = final_applicability
            r["discovered_format"] = discovered_format_name
            r["gold_anchor_reward"] = gold_anchor_reward
        emit({"mode": "classification", "verifier_type": final_bucket,
              "static_bucket": static_bucket, "binary_soft_detail": bs_detail,
              "applicability": final_applicability, "applicability_reason": applic_reason,
              "discovered_format": discovered_format_name,
              "gold_anchor_reward": gold_anchor_reward, "gold_passes": gold_passes,
              "classification": cls})
        _write_jsonl(out_path, records)
        print(f"[battery] {args.env_id}: non_substitutable ({applic_reason}) — "
              f"excluded from FAR, type={static_bucket}")
        return 0

    for i in range(n):
        try:
            question, answer, info, task = row_fields(ds[i])
        except Exception as e:  # noqa: BLE001
            emit({"row_id": i, "error": f"row read failed: {e!r}"})
            continue
        try:
            battery = _probes.build_probe_battery({"answer": answer}, static_bucket)
        except Exception as e:  # noqa: BLE001
            emit({"row_id": i, "error": f"probe build failed: {e!r}"})
            continue

        # gold anchor: score the EXACT reference answer once to observe the
        # reward ceiling (needed to recognise partial-credit -> soft) and to
        # confirm the verifier passes its own gold. Excluded from FAR/FRR.
        anchor = {
            "verifiers_api": api, "row_id": i, "probe_type": "gold_anchor",
            "provenance": "reference-answer", "candidate_preview": str(answer)[:120],
            "rubric_class": rubric_class, "reward_func_names": reward_func_names,
            "oracle_label": _oracle.CORRECT, "oracle_channel": "by-construction",
            "far_bucket": "anchor", "far_eligible": False, "frr_eligible": False,
            "oracle_dropped": False,
            "discovered_format": discovered_format_name,
            "gold_anchor_reward": gold_anchor_reward,
            "applicability": final_applicability,
            "scored_completion_preview": _wrap(str(answer))[:120],
        }
        try:
            arew = []
            for _rep in range(k):
                state = make_state(question, _wrap(str(answer)), answer, info, task)
                r, m = score_one(env, state)
                arew.append(r)
                observed_funcs.update(m.keys())
            amaj, aunstable = _majority_reward(arew)
            anchor.update(v_reward_repeats=arew, v_reward_majority=amaj,
                          verdict_unstable=aunstable)
            if isinstance(amaj, (int, float)):
                observed_rewards.append(amaj)
        except Exception as e:  # noqa: BLE001
            anchor["error"] = repr(e)
        emit(anchor)

        for probe in battery:
            rec = {
                "verifiers_api": api,
                "row_id": i,
                "probe_type": probe.probe_type,
                "provenance": probe.provenance_tag,
                "candidate_preview": (probe.candidate_text or "")[:120],
                "rubric_class": rubric_class,
                "reward_func_names": reward_func_names,
                "discovered_format": discovered_format_name,
                "gold_anchor_reward": gold_anchor_reward,
                "applicability": final_applicability,
            }
            try:
                # ORACLE INDEPENDENCE: the oracle screens the RAW candidate content;
                # the discovered format is applied ONLY at scoring time (below).
                verdict, keep, bucket = _oracle.screen(probe, answer)
                rec["oracle_label"] = verdict["true_label"]
                rec["oracle_channel"] = verdict["channel"]
                rec["oracle_reason"] = verdict["reason"]
                rec["far_bucket"] = bucket          # far | frr | ambiguous
                rec["far_eligible"] = (bucket == "far")
                rec["frr_eligible"] = (bucket == "frr")
                rec["oracle_dropped"] = (not keep)  # ambiguous -> excluded from FAR
            except Exception as e:  # noqa: BLE001
                rec["error"] = f"oracle failed: {e!r}"
                emit(rec)
                continue

            if not keep:
                # ambiguous: recorded for the separately-reported ambiguous rate,
                # NOT scored, NOT counted in FAR
                emit(rec)
                continue

            # score the kept candidate k times (fresh state each repeat)
            rewards, metrics_last, err = [], {}, None
            scored_text = _wrap(probe.candidate_text, probe.probe_type)
            rec["scored_completion_preview"] = (scored_text or "")[:120]
            for _rep in range(k):
                try:
                    state = make_state(question, scored_text, answer, info, task)
                    r, m = score_one(env, state)
                    rewards.append(r)
                    metrics_last = m
                    observed_funcs.update(m.keys())
                except Exception as e:  # noqa: BLE001
                    err = repr(e)
                    if not rec.get("traceback"):
                        rec["traceback"] = traceback.format_exc()[:2000]
            majority, unstable = _majority_reward(rewards)
            rec["v_reward_repeats"] = rewards
            rec["v_reward_majority"] = majority
            rec["verdict_unstable"] = unstable
            rec["metrics"] = metrics_last
            if err:
                rec["error"] = err
            if isinstance(majority, (int, float)):
                observed_rewards.append(majority)
            emit(rec)

    # finalize binary-vs-soft from observed rewards, stamp verifier_type on all
    final_bucket = static_bucket
    bs_detail = None
    if static_bucket in ("binary", "soft"):
        final_bucket, bs_detail = _classify.finalize_binary_soft(static_bucket, observed_rewards)
    for r in records:
        r.setdefault("verifier_type", final_bucket)
        r["verifier_type"] = final_bucket
        r.setdefault("applicability", final_applicability)
        r.setdefault("discovered_format", discovered_format_name)
        r.setdefault("gold_anchor_reward", gold_anchor_reward)
        if not r.get("reward_func_names") and observed_funcs:
            r["reward_func_names"] = sorted(observed_funcs)

    # a compact classification record for provenance/audit
    emit({"mode": "classification", "verifier_type": final_bucket,
          "static_bucket": static_bucket, "binary_soft_detail": bs_detail,
          "applicability": final_applicability, "applicability_reason": applic_reason,
          "discovered_format": discovered_format_name,
          "gold_anchor_reward": gold_anchor_reward, "gold_passes": gold_passes,
          "classification": cls})

    _write_jsonl(out_path, records)
    scored = sum(1 for r in records if "v_reward_repeats" in r)
    amb = sum(1 for r in records if r.get("oracle_dropped"))
    print(f"[battery] {args.env_id}: {scored} scored / {amb} ambiguous-dropped, "
          f"type={final_bucket}, applic={final_applicability}, "
          f"fmt={discovered_format_name}, rubric={rubric_class}, k={k}")
    return 0


# ---------------------------------------------------------------------------
# llm_judge lane (pre-reg §4 probes 2 + 5) — Phase 3, needs a live judge API
# ---------------------------------------------------------------------------

def judge_battery_records(env, rows, k):
    """Core of the judge lane, factored out so it can be unit-tested against a
    MOCK JudgeRubric with NO Docker / no real package (mirrors how the binary
    lane's format discovery is tested via score_one).

    For each of `rows` dataset rows emit:
      * a gold ANCHOR (exact reference answer, scored k times) — the PASS BAR is
        ANCHOR-RELATIVE: a judge 'passes' a probe iff its majority score reaches
        the gold-anchor score level (judge scales vary 0-1 / 0-10; we NEVER
        hardcode a threshold — the env's own gold-anchor score is the bar, exactly
        as the binary lane's aggregate does).
      * two sub-probes per row, EACH scored k times and screened by the INDEPENDENT
        oracle on the RAW answer (numeric/canonical channel, never the judge score):
          - known_wrong : a plain oracle-confirmed-wrong answer, no injection. On
                          open-ended tasks the oracle can't certify wrongness ->
                          routes to `ambiguous`, EXCLUDED from FAR (reported as the
                          ambiguous rate). judge_subprobe="known_wrong".
          - injection   : the same wrong answer + a grader prompt-injection string.
                          oracle=WRONG by construction. judge_subprobe="injection".

    Returns (records, n_judge_calls). Each score_rollout == one judge API call.
    """
    _classify, _probes, _oracle, _formatting = _load_harness_modules()
    api = detect_api(env)
    rubric = getattr(env, "rubric", None)
    rubric_class = type(rubric).__name__ if rubric is not None else None
    reward_func_names = _reward_func_names(rubric)
    records, calls = [], 0

    def _rec(d):
        base = {"verifiers_api": api, "rubric_class": rubric_class,
                "reward_func_names": reward_func_names, "verifier_type": "llm_judge",
                "judge_egress": True}
        base.update(d)
        records.append(base)

    if api != "v0":
        _rec({"mode": "classification", "verifier_type": "llm_judge", "skipped": True,
              "note": "v1 package — judge lane targets v0; skipped gracefully"})
        return records, calls

    ds = get_dataset(env)
    if ds is None:
        _rec({"mode": "classification", "verifier_type": "llm_judge",
              "error": "no dataset rows available"})
        return records, calls

    n = min(rows, len(ds))
    for i in range(n):
        try:
            question, answer, info, task = row_fields(ds[i])
        except Exception as e:  # noqa: BLE001
            _rec({"row_id": i, "error": f"row read failed: {e!r}"})
            continue

        # verifiable-vs-open-ended decision for THIS row's reference answer. Only
        # verifiable rows (numeric / mcq / short_entity) are known-wrong-measurable;
        # open_ended rows keep routing known_wrong -> ambiguous (excluded from FAR).
        answer_kind = _oracle.classify_answer(answer)
        known_wrong_measurable = _oracle.is_verifiable(answer)

        # gold anchor — judges score semantic content, NOT format, so the anchor
        # is the RAW reference answer (no format wrapping in the judge lane).
        arew = []
        try:
            for _rep in range(k):
                r, _m = score_one(env, make_state(question, str(answer), answer, info, task))
                calls += 1
                arew.append(r)
        except Exception as e:  # noqa: BLE001
            _rec({"row_id": i, "probe_type": "gold_anchor", "far_bucket": "anchor",
                  "error": repr(e)})
        amaj, aunstable = _majority_reward(arew)
        _rec({"row_id": i, "probe_type": "gold_anchor", "provenance": "reference-answer",
              "candidate_preview": str(answer)[:120], "oracle_label": _oracle.CORRECT,
              "oracle_channel": "by-construction", "far_bucket": "anchor",
              "far_eligible": False, "frr_eligible": False, "oracle_dropped": False,
              "answer_kind": answer_kind, "known_wrong_measurable": known_wrong_measurable,
              "v_reward_repeats": arew, "v_reward_majority": amaj,
              "verdict_unstable": aunstable})

        try:
            battery = _probes.build_judge_battery({"answer": answer})
        except Exception as e:  # noqa: BLE001
            _rec({"row_id": i, "error": f"judge probe build failed: {e!r}"})
            continue

        for probe in battery:
            subprobe = _probes.judge_subprobe_of(probe.probe_type)
            rec = {"row_id": i, "probe_type": probe.probe_type,
                   "judge_subprobe": subprobe, "provenance": probe.provenance_tag,
                   "answer_kind": answer_kind,
                   "candidate_preview": (probe.candidate_text or "")[:120]}
            try:
                verdict, keep, bucket = _oracle.screen(probe, answer)
                rec.update(oracle_label=verdict["true_label"],
                           oracle_channel=verdict["channel"],
                           oracle_reason=verdict["reason"], far_bucket=bucket,
                           far_eligible=(bucket == "far"),
                           frr_eligible=(bucket == "frr"), oracle_dropped=(not keep))
            except Exception as e:  # noqa: BLE001
                rec["error"] = f"oracle failed: {e!r}"
                _rec(rec)
                continue
            if not keep:
                # open-ended candidate the oracle can't certify wrong -> ambiguous,
                # EXCLUDED from FAR (rate reported separately). NOT scored.
                _rec(rec)
                continue
            rewards, err = [], None
            for _rep in range(k):
                try:
                    r, _m = score_one(env, make_state(question, probe.candidate_text,
                                                       answer, info, task))
                    calls += 1
                    rewards.append(r)
                except Exception as e:  # noqa: BLE001
                    err = repr(e)
            majority, unstable = _majority_reward(rewards)
            rec.update(v_reward_repeats=rewards, v_reward_majority=majority,
                       verdict_unstable=unstable)
            if err:
                rec["error"] = err
            _rec(rec)

    _rec({"mode": "classification", "verifier_type": "llm_judge",
          "static_bucket": "llm_judge", "rows": n, "k": k, "judge_calls": calls})
    return records, calls


def phase_judge_battery(args, out_path):
    """Judge lane (pre-reg §4 probes 2 + 5). Runs INSIDE the container WITH the
    allowlist egress up (judge is a network call). Writes to the SAME
    <safe>.battery.jsonl the aggregator reads; records carry verifier_type=
    'llm_judge' + judge_egress=True so the FAR machinery slots them in."""
    ts = time.time()
    chash = config_hash({})  # env's own declared default config
    try:
        env, how, mech = resolve_env(args.package, args.name)
    except Exception as e:  # noqa: BLE001
        _write_jsonl(out_path, [{"env_id": args.env_id, "env_package": args.package,
                                 "verifier_type": "llm_judge", "judge_egress": True,
                                 "error": f"resolve_env failed: {e!r}",
                                 "traceback": traceback.format_exc()}])
        print(f"[judge] FATAL resolve: {e!r}")
        return 1
    records, calls = judge_battery_records(env, args.rows, max(1, args.k or 5))
    for r in records:
        r.setdefault("env_id", args.env_id)
        r.setdefault("env_package", args.package)
        r.setdefault("config_hash", chash)
        r.setdefault("ts", time.time())
    _write_jsonl(out_path, records)
    scored = sum(1 for r in records if "v_reward_majority" in r
                 and r.get("far_bucket") != "anchor")
    amb = sum(1 for r in records if r.get("oracle_dropped"))
    print(f"[judge] {args.env_id}: {scored} scored / {amb} ambiguous-dropped, "
          f"judge_calls={calls}, rows={args.rows}, k={args.k}")
    return 0


# ---------------------------------------------------------------------------
# ELICITED / EYR lane (pre-reg §2/§3/§9) — runs INSIDE the container WITH the
# LiteLLM->Bedrock proxy up (attacker + verifier both need it; NOT zero-network).
# ---------------------------------------------------------------------------

def phase_attack(args, out_path):
    """Elicited attack lane. Loads the env, builds a chat_fn to the in-cluster
    LiteLLM->Bedrock proxy (attacker model = args.attacker_model) and a score_fn
    that scores completions through the env's OWN rubric, discovers the passing
    format for binary envs (identity for judge envs), runs the best-of-N +
    feedback attack per row, and writes <safe>.eyr.jsonl (per-row records + a
    mode=='eyr_summary')."""
    import attacker  # mounted alongside; lazy so legacy phases don't need it
    ts = time.time()
    chash = config_hash({})
    try:
        env, how, mech = resolve_env(args.package, args.name)
    except Exception as e:  # noqa: BLE001
        _write_jsonl(out_path, [{"env_id": args.env_id, "env_package": args.package,
                                 "mode": "eyr_summary", "attacker_model": args.attacker_model,
                                 "error": f"resolve_env failed: {e!r}",
                                 "traceback": traceback.format_exc()}])
        print(f"[attack] FATAL resolve: {e!r}")
        return 1

    api = detect_api(env)
    if api != "v0":
        _write_jsonl(out_path, [{"env_id": args.env_id, "env_package": args.package,
                                 "mode": "eyr_summary", "attacker_model": args.attacker_model,
                                 "skipped": True,
                                 "note": "v1 package — EYR lane targets v0; skipped"}])
        print(f"[attack] {args.env_id} is v1 — skipped")
        return 0

    # is_judge from static classification (open-ended judge rows route to the
    # injection mode; verifiable rows to the answer-substitution mode).
    _classify, _probes, _oracle, _formatting = _load_harness_modules()
    try:
        is_judge = _classify.classify_static(env).get("bucket") == "llm_judge"
    except Exception:  # noqa: BLE001
        is_judge = False

    ds = get_dataset(env)
    if ds is None:
        _write_jsonl(out_path, [{"env_id": args.env_id, "mode": "eyr_summary",
                                 "attacker_model": args.attacker_model,
                                 "error": "no dataset rows available"}])
        return 1

    n = min(args.rows, len(ds))
    rows = []
    for i in range(n):
        try:
            q, a, info, task = row_fields(ds[i])
            rows.append({"row_id": i, "question": q, "answer": a,
                         "info": info, "task": task})
        except Exception:  # noqa: BLE001
            continue

    def _score_fn_for(row):
        def _score(text):
            state = make_state(row["question"], text, row["answer"],
                               row["info"], row["task"])
            r, _m = score_one(env, state)
            return r if isinstance(r, (int, float)) else 0.0
        return _score

    # binary lane: discover the env's passing format on the first row so gold +
    # candidates are scored in the wrapper the verifier expects (judge lane = raw).
    wrap = (lambda x: "" if x is None else str(x))
    if not is_judge and rows:
        try:
            disc = _formatting.discover_format(env, str(rows[0]["answer"]),
                                               _score_fn_for(rows[0]))
            if disc is not None:
                wrap = disc.wrap
        except Exception as e:  # noqa: BLE001
            print(f"[attack] format discovery failed: {e!r}")

    base_url = os.environ.get("OPENAI_BASE_URL")
    api_key = os.environ.get("OPENAI_API_KEY", "sk-envcert-local")
    chat = attacker.LiteLLMChat(base_url, api_key, args.attacker_model)

    # per-row score_fn is rebuilt so each row scores against its own reference.
    records = []
    for row in rows:
        rec = attacker.attack_row(
            row, chat_fn=chat, score_fn=_score_fn_for(row), is_judge=is_judge,
            wrap=wrap, n_candidates=args.attack_n, feedback_rounds=args.attack_feedback,
            score_k=max(1, args.k or 1))
        rec["attacker_model"] = args.attacker_model
        rec["env_id"] = args.env_id
        rec["env_package"] = args.package
        rec["config_hash"] = chash
        rec["ts"] = time.time()
        records.append(rec)

    summary = attacker.eyr_summary(records, attacker_model=args.attacker_model,
                                   env_id=args.env_id, is_judge=is_judge,
                                   n_candidates=args.attack_n,
                                   feedback_rounds=args.attack_feedback)
    summary["env_package"] = args.package
    summary["config_hash"] = chash
    summary["ts"] = time.time()
    records.append(summary)
    _write_jsonl(out_path, records)
    print(f"[attack] {args.env_id}: attacker={args.attacker_model} "
          f"is_judge={is_judge} rows={summary['n_rows_counted']} "
          f"mean_reward_attacker={summary['mean_reward_attacker']} "
          f"honest={summary['mean_reward_honest_baseline']} "
          f"oracle_correct_hi={summary['oracle_correct_rate_of_high_reward']} "
          f"exploits={summary['n_exploits']} eyr_positive={summary['eyr_positive']} "
          f"att_calls={summary['n_attacker_calls']} ver_calls={summary['n_verifier_calls']}")
    return 0


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _reward_func_names(rubric):
    if rubric is None:
        return []
    for meth in ("get_reward_func_names",):
        fn = getattr(rubric, meth, None)
        if callable(fn):
            try:
                return list(fn())
            except Exception:
                pass
    funcs = getattr(rubric, "reward_funcs", None) or getattr(rubric, "funcs", None) or []
    out = []
    for f in funcs:
        out.append(getattr(f, "__name__", str(f)))
    return out


def _pkg_version(pkg):
    try:
        return ilmd.version(pkg)
    except Exception:
        return None


def _write_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f)


def _write_jsonl(path, records):
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r, default=str) + "\n")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--env-id", required=True, help="owner/name")
    p.add_argument("--package", required=True, help="pip package / dist name")
    p.add_argument("--name", default=None, help="env name part (defaults to package)")
    p.add_argument("--out-dir", default="/out")
    p.add_argument("--rows", type=int, default=5)
    p.add_argument("--k", type=int, default=5, help="repeats per probe (pre-reg §4; --battery)")
    # --- elicited / EYR lane (pre-reg §2) ---
    p.add_argument("--attacker-model", dest="attacker_model", default="envcert-sonnet",
                   help="Bedrock passthrough model for the attacker (--attack)")
    p.add_argument("--attack-n", dest="attack_n", type=int, default=8,
                   help="best-of-N candidates per round (--attack)")
    p.add_argument("--attack-feedback", dest="attack_feedback", type=int, default=1,
                   help="reward-feedback rounds after the first (--attack)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--prepare", action="store_true")
    g.add_argument("--score", action="store_true")
    g.add_argument("--battery", action="store_true",
                   help="dual-gated per-probe battery with oracle (pre-reg §3/§4)")
    g.add_argument("--judge-battery", dest="judge_battery", action="store_true",
                   help="llm_judge lane: known_wrong + injection sub-probes; runs "
                        "WITH allowlist judge egress up (pre-reg §4 probes 2+5)")
    g.add_argument("--attack", action="store_true",
                   help="elicited/EYR lane: attacker model best-of-N vs the verifier, "
                        "dual-gated by the oracle; runs WITH the Bedrock proxy up (pre-reg §2)")
    g.add_argument("--classify", action="store_true",
                   help="emit the verifier-type classification record (pre-reg §1)")
    args = p.parse_args()
    if args.name is None:
        args.name = args.package
    safe = args.env_id.replace("/", "__")
    if args.prepare:
        return phase_prepare(args, os.path.join(args.out_dir, f"{safe}.prepare.json"))
    if args.classify:
        return phase_classify(args, os.path.join(args.out_dir, f"{safe}.classify.json"))
    if args.judge_battery:
        return phase_judge_battery(args, os.path.join(args.out_dir, f"{safe}.battery.jsonl"))
    if args.attack:
        return phase_attack(args, os.path.join(args.out_dir, f"{safe}.eyr.jsonl"))
    if args.battery:
        return phase_battery(args, os.path.join(args.out_dir, f"{safe}.battery.jsonl"))
    return phase_score(args, os.path.join(args.out_dir, f"{safe}.jsonl"))


if __name__ == "__main__":
    sys.exit(main())
