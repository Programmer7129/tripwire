#!/usr/bin/env python3
"""envcert verifier-type classifier (pre-reg §1).

Runs INSIDE the disposable container (needs a loaded `env`). Introspects the
env's rubric + env class into exactly one bucket:

    binary | soft | llm_judge | sandbox | unknown

Two stages, because binary-vs-soft is partly EMPIRICAL (pre-reg §1):
  1. `classify_static(env)`  -> a provisional bucket from class names, reward-fn
     source, weights, env class, imports. Non-judge / non-sandbox / introspectable
     rubrics are provisionally `binary`.
  2. `finalize_binary_soft(bucket, observed_rewards)` -> flips `binary`->`soft`
     iff any probe reward is observed strictly between 0 and the max (partial
     credit, e.g. sivit/gsm8k-last-number -> 0.457 for a wrong number).

Weight-0 monitor funcs (e.g. the `num_turns` monitor that `load_environment`'s
RubricGroup injects) are excluded from the verdict.

No network, no verifier-verdict-as-truth — pure introspection.
"""
import inspect

SANDBOX_ENV_CLASSES = {"SandboxEnv", "PythonEnv"}
JUDGE_RUBRIC_CLASSES = {"JudgeRubric"}
# attribute names that betray an LLM client living on a rubric
JUDGE_CLIENT_ATTRS = ("judge_client", "judge", "client", "llm", "judge_model",
                      "judge_client_kwargs", "oai_client", "openai_client")
# substrings in reward-fn source / rubric repr that betray an LLM judge
JUDGE_SOURCE_HINTS = ("judge", "asyncopenai", "openai(", "client.chat",
                      "chat.completions", "get_judge_response", "judgerubric")
# substrings that betray a code-exec sandbox
SANDBOX_SOURCE_HINTS = ("prime_sandboxes", "sandbox", "run_code", "exec_code",
                        "subprocess", "pytest", "e2b", "docker_image")

EPS = 1e-9


def _class_tree(obj):
    """MRO class names for an object's type (lowercased kept separate)."""
    try:
        return [c.__name__ for c in type(obj).__mro__]
    except Exception:
        return [type(obj).__name__] if obj is not None else []


def _safe_source(fn):
    try:
        return inspect.getsource(fn)
    except Exception:
        return None


def iter_reward_funcs(rubric, _depth=0):
    """Flatten a rubric (or RubricGroup) into reward-func descriptors.

    Yields dicts: {name, weight, source, owner_class}. Recurses RubricGroup via
    its `.rubrics`. Weight is best-effort; group-level weights multiply in where
    discoverable, else default 1.0.
    """
    if rubric is None or _depth > 6:
        return
    owner_class = type(rubric).__name__

    # RubricGroup: has a list of child rubrics
    subs = getattr(rubric, "rubrics", None)
    if subs:
        # a group may carry its own per-sub weights
        group_w = getattr(rubric, "weights", None) or getattr(rubric, "reward_weights", None)
        for i, sub in enumerate(subs):
            gw = None
            if isinstance(group_w, (list, tuple)) and i < len(group_w):
                try:
                    gw = float(group_w[i])
                except (TypeError, ValueError):
                    gw = None
            for d in iter_reward_funcs(sub, _depth + 1):
                if gw is not None and isinstance(d.get("weight"), (int, float)):
                    d["weight"] = d["weight"] * gw
                yield d
        return

    funcs = (getattr(rubric, "reward_funcs", None)
             or getattr(rubric, "funcs", None) or [])
    weights = (getattr(rubric, "reward_weights", None)
               or getattr(rubric, "weights", None) or [])
    for i, f in enumerate(funcs):
        w = weights[i] if i < len(weights) else 1.0
        try:
            w = float(w)
        except (TypeError, ValueError):
            w = 1.0
        yield {
            "name": getattr(f, "__name__", str(f)),
            "weight": w,
            "source": _safe_source(f),
            "owner_class": owner_class,
        }


def _is_monitor(fd):
    """Weight-0 monitor func (e.g. num_turns) — excluded from the verdict."""
    if isinstance(fd.get("weight"), (int, float)) and abs(fd["weight"]) < EPS:
        return True
    return fd.get("name") in ("num_turns", "_num_turns", "num_turns_monitor")


def classify_static(env):
    """Provisional classification of a loaded env. Returns a record dict."""
    rubric = getattr(env, "rubric", None)
    rubric_class = type(rubric).__name__ if rubric is not None else None
    env_class = type(env).__name__ if env is not None else None
    env_tree = _class_tree(env)

    all_funcs = list(iter_reward_funcs(rubric))
    scoring_funcs = [fd for fd in all_funcs if not _is_monitor(fd)]
    monitor_funcs = [fd for fd in all_funcs if _is_monitor(fd)]

    reward_func_names = [fd["name"] for fd in scoring_funcs]
    weights = [(fd["name"], fd["weight"]) for fd in scoring_funcs]

    # class names anywhere in the rubric tree
    rubric_tree_classes = set()
    stack = [rubric]
    seen = 0
    while stack and seen < 200:
        r = stack.pop()
        seen += 1
        if r is None:
            continue
        rubric_tree_classes.add(type(r).__name__)
        for s in (getattr(r, "rubrics", None) or []):
            stack.append(s)

    src_blob = "\n".join(fd["source"] or "" for fd in scoring_funcs).lower()

    evidence = []

    # --- llm_judge signals ---
    judge_by_class = bool(rubric_tree_classes & JUDGE_RUBRIC_CLASSES)
    judge_by_attr = False
    if rubric is not None:
        for a in JUDGE_CLIENT_ATTRS:
            v = getattr(rubric, a, None)
            if v is not None and not isinstance(v, (str, bool, int, float)):
                judge_by_attr = True
                evidence.append(f"rubric has non-trivial attr {a!r} ({type(v).__name__})")
                break
    judge_by_source = any(h in src_blob for h in JUDGE_SOURCE_HINTS)
    if judge_by_class:
        evidence.append(f"JudgeRubric in rubric tree {sorted(rubric_tree_classes)}")
    if judge_by_source:
        evidence.append("reward-fn source references a judge/LLM client")

    # --- sandbox signals ---
    sandbox_by_env = bool(set(env_tree) & SANDBOX_ENV_CLASSES)
    sandbox_by_source = any(h in src_blob for h in SANDBOX_SOURCE_HINTS)
    if sandbox_by_env:
        evidence.append(f"env class tree hits sandbox {sorted(set(env_tree) & SANDBOX_ENV_CLASSES)}")
    if sandbox_by_source:
        evidence.append("reward-fn source references code-exec/sandbox")

    static_signals = {
        "judge_by_class": judge_by_class,
        "judge_by_attr": judge_by_attr,
        "judge_by_source": judge_by_source,
        "sandbox_by_env": sandbox_by_env,
        "sandbox_by_source": sandbox_by_source,
        "has_scoring_funcs": bool(scoring_funcs),
        "rubric_introspectable": rubric is not None,
        "math_rubric": "MathRubric" in rubric_tree_classes,
    }

    # --- routing (priority: judge > sandbox > binary/soft > unknown) ---
    if judge_by_class or judge_by_attr or judge_by_source:
        bucket = "llm_judge"
    elif sandbox_by_env or sandbox_by_source:
        bucket = "sandbox"
    elif rubric is None and not scoring_funcs:
        bucket = "unknown"
        evidence.append("no rubric and no introspectable reward funcs")
    else:
        # deterministic answer-match / symbolic; binary-vs-soft decided empirically
        bucket = "binary"
        if not scoring_funcs:
            # rubric object exists but funcs un-introspectable; still assume
            # binary provisionally but flag it
            evidence.append("rubric present but reward funcs un-introspectable; provisional binary")

    return {
        "bucket": bucket,               # provisional (binary may become soft)
        "static_bucket": bucket,
        "rubric_class": rubric_class,
        "rubric_tree_classes": sorted(rubric_tree_classes),
        "env_class": env_class,
        "env_class_tree": env_tree,
        "reward_func_names": reward_func_names,
        "weights": weights,
        "monitor_func_names": [fd["name"] for fd in monitor_funcs],
        "static_signals": static_signals,
        "evidence": evidence,
    }


def finalize_binary_soft(bucket, observed_rewards, eps=1e-9):
    """Flip a provisional `binary` -> `soft` from observed probe rewards.

    Soft iff any observed reward is strictly between 0 and the observed max
    (partial credit). Only ever touches `binary`; llm_judge/sandbox/unknown are
    passed through unchanged. Returns (final_bucket, detail_dict).
    """
    if bucket not in ("binary", "soft"):
        return bucket, {"reason": f"bucket {bucket!r} not subject to binary/soft finalization"}

    vals = [float(v) for v in (observed_rewards or []) if isinstance(v, (int, float))]
    if not vals:
        return bucket, {"reason": "no numeric rewards observed; provisional bucket kept",
                        "n_rewards": 0}

    mx = max(vals)
    mn = min(vals)
    lo = min(0.0, mn)  # floor at 0 (or below if a verifier emits negatives)
    partial_vals = [v for v in vals if lo + eps < v < mx - eps]
    is_soft = len(partial_vals) > 0
    return ("soft" if is_soft else "binary"), {
        "reason": ("partial-credit reward(s) observed strictly between floor and max"
                   if is_soft else "all rewards at floor or max (deterministic)"),
        "n_rewards": len(vals),
        "reward_min": mn,
        "reward_max": mx,
        "partial_examples": sorted(set(round(v, 6) for v in partial_vals))[:5],
    }


def classify(env, observed_rewards=None):
    """Convenience: static classify, then finalize binary/soft if rewards given."""
    rec = classify_static(env)
    if observed_rewards is not None and rec["bucket"] in ("binary", "soft"):
        final, detail = finalize_binary_soft(rec["bucket"], observed_rewards)
        rec["bucket"] = final
        rec["binary_soft_detail"] = detail
    return rec
