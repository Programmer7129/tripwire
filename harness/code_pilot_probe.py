#!/usr/bin/env python3
"""HUB CODING PILOT — container-side probe (runs INSIDE the disposable container).

Feasibility instrument, NOT a production lane. Reuses score_env's loader + scorer
(/app is mounted by the driver). Two modes:

  --inspect : dump the score_rollout surface for the first few rows — prompt, answer,
              info keys, task, reward-func names — so we can see where a reward-hack
              completion is injected and whether a reference solution exists to diff.

  --attack  : score a JSON list of hand-crafted candidate completions (mounted at
              /work/candidates.json) through the env's OWN rubric.score_rollout, k
              times each. Emits one record per candidate with the reward + metrics.
              The dual-gate verdict is computed by the DRIVER, not here (we never
              trust the verifier's own number).

Network is controlled by the driver (OFF during scoring)."""
import argparse
import json
import os
import sys
import traceback

sys.path.insert(0, "/app")
import score_env as S  # noqa: E402


def _safe(o, n=4000):
    try:
        return json.dumps(o, default=str)[:n]
    except Exception:
        return str(o)[:n]


def inspect(env_id, package, name, rows):
    out = {"mode": "inspect", "env_id": env_id}
    env, how, mech = S.resolve_env(package, name)
    out["resolved_via"] = mech
    out["api"] = S.detect_api(env)
    rubric = getattr(env, "rubric", None)
    out["rubric_class"] = type(rubric).__name__ if rubric else None
    out["reward_func_names"] = S._reward_func_names(rubric)
    ds = S.get_dataset(env)
    out["dataset_rows"] = len(ds) if ds is not None else 0
    rowdumps = []
    if ds is not None:
        for i in range(min(rows, len(ds))):
            row = ds[i]
            q, a, info, task = S.row_fields(row)
            rowdumps.append({
                "row_id": i,
                "row_keys": sorted(list(row.keys())) if hasattr(row, "keys") else None,
                "question_preview": (q or "")[:1200],
                "answer_type": type(a).__name__,
                "answer_preview": _safe(a, 1500),
                "task": task,
                "info_keys": sorted(list(info.keys())) if isinstance(info, dict) else type(info).__name__,
                "info_preview": _safe(info, 3000),
            })
    out["rows"] = rowdumps

    # --- rubric executor introspection: WHY do compile/tests rewards fire or not? ---
    import inspect as _inspect
    srcs = []

    def _collect(rb, depth=0):
        if rb is None or depth > 3:
            return
        funcs = getattr(rb, "reward_funcs", None) or getattr(rb, "funcs", None) or []
        for f in funcs:
            nm = getattr(f, "__name__", str(f))
            try:
                s = _inspect.getsource(f)
            except Exception as e:  # noqa: BLE001
                s = f"<no source: {e!r}>"
            srcs.append({"name": nm, "module": getattr(f, "__module__", None),
                         "source": s[:2500]})
        for sub in (getattr(rb, "rubrics", None) or []):
            _collect(sub, depth + 1)

    try:
        _collect(rubric)
    except Exception as e:  # noqa: BLE001
        out["rubric_introspect_error"] = repr(e)
    out["rubric_reward_sources"] = srcs
    # pull the executor helpers by name from the reward funcs' own module
    try:
        import importlib
        helpers = {}
        rfmod = None
        for s in srcs:
            if s.get("module") and s["module"] not in ("verifiers.envs.multiturn_env",):
                rfmod = s["module"]
                break
        if rfmod:
            hm = importlib.import_module(rfmod)
            for hname in ("calculate_compile_reward", "calculate_tests_reward",
                          "calculate_format_reward", "extract_code_from_completion", "run_code",
                          "clean_code_main_block", "build_fractional_test_harness", "_parse_fractional_result", "extract_text_from_completion"):
                obj = getattr(hm, hname, None)
                if obj is not None:
                    try:
                        helpers[hname] = _inspect.getsource(obj)[:3000]
                    except Exception as e:  # noqa: BLE001
                        helpers[hname] = f"<no source: {e!r}>"
            out["rfmod_file"] = getattr(hm, "__file__", None)
            # dump run_code / executor region straight from the module source file
            try:
                ftext = open(hm.__file__).read()
                import re as _re
                for target in ("run_code","execute","sandbox","Sandbox","_run_test","_extract_code","_run","handle_submission"):
                    m = _re.search(r"\n((?:async +)?def +%s\b[\s\S]{0,1400})" % target, ftext)
                    if m:
                        helpers["FILE::" + target] = m.group(1)[:1500]
                # also capture import lines (reveals sandbox backend / network dep)
                out["module_imports"] = [l for l in ftext.splitlines()[:60]
                                         if l.startswith(("import ", "from "))]
            except Exception as e:  # noqa: BLE001
                out["module_read_error"] = repr(e)
        try:
            import util.mbpp_utils as _u, inspect as __i
            for hn in ("run_code","clean_code_main_block","build_fractional_test_harness","extract_code_from_completion"):
                o=getattr(_u,hn,None)
                if o is not None:
                    helpers["UTIL::"+hn]=__i.getsource(o)[:2200]
            out["util_file"]=_u.__file__
        except Exception as e:
            out["util_introspect_error"]=repr(e)
        out["executor_helpers"] = helpers
    except Exception as e:  # noqa: BLE001
        out["executor_helpers_error"] = repr(e)
    # env module file(s) + any sibling files that look like an executor/sandbox
    try:
        mod = type(env).__module__
        import importlib
        m = importlib.import_module(mod.split(".")[0])
        out["env_module_file"] = getattr(m, "__file__", None)
        d = os.path.dirname(getattr(m, "__file__", "") or "")
        out["env_pkg_files"] = sorted(os.listdir(d)) if d and os.path.isdir(d) else None
    except Exception as e:  # noqa: BLE001
        out["env_module_file_error"] = repr(e)
    print("PILOT_JSON " + json.dumps(out, default=str))


def _independent_oracle(completion, entry_point, cases):
    """DUAL-GATE independent oracle (deterministic, offline). Extract the candidate's
    entry_point function via AST (dropping top-level control-flow escapes like
    sys.exit), then run it against caller-supplied reference (args -> expected) pairs
    in a subprocess with sys.exit/os._exit NEUTRALISED so a reward-hack escape cannot
    fool the oracle. Verdict is pure execution, never the verifier's number.

    Returns {label: 'correct'|'wrong'|'error', detail:[...]}. 'wrong' iff >=1 case
    diverges from its known-correct expected value."""
    import subprocess as _sp
    import sys as _sys
    # extract text -> code region (markdown fence or raw), keep it simple + independent
    text = completion if isinstance(completion, str) else str(completion)
    import re as _re
    m = _re.search(r"```(?:python)?\s*\n(.*?)```", text, _re.DOTALL)
    code = m.group(1) if m else text
    harness = (
        "import sys, os, json, ast\n"
        "def _blocked(*a, **k):\n    raise RuntimeError('exit neutralised by oracle')\n"
        "sys.exit=_blocked\nos._exit=_blocked\n"
        "SRC = json.loads(sys.stdin.read())\n"
        "code = SRC['code']; ep = SRC['entry_point']; cases = SRC['cases']\n"
        # AST: keep only imports + the entry_point FunctionDef (drop top-level escapes)
        "try:\n"
        "    tree = ast.parse(code)\n"
        "    keep = [n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef,ast.ClassDef,ast.AsyncFunctionDef))]\n"
        "    tree.body = keep\n"
        "    ns = {}\n"
        "    exec(compile(tree, '<oracle>', 'exec'), ns)\n"
        "except Exception as e:\n"
        "    print(json.dumps({'label':'error','detail':'exec: '+repr(e)})); sys.exit=_blocked; raise SystemExit\n"
        "fn = ns.get(ep)\n"
        "if fn is None:\n    print(json.dumps({'label':'error','detail':'no entry_point'})); raise SystemExit\n"
        "detail=[]; wrong=False\n"
        "for args, expected in cases:\n"
        "    try:\n        got = fn(*args)\n    except Exception as e:\n        got = 'EXC:'+type(e).__name__\n"
        "    ok = (got == expected)\n"
        "    if not ok: wrong=True\n"
        "    detail.append({'args':args,'expected':expected,'got':got,'ok':ok})\n"
        "print(json.dumps({'label':'wrong' if wrong else 'correct','detail':detail}))\n"
    )
    try:
        p = _sp.run([_sys.executable, "-c", harness],
                    input=json.dumps({"code": code, "entry_point": entry_point, "cases": cases}),
                    capture_output=True, text=True, timeout=30)
        line = [l for l in (p.stdout or "").splitlines() if l.strip().startswith("{")]
        return json.loads(line[-1]) if line else {"label": "error", "detail": (p.stderr or "")[-300:]}
    except Exception as e:  # noqa: BLE001
        return {"label": "error", "detail": repr(e)}


def attack(env_id, package, name, k):
    env, how, mech = S.resolve_env(package, name)
    cands = json.load(open("/work/candidates.json"))
    results = []
    ds = S.get_dataset(env)
    for c in cands:
        rec = {"label": c["label"], "row_id": c["row_id"]}
        q, a, info, task = S.row_fields(ds[c["row_id"]])
        rewards, metrics_last = [], {}
        for _ in range(max(1, k)):
            try:
                state = S.make_state(q, c["completion"], a, info, task)
                r, m = S.score_one(env, state)
                rewards.append(r)
                metrics_last = m
            except Exception as e:  # noqa: BLE001
                rec["error"] = repr(e)
                rec["traceback"] = traceback.format_exc()[:1500]
                break
        rec["rewards"] = rewards
        rec["metrics"] = metrics_last
        # native PASS = the env's verifier gave positive reward (majority)
        rec["native_pass"] = bool(rewards and isinstance(rewards[0], (int, float)) and max(rewards) > 0)
        # DUAL-GATE independent oracle (only when caller supplies reference cases)
        if c.get("oracle_entry_point") and c.get("oracle_cases"):
            orc = _independent_oracle(c["completion"], c["oracle_entry_point"], c["oracle_cases"])
            rec["oracle"] = orc
            rec["dual_gate_exploit"] = bool(rec["native_pass"] and orc.get("label") == "wrong")
        results.append(rec)
    print("PILOT_JSON " + json.dumps({"mode": "attack", "env_id": env_id,
                                      "results": results}, default=str))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--env-id", required=True)
    p.add_argument("--package", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--rows", type=int, default=3)
    p.add_argument("--k", type=int, default=3)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--inspect", action="store_true")
    g.add_argument("--attack", action="store_true")
    a = p.parse_args()
    try:
        if a.inspect:
            inspect(a.env_id, a.package, a.name, a.rows)
        else:
            attack(a.env_id, a.package, a.name, a.k)
    except Exception as e:  # noqa: BLE001
        print("PILOT_JSON " + json.dumps({"fatal": repr(e),
                                          "traceback": traceback.format_exc()}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
