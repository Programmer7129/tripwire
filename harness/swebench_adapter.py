#!/usr/bin/env python3
"""Tripwire SWE-bench adapter (04-code-cert-mvp §2, §9-P0) — the false-accept primitive.

Wraps swebench's native evaluation harness so we can apply an ARBITRARY candidate
patch to a SWE-bench-Verified task, run the SHIPPED verifier (the same Docker test
run the benchmark uses), and read `report[instance_id]['resolved']`. A `resolved`
patch that an independent oracle deems WRONG is a false accept (the dual-gate the
attacker loop closes later).

Design constraints (see CLAUDE.md guardrails + the plan):
  * NEVER run patched community/repo code on the host. Every apply + test run
    happens inside swebench's disposable per-instance Docker container.
  * REUSE Epoch/SWE-bench PREBUILT images (default Docker Hub namespace `swebench`);
    never build locally (local build is 100 GB+). On this arm64 Mac the x86_64
    images run under emulation (swebench pins arch=x86_64 -> platform linux/x86_64
    internally, so no --platform flag is needed).
  * Run each instance on its OWN default config: gold `test_patch`, FAIL_TO_PASS /
    PASS_TO_PASS, timeout — no custom tolerances.

We shell out to `python -m swebench.harness.run_evaluation` (the documented
entrypoint) rather than importing its internals: it fully isolates swebench's
global/Docker state per call and matches the reproducible CLI. Each call runs in
its own temp CWD so the per-instance report (`logs/run_evaluation/<run_id>/
<model>/<instance_id>/report.json`, a path swebench roots at CWD) can't collide
across candidates.

Verified P0 facts (astropy__astropy-12907, this Mac):
  image  swebench/sweb.eval.x86_64.astropy_1776_astropy-12907:latest  (public)
  gold   -> resolved=True ; no-op new-file patch -> resolved=False
  time   ~2:20 native test run/task under x86_64 emulation.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Iterable, Optional

DATASET_NAME = "princeton-nlp/SWE-bench_Verified"
SPLIT = "test"
NAMESPACE = "swebench"           # public prebuilt images on Docker Hub
MODEL_NAME = "candidate"         # -> subdir under logs/run_evaluation/<run_id>/
DEFAULT_TIMEOUT = 1800           # swebench per-instance test timeout (s)

# A guaranteed-independently-WRONG patch that still exercises the full
# apply -> test -> grade path (adds a new file; touches nothing the bug needs).
# git apply handles new files with no context, so it applies on any base_commit.
NOOP_PATCH = (
    "diff --git a/envcert_noop.py b/envcert_noop.py\n"
    "new file mode 100644\n"
    "index 0000000..e69de29\n"
    "--- /dev/null\n"
    "+++ b/envcert_noop.py\n"
    "@@ -0,0 +1 @@\n"
    "+# envcert no-op probe: applies cleanly, fixes nothing\n"
)

_REPO_KEY = "repo"
_ID_KEY = "instance_id"


# --------------------------------------------------------------------------- #
# subset loading
# --------------------------------------------------------------------------- #
def load_subset(
    repos: Iterable[str] = ("astropy/astropy", "django/django"),
    dataset_name: str = DATASET_NAME,
    split: str = SPLIT,
) -> list[dict]:
    """Return the SWE-bench-Verified instances whose `repo` is in `repos`.

    The anchor subset (04 §2) is astropy (22) + django (231) in Verified. Pass
    e.g. a single repo, or an explicit tuple, to narrow. Loaded from HF once.
    """
    from datasets import load_dataset

    want = set(repos)
    ds = load_dataset(dataset_name, split=split)
    return [dict(x) for x in ds if x[_REPO_KEY] in want]


def get_instance(instance_id: str, **kw) -> dict:
    """Fetch a single instance dict by id (convenience for CLI / one-offs)."""
    from datasets import load_dataset

    ds = load_dataset(kw.get("dataset_name", DATASET_NAME), split=kw.get("split", SPLIT))
    for x in ds:
        if x[_ID_KEY] == instance_id:
            return dict(x)
    raise KeyError(f"instance not found: {instance_id}")


# --------------------------------------------------------------------------- #
# core: apply an arbitrary patch and run the native verifier
# --------------------------------------------------------------------------- #
def apply_and_run(
    instance: dict,
    candidate_patch: str,
    run_id: Optional[str] = None,
    workdir: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    namespace: str = NAMESPACE,
    keep_logs: bool = True,
    python_exe: Optional[str] = None,
) -> dict:
    """Apply `candidate_patch` to `instance`, run the shipped verifier, read `resolved`.

    Returns a dict:
      resolved             bool  -- report[iid]['resolved'] (False if never graded)
      fail_to_pass_results {'success':[...], 'failure':[...]}  (empty if not run)
      pass_to_pass_results {'success':[...], 'failure':[...]}
      patch_applied        bool  -- did swebench apply the patch cleanly
      empty_patch          bool  -- swebench short-circuited (blank diff)
      error                bool  -- swebench errored (image/emulation/timeout)
      native_report        dict  -- full per-instance report.json (or {})
      run_report           dict  -- swebench's run-level summary
      logs                 dict  -- paths: run_instance.log, test_output.txt, report.json
      run_id, instance_id, returncode, stderr_tail

    A True `resolved` means the native verifier accepted this patch. Whether that
    is a FALSE accept is decided by the independent oracle, not here.
    """
    iid = instance[_ID_KEY]
    run_id = run_id or f"envcert-{uuid.uuid4().hex[:10]}"
    py = python_exe or sys.executable

    # Temp CWD: swebench roots logs/ at CWD, so isolate per call.
    tmp_ctx = None
    if workdir is None:
        tmp_ctx = tempfile.TemporaryDirectory(prefix="swebench_run_")
        base = tmp_ctx.name
    else:
        base = workdir
        os.makedirs(base, exist_ok=True)

    try:
        # single-instance local dataset -> no HF network per candidate
        ds_path = os.path.join(base, "instance.json")
        with open(ds_path, "w") as f:
            json.dump([instance], f)

        preds_path = os.path.join(base, "preds.jsonl")
        with open(preds_path, "w") as f:
            f.write(json.dumps({
                _ID_KEY: iid,
                "model_name_or_path": MODEL_NAME,
                "model_patch": candidate_patch,
            }) + "\n")

        cmd = [
            py, "-m", "swebench.harness.run_evaluation",
            "--dataset_name", ds_path,
            "--split", SPLIT,
            "--instance_ids", iid,
            "--predictions_path", preds_path,
            "--run_id", run_id,
            "--max_workers", "1",
            "--cache_level", "env",          # keep the prebuilt image, don't rebuild
            "--namespace", namespace,        # public prebuilt images
            "--report_dir", base,
        ]
        proc = subprocess.run(
            cmd, cwd=base, capture_output=True, text=True, timeout=timeout + 600,
        )

        report_path = (
            Path(base) / "logs" / "run_evaluation" / run_id / MODEL_NAME / iid / "report.json"
        )
        native = {}
        if report_path.exists():
            native = json.loads(report_path.read_text()).get(iid, {})

        run_report = _find_run_report(base, run_id, iid)

        log_dir = report_path.parent
        # Read log text into memory: when workdir is a tempdir it is deleted on
        # return, so the on-disk paths would dangle. The attacker feedback rounds
        # (04 §2) need the failing tracebacks, so keep the tails inline. Paths are
        # still returned (valid only when the caller supplies a persistent workdir).
        logs = {
            "run_instance_log": _p(log_dir / "run_instance.log"),
            "test_output": _p(log_dir / "test_output.txt"),
            "report_json": _p(report_path),
            "patch_diff": _p(log_dir / "patch.diff"),
            "test_output_tail": _tail(log_dir / "test_output.txt", 8000),
            "run_instance_log_tail": _tail(log_dir / "run_instance.log", 4000),
        }

        ts = native.get("tests_status", {})
        result = {
            "instance_id": iid,
            "run_id": run_id,
            "resolved": bool(native.get("resolved", False)),
            "fail_to_pass_results": ts.get("FAIL_TO_PASS", {"success": [], "failure": []}),
            "pass_to_pass_results": ts.get("PASS_TO_PASS", {"success": [], "failure": []}),
            "patch_applied": bool(native.get("patch_successfully_applied", False)),
            "empty_patch": bool(run_report.get("empty_patch_instances", 0))
            or iid in run_report.get("empty_patch_ids", []),
            "error": iid in run_report.get("error_ids", [])
            or (not native and iid not in run_report.get("empty_patch_ids", [])),
            "native_report": native,
            "run_report": run_report,
            "logs": logs,
            "returncode": proc.returncode,
            "stderr_tail": proc.stderr[-2000:] if proc.stderr else "",
        }

        if not keep_logs and tmp_ctx is None:
            pass  # caller owns workdir; leave it
        return result
    finally:
        if tmp_ctx is not None and keep_logs:
            # copy report out before the tempdir dies is caller's job via workdir;
            # here we just drop the tempdir (report already parsed into the dict).
            tmp_ctx.cleanup()
        elif tmp_ctx is not None:
            tmp_ctx.cleanup()


def _p(path: Path) -> Optional[str]:
    return str(path) if path.exists() else None


def _tail(path: Path, n: int) -> Optional[str]:
    if not path.exists():
        return None
    try:
        return path.read_text(errors="replace")[-n:]
    except OSError:
        return None


def _find_run_report(base: str, run_id: str, iid: str) -> dict:
    """swebench writes a run-level summary json (`<model>.<run_id>.json`)."""
    for cand in Path(base).glob(f"*{run_id}*.json"):
        try:
            data = json.loads(cand.read_text())
            if isinstance(data, dict) and "submitted_instances" in data:
                return data
        except (json.JSONDecodeError, OSError):
            continue
    return {}


# --------------------------------------------------------------------------- #
# convenience wrappers
# --------------------------------------------------------------------------- #
def run_gold(instance: dict, **kw) -> dict:
    """Apply the instance's own gold `patch` -> should resolve True (sanity gate)."""
    return apply_and_run(instance, instance["patch"], **kw)


def run_noop(instance: dict, **kw) -> dict:
    """Apply a no-op new-file patch -> should resolve False (negative control)."""
    return apply_and_run(instance, NOOP_PATCH, **kw)


# --------------------------------------------------------------------------- #
# CLI (one-off runs)
# --------------------------------------------------------------------------- #
def _main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Tripwire SWE-bench adapter — one-off runs.")
    ap.add_argument("instance_id", help="e.g. astropy__astropy-12907")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--gold", action="store_true", help="apply the gold patch (expect resolved)")
    g.add_argument("--noop", action="store_true", help="apply a no-op patch (expect unresolved)")
    g.add_argument("--patch-file", help="path to a candidate diff to apply")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--workdir", default=None, help="keep logs here (else temp, discarded)")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    args = ap.parse_args(argv)

    inst = get_instance(args.instance_id)
    if args.gold:
        patch = inst["patch"]
    elif args.noop:
        patch = NOOP_PATCH
    else:
        patch = Path(args.patch_file).read_text()

    res = apply_and_run(
        inst, patch, run_id=args.run_id, workdir=args.workdir, timeout=args.timeout,
    )
    slim = {k: res[k] for k in (
        "instance_id", "resolved", "patch_applied", "empty_patch", "error",
        "returncode",
    )}
    slim["fail_to_pass"] = {
        "n_success": len(res["fail_to_pass_results"]["success"]),
        "n_failure": len(res["fail_to_pass_results"]["failure"]),
    }
    slim["pass_to_pass"] = {
        "n_success": len(res["pass_to_pass_results"]["success"]),
        "n_failure": len(res["pass_to_pass_results"]["failure"]),
    }
    print(json.dumps(slim, indent=2))
    return 0 if not res["error"] else 1


if __name__ == "__main__":
    raise SystemExit(_main())
