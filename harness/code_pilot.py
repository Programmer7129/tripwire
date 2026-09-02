#!/usr/bin/env python3
"""HUB CODING PILOT — host-side driver. Feasibility instrument (NOT a production lane).

Mirrors runner.run_env's disposable-container lifecycle for ONE coding env, but runs a
custom probe (code_pilot_probe.py) instead of the generic battery:

  1. docker run  base image, resource caps, no-new-privileges, /out + /work + /app mounts.
  2. pip install the untrusted env wheel (NETWORK ON).
  3. --inspect  (NETWORK ON, one load) — dump the score_rollout surface.
  4. docker network disconnect  -> ZERO network.
  5. assert isolation (runner._ISOLATION_PROBE) — abort scoring if egress remains.
  6. --attack   (NETWORK OFF) — score hand-crafted candidate completions offline.
  7. docker rm -f  (always).

GUARDRAIL: the wheel is untrusted (RCE). It is only ever imported/executed inside this
disposable container; scoring runs zero-network with isolation asserted. DEVIATION from
full hardening: install uses open bridge egress (not the squid allowlist) — acceptable
for a one-off pilot, disclosed here. Reuses runner.assert_isolated + score_env loader."""
import argparse
import json
import os
import sys
import time

HARNESS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HARNESS)
sys.path.insert(0, HARNESS)
import runner as R  # noqa: E402  (reuse sh + assert_isolated + _ISOLATION_PROBE)

BASE_IMAGE = "envcert-base:latest"
WORK = os.path.join(REPO, "results", "pilot")
MODULES = ("score_env.py", "classify.py", "probes.py", "oracle.py", "formatting.py",
           "attacker.py", "code_pilot_probe.py")


def run(spec, rows, k, candidates_path):
    env_id, owner, name, version = R.parse_env_id(spec)
    safe = env_id.replace("/", "__")
    cname = f"pilot_{safe}_{os.getpid()}"
    index_url = f"https://hub.primeintellect.ai/{owner}/simple/"
    pkg = f"{name}=={version}" if version else name
    os.makedirs(WORK, exist_ok=True)
    module_mounts = []
    for m in MODULES:
        module_mounts += ["-v", f"{os.path.join(HARNESS, m)}:/app/{m}:ro"]
    status = {"env_id": env_id}
    t0 = time.time()
    try:
        # 1) launch (open bridge for install; caps + no-new-privileges)
        rc, out, err = R.sh([
            "docker", "run", "-d", "--name", cname, "--network", "bridge",
            "--cpus", "2", "--memory", "4g", "--memory-swap", "4g", "--pids-limit", "512",
            "--security-opt", "no-new-privileges",
            "-v", f"{WORK}:/work", *module_mounts,
            BASE_IMAGE, "sleep", "infinity"], timeout=120)
        if rc != 0:
            return {**status, "stage": "run", "ok": False, "error": err[-400:]}

        # 2) install (NETWORK ON)
        install = (f"pip install --no-cache-dir --index-url https://pypi.org/simple "
                   f"--extra-index-url {index_url} '{pkg}'")
        rc, out, err = R.sh(["docker", "exec", cname, "bash", "-lc", install],
                            timeout=R.INSTALL_TIMEOUT)
        if rc != 0:
            return {**status, "stage": "install", "ok": False, "error": (err or out)[-600:]}

        # 3) inspect (NETWORK ON — warm HF cache + dump surface)
        rc, out, err = R.sh([
            "docker", "exec", cname, "python", "/app/code_pilot_probe.py",
            "--inspect", "--env-id", env_id, "--package", name, "--name", name,
            "--rows", str(rows)], timeout=R.PREPARE_TIMEOUT)
        status["inspect"] = _extract(out) or {"raw_stdout": out[-1500:], "stderr": err[-800:]}

        # 4) CUT NETWORK
        rc, _, _ = R.sh(["docker", "network", "disconnect", "bridge", cname], timeout=60)
        status["network_cut"] = (rc == 0)
        # 5) assert isolation (reuse runner's probe)
        isolated, detail = R.assert_isolated(cname)
        status["network_isolated"] = isolated
        status["network_isolated_detail"] = detail
        if not isolated:
            return {**status, "stage": "isolation", "ok": False,
                    "error": f"isolation not confirmed: {detail}"}

        # 6) attack (NETWORK OFF) — only if candidates provided
        if candidates_path:
            dst = os.path.join(WORK, "candidates.json")
            with open(candidates_path) as f:
                cj = json.load(f)
            with open(dst, "w") as f:
                json.dump(cj, f)
            off = ["-e", "HF_HUB_OFFLINE=1", "-e", "HF_DATASETS_OFFLINE=1",
                   "-e", "TRANSFORMERS_OFFLINE=1"]
            rc, out, err = R.sh([
                "docker", "exec", *off, cname, "python", "/app/code_pilot_probe.py",
                "--attack", "--env-id", env_id, "--package", name, "--name", name,
                "--k", str(k)], timeout=R.SCORE_TIMEOUT)
            status["attack"] = _extract(out) or {"raw_stdout": out[-2000:], "stderr": err[-1000:]}
        return {**status, "stage": "done", "ok": True}
    finally:
        status["elapsed_s"] = round(time.time() - t0, 1)
        R.sh(["docker", "rm", "-f", cname], timeout=60)


def _extract(stdout):
    for line in (stdout or "").splitlines():
        if line.startswith("PILOT_JSON "):
            try:
                return json.loads(line[len("PILOT_JSON "):])
            except Exception:
                return None
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("env", help="owner/name[@version]")
    ap.add_argument("--rows", type=int, default=3)
    ap.add_argument("--k", type=int, default=3)
    ap.add_argument("--candidates", default=None, help="path to candidates.json for --attack")
    a = ap.parse_args()
    rc, out, _ = R.sh(["docker", "image", "inspect", BASE_IMAGE], timeout=30)
    if rc != 0:
        print(f"[!] {BASE_IMAGE} missing", file=sys.stderr)
        return 2
    st = run(a.env, a.rows, a.k, a.candidates)
    os.makedirs(WORK, exist_ok=True)
    with open(os.path.join(WORK, a.env.replace("/", "__") + ".pilot.json"), "w") as f:
        json.dump(st, f, indent=2, default=str)
    print(json.dumps(st, indent=2, default=str))
    return 0 if st.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
