#!/usr/bin/env python3
"""HUB CODING BATTERY — host-side driver. Generalizes code_pilot.py from ONE env +
hand-authored candidates to the pre-registered Class-A hub coding-env sample frame,
running the auto-generated dual-gated battery (code_battery_probe.py) per env.

Lifecycle per env (mirrors runner.run_env's disposable-container guardrail, spec §4):
  1. HEADROOM GATE — before install, sum running-container mem vs Docker total; if
     Docker has < MIN_HEADROOM_MB free, sleep + recheck (do NOT starve the SWE-500
     background run). Strictly serial: one env at a time.
  2. docker run -d   base image, bridge net (install only), cpu/mem/pids caps,
     no-new-privileges, /work (per-env battery out) + /app (trusted harness) mounts.
  3. pip install the untrusted env wheel (NETWORK ON).
  4. --prepare (NETWORK ON, one load) — warm the HF dataset cache + detect v0/v1.
  5. docker network disconnect -> ZERO network.
  6. assert_isolated (runner._ISOLATION_PROBE) — abort scoring if egress remains.
  7. code_battery_probe.py --battery (NETWORK OFF) — auto-build + score + oracle the
     battery over the env's OWN default rubric. Writes /work/<safe>.battery.jsonl.
  8. docker rm -f (always).

GUARDRAIL: the wheel is untrusted (RCE). It is only ever imported/executed inside the
disposable container; scoring runs zero-network with isolation asserted per env.
"""
import argparse
import json
import os
import sys
import time

HARNESS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HARNESS)
sys.path.insert(0, HARNESS)
import runner as R  # noqa: E402  (reuse sh + assert_isolated + parse_env_id + timeouts)

BASE_IMAGE = "envcert-base:latest"
OUT_DIR = os.path.join(REPO, "results", "pilot", "classA_battery")
MODULES = ("score_env.py", "classify.py", "probes.py", "oracle.py", "formatting.py",
           "attacker.py", "code_battery_probe.py")
MIN_HEADROOM_MB = 1500          # guardrail: leave >=1.5 GB for the SWE-500 run
HEADROOM_WAIT_S = 30
HEADROOM_MAX_WAITS = 20
BATTERY_TIMEOUT = 600


def _parse_mem_mib(s):
    """'67.2MiB' / '1.2GiB' / '512KiB' -> MiB float. Left side of 'used / limit'."""
    s = s.strip().split("/")[0].strip()
    num = "".join(ch for ch in s if (ch.isdigit() or ch == "."))
    if not num:
        return 0.0
    v = float(num)
    u = s.upper()
    if "GIB" in u or "GB" in u:
        return v * 1024
    if "KIB" in u or "KB" in u:
        return v / 1024
    if "B" in u and "MB" not in u and "MIB" not in u:  # bare bytes
        return v / (1024 * 1024)
    return v  # MiB / MB


def _docker_total_mib():
    rc, out, _ = R.sh(["docker", "info", "--format", "{{.MemTotal}}"], timeout=30)
    try:
        return int(out.strip()) / (1024 * 1024)
    except Exception:
        return 8192.0


def headroom_gate(label=""):
    """Block until Docker has >= MIN_HEADROOM_MB free (protect the SWE-500 run)."""
    total = _docker_total_mib()
    for attempt in range(HEADROOM_MAX_WAITS + 1):
        rc, out, _ = R.sh(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}"],
                          timeout=30)
        used = sum(_parse_mem_mib(l) for l in out.splitlines() if l.strip())
        free = total - used
        if free >= MIN_HEADROOM_MB:
            return {"ok": True, "docker_total_mib": round(total), "used_mib": round(used),
                    "free_mib": round(free), "waits": attempt}
        print("[headroom] %s Docker free %.0f MiB < %d MiB (used %.0f/%.0f); sleeping %ds "
              "(wait %d/%d)" % (label, free, MIN_HEADROOM_MB, used, total, HEADROOM_WAIT_S,
                                attempt + 1, HEADROOM_MAX_WAITS))
        time.sleep(HEADROOM_WAIT_S)
    return {"ok": False, "docker_total_mib": round(total), "free_mib": round(free),
            "error": "headroom never recovered — skipping to protect SWE-500"}


def _extract_json(stdout, tag):
    for line in (stdout or "").splitlines():
        if line.startswith(tag + " "):
            try:
                return json.loads(line[len(tag) + 1:])
            except Exception:
                return None
    return None


def run_one(spec, rows, k):
    env_id, owner, name, version = R.parse_env_id(spec)
    safe = env_id.replace("/", "__")
    cname = "codebat_%s_%d" % (safe, os.getpid())
    index_url = "https://hub.primeintellect.ai/%s/simple/" % owner
    pkg = "%s==%s" % (name, version) if version else name
    os.makedirs(OUT_DIR, exist_ok=True)
    batt_host = os.path.join(OUT_DIR, safe + ".battery.jsonl")
    for p in (batt_host,):
        if os.path.exists(p):
            os.remove(p)
    module_mounts = []
    for m in MODULES:
        module_mounts += ["-v", "%s:/app/%s:ro" % (os.path.join(HARNESS, m), m)]

    status = {"env_id": env_id, "container": cname, "rows": rows, "k": k}
    t0 = time.time()

    hg = headroom_gate(env_id)
    status["headroom"] = hg
    if not hg["ok"]:
        status.update(stage="headroom", ok=False, error=hg["error"])
        return status

    try:
        rc, out, err = R.sh([
            "docker", "run", "-d", "--name", cname, "--network", "bridge",
            "--cpus", "2", "--memory", "4g", "--memory-swap", "4g", "--pids-limit", "512",
            "--security-opt", "no-new-privileges",
            "-v", "%s:/work" % OUT_DIR, *module_mounts,
            BASE_IMAGE, "sleep", "infinity"], timeout=120)
        if rc != 0:
            status.update(stage="run", ok=False, error=(err or out)[-400:])
            return status

        install = ("pip install --no-cache-dir --index-url https://pypi.org/simple "
                   "--extra-index-url %s '%s'" % (index_url, pkg))
        rc, out, err = R.sh(["docker", "exec", cname, "bash", "-lc", install],
                            timeout=R.INSTALL_TIMEOUT)
        if rc != 0:
            status.update(stage="install", ok=False, error=(err or out)[-800:])
            return status

        # warm HF cache + detect v0/v1 (NETWORK ON)
        rc, out, err = R.sh([
            "docker", "exec", cname, "python", "/app/score_env.py",
            "--prepare", "--env-id", env_id, "--package", name, "--name", name,
            "--out-dir", "/work"], timeout=R.PREPARE_TIMEOUT)
        prep = None
        pp = os.path.join(OUT_DIR, safe + ".prepare.json")
        try:
            with open(pp) as f:
                prep = json.load(f)
        except Exception:
            pass
        status["prepare"] = prep
        if prep and prep.get("verifiers_api") == "v1":
            status["verifiers_api"] = "v1"

        # CUT NETWORK
        rc, _, _ = R.sh(["docker", "network", "disconnect", "bridge", cname], timeout=60)
        status["network_cut"] = (rc == 0)
        isolated, detail = R.assert_isolated(cname)
        status["network_isolated"] = isolated
        status["network_isolated_detail"] = detail
        if not isolated:
            status.update(stage="isolation", ok=False,
                          error="isolation not confirmed: %s" % detail)
            return status

        # OFFLINE BATTERY
        off = ["-e", "HF_HUB_OFFLINE=1", "-e", "HF_DATASETS_OFFLINE=1",
               "-e", "TRANSFORMERS_OFFLINE=1"]
        rc, out, err = R.sh([
            "docker", "exec", *off, cname, "python", "/app/code_battery_probe.py",
            "--env-id", env_id, "--package", name, "--name", name,
            "--rows", str(rows), "--k", str(k), "--out", "/work/%s.battery.jsonl" % safe],
            timeout=BATTERY_TIMEOUT)
        status["battery_summary"] = _extract_json(out, "BATTERY_JSON") or {
            "raw_stdout": (out or "")[-1500:], "stderr": (err or "")[-800:]}
        status["battery_jsonl"] = batt_host
        status.update(stage="done", ok=bool(status["battery_summary"].get("ok")))
        return status
    finally:
        status["elapsed_s"] = round(time.time() - t0, 1)
        R.sh(["docker", "rm", "-f", cname], timeout=60)
        try:
            with open(os.path.join(OUT_DIR, safe + ".status.json"), "w") as f:
                json.dump(status, f, indent=2, default=str)
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("envs", nargs="+", help="owner/name[@version] ...")
    ap.add_argument("--rows", type=int, default=2)
    ap.add_argument("--k", type=int, default=5)
    a = ap.parse_args()
    rc, out, _ = R.sh(["docker", "image", "inspect", BASE_IMAGE], timeout=30)
    if rc != 0:
        print("[!] %s missing" % BASE_IMAGE, file=sys.stderr)
        return 2
    os.makedirs(OUT_DIR, exist_ok=True)
    results = []
    for spec in a.envs:
        print("\n=== %s ===" % spec)
        st = run_one(spec, a.rows, a.k)
        results.append(st)
        bs = st.get("battery_summary", {})
        print("[%s] ok=%s stage=%s net_iso=%s rows=%s scored=%s refsol=%s cases=%s (%ss)" % (
            st["env_id"], st.get("ok"), st.get("stage"), st.get("network_isolated"),
            bs.get("n_rows"), bs.get("n_scored_probes"), bs.get("any_reference_solution"),
            bs.get("any_cases"), st.get("elapsed_s")))
        if not st.get("ok"):
            print("   ERR[%s]: %s" % (st.get("stage"), str(st.get("error"))[:300]))
    ok = sum(1 for s in results if s.get("ok"))
    print("\n=== %d/%d envs battery-scored ===" % (ok, len(results)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
