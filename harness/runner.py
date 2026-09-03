#!/usr/bin/env python3
"""Tripwire host-side orchestrator — disposable-container lifecycle per env.

Guardrail (spec §4): community env wheels are untrusted (pip install + import =
RCE). Every install + load_environment() + score_rollout() runs inside a
throwaway local Docker container with cpu/mem/pids caps, no-new-privileges, a
non-root user, and NO network during scoring.

Egress is allowlisted, never open (spec §4 hardening). The env container sits on
an --internal docker network with no route to the internet; its only path out is
a squid forward-proxy that permits ONLY the install+dataset hosts (harness/net.py
::ALLOWLIST) and TCP_DENIEs everything else. See harness/net.py for the topology.

Lifecycle per env:
  1. docker run -d   base image, INTERNAL egress network, HTTP(S)_PROXY set to
                     the allowlist proxy, resource caps, /out mounted.
  2. exec install    (proxy-only) pip install the env from the public prime hub
                                    index, forced through the allowlist proxy.
  3. exec prepare    (proxy-only) load_environment() once to warm the HF cache
                                    and detect v0/v1 (HF fetch via the proxy).
  4. network disconnect  -> container now has NO network at all (proxy included).
  5. ENFORCE isolation   -> probe from inside: assert no egress. Record
                            network_isolated. ABORT score if not confirmed.
  6. exec score      (network OFF) offline rubric scoring -> JSONL in /out.
  7. rm -f           always, even on failure.

Every exec is wrapped in a host wall-clock timeout; the finally-block rm -f is
the hard kill for anything still running in the container. The batch-scoped
proxy + internal network are torn down in main()'s finally.

Usage:
  python harness/runner.py owner/name [owner/name@version ...]
  python harness/runner.py --rows 5 will/gsm8k sivit/gsm8k-last-number
"""
import argparse
import json
import os
import subprocess
import sys
import time

from net import Egress

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_RAW = os.path.join(REPO, "results", "raw")
HARNESS = os.path.join(REPO, "harness")
SCORE_ENV = os.path.join(HARNESS, "score_env.py")
# trusted harness modules score_env.py imports at runtime; mounted into /app so
# they are importable inside the container (they post-date the base image build).
HARNESS_MODULES = ("score_env.py", "classify.py", "probes.py", "oracle.py",
                   "formatting.py", "attacker.py")
BASE_IMAGE = "envcert-base:latest"

INSTALL_TIMEOUT = 600
PREPARE_TIMEOUT = 300
SCORE_TIMEOUT = 300
# judge scoring makes real (paid) API calls and can be slower than offline scoring.
JUDGE_SCORE_TIMEOUT = 900

DEFAULT_JUDGE_BASE_URL = "https://openrouter.ai/api/v1"


def _load_dotenv(path):
    """Minimal KEY=VALUE .env parser (no external dep). Returns a dict; does NOT
    mutate os.environ. Never logged. Missing file -> {}."""
    out = {}
    if not path or not os.path.exists(path):
        return out
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return out


def resolve_judge_creds():
    """Resolve the judge API key + base url from os.environ, then .env (env wins).
    Returns {key, base_url, source} with key=None if unset. The key is NEVER
    printed — only its presence/source is surfaced (security §)."""
    dotenv = _load_dotenv(os.path.join(REPO, ".env"))

    def pick(*names):
        for n in names:
            if os.environ.get(n):
                return os.environ[n], f"env:{n}"
            if dotenv.get(n):
                return dotenv[n], f".env:{n}"
        return None, None

    key, ksrc = pick("OPENAI_API_KEY", "OPENROUTER_API_KEY")
    base_url, _ = pick("OPENAI_BASE_URL")
    return {"key": key, "key_source": ksrc,
            "base_url": base_url or DEFAULT_JUDGE_BASE_URL}

# Probe run INSIDE the container after the network cut. Attempts a raw TCP
# connect to public IPs (no DNS needed) and a DNS lookup. If EITHER succeeds the
# container still has egress and scoring must abort. Uses only stdlib so it works
# in the minimal image with no curl.
_ISOLATION_PROBE = (
    "import socket\n"
    "socket.setdefaulttimeout(2)\n"
    "up=False\n"
    "for hp in [('1.1.1.1',443),('8.8.8.8',53),('140.82.112.3',443)]:\n"
    "    try:\n"
    "        s=socket.create_connection(hp,2); s.close(); up=True; break\n"
    "    except OSError: pass\n"
    "try:\n"
    "    socket.gethostbyname('pypi.org'); up=True\n"
    "except OSError: pass\n"
    "print('NET_UP' if up else 'NET_DOWN')\n"
)


def assert_isolated(cname):
    """Return (isolated: bool, detail: str). isolated iff the container can reach
    NOTHING on the network. Belt-and-suspenders over the network disconnect."""
    rc, out, err = sh(["docker", "exec", cname, "python", "-c", _ISOLATION_PROBE], timeout=30)
    verdict = (out or "").strip().splitlines()[-1] if out.strip() else ""
    if verdict == "NET_DOWN":
        return True, "NET_DOWN"
    if verdict == "NET_UP":
        return False, "NET_UP (egress still reachable after cut)"
    return False, f"probe inconclusive rc={rc} out={verdict!r} err={err.strip()[:200]!r}"


def sh(cmd, timeout=None, check=False):
    """Run a host command, capturing output. Returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or ""), f"TIMEOUT after {timeout}s"
    if check and p.returncode != 0:
        raise RuntimeError(f"cmd failed ({p.returncode}): {' '.join(cmd)}\n{p.stderr}")
    return p.returncode, p.stdout, p.stderr


def parse_env_id(spec):
    """owner/name[@version] -> (env_id, owner, name, version)."""
    version = None
    if "@" in spec:
        spec, version = spec.split("@", 1)
    owner, name = spec.split("/", 1)
    return spec, owner, name, version


def run_env(spec, rows, k, egress, judge_force=False, judge_creds=None,
            judge_rows=3, judge_k=5, attack_mode=False, attacker_model="envcert-sonnet",
            attack_n=8, attack_feedback=1, attack_rows=5, attack_k=1, no_judge=False):
    env_id, owner, name, version = parse_env_id(spec)
    safe = env_id.replace("/", "__")
    cname = f"envcert_{safe}_{os.getpid()}"
    index_url = f"https://hub.primeintellect.ai/{owner}/simple/"
    pkg_spec = f"{name}=={version}" if version else name
    status = {"env_id": env_id, "container": cname}
    t0 = time.time()

    os.makedirs(RESULTS_RAW, exist_ok=True)
    # clean any stale artifacts for this env
    for suf in (".jsonl", ".prepare.json", ".battery.jsonl", ".classify.json",
                ".status.json", ".eyr.jsonl"):
        p = os.path.join(RESULTS_RAW, safe + suf)
        if os.path.exists(p):
            os.remove(p)

    module_mounts = []
    for m in HARNESS_MODULES:
        module_mounts += ["-v", f"{os.path.join(HARNESS, m)}:/app/{m}:ro"]

    try:
        # 1) launch disposable container on the INTERNAL egress network (no direct
        #    internet); HTTP(S)_PROXY forces pip+HF through the allowlist proxy.
        rc, out, err = sh([
            "docker", "run", "-d", "--name", cname,
            "--network", egress.net,
            *egress.env_flags(),
            "--cpus", "2", "--memory", "4g", "--memory-swap", "4g",
            "--pids-limit", "512",
            "--security-opt", "no-new-privileges",
            "-v", f"{RESULTS_RAW}:/out",
            *module_mounts,
            BASE_IMAGE, "sleep", "infinity",
        ], timeout=120)
        if rc != 0:
            status.update(stage="run", ok=False, error=err.strip()[:400])
            return status

        # 2) install env (NETWORK ON) — public prime hub index, no auth
        install_cmd = (
            f"pip install --no-cache-dir --index-url https://pypi.org/simple "
            f"--extra-index-url {index_url} '{pkg_spec}'"
        )
        rc, out, err = sh(["docker", "exec", cname, "bash", "-lc", install_cmd],
                          timeout=INSTALL_TIMEOUT)
        if rc != 0:
            status.update(stage="install", ok=False,
                          error=(err or out).strip()[-600:])
            return status

        # 3) prepare (NETWORK ON) — warm HF cache, detect v0/v1.
        #    Judge envs may require the API key at LOAD time (load_environment()
        #    validates config). prepare runs with the allowlist proxy up (egress
        #    scoped to install/dataset + judge host), so inject creds here too when
        #    available — harmless for non-judge envs (they still network-cut before
        #    scoring). Without this, load-time-key judge envs fail at prepare.
        prep_creds = []
        if (judge_creds or {}).get("key"):
            _c = judge_creds
            # NO_PROXY must include the LiteLLM host: the container's HTTP(S)_PROXY
            # points at squid, but the Bedrock proxy is on the internal net at a
            # non-safe port (4000) — squid would deny it. Bypass the proxy for that
            # host so the OpenAI client connects to LiteLLM directly.
            prep_creds = ["-e", f"OPENAI_API_KEY={_c['key']}",
                          "-e", f"OPENAI_BASE_URL={_c['base_url']}",
                          "-e", f"OPENROUTER_API_KEY={_c['key']}",
                          "-e", f"NO_PROXY={egress.litellm}",
                          "-e", f"no_proxy={egress.litellm}"]
        rc, out, err = sh([
            "docker", "exec", *prep_creds, cname,
            "python", "/app/score_env.py",
            "--prepare", "--env-id", env_id, "--package", name, "--name", name,
        ], timeout=PREPARE_TIMEOUT)
        prep_path = os.path.join(RESULTS_RAW, safe + ".prepare.json")
        prep = _read_json(prep_path)
        status["prepare"] = prep
        if rc != 0 and not (prep and prep.get("ok")):
            status.update(stage="prepare", ok=False,
                          error=(err or out).strip()[-600:])
            return status

        # 3a) ATTACK / EYR LANE (before the judge-mode decision). The elicited lane
        #     runs on binary AND judge envs: the attacker + verifier both need the
        #     Bedrock proxy, so — like judge mode — we KEEP the allowlist egress up
        #     (NOT zero-network) and point the untrusted container at the in-cluster
        #     LiteLLM proxy with the local master key only (no AWS creds, no internet).
        if attack_mode:
            creds = judge_creds or {}
            status["network_cut"] = False
            status["network_isolated"] = False
            status["attack_egress"] = True
            status["attack_mode"] = True
            status["attacker_model"] = attacker_model
            status["isolation_posture"] = (
                "attack-egress: env container + attacker reach ONLY the in-cluster "
                "LiteLLM->Bedrock proxy on the internal net (NOT zero-network, NO direct "
                "internet); AWS creds live in the trusted proxy only")
            est = attack_rows * ((1 + attack_feedback) * attack_n + 1 + 2 * attack_k)
            status["attack_calls_estimate"] = est
            print(f"[attack][SECURITY] pointing untrusted container {cname} at the "
                  f"LiteLLM->Bedrock proxy ({creds.get('base_url')}) with the local master "
                  f"key only — attacker={attacker_model}, ~{est} model+verifier calls est.")
            cred_flags = ["-e", f"OPENAI_API_KEY={creds.get('key')}",
                          "-e", f"OPENAI_BASE_URL={creds.get('base_url')}",
                          "-e", f"NO_PROXY={egress.litellm}",
                          "-e", f"no_proxy={egress.litellm}"]
            _ll_log0 = egress.litellm_log_len()
            rc, out, err = sh([
                "docker", "exec", *cred_flags, cname,
                "python", "/app/score_env.py",
                "--attack", "--env-id", env_id, "--package", name, "--name", name,
                "--attacker-model", attacker_model,
                "--attack-n", str(attack_n), "--attack-feedback", str(attack_feedback),
                "--rows", str(attack_rows), "--k", str(attack_k),
            ], timeout=JUDGE_SCORE_TIMEOUT)
            status["attack_stdout"] = out.strip()[-600:]
            try:
                _map = egress.litellm_model_mapping(_ll_log0)
                status["attacker_model_requested"] = _map["requested"]
                status["attacker_model_served"] = _map["served"]
            except Exception as _e:  # noqa: BLE001
                status["attack_model_mapping_error"] = repr(_e)
            if rc != 0:
                status.update(stage="attack", ok=False,
                              error=f"rc={rc}; " + (err or out).strip()[-600:])
                return status
            eyr_path = os.path.join(RESULTS_RAW, safe + ".eyr.jsonl")
            status["eyr_jsonl"] = eyr_path
            status.update(_summarise_eyr(eyr_path))
            status.update(stage="done", ok=True)
            return status

        # 3b) JUDGE-MODE DECISION (before the network cut). llm_judge envs invoke an
        #     LLM to score, so they CANNOT be scored zero-network — they run WITH the
        #     allowlist egress up, scoped to the judge host only. Auto-selected from
        #     the (introspection-only, no-scoring) static bucket, or forced via --judge.
        static_bucket = (prep or {}).get("static_bucket")
        status["verifier_bucket_static"] = static_bucket
        judge_mode = bool(judge_force or static_bucket == "llm_judge")
        status["judge_mode"] = judge_mode

        # --no-judge: for the $0 broadening census, classify judge envs (verifier_type
        # already captured in verifier_bucket_static) but SKIP their Bedrock scoring.
        if judge_mode and no_judge:
            status.update(stage="judge_skipped_no_judge", ok=True,
                          verifier_type="llm_judge", judge_scored=False)
            return status

        if judge_mode:
            # JUDGE LANE — keep the container ON the allowlist egress net. Record the
            # posture so the isolation stance is auditable: this env did NOT run
            # zero-network; egress was scoped to the judge API host by the proxy.
            status["network_cut"] = False
            status["network_isolated"] = False
            status["judge_egress"] = True
            status["isolation_posture"] = (
                "judge-egress: env container reaches ONLY the in-cluster LiteLLM->Bedrock "
                "proxy on the internal net (NOT zero-network, NO direct internet); "
                "AWS creds live in the trusted proxy only; judge served by AWS Bedrock")
            creds = judge_creds or {}
            status["judge_backend"] = "bedrock-via-litellm"
            status["judge_base_url"] = creds.get("base_url")
            # SECURITY: the only secret handed to the untrusted container is the LiteLLM
            # MASTER KEY (a local, non-AWS token). Even if the env exfiltrates it, it can
            # only reach the LiteLLM proxy on the internal net — the env has NO route to
            # AWS, no AWS creds, and no arbitrary internet. Strictly stronger than passing
            # a real OpenAI key. The proxy calls Bedrock with creds the env never sees.
            print(f"[judge][SECURITY] pointing untrusted container {cname} at the "
                  f"LiteLLM->Bedrock proxy ({creds.get('base_url')}) with the local master "
                  f"key only — env gets NO AWS creds and NO internet except this proxy.")
            est = judge_rows * max(1, judge_k) * (1 + 4 + 3)  # anchor + <=4 known_wrong + 3 inj
            status["judge_calls_estimate"] = est
            print(f"[judge] approx <= {est} judge calls for {env_id} "
                  f"(rows={judge_rows} x k={judge_k} x (1 anchor + <=4 known_wrong + 3 injection))")
            cred_flags = ["-e", f"OPENAI_API_KEY={creds['key']}",
                          "-e", f"OPENAI_BASE_URL={creds['base_url']}",
                          "-e", f"OPENROUTER_API_KEY={creds['key']}",
                          # bypass squid for the internal-net Bedrock proxy (port 4000
                          # is not a squid Safe_port; direct connect on the internal net)
                          "-e", f"NO_PROXY={egress.litellm}",
                          "-e", f"no_proxy={egress.litellm}"]
            # Snapshot the proxy log length so we can attribute ONLY this env's request
            # lines afterwards -> the disclosed config deviation (requested vs served).
            _ll_log0 = egress.litellm_log_len()
            # Judge mode is already non-zero-network (env reaches the Bedrock proxy only).
            # HF is on the squid allowlist, so DON'T force it offline — many judge envs
            # load their dataset lazily (after load_environment), which fails under
            # HF_HUB_OFFLINE even though the cache was warmed at prepare.
            rc, out, err = sh([
                "docker", "exec", *cred_flags, cname,
                "python", "/app/score_env.py",
                "--judge-battery", "--env-id", env_id, "--package", name, "--name", name,
                "--rows", str(judge_rows), "--k", str(judge_k),
            ], timeout=JUDGE_SCORE_TIMEOUT)
            status["battery_stdout"] = out.strip()[-400:]
            # DISCLOSED CONFIG DEVIATION (pre-reg §8): the model the env REQUESTED vs the
            # Bedrock model that actually SERVED it, parsed from the proxy log slice.
            try:
                _map = egress.litellm_model_mapping(_ll_log0)
                status["judge_model_requested"] = _map["requested"]
                status["judge_model_served"] = _map["served"]
                status["judge_route_log"] = _map["raw"]
            except Exception as _e:  # noqa: BLE001
                status["judge_model_mapping_error"] = repr(_e)
            if rc != 0:
                status.update(stage="judge_battery", ok=False,
                              error=(err or out).strip()[-600:])
                return status
            batt_path = os.path.join(RESULTS_RAW, safe + ".battery.jsonl")
            status["battery_jsonl"] = batt_path
            status["verifier_type"] = "llm_judge"
            status.update(_summarise_battery(batt_path, None))
            status.update(stage="done", ok=True)
            return status

        # 4) CUT THE NETWORK — detach from the internal egress net; the container
        #    now has no networks at all (proxy path included).
        rc, out, err = sh(["docker", "network", "disconnect", egress.net, cname], timeout=60)
        status["network_cut"] = (rc == 0)

        # 4b) ENFORCE + RECORD the isolation invariant (spec §4 hardening item 2).
        #     Probe from inside; if any egress remains, ABORT scoring for this env.
        isolated, iso_detail = assert_isolated(cname)
        status["network_isolated"] = isolated
        status["network_isolated_detail"] = iso_detail
        if not isolated:
            status.update(stage="isolation", ok=False,
                          error=f"network isolation NOT confirmed: {iso_detail}; scoring aborted")
            return status

        off_env = ["-e", "HF_HUB_OFFLINE=1", "-e", "HF_DATASETS_OFFLINE=1",
                   "-e", "TRANSFORMERS_OFFLINE=1"]

        # 5) classify (NETWORK OFF) — introspect the rubric -> verifier-type
        rc, out, err = sh([
            "docker", "exec", *off_env, cname,
            "python", "/app/score_env.py",
            "--classify", "--env-id", env_id, "--package", name, "--name", name,
        ], timeout=SCORE_TIMEOUT)
        cls_path = os.path.join(RESULTS_RAW, safe + ".classify.json")
        status["classify"] = _read_json(cls_path)
        if rc != 0 and not status["classify"]:
            status.update(stage="classify", ok=False, error=(err or out).strip()[-600:])
            return status

        # 6) battery (NETWORK OFF) — dual-gated probe battery, k repeats
        rc, out, err = sh([
            "docker", "exec", *off_env, cname,
            "python", "/app/score_env.py",
            "--battery", "--env-id", env_id, "--package", name, "--name", name,
            "--rows", str(rows), "--k", str(k),
        ], timeout=SCORE_TIMEOUT)
        status["battery_stdout"] = out.strip()[-400:]
        if rc != 0:
            status.update(stage="battery", ok=False, error=(err or out).strip()[-600:])
            return status

        # 7) summarise the dual-gated battery records (Phase 2 computes aggregates)
        batt_path = os.path.join(RESULTS_RAW, safe + ".battery.jsonl")
        status["battery_jsonl"] = batt_path
        status.update(_summarise_battery(batt_path, status.get("classify")))
        status.update(stage="done", ok=True)
        return status

    finally:
        status["elapsed_s"] = round(time.time() - t0, 1)
        sh(["docker", "rm", "-f", cname], timeout=60)  # hard kill / teardown
        # persist the per-env status (carries the recorded isolation invariant)
        try:
            with open(os.path.join(RESULTS_RAW, safe + ".status.json"), "w") as f:
                json.dump(status, f, default=str)
        except Exception:
            pass


def _read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _summarise(jsonl_path):
    recs = []
    try:
        with open(jsonl_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    recs.append(json.loads(line))
    except Exception as e:
        return {"records": 0, "summary_error": repr(e)}

    def best(prefix):
        # max reward any probe of this family earned — for gold: did it pass;
        # for known_wrong/empty: did a wrong answer sneak a high reward.
        vals = [r["reward"] for r in recs
                if r.get("probe_type", "").startswith(prefix) and isinstance(r.get("reward"), (int, float))]
        return (max(vals) if vals else None)

    errs = sum(1 for r in recs if "error" in r)
    return {
        "records": len(recs),
        "record_errors": errs,
        "gold_best_reward": best("gold"),
        "empty_reward": best("empty"),
        "known_wrong_best_reward": best("known_wrong"),
        "verifiers_api": (recs[0].get("verifiers_api") if recs else None),
        "rubric_class": (recs[0].get("rubric_class") if recs else None),
        "reward_func_names": (recs[0].get("reward_func_names") if recs else None),
    }


def _summarise_battery(path, classify):
    """Preview counts over the dual-gated battery records. NOT the aggregate — FAR
    with Wilson CIs + BH-FDR is Phase 2 over results/raw. `n_far_pass` here is just
    'known-wrong probes the verifier gave a positive reward' as a per-env sanity
    signal; it is not the pre-registered FAR."""
    recs = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    recs.append(json.loads(line))
    except Exception as e:
        return {"records": 0, "summary_error": repr(e)}

    vtype = None
    for r in recs:
        if r.get("mode") == "classification":
            vtype = r.get("verifier_type")
    if vtype is None and classify:
        vtype = classify.get("bucket") or classify.get("verifier_type")

    def is_pass(r):
        v = r.get("v_reward_majority")
        return isinstance(v, (int, float)) and v > 0

    probe_recs = [r for r in recs if "v_reward_majority" in r]
    far = [r for r in probe_recs if r.get("far_eligible")]
    frr = [r for r in probe_recs if r.get("frr_eligible")]
    anchors = [r for r in probe_recs if r.get("far_bucket") == "anchor"]
    amb = [r for r in recs if r.get("far_bucket") == "ambiguous"]
    return {
        "records": len(recs),
        "record_errors": sum(1 for r in recs if "error" in r),
        "verifier_type": vtype,
        "n_far_eligible": len(far),
        "n_far_pass": sum(1 for r in far if is_pass(r)),
        "n_frr_eligible": len(frr),
        "n_frr_reject": sum(1 for r in frr if not is_pass(r)),
        "n_ambiguous": len(amb),
        "n_anchor": len(anchors),
        "n_anchor_pass": sum(1 for r in anchors if is_pass(r)),
        "verdict_unstable": sum(1 for r in probe_recs if r.get("verdict_unstable")),
    }


def _summarise_eyr(path):
    """Pull the EYR summary line out of the per-env <safe>.eyr.jsonl for the status
    record (the full per-row detail lives in the jsonl; aggregate_eyr pools them)."""
    try:
        with open(path) as f:
            recs = [json.loads(l) for l in f if l.strip()]
    except Exception as e:  # noqa: BLE001
        return {"records": 0, "summary_error": repr(e)}
    summ = next((r for r in recs if r.get("mode") == "eyr_summary"), {})
    keys = ("attacker_model", "n_rows_counted", "mean_reward_attacker",
            "mean_reward_honest_baseline", "reward_lift",
            "oracle_correct_rate_of_high_reward", "n_exploits", "eyr_positive",
            "n_attacker_calls", "n_verifier_calls")
    out = {"records": len(recs), "verifier_type": "eyr"}
    out.update({k: summ.get(k) for k in keys})
    return out


def main():
    ap = argparse.ArgumentParser(description="Tripwire disposable-container scoring runner")
    ap.add_argument("envs", nargs="+", help="owner/name[@version] ...")
    ap.add_argument("--rows", type=int, default=5, help="dataset rows to probe per env")
    ap.add_argument("--k", type=int, default=5, help="probe repeats (pre-reg §4)")
    # --- llm_judge lane (cost control: judge calls cost money) ---
    ap.add_argument("--judge", action="store_true",
                    help="force judge mode for every env (else auto-selected when an "
                         "env classifies llm_judge). Keeps allowlist judge-egress up "
                         "for scoring instead of cutting the network.")
    ap.add_argument("--judge-rows", dest="judge_rows", type=int, default=3,
                    help="dataset rows to probe per judge env (SMALL by default; each "
                         "row costs (1 anchor + <=4 known_wrong + 3 injection) x k calls)")
    ap.add_argument("--judge-k", dest="judge_k", type=int, default=5,
                    help="probe repeats in the judge lane (pre-reg §4; judges are stochastic)")
    ap.add_argument("--no-judge", dest="no_judge", action="store_true",
                    help="classify judge envs but SKIP Bedrock scoring ($0 broadening census)")
    ap.add_argument("--limit", type=int, default=None,
                    help="cap the number of envs processed this run (cost/blast-radius)")
    # --- elicited / EYR lane (pre-reg §2) ---
    ap.add_argument("--attack", action="store_true",
                    help="run the ELICITED/EYR lane instead of the probe battery: an "
                         "attacker model best-of-N vs the verifier, dual-gated by the "
                         "oracle. Keeps the Bedrock proxy egress up (like judge mode).")
    ap.add_argument("--attacker-model", dest="attacker_model", default="envcert-sonnet",
                    help="Bedrock passthrough for the attacker (ladder: envcert-nova/"
                         "haiku/sonnet/opus/deepseek/llama)")
    ap.add_argument("--attack-n", dest="attack_n", type=int, default=8,
                    help="best-of-N candidates per round (pre-reg: reward-weighting first)")
    ap.add_argument("--attack-feedback", dest="attack_feedback", type=int, default=1,
                    help="reward-feedback rounds after the first")
    ap.add_argument("--attack-rows", dest="attack_rows", type=int, default=5,
                    help="dataset rows to attack per env (SMALL by default; cost)")
    ap.add_argument("--attack-k", dest="attack_k", type=int, default=1,
                    help="re-score repeats for the best candidate + anchor (stability)")
    args = ap.parse_args()
    if args.limit is not None:
        args.envs = args.envs[:args.limit]

    # sanity: image present?
    rc, out, _ = sh(["docker", "image", "inspect", BASE_IMAGE], timeout=30)
    if rc != 0:
        print(f"[!] {BASE_IMAGE} not found — run docker/build.sh first", file=sys.stderr)
        return 2

    # Batch-scoped allowlist egress: one proxy + internal network for the run.
    egress = Egress(os.getpid())
    try:
        print(f"[net] bringing up allowlist proxy {egress.proxy} on {egress.net} ...")
        egress.up()
        print(f"[net] proxy ready at {egress.proxy_url} (allowlist-only egress)")
    except Exception as e:
        print(f"[!] failed to bring up egress proxy: {e}", file=sys.stderr)
        egress.down(quiet=True)
        return 3

    # JUDGE CREDS = the LiteLLM->Bedrock proxy (ZERO OpenAI/OpenRouter). The env
    # container is pointed at the in-cluster proxy with the LiteLLM master key;
    # LiteLLM translates the OpenAI-compatible call into a Bedrock invoke using
    # AWS creds mounted into the TRUSTED proxy only. The untrusted env never gets
    # AWS creds and has no internet except the proxy. resolve_judge_creds() is
    # retained for reference/fallback but is NOT used in the Bedrock path.
    judge_creds = {"key": egress.litellm_key, "base_url": egress.litellm_url,
                   "key_source": "bedrock-litellm(us-east-1)"}
    if args.judge or True:
        print(f"[judge] judge lane enabled (force={args.judge}); backend=AWS Bedrock "
              f"via LiteLLM proxy {egress.litellm}; base_url={judge_creds['base_url']}; "
              f"judge_rows={args.judge_rows} judge_k={args.judge_k}. "
              f"NO OpenAI/OpenRouter in the path; cost is Bedrock (AWS credits).")

    try:
        all_status = []
        for spec in args.envs:
            print(f"\n=== {spec} ===")
            st = run_env(spec, args.rows, args.k, egress,
                         judge_force=args.judge, judge_creds=judge_creds,
                         judge_rows=args.judge_rows, judge_k=args.judge_k,
                         attack_mode=args.attack, attacker_model=args.attacker_model,
                         attack_n=args.attack_n, attack_feedback=args.attack_feedback,
                         attack_rows=args.attack_rows, attack_k=args.attack_k,
                         no_judge=args.no_judge)
            all_status.append(st)
            if args.attack:
                line = (f"[{st['env_id']}] ok={st.get('ok')} stage={st.get('stage')} "
                        f"attacker={st.get('attacker_model')} rows={st.get('n_rows_counted')} "
                        f"mean_reward_attacker={st.get('mean_reward_attacker')} "
                        f"honest={st.get('mean_reward_honest_baseline')} "
                        f"oracle_correct_hi={st.get('oracle_correct_rate_of_high_reward')} "
                        f"exploits={st.get('n_exploits')} eyr_positive={st.get('eyr_positive')} "
                        f"att_calls={st.get('n_attacker_calls')} ver_calls={st.get('n_verifier_calls')} "
                        f"({st.get('elapsed_s')}s)")
                if not st.get("ok"):
                    line += f"  ERR[{st.get('stage')}]: {str(st.get('error'))[:200]}"
                print(line)
                continue
            line = (f"[{st['env_id']}] ok={st.get('ok')} stage={st.get('stage')} "
                    f"type={st.get('verifier_type')} records={st.get('records')} "
                    f"judge={st.get('judge_mode')} net_isolated={st.get('network_isolated')} "
                    f"far_elig={st.get('n_far_eligible')} far_pass={st.get('n_far_pass')} "
                    f"frr_elig={st.get('n_frr_eligible')} amb={st.get('n_ambiguous')} "
                    f"unstable={st.get('verdict_unstable')} ({st.get('elapsed_s')}s)")
            if not st.get("ok"):
                line += f"  ERR[{st.get('stage')}]: {str(st.get('error'))[:200]}"
            print(line)

        ok = sum(1 for s in all_status if s.get("ok"))
        print(f"\n=== {ok}/{len(all_status)} envs scored ===")
        return 0 if ok else 1
    finally:
        print(f"[net] tearing down egress proxy {egress.proxy} + network {egress.net}")
        egress.down()


if __name__ == "__main__":
    sys.exit(main())
