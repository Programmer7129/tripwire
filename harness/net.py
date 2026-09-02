#!/usr/bin/env python3
"""Tripwire egress isolation — allowlist forward-proxy + internal network.

Spec §4 hardening (phase0-log "Residual-risk HARDENING items"):
untrusted env code runs during `pip install` and `--prepare` (load_environment()
pulls the HF dataset). It must reach ONLY the hosts needed for install + dataset
load, nothing else — no direct internet.

Topology per batch:

    [untrusted env container]                 [envcert-proxy (squid)]
      network: envcert-egress-<tag>  ──req──▶   envcert-egress-<tag> (internal)
      (--internal: NO default route)            + bridge (its own egress)
      HTTP(S)_PROXY -> envcert-proxy:3128        allowlist gate -> internet

The env container has no route to the internet on its own; its only path out is
the proxy, which forwards to allowlisted domains and TCP_DENIEs the rest. A
proxy-bypassing direct connection has nowhere to go (internal network).

`--score` runs with the network fully cut (see runner.py) — proxy included.

THE ALLOWLIST BELOW IS THE SINGLE SOURCE OF TRUTH. Edit it here; it is rendered
into docker/proxy/allowlist.txt (squid dstdomain format) at proxy start.
A leading "." matches the domain and all subdomains.
"""
import os
import re
import subprocess
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY_DIR = os.path.join(REPO, "docker", "proxy")
SQUID_CONF = os.path.join(PROXY_DIR, "squid.conf")
ALLOWLIST_TXT = os.path.join(PROXY_DIR, "allowlist.txt")
SQUID_IMAGE = "ubuntu/squid:latest"
PROXY_PORT = 3128

# --- LiteLLM (Bedrock) judge proxy -------------------------------------------
# TRUSTED infra we control: an OpenAI-compatible server that fronts AWS Bedrock.
# The judge lane points untrusted env containers here (over the internal net) so
# their judge calls become Bedrock calls — ZERO OpenAI/OpenRouter in the path,
# and the env containers never see AWS creds (mounted read-only into THIS
# container only). See docker/litellm/config.yaml for the model mapping.
LITELLM_DIR = os.path.join(REPO, "docker", "litellm")
LITELLM_CONF = os.path.join(LITELLM_DIR, "config.yaml")
LITELLM_IMAGE = "ghcr.io/berriai/litellm:main-stable"
LITELLM_PORT = 4000
LITELLM_MASTER_KEY = "sk-envcert-local"
LITELLM_AWS_REGION = "us-east-1"
# host-local publish so the host can curl the proxy for verification (bound to
# loopback only — untrusted envs reach it by container name on the internal net,
# never via this host port).
LITELLM_HOST_PORT = 4000
AWS_DIR = os.path.expanduser("~/.aws")

# --- THE EGRESS ALLOWLIST (single editable list) -----------------------------
ALLOWLIST = [
    # PyPI + wheels (pip install)
    "pypi.org",
    "files.pythonhosted.org",
    # Prime Intellect hub (env package index) + API
    "hub.primeintellect.ai",
    "api.primeintellect.ai",
    # Prime serves the actual wheel BYTES from a GCS signed URL that the hub
    # simple-index redirects to (pihub-environments-prod bucket). Required for
    # `pip install` to complete; host-level allowlist can't scope to the bucket.
    "storage.googleapis.com",
    # Hugging Face (dataset load at load_environment() time)
    "huggingface.co",
    ".huggingface.co",          # *.huggingface.co (incl. cdn-lfs.huggingface.co)
    "cdn-lfs.huggingface.co",
    ".hf.co",                   # *.hf.co (LFS CDN edges)
    # GitHub raw (some dataset loading scripts fetch from here)
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    # LLM-JUDGE lane ONLY (runner.py judge mode). The judge is a network call, so
    # judge envs cannot be scored zero-network; their score phase runs on this
    # egress net with the allowlist scoped to the judge API host below (and
    # NOTHING else — no arbitrary exfil target). Binary/soft/sandbox envs still
    # score with the network fully cut; the key is passed ONLY in judge mode.
    # OpenRouter (OpenAI-compatible base url https://openrouter.ai/api/v1).
    "openrouter.ai",
    "api.openrouter.ai",
    # OpenAI direct (judge lane when the key is an OpenAI sk-... key).
    "api.openai.com",
]


def _load_dotenv(path):
    """Minimal KEY=VALUE .env reader (no external dep). Never logs values."""
    out = {}
    if not path or not os.path.exists(path):
        return out
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return out


def _sh(cmd, timeout=120, check=False):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or ""), f"TIMEOUT after {timeout}s"
    if check and p.returncode != 0:
        raise RuntimeError(f"cmd failed ({p.returncode}): {' '.join(cmd)}\n{p.stderr}")
    return p.returncode, p.stdout, p.stderr


_CONFIG_MAP_CACHE = None


def _load_litellm_map():
    """Parse docker/litellm/config.yaml -> {model_name: bedrock_model}. Cached.
    Uses PyYAML if present, else a tiny line parser (config is flat enough).
    The '*' catch-all is stored under the literal key '*'."""
    global _CONFIG_MAP_CACHE
    if _CONFIG_MAP_CACHE is not None:
        return _CONFIG_MAP_CACHE
    mapping = {}
    try:
        import yaml  # type: ignore
        with open(LITELLM_CONF) as f:
            doc = yaml.safe_load(f)
        for entry in (doc or {}).get("model_list", []):
            name = entry.get("model_name")
            model = (entry.get("litellm_params") or {}).get("model")
            if name and model:
                mapping[name] = model
    except Exception:
        # yaml missing/parse failed — anchor-aware line parser. Resolves YAML
        # anchors (&name defined on a tier's first member) and alias refs
        # (*name on inline siblings/passthroughs), plus the '*' catch-all.
        try:
            anchors = {}          # anchor_name -> bedrock model
            pending_names = []    # block-form model_names awaiting a model: line
            pending_anchor = None # anchor being defined by the next model: line
            inline_re = re.compile(
                r"model_name:\s*['\"]?([^'\",}\s]+)['\"]?.*litellm_params:\s*\*([A-Za-z0-9_]+)")
            mn_re = re.compile(r"model_name:\s*['\"]?([^'\",}\s]+)")
            anc_re = re.compile(r"litellm_params:\s*&([A-Za-z0-9_]+)")
            md_re = re.compile(r"\bmodel:\s*(bedrock/[^\s'\"}]+)")
            with open(LITELLM_CONF) as f:
                for raw in f:
                    line = raw.split("#", 1)[0].rstrip()
                    inl = inline_re.search(line)
                    if inl:
                        mapping[inl.group(1)] = anchors.get(inl.group(2))
                        continue
                    if "litellm_params" not in line:
                        mn = mn_re.search(line)
                        if mn:
                            pending_names.append(mn.group(1))
                    anc = anc_re.search(line)
                    if anc:
                        pending_anchor = anc.group(1)
                    md = md_re.search(line)
                    if md:
                        for nm in pending_names:
                            mapping[nm] = md.group(1)
                        if pending_anchor:
                            anchors[pending_anchor] = md.group(1)
                        pending_names, pending_anchor = [], None
        except Exception:
            pass
    _CONFIG_MAP_CACHE = mapping
    return mapping


def served_for(requested_name):
    """The Bedrock model our committed LiteLLM config serves for `requested_name`
    (exact match else the '*' catch-all). Strips the bedrock/ + converse/ prefix
    so the recorded served id is the bare Bedrock model/inference-profile id."""
    m = _load_litellm_map()
    target = m.get(requested_name) or m.get("*")
    if not target:
        return None
    t = target
    for pfx in ("bedrock/converse/", "bedrock/invoke/", "bedrock/"):
        if t.startswith(pfx):
            t = t[len(pfx):]
            break
    return t


def _dedupe_for_squid(domains):
    """Squid 6 FATALs if an exact entry is a subdomain of a leading-dot entry
    (e.g. 'huggingface.co'/'cdn-lfs.huggingface.co' vs '.huggingface.co'), since
    a leading dot already matches the apex and all subdomains. Drop the covered
    exact entries so ALLOWLIST can stay human-readable while the rendered file is
    squid-valid. Order preserved."""
    dot = [d for d in domains if d.startswith(".")]

    def covered(dom):
        for d in dot:  # d == ".huggingface.co"; base == "huggingface.co"
            base = d[1:]
            if dom == base or dom.endswith("." + base):
                return True
        return False

    out = []
    for dom in domains:
        if not dom.startswith(".") and covered(dom):
            continue
        if dom not in out:
            out.append(dom)
    return out


def _render_allowlist():
    """Write ALLOWLIST -> docker/proxy/allowlist.txt in squid dstdomain format."""
    with open(ALLOWLIST_TXT, "w") as f:
        f.write("# generated from harness/net.py::ALLOWLIST — do not edit by hand\n")
        for dom in _dedupe_for_squid(ALLOWLIST):
            f.write(dom + "\n")
    return ALLOWLIST_TXT


class Egress:
    """Batch-scoped allowlist proxy + internal network. up() once, down() once.

    tag is a per-invocation suffix (typically the runner pid) so parallel runner
    invocations don't collide on network/container names.
    """

    def __init__(self, tag):
        self.tag = str(tag)
        self.net = f"envcert-egress-{self.tag}"
        self.proxy = f"envcert-proxy-{self.tag}"
        # proxy is reachable by container name on the user-defined internal net
        self.proxy_url = f"http://{self.proxy}:{PROXY_PORT}"
        # LiteLLM->Bedrock judge proxy (trusted; brought up alongside squid).
        self.litellm = f"envcert-litellm-{self.tag}"
        # env containers reach it by NAME on the internal net (no host port).
        self.litellm_url = f"http://{self.litellm}:{LITELLM_PORT}/v1"
        self.litellm_key = LITELLM_MASTER_KEY
        # pid-derived loopback port so PARALLEL runner shards don't collide on 4000
        # (env containers reach the proxy by name on the internal net, not this port).
        try:
            self.litellm_host_port = LITELLM_HOST_PORT + (int(self.tag) % 2000)
        except (ValueError, TypeError):
            self.litellm_host_port = LITELLM_HOST_PORT

    # -- container-facing env: force pip + HF + urllib through the allowlist ---
    def env_flags(self):
        """`docker run -e ...` flags that pin all egress to the proxy."""
        u = self.proxy_url
        flags = []
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            flags += ["-e", f"{k}={u}"]
        # Nothing bypasses the proxy (empty NO_PROXY = no exceptions).
        for k in ("NO_PROXY", "no_proxy"):
            flags += ["-e", f"{k}="]
        # pip: also pin explicitly (belt & suspenders alongside env vars).
        flags += ["-e", f"PIP_PROXY={u}"]
        return flags

    def up(self):
        os.makedirs(PROXY_DIR, exist_ok=True)
        _render_allowlist()

        # pull squid image (needs network; one-time, cached thereafter)
        _sh(["docker", "pull", SQUID_IMAGE], timeout=300)

        # tear down any stale artifacts from a crashed prior run
        self.down(quiet=True)

        # internal network: NO route to the internet for anything attached.
        rc, _, err = _sh([
            "docker", "network", "create", "--internal", "--driver", "bridge", self.net,
        ], timeout=60)
        if rc != 0:
            raise RuntimeError(f"network create failed: {err.strip()}")

        # proxy on the default bridge (its OWN egress to the allowlisted hosts).
        rc, _, err = _sh([
            "docker", "run", "-d", "--name", self.proxy,
            "--network", "bridge",
            "--cpus", "1", "--memory", "512m",
            "--security-opt", "no-new-privileges",
            "-v", f"{SQUID_CONF}:/etc/squid/squid.conf:ro",
            "-v", f"{ALLOWLIST_TXT}:/etc/squid/allowlist.txt:ro",
            SQUID_IMAGE,
        ], timeout=120)
        if rc != 0:
            raise RuntimeError(f"proxy run failed: {err.strip()}")

        # also attach the proxy to the internal net so env containers can reach it.
        rc, _, err = _sh(["docker", "network", "connect", self.net, self.proxy], timeout=60)
        if rc != 0:
            raise RuntimeError(f"proxy network connect failed: {err.strip()}")

        self._wait_ready()

        # LiteLLM->Bedrock judge proxy, DUAL-HOMED like squid: launched on the
        # default bridge (its own egress to bedrock-runtime.us-east-1) then also
        # connected to the internal net (env containers reach it by name). AWS
        # creds are mounted read-only into THIS trusted container ONLY.
        self._litellm_up()
        return self

    def _litellm_up(self):
        if not os.path.exists(LITELLM_CONF):
            raise RuntimeError(f"litellm config missing: {LITELLM_CONF}")
        # Credentials: PREFER the scoped, least-privilege .env.bedrock key (bedrock
        # invoke only) passed as env vars; fall back to mounting ~/.aws (broader) if
        # the scoped file is absent. The env container never sees either — creds go
        # into THIS trusted proxy only.
        bedrock = _load_dotenv(os.path.join(REPO, ".env.bedrock"))
        if bedrock.get("AWS_ACCESS_KEY_ID") and bedrock.get("AWS_SECRET_ACCESS_KEY"):
            cred_args = ["-e", f"AWS_ACCESS_KEY_ID={bedrock['AWS_ACCESS_KEY_ID']}",
                         "-e", f"AWS_SECRET_ACCESS_KEY={bedrock['AWS_SECRET_ACCESS_KEY']}"]
            self.creds_source = "scoped:.env.bedrock (bedrock-invoke-only)"
        elif os.path.isdir(AWS_DIR):
            cred_args = ["-v", f"{AWS_DIR}:/root/.aws:ro"]
            self.creds_source = "mount:~/.aws"
        else:
            raise RuntimeError("no Bedrock creds: create .env.bedrock or ~/.aws")
        rc, _, err = _sh([
            "docker", "run", "-d", "--name", self.litellm,
            "--network", "bridge",
            "-p", f"127.0.0.1:{self.litellm_host_port}:{LITELLM_PORT}",
            "--cpus", "2", "--memory", "2g",
            "--security-opt", "no-new-privileges",
            "-e", f"LITELLM_MASTER_KEY={self.litellm_key}",
            "-e", f"AWS_REGION={LITELLM_AWS_REGION}",
            "-e", f"AWS_REGION_NAME={LITELLM_AWS_REGION}",
            "-e", "AWS_DEFAULT_REGION=" + LITELLM_AWS_REGION,
            *cred_args,
            "-v", f"{LITELLM_CONF}:/app/config.yaml:ro",
            LITELLM_IMAGE,
            "--config", "/app/config.yaml", "--port", str(LITELLM_PORT), "--host", "0.0.0.0",
        ], timeout=120)
        if rc != 0:
            raise RuntimeError(f"litellm run failed: {err.strip()}")
        rc, _, err = _sh(["docker", "network", "connect", self.net, self.litellm], timeout=60)
        if rc != 0:
            raise RuntimeError(f"litellm network connect failed: {err.strip()}")
        self._wait_litellm_ready()

    def _wait_litellm_ready(self, timeout=240):
        """Block until the LiteLLM server is accepting connections. Primary signal:
        a 2xx/4xx from the health endpoint on the published loopback port (a live
        socket). Fallback: the uvicorn startup banner in the logs. Cold starts can
        exceed a minute under Docker load (image pulls / concurrent runs), so the
        window is generous; a crashed container is surfaced immediately."""
        import urllib.request
        import urllib.error
        url = f"http://127.0.0.1:{self.litellm_host_port}/health/liveliness"
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                urllib.request.urlopen(url, timeout=5)
                return True
            except urllib.error.HTTPError:
                return True  # server answered (e.g. 401/404) => it's live
            except Exception:
                pass
            rc, out, _ = _sh(["docker", "logs", self.litellm], timeout=15)
            log = out or ""
            if "Application startup complete" in log or "Uvicorn running" in log:
                return True
            rc2, st, _ = _sh(["docker", "inspect", "-f", "{{.State.Running}}", self.litellm], timeout=15)
            if st.strip() == "false":
                _, logs, _ = _sh(["docker", "logs", self.litellm], timeout=15)
                raise RuntimeError(f"litellm exited during startup:\n{logs[-1500:]}")
            time.sleep(1.5)
        raise RuntimeError("litellm did not report ready within timeout")

    def _logs_merged(self):
        """Container logs with stderr+stdout MERGED chronologically. LiteLLM writes
        its routing/error detail (Received Model Group, bedrock URL) to STDERR, so
        stdout-only capture misses it."""
        try:
            p = subprocess.run(["docker", "logs", self.litellm],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, timeout=25)
            return p.stdout or ""
        except Exception:
            return ""

    def litellm_log_len(self):
        """Current line count of the litellm container log — snapshot BEFORE a
        judge run so the caller can diff only that env's request lines after."""
        return len(self._logs_merged().splitlines())

    # requested model group. On Bedrock errors litellm logs "Received Model
    # Group=<name>"; under set_verbose successful routes log "model=<name>" /
    # "model_group: <name>". Capture all three; bedrock/* targets are filtered out.
    _REQ_RES = (
        re.compile(r"Received Model Group\s*=\s*([^\s]+)"),
        re.compile(r"model_group['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9._*/-]+)"),
        re.compile(r"LiteLLM completion\(\)\s*model=\s*([A-Za-z0-9._*/-]+)"),
    )
    # served Bedrock id, url-encoded, from the bedrock-runtime request URL
    # (logged on Bedrock errors; e.g. .../model/us.anthropic.claude-...%3A0/converse)
    _URL_RE = re.compile(r"amazonaws\.com/model/([^/\s]+)/(?:converse|invoke)")

    def litellm_model_mapping(self, since_line):
        """Extract the (requested -> served) model routing for the disclosed config
        deviation (pre-reg §8). `requested` names are parsed from the proxy log
        slice since `since_line`; each is resolved to the Bedrock model our config
        maps it to (authoritative, no log-scrape needed for success). Any served id
        directly observed in the logs (Bedrock error URLs) is unioned in as
        corroboration. Returns {requested, served, served_by_config, raw}."""
        ansi = re.compile(r"\x1b\[[0-9;]*m")
        lines = [ansi.sub("", l) for l in self._logs_merged().splitlines()[since_line:]]
        requested, served_obs = [], []
        for ln in lines:
            for rx in self._REQ_RES:
                for m in rx.findall(ln):
                    if m and not m.startswith("bedrock") and m not in requested:
                        requested.append(m)
            for m in self._URL_RE.findall(ln):
                dec = m.replace("%3A", ":").replace("%3a", ":")
                if dec not in served_obs:
                    served_obs.append(dec)
        by_cfg = {r: served_for(r) for r in requested}
        served = list(dict.fromkeys(list(by_cfg.values()) + served_obs))
        served = [s for s in served if s]
        return {"requested": requested, "served": served,
                "served_by_config": by_cfg, "raw": "\n".join(lines)[-4000:]}

    def _wait_ready(self, timeout=30):
        """Block until squid is accepting connections."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            rc, out, _ = _sh(["docker", "logs", self.proxy], timeout=15)
            if "Accepting HTTP Socket connections" in (out or ""):
                return True
            # crashed? surface it fast
            rc2, st, _ = _sh(["docker", "inspect", "-f", "{{.State.Running}}", self.proxy], timeout=15)
            if st.strip() == "false":
                _, logs, _ = _sh(["docker", "logs", self.proxy], timeout=15)
                raise RuntimeError(f"proxy exited during startup:\n{logs[-1000:]}")
            time.sleep(0.5)
        # squid sometimes doesn't emit the banner; proceed — the functional
        # allow/deny tests in the runner are the real gate.
        return False

    def down(self, quiet=False):
        _sh(["docker", "rm", "-f", self.litellm], timeout=60)
        _sh(["docker", "rm", "-f", self.proxy], timeout=60)
        _sh(["docker", "network", "rm", self.net], timeout=60)
