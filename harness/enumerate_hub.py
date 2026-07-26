#!/usr/bin/env python3
"""Snapshot the Prime Intellect Environments Hub to results/hub_index.jsonl.

Host-side only: read-only calls to the public unauthenticated API + JSON writes.
No untrusted env package is installed or executed. See docs/01-technical-spec.md §3.

One JSON object per env: the list-endpoint fields plus a `versions` field holding
the manifest for `latest_version` (or `versions: null` + `versions_error` on failure).

Resumable: on re-run, envs already present in the output file are skipped.
"""
import json
import os
import sys
import time
import random
import threading
import urllib.error
import urllib.request
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

API = "https://api.primeintellect.ai/api/v1/environmentshub"
LIST_LIMIT = 300
CONCURRENCY = 8
TIMEOUT = 20          # seconds per request
MAX_RETRIES = 5       # transient failures per request
MAX_BACKOFF = 30.0    # cap for exponential backoff
USER_AGENT = "envcert-hub-enumerator/1.0 (research audit; read-only)"

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
OUT_PATH = os.path.join(REPO, "results", "hub_index.jsonl")

_write_lock = threading.Lock()


def _get(url):
    """GET a URL, returning parsed JSON. Retries transient errors; honours 429/Retry-After.

    Raises the last exception after MAX_RETRIES exhausted."""
    last_exc = None
    for attempt in range(MAX_RETRIES):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                       "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last_exc = e
            if e.code == 429:
                ra = e.headers.get("Retry-After") if e.headers else None
                if ra and ra.strip().isdigit():
                    wait = min(float(ra.strip()), MAX_BACKOFF)
                else:
                    wait = min(MAX_BACKOFF, (2 ** attempt) + random.random())
                time.sleep(wait)
                continue
            if 500 <= e.code < 600:  # transient server error
                time.sleep(min(MAX_BACKOFF, (2 ** attempt) + random.random()))
                continue
            raise  # 4xx (other than 429) -> not retryable
        except (urllib.error.URLError, TimeoutError, ConnectionError,
                json.JSONDecodeError) as e:
            last_exc = e
            time.sleep(min(MAX_BACKOFF, (2 ** attempt) + random.random()))
            continue
    raise last_exc if last_exc else RuntimeError("request failed: %s" % url)


def fetch_all_envs():
    """Paginate the list endpoint. Returns (total_count, [env dicts])."""
    offset = 0
    total = None
    envs = []
    while True:
        url = "%s/?limit=%d&offset=%d" % (API, LIST_LIMIT, offset)
        payload = _get(url)
        total = payload.get("total_count", total)
        batch = payload.get("data", []) or []
        envs.extend(batch)
        got = len(batch)
        print("  list: offset=%d fetched=%d cumulative=%d total=%s"
              % (offset, got, len(envs), total), flush=True)
        offset += LIST_LIMIT
        if total is None or got == 0 or offset >= total:
            break
    return total, envs


def pick_latest_version(manifest_versions, latest_version):
    """Choose the manifest entry corresponding to the env's latest_version."""
    if not manifest_versions:
        return None
    if latest_version:
        for v in manifest_versions:
            if v.get("semantic_version") == latest_version:
                return v
    for v in manifest_versions:  # fall back to the one flagged "(latest)"
        if "(latest)" in (v.get("version") or ""):
            return v
    return manifest_versions[0]


def slim_version(v):
    """Reduce a manifest version entry to the fields the audit needs."""
    md = v.get("metadata") or {}
    return {
        "version": v.get("version"),
        "semantic_version": v.get("semantic_version"),
        "created_at": v.get("created_at"),
        "sha256": v.get("sha256"),
        "content_hash": v.get("content_hash"),
        "size": v.get("size"),
        "metadata": {
            "license": md.get("license"),
            "dependencies": md.get("dependencies"),
            "requires_dist": md.get("requires_dist"),
            "python_requires": md.get("python_requires"),
            "original_filename": md.get("original_filename"),
            "tags": md.get("tags"),
        },
    }


def fetch_versions_record(env):
    """Return an env record enriched with its latest-version manifest.

    Never raises: on failure sets versions=None and versions_error."""
    rec = dict(env)
    owner = (env.get("owner") or {}).get("name")
    name = env.get("name")
    latest_version = env.get("latest_version")
    if not owner or not name:
        rec["versions"] = None
        rec["versions_error"] = "missing owner/name"
        return rec
    url = "%s/%s/%s/versions" % (API,
                                 urllib.parse.quote(str(owner)),
                                 urllib.parse.quote(str(name)))
    try:
        payload = _get(url)
        vlist = ((payload.get("data") or {}).get("versions")) or []
        chosen = pick_latest_version(vlist, latest_version)
        if chosen is None:
            rec["versions"] = None
            rec["versions_error"] = "no versions in manifest"
        else:
            rec["versions"] = slim_version(chosen)
    except Exception as e:  # noqa: BLE001 - record, never crash the run
        rec["versions"] = None
        rec["versions_error"] = "%s: %s" % (type(e).__name__, e)
    return rec


def load_existing_ids(path):
    """Env ids already written, for resumability."""
    ids = set()
    if not os.path.exists(path):
        return ids
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ids.add(json.loads(line).get("id"))
            except json.JSONDecodeError:
                continue
    ids.discard(None)
    return ids


def summarize(path):
    total = 0
    with_versions = 0
    errored = 0
    null_latest = 0
    tag_counter = Counter()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            total += 1
            if rec.get("versions") is not None:
                with_versions += 1
            elif rec.get("versions_error"):
                errored += 1
            if rec.get("latest_version") is None:
                null_latest += 1
            for t in (rec.get("tags") or []):
                tag_counter[t] += 1
    print("\n===== hub_index.jsonl summary =====")
    print("env records written:            %d" % total)
    print("versions fetched successfully:  %d" % with_versions)
    print("versions errored (null):        %d" % errored)
    print("latest_version == null:         %d (never-published)" % null_latest)
    print("\ntop tags:")
    for tag, n in tag_counter.most_common(20):
        print("  %-24s %d" % (tag, n))


def main():
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    print("Enumerating hub list endpoint...", flush=True)
    total_count, envs = fetch_all_envs()
    print("list endpoint total_count=%s, envs collected=%d" % (total_count, len(envs)),
          flush=True)

    done_ids = load_existing_ids(OUT_PATH)
    pending = [e for e in envs if e.get("id") not in done_ids]
    print("already have %d records; fetching versions for %d envs (concurrency=%d)..."
          % (len(done_ids), len(pending), CONCURRENCY), flush=True)

    written = 0
    with open(OUT_PATH, "a", encoding="utf-8") as out:
        with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            futs = {pool.submit(fetch_versions_record, e): e for e in pending}
            for fut in as_completed(futs):
                rec = fut.result()
                line = json.dumps(rec, ensure_ascii=False)
                with _write_lock:
                    out.write(line + "\n")
                    out.flush()
                written += 1
                if written % 50 == 0:
                    print("  progress: %d/%d versions fetched"
                          % (written, len(pending)), flush=True)

    print("wrote %d new records this run (%d skipped as already present)"
          % (written, len(done_ids)), flush=True)
    summarize(OUT_PATH)
    print("\ntotal_count (list endpoint): %s" % total_count)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted; re-run to resume", file=sys.stderr)
        sys.exit(130)
