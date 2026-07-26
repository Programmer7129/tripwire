#!/usr/bin/env python3
"""envcert auto-format discovery (Phase 2 validity fix) — runs INSIDE the container.

THE PROBLEM this fixes: many envs ship a `format_reward_func` that only rewards a
specific completion FORMAT (a `\\boxed{}` / `<answer>...</answer>` / think-tag
wrapper). Submitting the raw gold string (`72`, `D`) fails that component, so the
verifier rejects its OWN gold and the env is (wrongly) discarded as a `gold_fail`.
We then test formatting instead of correctness on exactly the complex envs most
likely to be broken.

THE FIX: discover the passing completion FORMAT *from the env itself*, using the
env's OWN parser and OWN reward (this preserves the "own declared config" rule).

  1. PRIMARY  — introspect `env.parser` (verifiers 0.2.0: XMLParser / ThinkParser /
     boxed Parser) and `env.system_prompt` to build a best-guess conformant
     completion for the gold.
  2. EMPIRICAL — generate a battery of candidate wrappers for the gold, score EACH
     through the env's OWN `rubric.score_rollout` (offline; via the caller-supplied
     `score_completion` callback), and pick the wrapper that MAXIMIZES the gold's
     reward. That winner is the env's `discovered_format`.

ORACLE INDEPENDENCE (pre-reg §3) is preserved because this module NEVER touches the
oracle: it only maximizes the env's own reward on the *gold*. The format wrapper is
applied only at SCORING time (what the verifier sees); the oracle continues to judge
the RAW, unwrapped candidate content. The wrapper cannot leak into the oracle's
correctness decision.

No network. Pure introspection + offline scoring through the caller's callback.
"""
import json

# Benign filler for reasoning/think fields — never numeric, never near an answer,
# so it can't be mistaken for answer content by a lenient parser.
THINK_FILLER = "Working through the problem carefully."


# ---------------------------------------------------------------------------
# candidate format wrappers (env-agnostic empirical battery)
# ---------------------------------------------------------------------------

def _w_raw(x):               return f"{x}"
def _w_boxed(x):             return f"\\boxed{{{x}}}"
def _w_xml_answer(x):        return f"<answer>{x}</answer>"
def _w_think_xml_answer(x):  return f"<think>{THINK_FILLER}</think>\n<answer>{x}</answer>"
def _w_think_raw(x):         return f"<think>{THINK_FILLER}</think>\n{x}"
def _w_prose(x):             return f"The answer is {x}."
def _w_boxed_think(x):       return f"<think>{THINK_FILLER}</think>\n\\boxed{{{x}}}"

# Ordered so ties resolve toward the simpler wrapper (raw first).
BASE_FORMATS = (
    ("raw",              _w_raw),
    ("boxed",            _w_boxed),
    ("xml_answer",       _w_xml_answer),
    ("think_xml_answer", _w_think_xml_answer),
    ("think_raw",        _w_think_raw),
    ("prose",            _w_prose),
    ("boxed_think",      _w_boxed_think),
)

# answer-ish field names inside a structured parser (the field that holds the
# actual answer, as opposed to reasoning/think scaffolding fields).
_ANSWER_FIELD_NAMES = ("answer", "ans", "final_answer", "result", "solution",
                       "output", "response", "code")


class DiscoveredFormat:
    """The winning completion format for an env, plus the audit trail.

    `wrap(x)` produces the conformant completion for any answer value `x` — the
    template is value-independent, so a format discovered on one row's gold is
    reused verbatim for every other row and every probe candidate.
    """

    __slots__ = ("name", "_fn", "gold_anchor_reward", "gold_passes", "per_format",
                 "source", "system_prompt_hints")

    def __init__(self, name, fn, gold_anchor_reward, gold_passes, per_format,
                 source="empirical", system_prompt_hints=None):
        self.name = name
        self._fn = fn
        self.gold_anchor_reward = gold_anchor_reward
        self.gold_passes = gold_passes
        self.per_format = per_format or []
        self.source = source
        self.system_prompt_hints = system_prompt_hints or []

    def wrap(self, value):
        try:
            return self._fn(str(value))
        except Exception:
            return f"{value}"

    def as_record(self):
        """Compact, JSON-serialisable summary for the battery records."""
        return {
            "format": self.name,
            "source": self.source,
            "gold_anchor_reward": self.gold_anchor_reward,
            "gold_passes": self.gold_passes,
            "system_prompt_hints": self.system_prompt_hints,
            "per_format_rewards": self.per_format,
        }


# ---------------------------------------------------------------------------
# PRIMARY: parser + system-prompt introspection (verifiers 0.2.0)
# ---------------------------------------------------------------------------

def _system_prompt_text(env):
    """Best-effort: the env's declared system prompt (where a format is often
    stated in words, e.g. 'put your final answer in \\boxed{}')."""
    for attr in ("system_prompt",):
        v = getattr(env, attr, None)
        if isinstance(v, str) and v.strip():
            return v
    # some envs stash it on the parser or dataset prompt
    parser = getattr(env, "parser", None)
    v = getattr(parser, "system_prompt", None)
    if isinstance(v, str) and v.strip():
        return v
    return ""


def _system_prompt_hints(text):
    """Format tokens declared in the system prompt (audit trail only; the
    empirical battery already covers every wrapper regardless)."""
    if not text:
        return []
    low = text.lower()
    hints = []
    if "\\boxed" in low or "boxed{" in low:
        hints.append("boxed")
    if "<answer>" in low:
        hints.append("xml_answer")
    if "<think>" in low or "think tag" in low or "reasoning" in low and "<think" in low:
        hints.append("think")
    return hints


def _parser_field_names(parser):
    """Extract the declared field names of an XMLParser-style parser.

    verifiers 0.2.0 XMLParser accepts `fields=["think", "answer"]` or
    `fields=[("answer", ["ans"])]` (canonical, [aliases]). We read the canonical
    names defensively — the parser API is not guaranteed, so every access is
    guarded and failure just means we fall back to the empirical battery."""
    fields = getattr(parser, "fields", None)
    names = []
    if not fields:
        return names
    try:
        for f in fields:
            if isinstance(f, (list, tuple)) and f:
                names.append(str(f[0]))
            else:
                names.append(str(f))
    except Exception:
        return []
    return names


def parser_derived_formats(env):
    """Build wrapper(s) from the env's OWN parser (verifiers 0.2.0).

    Returns a list of (name, wrap_fn). Best-effort and fully guarded: the parser
    API varies across verifiers point releases, so any failure yields fewer
    candidates, never an exception. The empirical selection confirms the winner
    regardless of whether this fires.
    """
    out = []
    parser = getattr(env, "parser", None)
    if parser is None:
        return out
    cls = type(parser).__name__

    # (1) If the parser exposes a `.format(**fields)` helper (XMLParser does),
    #     build a conformant string: the answer-ish field carries the gold, all
    #     other (reasoning) fields carry benign filler.
    names = _parser_field_names(parser)
    fmt = getattr(parser, "format", None)
    if names and callable(fmt):
        # choose which field holds the answer
        ans_idx = None
        for i, nm in enumerate(names):
            if nm.lower() in _ANSWER_FIELD_NAMES:
                ans_idx = i
                break
        if ans_idx is None:
            ans_idx = len(names) - 1  # convention: answer is the last field

        def _mk_parser_fmt(field_names, answer_index, format_fn):
            def _wrap(x):
                kwargs = {}
                for j, nm in enumerate(field_names):
                    kwargs[nm] = str(x) if j == answer_index else THINK_FILLER
                return format_fn(**kwargs)
            return _wrap

        out.append((f"parser_{cls}_format", _mk_parser_fmt(names, ans_idx, fmt)))

    # (2) XMLParser with known fields but no usable .format(): assemble tags by hand.
    if names and not any(n.startswith("parser_") for n, _ in out):
        def _mk_xml(field_names):
            ans_idx = len(field_names) - 1
            for i, nm in enumerate(field_names):
                if nm.lower() in _ANSWER_FIELD_NAMES:
                    ans_idx = i
                    break

            def _wrap(x):
                parts = []
                for j, nm in enumerate(field_names):
                    val = str(x) if j == ans_idx else THINK_FILLER
                    parts.append(f"<{nm}>{val}</{nm}>")
                return "\n".join(parts)
            return _wrap

        out.append((f"parser_{cls}_xml", _mk_xml(names)))

    # (3) ThinkParser / boxed Parser hints — these are already covered by the
    #     base battery (think_raw / boxed), but naming the parser-derived variant
    #     gives the audit trail a clearer provenance when it wins.
    low_cls = cls.lower()
    if "think" in low_cls:
        out.append((f"parser_{cls}_think", _w_think_raw))
    if "boxed" in low_cls or "math" in low_cls:
        out.append((f"parser_{cls}_boxed", _w_boxed))

    return out


# ---------------------------------------------------------------------------
# EMPIRICAL SELECTION
# ---------------------------------------------------------------------------

def discover_format(env, gold, score_completion, near_max=None):
    """Discover the env's passing completion FORMAT from the env itself.

    Args:
      env: the loaded environment (for parser / system-prompt introspection).
      gold: the reference answer string for the discovery row.
      score_completion: callable(text) -> reward (float) or None. MUST score the
        given completion text through the env's OWN `rubric.score_rollout`
        offline. This is the only channel this function uses — it never consults
        the oracle, so oracle independence (pre-reg §3) is preserved.
      near_max: optional known reward ceiling; unused for the pass decision
        (we treat any positive reward on the gold as passing) but recorded.

    Returns a DiscoveredFormat with:
      * name / wrap()          — the winning wrapper (maximizes gold reward)
      * gold_anchor_reward     — the reward that winner achieved on the gold
      * gold_passes            — True iff that reward is positive (verifier
                                  accepts its own gold under some format)
      * per_format             — [{format, reward, ...}] full audit trail
    """
    sys_text = _system_prompt_text(env)
    hints = _system_prompt_hints(sys_text)

    # candidate battery: parser-derived first (primary), then the env-agnostic base.
    candidates = []
    seen_names = set()
    try:
        for name, fn in parser_derived_formats(env):
            if name not in seen_names:
                candidates.append((name, fn, "parser"))
                seen_names.add(name)
    except Exception:
        pass
    for name, fn in BASE_FORMATS:
        if name not in seen_names:
            candidates.append((name, fn, "empirical"))
            seen_names.add(name)

    per_format = []
    best = None            # (reward, order_index, name, fn, source)
    seen_texts = {}
    for order, (name, fn, source) in enumerate(candidates):
        try:
            text = fn(str(gold))
        except Exception as e:  # noqa: BLE001
            per_format.append({"format": name, "source": source,
                               "reward": None, "error": f"wrap failed: {e!r}"})
            continue
        # dedupe identical produced strings (raw vs a no-op parser wrapper)
        if text in seen_texts:
            per_format.append({"format": name, "source": source,
                               "reward": seen_texts[text], "dup_of_text": True})
            continue
        try:
            reward = score_completion(text)
            if isinstance(reward, tuple):  # tolerate (reward, metrics)
                reward = reward[0]
        except Exception as e:  # noqa: BLE001
            per_format.append({"format": name, "source": source,
                               "reward": None, "error": f"score failed: {e!r}"})
            continue
        rnum = float(reward) if isinstance(reward, (int, float)) else None
        seen_texts[text] = rnum
        per_format.append({"format": name, "source": source, "reward": rnum,
                           "text_preview": text[:120]})
        if rnum is not None:
            key = (rnum, -order)  # higher reward wins; lower order breaks ties
            if best is None or key > (best[0], -best[1]):
                best = (rnum, order, name, fn, source)

    if best is None:
        # nothing scored numerically — cannot discover; fall back to raw, not passing.
        return DiscoveredFormat("raw", _w_raw, None, False, per_format,
                                source="fallback", system_prompt_hints=hints)

    reward, _order, name, fn, source = best
    gold_passes = reward > 0.0
    return DiscoveredFormat(name, fn, reward, gold_passes, per_format,
                            source=source, system_prompt_hints=hints)


# ---------------------------------------------------------------------------
# APPLICABILITY GATING (pre-reg §1 routing refinement; logged, never silent)
# ---------------------------------------------------------------------------

def classify_applicability(answer, info=None):
    """Is this env's answer a substitutable scalar/short-string we can vary?

    Returns (label, reason):
      * "substitutable"     — a scalar / short string; FAR applies (subject to
                              gold passing under a discovered format).
      * "non_substitutable" — the answer/info is a structured constraints/scenario
                              blob (dict / list / JSON) or empty; a wrong-answer
                              STRING doesn't map to the verifier. EXCLUDED from FAR,
                              reported with a reason (never a silent drop, never
                              gold_fail-spam).

    NOTE: `gold_reject` (substitutable but no format makes gold pass) is decided
    AFTER discovery by the caller, not here.
    """
    # native structured answer
    if isinstance(answer, (dict, list, tuple)):
        return "non_substitutable", f"answer is a structured {type(answer).__name__}"

    s = "" if answer is None else str(answer).strip()

    if s == "":
        if info:
            return "non_substitutable", "empty answer; constraints/scenario carried in `info`"
        return "non_substitutable", "empty answer and no info to vary"

    # JSON object / array serialised as a string (ifeval-style constraint blobs)
    if s[:1] in "{[":
        try:
            parsed = json.loads(s)
            if isinstance(parsed, (dict, list)):
                return "non_substitutable", "answer is a JSON dict/list constraints blob"
        except (ValueError, TypeError):
            pass

    return "substitutable", "scalar/short-string answer"


def resolve_applicability(applicability, gold_passes):
    """Fold the discovery result into the final applicability label.

    substitutable + gold passes under some format  -> "substitutable"
    substitutable + NO format makes gold pass       -> "gold_reject" (real defect)
    non_substitutable                               -> "non_substitutable"
    """
    if applicability == "non_substitutable":
        return "non_substitutable"
    if gold_passes:
        return "substitutable"
    return "gold_reject"
