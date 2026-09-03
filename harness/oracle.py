#!/usr/bin/env python3
"""Tripwire dual-gate oracle (pre-reg §3, methodology §1) — THE CRUX.

The oracle assigns the TRUE label (WRONG / CORRECT / AMBIGUOUS) to a candidate
answer via a channel that is INDEPENDENT of the environment's verifier. It never
consults the env's parser, matcher, or reward — only:

  * numeric channel: parse candidate and reference with OUR OWN numeric parser
    (strips $ , % and \\boxed{}/<answer> wrappers, understands simple word-
    numbers) and compare with tolerance; or
  * canonical-string channel: our own normalization (casefold, strip punctuation,
    collapse whitespace) and exact equality.

Dual-gate contract (a soundness failure is `verifier=PASS AND oracle=WRONG`):
  (a) `degenerate` probes are WRONG by construction (empty/whitespace/stub).
  (b) a known-wrong / format-only / substring variant is KEPT for FAR only if the
      oracle confirms it UNAMBIGUOUSLY WRONG; otherwise it drops to `ambiguous`
      and is EXCLUDED from FAR.
  (c) an FRR paraphrase is KEPT only if the oracle confirms it CORRECT
      (canonically equal to gold); otherwise dropped.
  (d) every verdict exposes the provenance tag AND which channel decided it, so a
      reviewer audits the label, not the verifier.
"""
import re
import string

WRONG = "WRONG"
CORRECT = "CORRECT"
AMBIGUOUS = "AMBIGUOUS"

NUM_TOL = 1e-9

_PUNCT_TABLE = str.maketrans("", "", string.punctuation)

# Provenance tags for the verifiable-answer judge known-wrong lane (mirrors the
# literals probes.py stamps; kept here so label_candidate can key on them).
P_MCQ_WRONG = "constructed-mcq-wrong"
P_ENTITY_WRONG = "constructed-entity-wrong"

# Function words that signal a DESCRIPTIVE phrase rather than a canonical short
# entity/name. Their presence pushes an answer to `open_ended` (conservative:
# we would rather under-count entity known-wrong FAR than falsely certify).
_STOPWORDS = {
    "the", "a", "an", "of", "is", "are", "was", "were", "be", "been", "being",
    "to", "in", "on", "at", "for", "and", "or", "by", "with", "as", "that",
    "this", "these", "those", "from", "into", "than", "then", "which", "who",
    "whom", "whose", "what", "when", "where", "why", "how", "it", "its", "if",
    "but", "not", "no", "do", "does", "did", "has", "have", "had", "will",
    "would", "should", "could", "may", "might", "can", "about", "over", "under",
}

# A bare MCQ option: an optional (/[ wrapper, a single A–J letter, an optional
# ). ] : . trailer. We cap at A–J so a stray single-letter entity is unlikely to
# be mistaken for an option.
_MCQ_LETTERS = "ABCDEFGHIJ"
_MCQ_RE = re.compile(r"^[\(\[\{]?\s*([A-Za-z])\s*[\)\]\}\.\:\,]?$")

_ONES = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
    "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16,
    "seventeen": 17, "eighteen": 18, "nineteen": 19,
}
_TENS = {
    "twenty": 20, "thirty": 30, "forty": 40, "fifty": 50, "sixty": 60,
    "seventy": 70, "eighty": 80, "ninety": 90,
}
_SCALES = {"hundred": 100, "thousand": 1000, "million": 1_000_000}


# ---------------------------------------------------------------------------
# our own normalizers (independent of any env parser)
# ---------------------------------------------------------------------------

def _strip_wrappers(s):
    """Remove common answer wrappers so a bare value can be compared. This is our
    own light unwrap, NOT the env's parser."""
    t = s.strip()
    # \boxed{...}
    m = re.search(r"\\boxed\s*\{([^{}]*)\}", t)
    if m:
        return m.group(1).strip()
    # <answer>...</answer>
    m = re.search(r"<answer>\s*(.*?)\s*</answer>", t, flags=re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()
    # "The answer is X" / "final answer: X"
    m = re.search(r"(?:the\s+)?(?:final\s+)?answer\s*(?:is|:)\s*(.+)$",
                  t, flags=re.IGNORECASE)
    if m:
        return m.group(1).strip().rstrip(".")
    return t


def words_to_num(s):
    """Best-effort English word-number -> int (0..~10^6). None if not a clean
    word-number. Handles 'seventy-two', 'one hundred five', etc."""
    toks = re.split(r"[\s\-]+", s.strip().lower())
    toks = [t for t in toks if t and t != "and"]
    if not toks or any(t not in _ONES and t not in _TENS and t not in _SCALES for t in toks):
        return None
    total = 0
    current = 0
    for t in toks:
        if t in _ONES:
            current += _ONES[t]
        elif t in _TENS:
            current += _TENS[t]
        elif t in _SCALES:
            scale = _SCALES[t]
            if scale == 100:
                current = (current or 1) * 100
            else:
                total += (current or 1) * scale
                current = 0
    return total + current


def parse_number(value):
    """Our own numeric parse. Returns float or None. The WHOLE cleaned string
    must be a number (or a clean word-number) — we deliberately do NOT fish a
    number out of prose (that's the env's job; doing so would couple us to it)."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    if not s:
        return None
    s = _strip_wrappers(s)
    cleaned = s.replace(",", "").replace("$", "").replace("%", "").strip()
    cleaned = cleaned.rstrip(".")
    # bare numeric (int/float/scientific/leading +-)
    try:
        return float(cleaned)
    except (TypeError, ValueError):
        pass
    # fraction a/b
    m = re.fullmatch(r"([+-]?\d+)\s*/\s*(\d+)", cleaned)
    if m:
        denom = float(m.group(2))
        if denom != 0:
            return float(m.group(1)) / denom
    # word-number
    w = words_to_num(cleaned)
    return float(w) if w is not None else None


def canonical_string(value):
    """Casefold, strip punctuation, collapse whitespace. Our own canonical form."""
    if value is None:
        return ""
    s = str(value)
    s = _strip_wrappers(s)
    s = s.casefold().translate(_PUNCT_TABLE)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def parse_mcq_letter(value):
    """Our own MCQ-option parse. Returns an upper-case option letter in A–J, or
    None. Understands bare/wrapped/trailing-punct forms ('C', '(C)', 'C.', '[b]')
    and 'the answer is C' via _strip_wrappers. This is a channel the verifier does
    NOT use — a structural letter comparison, independent of the env's matcher."""
    if value is None:
        return None
    s = _strip_wrappers(str(value)).strip()
    if not s:
        return None
    m = _MCQ_RE.match(s)
    if not m:
        return None
    letter = m.group(1).upper()
    return letter if letter in _MCQ_LETTERS else None


def classify_answer(reference):
    """Decide whether the dataset reference `answer` is a VERIFIABLE short
    ground-truth (an oracle-certifiable known-wrong candidate exists) or
    OPEN-ENDED (style/quality/preference target, long free text, empty — the
    oracle cannot certify any candidate unambiguously wrong).

    Returns one of: 'numeric' | 'mcq' | 'short_entity' | 'open_ended'.
    The first three are verifiable; 'open_ended' is not. The rule is deliberately
    conservative: ANY sign of a descriptive phrase (stop/function words, length)
    pushes to 'open_ended' so we under-count rather than falsely certify."""
    if reference is None:
        return "open_ended"
    if str(reference).strip() == "":
        return "open_ended"
    if parse_number(reference) is not None:
        return "numeric"
    if parse_mcq_letter(reference) is not None:
        return "mcq"
    c = canonical_string(reference)
    if not c:
        return "open_ended"
    toks = c.split()
    if len(toks) <= 5 and not any(t in _STOPWORDS for t in toks):
        return "short_entity"
    return "open_ended"


def is_verifiable(reference):
    """True iff a plain wrong-but-plausible candidate CAN be oracle-certified
    wrong for this reference (numeric / MCQ / short canonical entity)."""
    return classify_answer(reference) in ("numeric", "mcq", "short_entity")


def _paraphrase_risk(cand_c, ref_c):
    """Conservative paraphrase/equivalence guard for the short-entity channel.
    Returns True when a canonically-unequal candidate could still be a paraphrase
    or a sub/superstring of the reference (e.g. 'myocardial infarction' vs
    'acute myocardial infarction') — in which case the oracle must NOT certify it
    wrong. String- and token-level containment + high token overlap all trip it."""
    if not cand_c or not ref_c:
        return False
    if cand_c == ref_c:
        return True
    if cand_c in ref_c or ref_c in cand_c:
        return True
    ct, rt = set(cand_c.split()), set(ref_c.split())
    if not ct or not rt:
        return False
    if ct <= rt or rt <= ct:          # one token set contained in the other
        return True
    inter, union = ct & rt, ct | rt
    return bool(union) and (len(inter) / len(union)) >= 0.5


# ---------------------------------------------------------------------------
# the oracle
# ---------------------------------------------------------------------------

class OracleVerdict(dict):
    """Structured verdict: true_label, channel, provenance, reason, plus previews."""
    @property
    def label(self):
        return self["true_label"]


def label_candidate(candidate, reference, provenance):
    """Assign the TRUE label of `candidate` vs the dataset reference `answer`.

    Never consults the verifier. Returns an OracleVerdict. `provenance` is the
    probe's provenance tag (`degenerate`, `constructed-numeric-wrong`,
    `reference-answer`, `oracle-label`, `held-out-test`)."""
    v = OracleVerdict({
        "provenance": provenance,
        "reference": str(reference),
        "candidate_preview": (str(candidate)[:120] if candidate is not None else ""),
    })

    # (a) degenerate is WRONG by construction, zero ambiguity
    if provenance == "degenerate":
        v.update(true_label=WRONG, channel="by-construction",
                 reason="degenerate/stub output is wrong by construction")
        return v

    cand_num = parse_number(candidate)
    ref_num = parse_number(reference)

    # numeric channel — when BOTH sides parse as numbers under our parser
    if cand_num is not None and ref_num is not None:
        equal = abs(cand_num - ref_num) <= NUM_TOL * max(1.0, abs(ref_num))
        v.update(
            true_label=(CORRECT if equal else WRONG),
            channel="numeric",
            reason=f"numeric compare: candidate={cand_num!r} vs reference={ref_num!r}",
            candidate_value=cand_num, reference_value=ref_num,
        )
        return v

    # MCQ-letter channel — fires only when BOTH sides parse as option letters, so
    # it is inert for the binary lane (whose wrong candidates aren't bare letters)
    # and for open-ended text. Options are mutually exclusive: a different letter
    # is UNAMBIGUOUSLY wrong, a structural comparison the verifier never performs.
    ref_mcq = parse_mcq_letter(reference)
    cand_mcq = parse_mcq_letter(candidate)
    if ref_mcq is not None and cand_mcq is not None:
        equal = (cand_mcq == ref_mcq)
        v.update(true_label=(CORRECT if equal else WRONG), channel="mcq-letter",
                 reason=f"mcq letter compare: candidate={cand_mcq!r} vs reference={ref_mcq!r}",
                 candidate_value=cand_mcq, reference_value=ref_mcq)
        return v

    # canonical-string channel
    cand_c = canonical_string(candidate)
    ref_c = canonical_string(reference)
    if not ref_c:
        # no usable reference to compare against -> cannot sign off either way
        v.update(true_label=AMBIGUOUS, channel="canonical-string",
                 reason="empty/absent reference under canonical normalization")
        return v
    if cand_c == ref_c:
        v.update(true_label=CORRECT, channel="canonical-string",
                 reason="canonically equal to reference")
        return v
    if not cand_c:
        # candidate collapses to empty but wasn't tagged degenerate
        v.update(true_label=WRONG, channel="canonical-string",
                 reason="candidate empty under canonical normalization")
        return v

    # short-entity distractor: a constructed different entity of the SAME type.
    # Certify WRONG only when it is canonically disjoint from the reference; if it
    # could be a paraphrase/sub-superstring, stay AMBIGUOUS (conservative — never
    # falsely flag a semantically-equivalent answer). pre-reg §3.
    if provenance == P_ENTITY_WRONG:
        if _paraphrase_risk(cand_c, ref_c):
            v.update(true_label=AMBIGUOUS, channel="canonical-string",
                     reason="entity distractor shares tokens/substring with reference "
                            "-> possible paraphrase, cannot certify wrong")
        else:
            v.update(true_label=WRONG, channel="canonical-string",
                     reason="constructed entity distractor canonically disjoint from reference")
        return v

    # canonically-unequal strings. For a CONSTRUCTED wrong (we built it), the
    # inequality is a confident WRONG. For anything else (free-text reference)
    # inequality alone can be a paraphrase -> AMBIGUOUS, excluded from FAR.
    if provenance in ("constructed-numeric-wrong", "constructed-mcq-wrong",
                      "oracle-label", "held-out-test"):
        v.update(true_label=WRONG, channel="canonical-string",
                 reason="constructed variant canonically unequal to reference")
        return v
    v.update(true_label=AMBIGUOUS, channel="canonical-string",
             reason="canonically unequal but cannot rule out paraphrase/equivalence")
    return v


def screen(probe, reference):
    """Screen a probe candidate through the oracle and route it.

    `probe` is a Probe(probe_type, candidate_text, intended_oracle_label,
    provenance_tag) (from probes.py) or any object/tuple with those fields.

    Returns (verdict, keep, bucket):
      bucket in {'far', 'frr', 'ambiguous'}.
      keep == (bucket != 'ambiguous'): only kept probes are scored & counted.
        * far  : oracle-confirmed WRONG (degenerate, known-wrong, format-only,
                 substring-accept, injection) -> feeds FAR/RHS.
        * frr  : oracle-confirmed CORRECT paraphrase -> feeds FRR.
        * ambiguous: oracle could not sign off (intended-wrong that isn't
                 confirmably wrong, or intended-correct that isn't confirmably
                 correct) -> EXCLUDED from FAR, rate reported separately.
    """
    candidate = _probe_field(probe, "candidate_text", 1)
    provenance = _probe_field(probe, "provenance_tag", 3)
    intended = _probe_field(probe, "intended_oracle_label", 2)

    verdict = label_candidate(candidate, reference, provenance)
    tl = verdict["true_label"]

    if intended == CORRECT:
        # FRR paraphrase: keep only if oracle confirms CORRECT
        if tl == CORRECT:
            return verdict, True, "frr"
        return verdict, False, "ambiguous"

    # intended WRONG: keep for FAR only if oracle confirms WRONG
    if tl == WRONG:
        return verdict, True, "far"
    return verdict, False, "ambiguous"


def _probe_field(probe, name, idx):
    if isinstance(probe, dict):
        return probe.get(name)
    if hasattr(probe, name):
        return getattr(probe, name)
    try:
        return probe[idx]
    except (TypeError, IndexError, KeyError):
        return None
