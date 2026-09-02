"""Verifier-type taxonomy and routing (pre-registration §1).

Every env is classified into exactly one bucket — binary / soft / llm_judge /
sandbox / unknown — BEFORE any FAR is computed, and the bucket decides which
metric the env is scored under. The hard rule under test: **a soft grader is
NEVER subjected to binary FAR**, because binary FAR on a partial-credit reward
is a category error.

The fakes below stand in for a loaded `verifiers` env. Classification is pure
introspection, so no env package, network or API key is needed.
"""
from __future__ import annotations

import pytest

import classify as C


# --------------------------------------------------------------------------- #
# Minimal stand-ins for a loaded env / rubric
# --------------------------------------------------------------------------- #
def exact_match_reward(completion, answer):
    return 1.0 if completion.strip() == answer.strip() else 0.0


def numeric_close_reward(completion, answer):
    return 1.0 if completion == answer else 0.0


def num_turns(state):
    return len(state)


def ask_the_model_to_score(completion, answer):
    # source mentions an LLM client, which is itself a routing signal
    return _client.chat.completions.create(model="x")  # noqa: F821


def run_in_a_container(completion):
    # source mentions code execution, which routes the env to the sandbox bucket
    return _sandbox.run_code(completion)  # noqa: F821


class Rubric:
    def __init__(self, funcs, weights=None):
        self.reward_funcs = list(funcs)
        self.reward_weights = list(weights) if weights is not None else [1.0] * len(funcs)


class RubricGroup:
    def __init__(self, rubrics, weights=None):
        self.rubrics = list(rubrics)
        self.weights = list(weights) if weights is not None else None


class JudgeRubric(Rubric):
    pass


class Env:
    def __init__(self, rubric):
        self.rubric = rubric


class SandboxEnv(Env):
    pass


class SingleTurnEnv(Env):
    pass


# --------------------------------------------------------------------------- #
# Static routing — priority judge > sandbox > binary/soft > unknown
# --------------------------------------------------------------------------- #
def test_deterministic_answer_match_rubric_is_provisionally_binary():
    rec = C.classify_static(SingleTurnEnv(Rubric([exact_match_reward])))
    assert rec["bucket"] == "binary"
    assert rec["reward_func_names"] == ["exact_match_reward"]


def test_judge_rubric_class_routes_to_llm_judge():
    rec = C.classify_static(SingleTurnEnv(JudgeRubric([exact_match_reward])))
    assert rec["bucket"] == "llm_judge"
    assert rec["static_signals"]["judge_by_class"] is True


def test_reward_function_calling_an_llm_client_routes_to_llm_judge():
    rec = C.classify_static(SingleTurnEnv(Rubric([ask_the_model_to_score])))
    assert rec["bucket"] == "llm_judge"
    assert rec["static_signals"]["judge_by_source"] is True


def test_sandbox_env_class_routes_to_sandbox():
    rec = C.classify_static(SandboxEnv(Rubric([exact_match_reward])))
    assert rec["bucket"] == "sandbox"
    assert rec["static_signals"]["sandbox_by_env"] is True


def test_code_executing_reward_function_routes_to_sandbox():
    rec = C.classify_static(SingleTurnEnv(Rubric([run_in_a_container])))
    assert rec["bucket"] == "sandbox"


def test_judge_signal_outranks_the_sandbox_signal():
    """Routing is a priority order, not a set: an env that trips both must land
    in exactly one bucket, and llm_judge wins."""
    rec = C.classify_static(SandboxEnv(JudgeRubric([exact_match_reward])))
    assert rec["bucket"] == "llm_judge"


def test_env_without_a_rubric_is_unknown_never_silently_dropped():
    rec = C.classify_static(SingleTurnEnv(None))
    assert rec["bucket"] == "unknown"
    assert any("no rubric" in e for e in rec["evidence"])


# --------------------------------------------------------------------------- #
# Weight-0 monitor funcs are excluded from the verdict (pre-reg §1)
# --------------------------------------------------------------------------- #
def test_weight_zero_monitor_func_is_excluded_from_the_verdict():
    rubric = Rubric([exact_match_reward, num_turns], weights=[1.0, 0.0])
    rec = C.classify_static(SingleTurnEnv(rubric))
    assert rec["reward_func_names"] == ["exact_match_reward"]
    assert rec["monitor_func_names"] == ["num_turns"]


def test_num_turns_is_a_monitor_even_when_it_carries_a_weight():
    rubric = Rubric([exact_match_reward, num_turns], weights=[1.0, 1.0])
    rec = C.classify_static(SingleTurnEnv(rubric))
    assert rec["monitor_func_names"] == ["num_turns"]


def test_rubric_group_is_flattened_and_group_weights_multiply_through():
    group = RubricGroup([Rubric([exact_match_reward]), Rubric([numeric_close_reward])],
                        weights=[1.0, 0.5])
    rec = C.classify_static(SingleTurnEnv(group))
    assert rec["weights"] == [("exact_match_reward", 1.0), ("numeric_close_reward", 0.5)]


def test_a_group_member_zeroed_by_its_group_weight_becomes_a_monitor():
    group = RubricGroup([Rubric([exact_match_reward]), Rubric([numeric_close_reward])],
                        weights=[1.0, 0.0])
    rec = C.classify_static(SingleTurnEnv(group))
    assert rec["reward_func_names"] == ["exact_match_reward"]
    assert rec["monitor_func_names"] == ["numeric_close_reward"]


# --------------------------------------------------------------------------- #
# The empirical half: binary -> soft on observed partial credit (pre-reg §1)
# --------------------------------------------------------------------------- #
def test_all_or_nothing_rewards_stay_binary():
    bucket, detail = C.finalize_binary_soft("binary", [0.0, 1.0, 0.0, 1.0, 0.0])
    assert bucket == "binary"
    assert "floor or max" in detail["reason"]


def test_partial_credit_on_a_wrong_answer_flips_binary_to_soft():
    """The registered example: a wrong number scoring 0.457 is partial credit,
    so the env is a soft grader and leaves the binary FAR lane."""
    bucket, detail = C.finalize_binary_soft("binary", [0.0, 1.0, 0.457])
    assert bucket == "soft"
    assert 0.457 in detail["partial_examples"]


def test_a_reward_at_the_max_is_not_partial_credit():
    bucket, _ = C.finalize_binary_soft("binary", [0.0, 0.5, 0.5])
    assert bucket == "binary", "0.5 is the observed max here, not partial credit"


def test_finalization_never_touches_judge_or_sandbox_buckets():
    for bucket in ("llm_judge", "sandbox", "unknown"):
        final, detail = C.finalize_binary_soft(bucket, [0.0, 0.457, 1.0])
        assert final == bucket
        assert "not subject to" in detail["reason"]


def test_no_observed_rewards_keeps_the_provisional_bucket():
    final, detail = C.finalize_binary_soft("binary", [])
    assert final == "binary"
    assert detail["n_rewards"] == 0


def test_classify_applies_the_empirical_flip_end_to_end():
    env = SingleTurnEnv(Rubric([exact_match_reward]))
    assert C.classify(env, observed_rewards=[0.0, 1.0])["bucket"] == "binary"
    rec = C.classify(env, observed_rewards=[0.0, 0.457, 1.0])
    assert rec["bucket"] == "soft"
    assert rec["static_bucket"] == "binary", "the provisional bucket stays on the record"


@pytest.mark.parametrize("rewards", [[0.0, 1.0], [0.0, 0.457, 1.0]])
def test_final_bucket_is_always_exactly_one_of_the_five(rewards):
    rec = C.classify(SingleTurnEnv(Rubric([exact_match_reward])), observed_rewards=rewards)
    assert rec["bucket"] in {"binary", "soft", "llm_judge", "sandbox", "unknown"}
