"""The agent trace, and the claim it is not allowed to make.

A trace exists so a reader can tell model-authored output from the engine's own
deterministic work. The failure that matters is therefore not a missing step. It
is a trace that says a model answered when none did -- which is exactly the
state this deployment sat in for weeks, serving fallbacks against a placeholder
API key with nothing on screen to say so.
"""

from __future__ import annotations

import pytest

from src.advisory import trace as T


def test_nothing_is_recorded_outside_a_capture_block():
    """The collector is opt-in. The engine's own hot paths call `complete()`
    too, and instrumenting them by default would put prompts on every code
    path that has never asked for one."""
    assert T.current() is None
    T.record_model_call(provider="ollama", model="m", system="s", user="u",
                        response="r", ok=True, error=None, ms=1)
    # No collector, no crash, nothing kept.
    assert T.current() is None


def test_a_capture_collects_model_calls_with_both_sides_of_the_exchange():
    with T.capture() as tr:
        T.record_model_call(provider="ollama", model="qwen", system="SYS", user="USR",
                            response="OUT", ok=True, error=None, ms=42,
                            prompt_tokens=11, completion_tokens=7, capability="remediate")
    (step,) = tr.steps
    assert step.kind == "model_call"
    assert (step.system, step.user, step.response) == ("SYS", "USR", "OUT")
    assert step.provider == "ollama" and step.model == "qwen"
    assert step.ms == 42 and step.prompt_tokens == 11 and step.completion_tokens == 7
    assert "remediate" in step.label


def test_a_failed_call_is_a_step_and_does_not_count_as_a_model_answer():
    """THE RULE THIS MODULE EXISTS FOR.

    A 401 followed by a deterministic fallback must appear in the trace AND
    must not let the console badge the output as model-authored. Both halves
    are asserted together because either one alone is the bug.
    """
    with T.capture() as tr:
        T.record_model_call(provider="openai", model="gpt-4o", system="s", user="u",
                            response="", ok=False, error="AuthenticationError: 401", ms=120)
        tr.note("fallback", "writing it deterministically instead", ok=False)

    assert len(tr.steps) == 2, "the failed call must be kept, not dropped"
    assert tr.model_calls == 1
    assert tr.used_a_model is False
    assert tr.steps[0].error and "401" in tr.steps[0].error
    assert tr.steps[0].detail == "AuthenticationError: 401", "the reason must be readable collapsed"


def test_one_successful_call_among_failures_does_count():
    with T.capture() as tr:
        T.record_model_call(provider="openai", model="x", system="s", user="u",
                            response="", ok=False, error="401", ms=1)
        T.record_model_call(provider="ollama", model="y", system="s", user="u",
                            response="text", ok=True, error=None, ms=900)
    assert tr.used_a_model is True
    assert tr.model_calls == 2


def test_a_step_that_raises_is_recorded_before_the_exception_propagates():
    """A tool that threw is the step a reader most needs; the alternative is a
    trace that simply stops mid-way with no explanation."""
    with T.capture() as tr:
        with pytest.raises(ValueError):
            with tr.step("tool", "re-analyse the estate"):
                raise ValueError("boom")
    (step,) = tr.steps
    assert step.kind == "tool" and step.ok is False
    assert step.error and "boom" in step.error
    assert step.ms is not None, "a failed step is still timed"


def test_oversized_payloads_are_cut_and_say_so():
    """A 500-rule paste is a legitimate prompt and a terrible thing to put
    through an API response. Cut, and MARKED cut -- a silently truncated prompt
    shown as the prompt is a lie about what was sent."""
    big = "x" * (T.MAX_TEXT + 500)
    with T.capture() as tr:
        T.record_model_call(provider="ollama", model="m", system="s", user=big,
                            response="r", ok=True, error=None, ms=1)
    (step,) = tr.steps
    assert len(step.user) == T.MAX_TEXT
    assert step.truncated is True


def test_captures_do_not_leak_into_each_other():
    """Nested captures stay independent, so a capability that calls another
    cannot silently absorb its trace and report it as its own work."""
    with T.capture() as outer:
        T.record_model_call(provider="a", model="1", system="s", user="u",
                            response="r", ok=True, error=None, ms=1)
        with T.capture() as inner:
            T.record_model_call(provider="b", model="2", system="s", user="u",
                                response="r", ok=True, error=None, ms=1)
        T.record_model_call(provider="c", model="3", system="s", user="u",
                            response="r", ok=True, error=None, ms=1)

    assert [s.provider for s in outer.steps] == ["a", "c"]
    assert [s.provider for s in inner.steps] == ["b"]


def test_the_serialised_form_drops_empty_keys_but_keeps_a_failure():
    """`as_list` is what reaches the browser. A step's absent fields are omitted
    to keep the payload small -- but `ok: False` must survive, since the whole
    UI branches on it."""
    with T.capture() as tr:
        tr.note("note", "plain step")
        tr.note("fallback", "it failed", ok=False)
    plain, failed = tr.as_list()
    assert "provider" not in plain and "system" not in plain
    assert failed["ok"] is False


def test_draft_attaches_a_trace_naming_every_tool_run(monkeypatch):
    """The end-to-end shape the console consumes: a remediation trace contains
    the model call, the deduction it produced, and the RE-ANALYSIS that judged
    it -- so a reader can see the loop rather than only its verdict."""
    import app.main as main
    from src.advisory import remediation as R

    result = main.engine()
    finding = next(f for f in result.findings
                   if f.type == "over_permissive" and f.forced_critical)
    out = R.draft(finding, result, max_attempts=1)

    assert "agent_trace" in out and "used_a_model" in out
    kinds = [s["kind"] for s in out["agent_trace"]]
    assert "model_call" in kinds or "fallback" in kinds, \
        "a draft either called a model or recorded why it did not"
    # The engine's own re-analysis is a tool step, present on every path that
    # produced a change -- that is the step proving the verdict was measured.
    assert "tool" in kinds
    for step in out["agent_trace"]:
        assert step["label"], "every step must be readable without expanding it"
