"""What the agent actually did, captured as it happens.

The console could already show WHAT the advisory layer concluded and, per
attempt, whether the engine accepted it. What it could not show was the work:
which provider answered, on which model, how long it took, what was sent, and
what came back. That gap is not cosmetic. For most of this build every model
call was 401ing against a placeholder key and every capability was silently
serving its deterministic fallback -- correct behaviour, invisible behaviour,
and indistinguishable on screen from a model that had answered. A trace would
have shown it in one glance.

So every step goes on the record, and a FALLBACK IS A STEP. The point is not to
advertise that a model was used; it is to let a reader see exactly where the
answer came from, including when the answer came from nowhere near a model.

SCOPE, not plumbing. `capture()` opens a collector in a context variable and
`complete()` appends to whatever collector is active, so instrumenting a
capability means wrapping its entry point rather than threading a recorder
through every call site. Nothing outside a `capture()` block records anything,
which keeps the engine's own hot paths untouched.

WHAT IS STORED, and the one thing that is not. The system prompt, the user
prompt and the raw response text are kept verbatim: "see what was sent vs what
we got back" is the whole point, and a summary of a prompt is not a prompt. They
are the operator's own policy data, which they are already looking at. Provider
credentials never appear -- they travel in client headers, not in prompts -- and
this module never reads settings.
"""

from __future__ import annotations

import contextvars
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator, Literal

#: A step's kind. `model_call` is emitted by `client.complete`; the rest are
#: emitted by the capability itself to say what it did around the call.
StepKind = Literal["model_call", "tool", "deduction", "fallback", "note"]

#: Hard cap on a single captured payload. A 500-rule paste into the connector
#: authoring box is a legitimate prompt and a terrible thing to put through an
#: API response and into a browser; past this the text is cut and marked.
MAX_TEXT = 12_000


def _clip(s: str | None) -> tuple[str | None, bool]:
    if s is None:
        return None, False
    if len(s) <= MAX_TEXT:
        return s, False
    return s[:MAX_TEXT], True


@dataclass
class Step:
    kind: StepKind
    label: str
    #: One line of detail, safe to show collapsed.
    detail: str | None = None
    ok: bool = True
    ms: int | None = None
    #: `model_call` only.
    provider: str | None = None
    model: str | None = None
    system: str | None = None
    user: str | None = None
    response: str | None = None
    error: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    truncated: bool = False

    #: Never dropped by `as_dict`, whatever their value.
    #
    #: `ok` is the one that matters and it was the bug: filtering falsy values
    #: removed `ok: False` from the payload, so the browser read `undefined`,
    #: compared it against `false`, and drew a FAILED model call as a
    #: successful one. That is precisely the confusion this whole record exists
    #: to end, reintroduced by an over-eager payload trim.
    _ALWAYS = ("kind", "label", "ok")

    def as_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()
                if k in self._ALWAYS or (v is not None and v is not False)}


@dataclass
class Trace:
    steps: list[Step] = field(default_factory=list)

    def add(self, step: Step) -> None:
        self.steps.append(step)

    def note(self, kind: StepKind, label: str, detail: str | None = None, *,
             ok: bool = True, ms: int | None = None) -> None:
        """Record a non-model step: a tool run, a deduction, a fallback taken."""
        self.add(Step(kind=kind, label=label, detail=detail, ok=ok, ms=ms))

    @contextmanager
    def step(self, kind: StepKind, label: str, detail: str | None = None) -> Iterator[None]:
        """Time a block and record it, whether or not it raised.

        The failure case is the one worth having: a tool that threw is a step a
        reader needs to see, and the alternative is a trace that simply stops.
        """
        t0 = time.perf_counter()
        try:
            yield
        except Exception as exc:  # noqa: BLE001 — recorded, then re-raised
            self.add(Step(kind=kind, label=label, detail=detail, ok=False,
                          ms=round((time.perf_counter() - t0) * 1000),
                          error=f"{type(exc).__name__}: {exc}"[:400]))
            raise
        self.add(Step(kind=kind, label=label, detail=detail,
                      ms=round((time.perf_counter() - t0) * 1000)))

    def as_list(self) -> list[dict[str, Any]]:
        return [s.as_dict() for s in self.steps]

    @property
    def model_calls(self) -> int:
        return sum(1 for s in self.steps if s.kind == "model_call")

    @property
    def used_a_model(self) -> bool:
        """True only if a model call actually SUCCEEDED. A failed call plus a
        deterministic fallback is not model-authored output, and the badge the
        console draws from this must not say it was."""
        return any(s.kind == "model_call" and s.ok for s in self.steps)


_CURRENT: contextvars.ContextVar[Trace | None] = contextvars.ContextVar("npr_trace", default=None)


@contextmanager
def capture() -> Iterator[Trace]:
    """Collect every step recorded inside this block.

    Nested captures are deliberately independent: the inner block's steps go to
    the inner trace only, so a capability that calls another does not silently
    absorb its trace. Nothing has needed nesting yet; this is what it does if it
    ever does.
    """
    tr = Trace()
    token = _CURRENT.set(tr)
    try:
        yield tr
    finally:
        _CURRENT.reset(token)


def current() -> Trace | None:
    """The active collector, or None outside a `capture()` block."""
    return _CURRENT.get()


def record_model_call(*, provider: str, model: str, system: str, user: str,
                      response: str, ok: bool, error: str | None, ms: int,
                      prompt_tokens: int | None = None,
                      completion_tokens: int | None = None,
                      capability: str | None = None) -> None:
    """Called by `client.complete` for every attempt. A no-op when nothing is
    capturing, which is every code path that has not opted in."""
    tr = _CURRENT.get()
    if tr is None:
        return
    sys_t, c1 = _clip(system)
    usr_t, c2 = _clip(user)
    rsp_t, c3 = _clip(response)
    tr.add(Step(
        kind="model_call",
        label=f"{provider} · {model}" + (f" · {capability}" if capability else ""),
        detail=None if ok else (error or "the call did not produce a usable answer"),
        ok=ok, ms=ms, provider=provider, model=model,
        system=sys_t, user=usr_t, response=rsp_t, error=error,
        prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
        truncated=c1 or c2 or c3,
    ))
