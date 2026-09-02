"""No path in the backend may degrade the answer without saying so.

The audit's sixth blocker was not "there are bugs in the error handling" -- it
was that the error handling had no OUTPUT. 29 `except Exception: pass/return []`
across ~6,500 lines with zero logging statements, so the product's failure modes
and its empty states were the same pixels:

    "a transient DB error makes the engine silently recompute WITHOUT confirmed
    merges or pushed changes and then persists that as authoritative, while the
    dashboard reads '0 critical'. When a user reports 'the findings disappeared'
    there is no log, no metric, no request id to investigate with."

This file pins the invariant from both ends, because either half alone rots:

  * STRUCTURALLY (`_silent_handlers`): an AST scan of `backend/src` and
    `backend/app` for a broad `except` that neither logs, re-raises, nor carries
    the failure into a value. A grep would miss a reformatted handler and would
    fire on every legitimate narrow guard; the AST does neither.
  * BEHAVIOURALLY: the paths this workstream changed are FORCED to fail and the
    log line is asserted -- name, level and event -- along with the caller-facing
    difference between "nothing found" and "we could not look". Asserting on
    source text proves a string exists; asserting on `caplog` proves an operator
    would actually have something to read at 03:00.

WHY THE SCANNER'S RULE IS THE RULE IT IS
----------------------------------------
It flags a handler when ALL of the following hold:

  1. the handler is BROAD -- bare `except:`, `except Exception`,
     `except BaseException`, or a tuple containing one. Narrow handlers are
     exempt on purpose: `except ValueError: pass` around `ipaddress.ip_address`
     is not a swallowed failure, it is a type test written as control flow
     (`identity.canonical_ip`, `netaddr.parse_net`, `client.parse_json`), and a
     rule that fired on those would be turned off within a week;
  2. no logging call anywhere in the handler body;
  3. no `raise` -- a handler that translates and re-raises has not hidden
     anything;
  4. no reference to the bound exception (`except X as e` where `e` is never
     read). This is the "carries the failure into the value" escape hatch:
     `agent.tools.dispatch` answers `{"error": f"{type(e).__name__}: {e}"}`, and
     the model reads that error and reacts to it. A failure that reaches the
     caller as data is not silent -- which is also why `except Exception:` with
     no `as` clause can never satisfy this clause and must log or re-raise.

Run against the pre-remediation tree the rule finds exactly the handlers the
audit counted, and `test_the_scanner_fires_on_the_real_pre_remediation_handlers`
keeps a verbatim copy of four of them so the scanner cannot quietly stop
matching -- a source scanner that reports green forever is worse than none.

No database, no network: the DB-touching tests patch the connection helper.
"""

from __future__ import annotations

import ast
import json
import logging
import types
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from src import identity, metrics, scenarios, settings as settings_mod
from src.advisory import client as llm
from src.agent import assistant
from src.change import apply as overlay
from src.models import PolicyRecord
from src.normalizers.common import ObservedEntity

# Captured at IMPORT time, which is before conftest's autouse `_offline` fixture
# rebinds them to offline stubs. These two functions are the SUBJECT of tests
# below, so those tests have to hold the real ones rather than the stubs;
# `test_the_offline_stubs_are_in_place_and_this_module_holds_the_real_functions`
# asserts the capture actually happened rather than trusting the ordering.
_REAL_OLLAMA_PROBE = settings_mod.ollama_probe
_REAL_RECORD_METRIC = metrics.record_metric

BACKEND = Path(__file__).resolve().parents[1]
SCANNED_DIRS = ("src", "app")

# Logging methods a handler can use to break its silence. `log` is included for
# `logger.log(level, ...)`; `warn` because the stdlib alias still exists.
LOG_METHODS = frozenset({"debug", "info", "warning", "warn", "error",
                         "exception", "critical", "fatal", "log"})

# Files allowed to hold a silent broad handler, each with the reason it is one.
# EMPTY, and meant to stay empty: this is a subset check, so another workstream
# fixing its file keeps the suite green, while ADDING a swallowed failure fails
# it. An entry here is a decision somebody has to write down, not a comment in a
# module nobody re-reads.
KNOWN_SILENT: dict[str, str] = {}


# ---------------------------------------------------------------------------
# The structural scanner
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    source: str

    def __str__(self) -> str:                     # what the failure message prints
        return f"{self.path}:{self.line}: {self.source}"


def _is_broad(handler: ast.ExceptHandler) -> bool:
    """`except:`, `except Exception`, `except BaseException`, or a tuple with one."""
    node = handler.type
    if node is None:
        return True                               # a bare `except:` catches everything
    candidates = list(node.elts) if isinstance(node, ast.Tuple) else [node]
    for c in candidates:
        # `Exception` and `builtins.Exception` are the same catch; match on the
        # trailing name so an aliased import cannot slip past.
        name = c.id if isinstance(c, ast.Name) else c.attr if isinstance(c, ast.Attribute) else None
        if name in ("Exception", "BaseException"):
            return True
    return False


def _handler_speaks(handler: ast.ExceptHandler) -> bool:
    """Does this handler log, re-raise, or carry the failure into a value?"""
    body = ast.Module(body=list(handler.body), type_ignores=[])
    for node in ast.walk(body):
        if isinstance(node, ast.Raise):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in LOG_METHODS:
            return True
        if handler.name and isinstance(node, ast.Name) and node.id == handler.name:
            return True
    return False


def _silent_handlers(source: str, path: str = "<memory>") -> list[Violation]:
    """Every broad exception handler in `source` that says nothing at all."""
    tree = ast.parse(source, filename=path)
    lines = source.splitlines()
    out: list[Violation] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if not _is_broad(node) or _handler_speaks(node):
            continue
        text = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
        out.append(Violation(path=path, line=node.lineno, source=text))
    return sorted(out, key=lambda v: (v.path, v.line))


def _scan_backend() -> list[Violation]:
    out: list[Violation] = []
    for d in SCANNED_DIRS:
        for p in sorted((BACKEND / d).rglob("*.py")):
            if "__pycache__" in p.parts:
                continue
            rel = p.relative_to(BACKEND).as_posix()
            out.extend(_silent_handlers(p.read_text(encoding="utf-8"), rel))
    return out


# ---------------------------------------------------------------------------
# 1. The scanner's own tests. A scanner that never fires is worse than none.
# ---------------------------------------------------------------------------

def test_the_scanner_fires_on_every_shape_of_swallowed_failure() -> None:
    planted = (
        "try:\n    a()\nexcept Exception:\n    pass\n"                       # 3
        "try:\n    b()\nexcept Exception:\n    return []\n"                  # 7
        "try:\n    c()\nexcept Exception:\n    return None\n"                # 11
        "try:\n    d()\nexcept:\n    pass\n"                                 # 15
        "try:\n    e()\nexcept BaseException:\n    return {}\n"              # 19
        "try:\n    f()\nexcept (ValueError, Exception):\n    continue\n"     # 23
        "try:\n    g()\nexcept builtins.Exception:\n    pass\n"              # 27
        "try:\n    h()\nexcept Exception as exc:\n    return []\n"           # 31 (exc unused)
        # reformatted onto several lines: a grep for `except Exception: pass`
        # would miss this, which is the whole reason the scan is an AST walk.
        "try:\n    i()\nexcept Exception:\n    x = 1\n    y = 2\n    return []\n"   # 35
    )
    assert [v.line for v in _silent_handlers(planted)] == [3, 7, 11, 15, 19, 23, 27, 31, 35]


def test_the_scanner_leaves_handlers_that_actually_speak_alone() -> None:
    """The four escapes, one per clause of the rule in the module docstring."""
    allowed = (
        # 1. narrow: a type test written as control flow, not a swallowed failure
        "try:\n    a()\nexcept ValueError:\n    pass\n"
        "try:\n    a()\nexcept (ValueError, TypeError):\n    return None\n"
        "try:\n    a()\nexcept httpx.HTTPError:\n    continue\n"
        # 2. logs
        "try:\n    b()\nexcept Exception:\n    log.warning('x', extra={'event': 'y'})\n"
        "try:\n    b()\nexcept Exception:\n    logger.exception('x')\n"
        "try:\n    b()\nexcept Exception:\n    logging.error('x')\n"
        # 3. re-raises (a translated error is not a hidden one)
        "try:\n    c()\nexcept Exception:\n    raise HTTPException(422, 'nope')\n"
        # 4. carries the failure into the value the caller reads
        "try:\n    d()\nexcept Exception as e:\n    return {'error': str(e)}\n"
    )
    assert _silent_handlers(allowed) == []


def test_the_scanner_fires_on_the_real_pre_remediation_handlers() -> None:
    """Verbatim copies of four handlers this workstream removed.

    Pinned in their original shape (not a stylised stand-in) so that if the
    scanner's rule is ever loosened -- a broadened escape clause, a bug in the
    AST walk -- the loosening is caught by the exact code it was meant to catch,
    rather than by nothing.
    """
    # advisory/client.py:169 and :181 -- both embedding providers
    embed_arm = (
        "def embed(texts):\n"
        "    if settings.ollama_available():\n"
        "        try:\n"
        "            r = httpx.post(url, json=body, timeout=t)\n"
        "            r.raise_for_status()\n"
        "            vecs = r.json().get('embeddings', [])\n"
        "            if vecs:\n"
        "                return vecs\n"
        "        except Exception:\n"
        "            pass\n"
        "    return []\n"
    )
    # agent/assistant.py:93 -- the flagship 'ask your network' degradation
    ask = (
        "def ask(ctx, question):\n"
        "    try:\n"
        "        if settings.active_provider() == 'ollama':\n"
        "            return _ollama_loop(ctx, question)\n"
        "    except Exception:\n"
        "        pass\n"
        "    return _grounded_fallback(ctx, question)\n"
    )
    # metrics.py:52 -- the AI-usage dashboard's silent undercount
    metric = (
        "def record_metric(**kw):\n"
        "    try:\n"
        "        write(kw)\n"
        "    except Exception:\n"
        "        pass  # metrics are best-effort; never break the measured call\n"
    )
    # settings.py:85 -- 'is a local model available?' answered by a swallowed error
    probe = (
        "def ollama_probe():\n"
        "    ok, models = False, []\n"
        "    try:\n"
        "        r = httpx.get(url, timeout=1.5)\n"
        "        if r.status_code == 200:\n"
        "            models = sorted(m['name'] for m in r.json().get('models', []))\n"
        "            ok = bool(models)\n"
        "    except Exception:\n"
        "        ok, models = False, []\n"
        "    return ok, models\n"
    )
    for label, src in (("embed", embed_arm), ("ask", ask),
                       ("record_metric", metric), ("ollama_probe", probe)):
        assert _silent_handlers(src), f"the scanner stopped detecting the {label} handler"


def test_the_scanner_actually_reads_the_backend() -> None:
    """Guard against a green run produced by scanning nothing at all.

    `test_no_silent_broad_handler_in_the_backend` asserts an EMPTY list, which is
    also what a broken path glob returns. Pin the corpus so the two failures are
    distinguishable.
    """
    files = [p for d in SCANNED_DIRS for p in (BACKEND / d).rglob("*.py")
             if "__pycache__" not in p.parts]
    assert len(files) > 40, f"only {len(files)} python files found under {SCANNED_DIRS}"
    handlers = sum(
        len([n for n in ast.walk(ast.parse(p.read_text(encoding='utf-8')))
             if isinstance(n, ast.ExceptHandler)])
        for p in files
    )
    assert handlers > 30, f"only {handlers} exception handlers found; the scan is not reaching the code"


# ---------------------------------------------------------------------------
# 2. The invariant itself
# ---------------------------------------------------------------------------

def test_no_silent_broad_handler_in_the_backend() -> None:
    """No `except Exception` in backend/src or backend/app degrades in silence."""
    found = _scan_backend()
    unexpected = [v for v in found if v.path not in KNOWN_SILENT]
    assert not unexpected, (
        "A failure is being swallowed with nothing to investigate it with. Either "
        "log it on the module's `npr.api.*` logger with an `event` name, narrow the "
        "catch to the exception the call can actually raise, re-raise it, or return "
        "it to the caller as data:\n  " + "\n  ".join(str(v) for v in unexpected)
    )


def test_the_silent_handler_exemption_list_stays_a_written_decision() -> None:
    """Every exemption names a file that still has one. A stale entry is a
    licence nobody re-examined, so it is removed the moment it stops applying."""
    still_silent = {v.path for v in _scan_backend()}
    stale = sorted(set(KNOWN_SILENT) - still_silent)
    assert not stale, f"KNOWN_SILENT lists files that no longer swallow anything: {stale}"


# ---------------------------------------------------------------------------
# 3. Behaviour: force the failure, read the log
# ---------------------------------------------------------------------------

@pytest.fixture
def npr_logs(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    """Capture `npr.api.*` records regardless of what has already been imported.

    `app/main.py` sets `propagate = False` on the "npr.api" logger so its JSON
    lines do not double-print through uvicorn's root handler. caplog attaches to
    the ROOT logger, so in any session where an API test imported main first,
    every assertion below would silently see zero records -- the exact failure
    mode this file exists to outlaw. Attaching caplog's handler to "npr.api"
    itself makes the capture independent of import order.

    Propagation is then pinned OFF for the duration: with main not yet imported
    the logger still propagates, caplog's root handler sees the same record a
    second time, and every `(record,) = ...` below unpacks two. Pinning it means
    each event is asserted exactly once whichever modules a session imported.
    """
    logger = logging.getLogger("npr.api")
    previous_propagate, previous_level = logger.propagate, logger.level
    logger.addHandler(caplog.handler)
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    caplog.set_level(logging.DEBUG)
    try:
        yield caplog
    finally:
        logger.removeHandler(caplog.handler)
        logger.propagate, logger.level = previous_propagate, previous_level


def _events(caplog: pytest.LogCaptureFixture, name: str) -> list[logging.LogRecord]:
    """Every captured record whose structured `event` field is `name`."""
    return [r for r in caplog.records if getattr(r, "event", None) == name]


def test_the_offline_stubs_are_in_place_and_this_module_holds_the_real_functions() -> None:
    """The two module-level captures at the top are load-bearing; prove them."""
    assert settings_mod.ollama_probe is not _REAL_OLLAMA_PROBE, \
        "conftest's offline stub is not applied; these tests are not running offline"
    assert metrics.record_metric is not _REAL_RECORD_METRIC
    assert _REAL_OLLAMA_PROBE.__module__ == "src.settings"
    assert _REAL_RECORD_METRIC.__module__ == "src.metrics"


# --- the LLM provider path -------------------------------------------------

def test_a_dead_model_provider_is_logged_not_only_returned(
        npr_logs: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    """`complete()` fails closed; it must also fail LOUDLY.

    `ok=False` reaches the caller, but every caller's response to it is to
    substitute deterministic output -- so without this line the only trace that a
    capability stopped being model-driven was a metrics row written to the very
    database that is the usual reason the call failed.
    """
    monkeypatch.setattr(settings_mod, "active_provider", lambda: "ollama")

    def boom(*_a, **_kw):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(llm, "_ollama_complete", boom)

    res = llm.complete(system="s", user="u", capability="explain")

    assert res.ok is False and "connection refused" in (res.error or "")
    (record,) = _events(npr_logs, "llm_call_failed")
    assert record.levelno == logging.WARNING
    assert record.name == "npr.api.llm"
    assert record.capability == "explain" and record.provider == "ollama"
    assert "ConnectError" in record.error


def test_embedding_failure_is_distinguishable_from_having_nothing_to_embed(
        npr_logs: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    """The half of this workstream that is not about logging.

    `embed([])` and `embed(x)` with every provider down both answered `[]`, and
    `entity_suggest` turns a missing vector into `name_similarity: 0.0` -- a
    positive claim ("these two PCI assets do not resemble each other") derived
    from no data at all. The result now carries which one happened.
    """
    monkeypatch.setattr(settings_mod, "ollama_available", lambda: True)
    monkeypatch.setattr(settings_mod, "has_openai", lambda: False)
    monkeypatch.setattr(llm.httpx, "post", lambda *a, **k: (_ for _ in ()).throw(
        httpx.ReadTimeout("embed timed out")))

    nothing_asked = llm.embed_texts([])
    assert nothing_asked.ok is True and nothing_asked.vectors == []
    assert not _events(npr_logs, "embed_unavailable"), "an empty request is not a failure"

    failed = llm.embed_texts(["app-server-07", "appsrv-07"])
    assert failed.ok is False and failed.vectors == []
    assert "ReadTimeout" in (failed.error or "")

    (unavailable,) = _events(npr_logs, "embed_unavailable")
    assert unavailable.levelno == logging.ERROR
    (provider_failed,) = _events(npr_logs, "embed_provider_failed")
    assert provider_failed.provider == "ollama"

    # ...and the old contract still holds for callers not yet ported, so nothing
    # breaks while `entity_suggest` is still on the vectors-only helper.
    assert llm.embed(["a", "b"]) == []


def test_unparseable_model_json_names_what_the_model_actually_said(
        npr_logs: pytest.LogCaptureFixture) -> None:
    """`parse_json` returning `default` IS the moment a capability goes generic."""
    sentinel = {"decision": "escalate"}
    assert llm.parse_json("I'm sorry, I can't help with that.", sentinel) is sentinel

    (record,) = _events(npr_logs, "llm_json_unparseable")
    assert record.levelno == logging.WARNING
    assert "I'm sorry" in record.sample

    npr_logs.clear()
    # Valid JSON, a code fence, and the substring salvage must all stay quiet:
    # a log line on the happy path is how a log stops being read.
    assert llm.parse_json('{"a": 1}', None) == {"a": 1}
    assert llm.parse_json('```json\n{"a": 1}\n```', None) == {"a": 1}
    assert llm.parse_json('sure! {"a": 1} hope that helps', None) == {"a": 1}
    assert llm.parse_json("", sentinel) is sentinel      # already logged by complete()
    assert _events(npr_logs, "llm_json_unparseable") == []


# --- the assistant ---------------------------------------------------------

@pytest.fixture
def fake_ctx() -> types.SimpleNamespace:
    """The engine result the assistant reads; only `.findings` is touched."""
    return types.SimpleNamespace(findings=[])


def _ok_completion(**_kw):
    return llm.LLMResponse(text="an answer", provider="openai", model="gpt-4o", ok=True)


def test_the_assistant_says_when_it_did_not_call_a_single_tool(
        npr_logs: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch,
        fake_ctx: types.SimpleNamespace) -> None:
    """The shipped hosted deployment's permanent state, made visible.

    render.yaml pins ADVISORY_PROVIDER=openai, for which no tool-calling loop
    exists. The answer used to come back labelled `by: "openai:gpt-4o"` -- styled
    exactly like a tool-grounded one -- above a "Tool trace" header, from a model
    that had been handed finding TITLES and told to cite concrete paths.
    """
    monkeypatch.setattr(settings_mod, "active_provider", lambda: "openai")
    monkeypatch.setattr(assistant, "complete", _ok_completion)

    res = assistant.ask(fake_ctx, "Can the internet reach db-prod-01?")

    assert res["tool_calling"] is False
    assert res["degraded"]["provider"] == "openai"
    assert "not implemented" in res["degraded"]["reason"]
    assert "grounded fallback" in res["by"], res["by"]
    assert "openai:gpt-4o" in res["by"]              # the model is still named

    (record,) = _events(npr_logs, "assistant_no_tool_calling")
    assert record.levelno == logging.WARNING and record.provider == "openai"


def test_a_broken_tool_loop_degrades_visibly_rather_than_invisibly(
        npr_logs: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch,
        fake_ctx: types.SimpleNamespace) -> None:
    monkeypatch.setattr(settings_mod, "active_provider", lambda: "ollama")
    monkeypatch.setattr(assistant, "complete", _ok_completion)
    monkeypatch.setattr(assistant.httpx, "post", lambda *a, **k: (_ for _ in ()).throw(
        httpx.ConnectError("ollama is not running")))

    res = assistant.ask(fake_ctx, "Can the internet reach db-prod-01?")

    assert res["tool_calling"] is False
    assert "ConnectError" in res["degraded"]["detail"]
    (record,) = _events(npr_logs, "assistant_loop_failed")
    assert record.levelno == logging.ERROR
    assert record.exc_info is not None, "the traceback is the point of an ERROR line"


def test_a_defect_in_the_tool_loop_crashes_instead_of_quietly_confabulating(
        monkeypatch: pytest.MonkeyPatch, fake_ctx: types.SimpleNamespace) -> None:
    """`except Exception: pass` meant a typo downgraded the flagship feature for
    every user, forever, with nothing to read. Only transport/decode failures
    mean "the model is unavailable"; a NameError means this file is broken and
    must surface as a 500 the global handler stamps with a request id."""
    monkeypatch.setattr(settings_mod, "active_provider", lambda: "ollama")
    monkeypatch.setattr(assistant.httpx, "post", lambda *a, **k: (_ for _ in ()).throw(
        NameError("typo in the loop")))

    with pytest.raises(NameError):
        assistant.ask(fake_ctx, "Can the internet reach db-prod-01?")


def test_tool_arguments_that_could_not_be_parsed_are_named_on_the_trace() -> None:
    """`{}` meant both "the model passed nothing" and "we could not read what it
    passed", and the two produce different tool calls."""
    assert assistant._normalize_args({"src": "a"}) == ({"src": "a"}, None)
    assert assistant._normalize_args('{"src": "a"}') == ({"src": "a"}, None)
    assert assistant._normalize_args(None) == ({}, None)

    args, why = assistant._normalize_args("{not json")
    assert args == {} and "unparseable" in why
    args, why = assistant._normalize_args("[1, 2]")
    assert args == {} and "expected an object" in why
    args, why = assistant._normalize_args(7)
    assert args == {} and "expected an object" in why


# --- provider routing ------------------------------------------------------

@pytest.fixture
def fresh_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset the probe's cache AND its "already reported" memo for one test."""
    monkeypatch.setitem(settings_mod._OLLAMA_PROBE, "checked_at", 0.0)
    monkeypatch.setitem(settings_mod._OLLAMA_PROBE, "ok", False)
    monkeypatch.setitem(settings_mod._OLLAMA_PROBE, "models", [])
    monkeypatch.setitem(settings_mod._OLLAMA_PROBE, "reported", None)
    monkeypatch.setitem(settings_mod._AUTO_ROUTE, "reported", None)


def _probe_answering(monkeypatch: pytest.MonkeyPatch, models: list[str] | None,
                     exc: Exception | None = None) -> None:
    """Point the real probe at a fake /api/tags."""
    import httpx as real_httpx

    def fake_get(*_a, **_kw):
        if exc is not None:
            raise exc
        return real_httpx.Response(200, json={"models": [{"name": m} for m in (models or [])]})

    monkeypatch.setattr(real_httpx, "get", fake_get)


def test_an_unreachable_model_server_is_reported_once_not_never(
        npr_logs: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch,
        fresh_probe: None) -> None:
    _probe_answering(monkeypatch, None, exc=httpx.ConnectError("connection refused"))

    assert _REAL_OLLAMA_PROBE() == (False, [])
    (record,) = _events(npr_logs, "ollama_unreachable")
    assert record.levelno == logging.WARNING
    assert "ConnectError" in record.error

    # A second fresh probe in the same state must not repeat itself: the probe
    # runs twice a minute forever, and a line per probe is a line nobody reads.
    monkeypatch.setitem(settings_mod._OLLAMA_PROBE, "checked_at", 0.0)
    assert _REAL_OLLAMA_PROBE() == (False, [])
    assert len(_events(npr_logs, "ollama_unreachable")) == 1


def test_a_server_that_is_up_without_the_configured_tag_is_the_loudest_case(
        npr_logs: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch,
        fresh_probe: None) -> None:
    """The audit's "works on my machine" trap: `ollama pull qwen3-coder` gives
    `:latest`, the configured tag is `:30b`, the probe says LOCAL, the residency
    badge says LOCAL, and every capability is on deterministic fallback because
    each individual call 404s at request time."""
    monkeypatch.setattr(settings_mod, "OLLAMA_JUDGE_MODEL", "qwen3-coder:30b")
    monkeypatch.setattr(settings_mod, "OLLAMA_PROSE_MODEL", "qwen3-coder:30b")
    monkeypatch.setattr(settings_mod, "OLLAMA_EMBED_MODEL", "nomic-embed-text")
    _probe_answering(monkeypatch, ["qwen3-coder:latest", "nomic-embed-text"])

    ok, models = _REAL_OLLAMA_PROBE()

    # The routing ANSWER is deliberately unchanged -- moving it is a different
    # workstream -- so the log line is the entire difference.
    assert ok is True and models == ["nomic-embed-text", "qwen3-coder:latest"]
    (record,) = _events(npr_logs, "ollama_model_missing")
    assert record.levelno == logging.WARNING
    assert record.missing == ["qwen3-coder:30b"]
    assert not _events(npr_logs, "ollama_unreachable")


def test_a_healthy_local_server_says_so_quietly(
        npr_logs: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch,
        fresh_probe: None) -> None:
    monkeypatch.setattr(settings_mod, "OLLAMA_JUDGE_MODEL", "m:1")
    monkeypatch.setattr(settings_mod, "OLLAMA_PROSE_MODEL", "m:1")
    monkeypatch.setattr(settings_mod, "OLLAMA_EMBED_MODEL", "m:1")
    _probe_answering(monkeypatch, ["m:1"])

    assert _REAL_OLLAMA_PROBE() == (True, ["m:1"])
    (record,) = _events(npr_logs, "ollama_ready")
    assert record.levelno == logging.INFO


def test_escalating_off_the_box_to_a_hosted_provider_is_announced(
        npr_logs: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch,
        fresh_probe: None) -> None:
    """Under `auto`, a failed probe silently moved the customer's topology to a
    hosted API and switched the assistant's tool calling off. Same decision, now
    on the record -- once, at the transition, not once per model call."""
    monkeypatch.setattr(settings_mod, "ADVISORY_PROVIDER", "auto")
    monkeypatch.setattr(settings_mod, "OPENAI_API_KEY", "sk-test")
    # conftest's stub already answers "no local model"; assert that, so this test
    # cannot pass because a developer happens to be running Ollama.
    assert settings_mod.ollama_available() is False

    assert settings_mod.active_provider() == "openai"
    (record,) = _events(npr_logs, "provider_route")
    assert record.levelno == logging.WARNING
    assert record.provider == "openai" and record.residency == "hosted"
    assert record.tool_calling is False

    for _ in range(5):                     # every model call goes through here
        settings_mod.active_provider()
    assert len(_events(npr_logs, "provider_route")) == 1


# --- metrics ---------------------------------------------------------------

def test_a_dropped_metric_row_says_the_dashboard_is_undercounting(
        npr_logs: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(metrics.db, "DATABASE_URL", "postgresql://configured/but-broken")

    def boom(*_a, **_kw):
        raise RuntimeError("connection pool exhausted")

    monkeypatch.setattr(metrics, "get_conn", boom)

    _REAL_RECORD_METRIC(kind="llm", capability="explain", provider="ollama", ok=True)

    (record,) = _events(npr_logs, "metric_write_failed")
    assert record.levelno == logging.WARNING
    assert record.capability == "explain" and "pool exhausted" in record.error
    assert not _events(npr_logs, "metric_sink_unconfigured")


def test_an_unconfigured_metrics_sink_is_reported_once_per_process(
        npr_logs: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    """The state this repo ships in. It cannot change without a restart, so it is
    said once -- repeating it on every model call would bury the real failures."""
    monkeypatch.setattr(metrics, "_UNCONFIGURED_REPORTED", False)
    monkeypatch.setattr(metrics.db, "DATABASE_URL", "")

    for _ in range(3):
        _REAL_RECORD_METRIC(kind="llm", capability="rank", ok=True)

    assert len(_events(npr_logs, "metric_sink_unconfigured")) == 1
    assert not _events(npr_logs, "metric_write_failed")


class _BrokenSink(logging.Handler):
    """A log destination that is itself down -- stdout closed, a shipper refusing
    connections. The realistic version of "the reporting is broken"."""

    def emit(self, record: logging.LogRecord) -> None:
        raise OSError("the log sink is gone")


def test_a_metric_failure_never_reaches_the_call_it_measures(
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Reporting the drop must not turn a working answer into a 500.

    `record_metric`'s one guarantee is that nobody loses an answer because the
    telemetry table is unreachable, and this workstream put a `log.warning`
    directly on that path. `logging` does NOT make that safe on its own:
    `Handler.handle` calls `emit` straight, and only handlers that opt into the
    `handleError` convention swallow their own failures -- so a sink that raises
    would ride a dead metrics table into a working request. Written as a test
    because it was written as a bug first: this handler is what caught it.
    """
    sink = _BrokenSink()
    logger = logging.getLogger("npr.api.metrics")
    logger.addHandler(sink)
    monkeypatch.setattr(metrics.db, "DATABASE_URL", "postgresql://configured/but-broken")
    monkeypatch.setattr(metrics, "get_conn",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    try:
        _REAL_RECORD_METRIC(kind="llm", capability="explain", ok=True)   # must not raise
    finally:
        logger.removeHandler(sink)

    # ...and even then it is not silent: the last resort is stderr, which is the
    # same place logging's own handleError writes.
    assert "metric drop could not be reported" in capsys.readouterr().err


# --- the accepted-change overlay -------------------------------------------

def _record(ref: str = "R-1", **over) -> PolicyRecord:
    base = dict(id=f"id-{ref}", source_tool="algosec", raw_ref=ref, source="10.0.0.0/8",
                source_kind="cidr", destination="db-prod-01", destination_kind="identity",
                service="tcp/5432", port=5432, action="allow", order=1)
    base.update(over)
    return PolicyRecord(**base)


def test_an_accepted_rule_that_cannot_be_rebuilt_is_an_error_not_a_shrug(
        npr_logs: pytest.LogCaptureFixture) -> None:
    """`_added_record` answering None dropped an APPROVED rule out of the
    snapshot, which was then persisted as authoritative."""
    records = [_record("R-1")]
    out = overlay.apply_overlay(records, [{"kind": "add_allow",
                                           "payload": {"raw_ref": "R-NEW", "source": "10.1.0.0/16"}}])

    assert [r.raw_ref for r in out] == ["R-1"], "the malformed rule is still not applied..."
    (record,) = _events(npr_logs, "overlay_add_allow_invalid")   # ...but it is no longer silent
    assert record.levelno == logging.ERROR
    assert record.raw_ref == "R-NEW"
    assert "ValidationError" in record.error


def test_a_remediation_that_matches_no_rule_is_reported(
        npr_logs: pytest.LogCaptureFixture) -> None:
    """"Applied" while the finding it was proven against is untouched: the
    staging screen says done, the dashboard still shows the critical."""
    records = [_record("R-1")]
    out = overlay.apply_remediation(records, {"op": "remove", "target_ref": "R-DOES-NOT-EXIST"})

    assert [r.raw_ref for r in out] == ["R-1"]
    (record,) = _events(npr_logs, "overlay_remediation_unmatched")
    assert record.levelno == logging.ERROR
    assert record.target_ref == "R-DOES-NOT-EXIST" and record.op == "remove"


def test_a_reorder_with_nothing_to_reorder_before_is_reported(
        npr_logs: pytest.LogCaptureFixture) -> None:
    records = [_record("R-1")]
    out = overlay.apply_remediation(records, {"op": "reorder_before", "target_ref": "R-1",
                                              "shadowing_ref": "R-GONE"})

    assert [r.order for r in out] == [1], "unchanged, which is exactly the problem"
    (record,) = _events(npr_logs, "overlay_reorder_unresolved")
    assert record.levelno == logging.ERROR
    assert record.shadowing_ref == "R-GONE"


def test_a_remediation_that_does_match_stays_quiet(npr_logs: pytest.LogCaptureFixture) -> None:
    """The guard must not cry wolf on the path it exists to protect."""
    out = overlay.apply_remediation([_record("R-1"), _record("R-2")],
                                    {"op": "remove", "target_ref": "R-1"})
    assert [r.raw_ref for r in out] == ["R-2"]
    assert not _events(npr_logs, "overlay_remediation_unmatched")


# --- the scenario writer ---------------------------------------------------

@pytest.fixture
def sandbox_mock_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect data/mock into tmp. The real directory is the ENGINE'S ONLY
    INPUT and every other test in this suite reads it; a test that writes there
    would be exactly the cross-contamination this module is about."""
    monkeypatch.setattr(scenarios, "MOCK_DIR", tmp_path)
    for name in ("algosec_export.json", "guardicore_export.json", "wiz_export.json"):
        (tmp_path / name).write_text('{"vendor": "PREVIOUS GOOD DATASET"}\n')
    return tmp_path


def _previous(d: Path) -> list[str]:
    return sorted(p.name for p in d.glob("*.json")
                  if "PREVIOUS GOOD DATASET" in p.read_text())


def test_a_builder_that_raises_leaves_the_previous_dataset_completely_intact(
        sandbox_mock_dir: Path) -> None:
    """Serialize everything before touching a file. `write_text` TRUNCATES first,
    so the old code's failure mode was not "the old file" -- it was an empty or
    half-written JSON document that `normalize_all` cannot read."""
    with pytest.raises(TypeError):
        scenarios._write({"ok": True}, {"bad": object()}, {"ok": True})

    assert _previous(sandbox_mock_dir) == ["algosec_export.json", "guardicore_export.json",
                                           "wiz_export.json"]
    assert list(sandbox_mock_dir.glob(".*.tmp")) == []


def test_a_failure_mid_swap_names_which_files_moved(
        npr_logs: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch,
        sandbox_mock_dir: Path) -> None:
    """The residual risk that `os.replace` cannot remove: three files, three
    moves. It cannot be silent, because a mixed dataset is a topology that never
    existed and the engine will happily analyze it."""
    calls = {"n": 0}
    real_replace = scenarios.os.replace

    def flaky(src, dst):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full")
        return real_replace(src, dst)

    monkeypatch.setattr(scenarios.os, "replace", flaky)

    with pytest.raises(OSError):
        scenarios._write({"v": "new"}, {"v": "new"}, {"v": "new"})

    (record,) = _events(npr_logs, "scenario_write_partial")
    assert record.levelno == logging.ERROR
    assert record.replaced == ["algosec_export.json"]
    assert record.pending == ["guardicore_export.json", "wiz_export.json"]
    assert list(sandbox_mock_dir.glob(".*.tmp")) == [], "temp files must never be left behind"


def test_writing_a_scenario_says_which_dataset_the_engine_will_now_read(
        npr_logs: pytest.LogCaptureFixture, sandbox_mock_dir: Path) -> None:
    """This overwrites the engine's only input on every cold build and every
    recompute, so "the dataset changed under me" needs an answer."""
    scenarios.write_scenario("clean")

    assert _previous(sandbox_mock_dir) == []          # all three replaced
    payload = json.loads((sandbox_mock_dir / "algosec_export.json").read_text())
    assert payload["vendor"] == "AlgoSec"
    (record,) = _events(npr_logs, "scenario_written")
    assert record.levelno == logging.INFO and record.scenario == "clean"


def test_an_unknown_scenario_raises_and_leaves_the_dataset_alone(
        npr_logs: pytest.LogCaptureFixture, sandbox_mock_dir: Path) -> None:
    with pytest.raises(ValueError, match="unknown scenario"):
        scenarios.write_scenario("not-a-scenario")

    assert len(_previous(sandbox_mock_dir)) == 3
    (record,) = _events(npr_logs, "scenario_unknown")
    assert record.levelno == logging.ERROR and "demo" in record.known


# --- the identity layer ----------------------------------------------------

def _ent(name: str, tool: str = "wiz", *, ip: str | None = None,
         context: str | None = None) -> ObservedEntity:
    e = ObservedEntity(name=name, kind="identity", tool=tool, ip=ip)
    if context is not None:
        e.context = context
    return e


def test_withheld_merges_are_said_out_loud_and_not_only_counted(
        npr_logs: pytest.LogCaptureFixture) -> None:
    """`IdentityResult.suppressed_merges` is computed correctly and then dropped
    by `run_all.run()`, so to an operator staring at two asset cards for one host
    the engine looked like it had simply not noticed."""
    result = identity.resolve_identities([
        _ent("prod-web-01", "wiz", ip="10.0.1.5", context="aws-prod"),
        _ent("dev-web-01", "algosec", ip="10.0.1.5", context="aws-dev"),
    ])

    assert result.suppressed_merges == 1
    (record,) = _events(npr_logs, "identity_merges_withheld")
    assert record.levelno == logging.INFO        # correct behaviour, not a failure
    assert record.withheld == 1
    assert record.by_reason == {"context_mismatch": 1}


def test_an_estate_with_nothing_to_withhold_stays_quiet(
        npr_logs: pytest.LogCaptureFixture) -> None:
    identity.resolve_identities([_ent("a", "wiz", ip="10.0.1.5", context="vpc-a"),
                                _ent("b", "algosec", ip="10.0.2.9", context="vpc-a")])
    assert _events(npr_logs, "identity_merges_withheld") == []


def test_a_confirmed_merge_the_engine_cannot_apply_is_a_warning(
        npr_logs: pytest.LogCaptureFixture) -> None:
    """A human went to the review queue and answered. If the names are not in
    this snapshot -- a renamed host, a tool no longer ingested, a decision made
    against an older export -- the answer is DROPPED. Nothing said so, and
    because merges reach the snapshot fingerprint the id even changed: a brand
    new snapshot, identical to the one before it."""
    result = identity.resolve_identities(
        [_ent("app-server-07", "algosec", ip="10.30.7.7")],
        manual_merges=[("app-server-07", "appsrv-07-renamed")],
    )

    assert result.alias_map == {"app-server-07": "app-server-07"}
    (record,) = _events(npr_logs, "identity_manual_merge_unmatched")
    assert record.levelno == logging.WARNING
    assert record.count == 1
    assert record.pairs == [{"a": "app-server-07", "b": "appsrv-07-renamed",
                             "missing": ["appsrv-07-renamed"]}]


def test_a_confirmed_merge_that_applies_stays_quiet(
        npr_logs: pytest.LogCaptureFixture) -> None:
    result = identity.resolve_identities(
        [_ent("app-server-07", "algosec", ip="10.30.7.7"),
         _ent("appsrv-07", "wiz", ip="10.30.9.9")],
        manual_merges=[("app-server-07", "appsrv-07")],
    )

    assert result.alias_map["appsrv-07"] == result.alias_map["app-server-07"]
    assert _events(npr_logs, "identity_manual_merge_unmatched") == []


def test_the_new_log_calls_cannot_reach_the_engine_output() -> None:
    """Determinism is the engine's selling point and this workstream added log
    calls inside it. Same input, same output, whatever the log level."""
    entities = [_ent("prod-web-01", "wiz", ip="10.0.1.5", context="aws-prod"),
                _ent("dev-web-01", "algosec", ip="10.0.1.5", context="aws-dev")]

    def dump() -> str:
        r = identity.resolve_identities(entities)
        return json.dumps({
            "assets": [a.model_dump() for a in r.assets],
            "correlations": [c.model_dump() for c in r.correlations],
            "alias_map": r.alias_map, "suppressed": r.suppressed_by_reason,
        }, sort_keys=True, default=str)

    logger = logging.getLogger("npr.api.identity")
    previous = logger.level
    try:
        logger.setLevel(logging.CRITICAL)
        quiet = dump()
        logger.setLevel(logging.DEBUG)
        loud = dump()
    finally:
        logger.setLevel(previous)
    assert quiet == loud
