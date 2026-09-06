"""The stored AI-provider configuration: its shape, its resolution order, and
the one distinction it exists to preserve.

`ztpa.ai_config` moves "which model does this product talk to" out of the
container spec and into the system of record, where it is attributable. That
makes three things worth pinning here, and they are three different kinds of
test:

  * **THE SHAPE, STATICALLY.** `db/schema.sql` (fresh install) and
    `db/migrations/0004_ai_config.sql` (existing install) must declare the same
    table, or a database's shape depends on its age -- the exact drift Phase 2
    removed. And neither may ever grow a column that could hold an API key: the
    row is read on every model call, lands in every `pg_dump`, and is served by
    an admin endpoint, so a secret in it is a secret in all three. That is a
    checked property here, not a comment in a migration somebody can delete.

  * **"COULD NOT READ" IS NOT "NOT CONFIGURED".** The audit that drove this
    codebase's last three phases found silent degradation to be its worst
    failure mode, and this is the highest-stakes instance of it available:
    reading an unreachable database as "no configuration" would route the
    customer's network topology to a provider they did not choose -- possibly
    off their tenant -- and report it as normal operation. So `load()` RAISES,
    `stored()` degrades but names the state it degraded into, and the two are
    asserted to be distinguishable from each other AND from an empty table.

  * **THE RESOLUTION ORDER**, exercised with a stored row and an environment
    variable both set, in both directions, including the break-glass that puts
    the environment back on top.

  * **THE DATABASE ITSELF**, where a database is available: the single-row
    constraint is enforced by Postgres rather than by convention, a save
    round-trips, and the live catalog has no secret-shaped column either.

HOW TO RUN THE REAL-DATABASE HALF
---------------------------------
    NPR_TEST_DATABASE_URL=postgresql://npr:nprdev@localhost:55433/npr pytest

Without that variable those tests SKIP and everything else here still runs, so
the default offline run stays green in CI. The variable is deliberately not
`DATABASE_URL` (backend/conftest.py blanks that one so the unit suite cannot
reach a server) and a variable that is SET but unreachable fails collection
rather than skipping -- see `tests/dbharness.py` for why.

**Nothing here commits.** The write tests run inside one transaction that the
fixture rolls back, with `ai_config.get_conn` pointed at that transaction, so
`save()` itself is exercised rather than a re-implementation of it.
"""

from __future__ import annotations

import contextlib
import logging
import os
import pathlib
import re
from typing import Any, Iterator

import psycopg
import pytest

from src import ai_config, settings as settings_mod
from src.ai_config import AiConfig, AiConfigError, AiConfigUnavailable
from tests.dbharness import FAIL, SKIP, TEST_DB_ENV, collection_decision

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_SQL = REPO_ROOT / "db" / "schema.sql"
MIGRATION_0004 = REPO_ROOT / "db" / "migrations" / "0004_ai_config.sql"


# --------------------------------------------------------------------------
# fixtures shared by the whole file
# --------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _fresh_config_cache() -> Iterator[None]:
    """Drop `ai_config`'s cached read around every test in this file.

    The cache is a module global with a 30s TTL, so without this a test that
    installs a stored configuration would leak it into the next test -- and,
    worse, out of this file entirely: `settings.active_provider()` reads it, and
    every other module's routing assertions would start depending on the order
    pytest happened to collect files in.
    """
    ai_config.invalidate()
    # `active_provider()` logs its decisions ON CHANGE, against these two module
    # globals. Left alone, whether a test sees its own routing log would depend
    # on what the test before it happened to resolve to -- so the log assertions
    # would pass or fail by collection order.
    settings_mod._AUTO_ROUTE.update(reported=None, unusable=None)
    yield
    ai_config.invalidate()


@pytest.fixture()
def npr_logs(caplog: pytest.LogCaptureFixture) -> Iterator[pytest.LogCaptureFixture]:
    """Capture `npr.api.*` records whatever has already been imported.

    Same reasoning as test_no_silent_failure.py's fixture of this name:
    `app/main.py` sets `propagate = False` on "npr.api", so attaching to the
    root logger would silently capture nothing in a session where an API test
    imported main first. Propagation is pinned off so each record is seen once.
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
    return [r for r in caplog.records if getattr(r, "event", None) == name]


def _stored(monkeypatch: pytest.MonkeyPatch, cfg: AiConfig | None) -> None:
    """Pretend the store holds `cfg` (or nothing), without a database.

    Patches `stored()` rather than the connection, because these tests are about
    the resolution order -- what happens once a row has been read -- and the
    reading itself is covered separately, offline and against real Postgres.
    """
    answer = cfg if cfg is not None else ai_config.DEFAULTS
    monkeypatch.setattr(ai_config, "stored", lambda: answer)


def _boom(exc: BaseException):
    """A stand-in for `get_conn` / `load` that always fails, for the paths whose
    whole subject is what happens when the store cannot be reached."""
    def raiser(*_a: Any, **_kw: Any):
        raise exc
    return raiser


_raise = _boom


AZURE_ROW = AiConfig(
    provider="azure",
    azure_endpoint="https://acct.cognitiveservices.azure.com/",
    azure_deployment="Mistral-Large-3",
    azure_api_version="2024-10-21",
    azure_auth_mode="identity",
    configured_by="grace@example.com",
    source=ai_config.SOURCE_DATABASE,
)


# ==========================================================================
# 1. the shape, read statically out of the two .sql files
# ==========================================================================

_COMMENT = re.compile(r"--[^\n]*")
_CREATE_TABLE = re.compile(r"CREATE TABLE IF NOT EXISTS\s+(\w+)\s*\((.*?)\n\);", re.S | re.I)


def _table_body(path: pathlib.Path, table: str = "ai_config") -> str:
    """The CREATE TABLE body for `table`, with line comments stripped.

    Comments are stripped because both files explain at length why there is no
    key column -- the words "key" and "secret" appear repeatedly in prose, and a
    test that read them would fail on its own documentation.
    """
    text = _COMMENT.sub("", path.read_text())
    bodies = {m.group(1).lower(): m.group(2) for m in _CREATE_TABLE.finditer(text)}
    assert table in bodies, f"{table} is not declared in {path.name}"
    return bodies[table]


# A column declaration is a name followed by a TYPE. Matching on the type is
# what keeps `provider <> 'azure'` -- a continuation line inside the table-level
# CHECK -- from being counted as a second `provider` column.
_COLUMN_LINE = re.compile(
    r"^\s+([a-z_][a-z0-9_]*)\s+(boolean|text|timestamptz|integer|bigint|numeric|jsonb|uuid)\b",
    re.M)


def _columns_of(body: str) -> list[str]:
    """Column names in declaration order. Table constraints are not columns."""
    return [m.group(1) for m in _COLUMN_LINE.finditer(body)]


def test_the_table_is_declared_for_a_fresh_install_and_for_an_existing_one() -> None:
    """db/migrate.py applies schema.sql as the baseline on a fresh install and the
    numbered migrations on an existing one. A table in only one of them produces
    a database whose shape depends on its age."""
    assert _columns_of(_table_body(SCHEMA_SQL))
    assert _columns_of(_table_body(MIGRATION_0004))


def test_the_baseline_and_the_migration_declare_the_same_columns() -> None:
    assert _columns_of(_table_body(SCHEMA_SQL)) == _columns_of(_table_body(MIGRATION_0004))


def test_the_declared_columns_are_exactly_the_shared_contract() -> None:
    """The column list the API, the config page and the provider all code to."""
    assert _columns_of(_table_body(SCHEMA_SQL)) == [
        "id",                                   # the singleton key
        "provider", "azure_endpoint", "azure_deployment", "azure_api_version",
        "azure_auth_mode", "azure_client_id", "configured_by", "updated_at",
    ]


def test_the_module_and_the_schema_agree_on_the_column_list() -> None:
    """`ai_config.COLUMNS` builds the SELECT. If it drifts from the table the
    error is a runtime UndefinedColumn on the routing path."""
    declared = [c for c in _columns_of(_table_body(SCHEMA_SQL)) if c != "id"]
    assert list(ai_config.COLUMNS) == declared


@pytest.mark.parametrize("path", [SCHEMA_SQL, MIGRATION_0004], ids=["schema", "migration"])
def test_no_column_could_hold_a_secret(path: pathlib.Path) -> None:
    """THE constraint on this table. A key belongs in a Container Apps secret
    surfaced as an environment variable, never in a row that is read on every
    model call, dumped into every backup and served by an admin endpoint.

    `azure_client_id` is a public identifier (the GUID of a managed identity),
    not a credential, and is the one name that has to survive this rule.
    """
    for column in _columns_of(_table_body(path)):
        if column == "azure_client_id":
            continue
        for pattern in ai_config.SECRET_COLUMN_PATTERNS:
            assert pattern not in column, (
                f"{path.name} declares ai_config.{column}, which looks like it holds a secret. "
                f"Secrets are environment-only -- see the module docstring in src/ai_config.py.")


@pytest.mark.parametrize("path", [SCHEMA_SQL, MIGRATION_0004], ids=["schema", "migration"])
def test_the_single_row_constraint_is_declared_in_both(path: pathlib.Path) -> None:
    """A constant primary key: `id boolean PRIMARY KEY DEFAULT true CHECK (id)`.
    A PK is NOT NULL and the CHECK pins the only value, so a second row is
    refused by Postgres rather than by an application convention."""
    body = " ".join(_table_body(path).split())
    assert "id boolean PRIMARY KEY DEFAULT true CHECK (id)" in body, body


def test_the_migration_says_out_loud_that_a_key_column_is_forbidden() -> None:
    """The comment is the thing a future author reads before adding a column
    'just for the manual path'. Its absence is how the rule gets lost."""
    text = MIGRATION_0004.read_text()
    assert "NO API KEY COLUMN" in text
    assert "Container Apps secret" in text


def test_the_dataclass_carries_no_secret_field_either() -> None:
    """The table cannot hold a key; neither may the object modelling it, or a
    key would travel through the API layer on its way to nowhere."""
    fields = set(AiConfig.__dataclass_fields__) | set(ai_config.DEFAULTS.public())
    for name in fields:
        if name == "azure_client_id":
            continue
        for pattern in ai_config.SECRET_COLUMN_PATTERNS:
            assert pattern not in name, f"AiConfig.{name} looks like it carries a secret"


# ==========================================================================
# 2. "could not read" is not "not configured"
# ==========================================================================

def test_no_database_at_all_reads_as_unconfigured_rather_than_as_a_failure(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """conftest blanks DATABASE_URL, so this is the state the whole offline
    suite runs in. There is no store to read, which is a real deployment (and
    was the only one before this table existed) -- not a fault."""
    monkeypatch.setattr(ai_config.db, "DATABASE_URL", "")

    cfg = ai_config.load()

    assert cfg is ai_config.DEFAULTS
    assert cfg.source == ai_config.SOURCE_DEFAULTS
    assert cfg.is_stored is False and cfg.store_readable is True


def test_an_unreadable_store_raises_instead_of_reading_as_unconfigured(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The failure this module exists to prevent. Returning DEFAULTS here would
    silently move inference to whatever the environment says."""
    monkeypatch.setattr(ai_config.db, "DATABASE_URL", "postgresql://configured/but-down")
    monkeypatch.setattr(ai_config, "get_conn", _boom(psycopg.OperationalError("no route to host")))

    with pytest.raises(AiConfigUnavailable) as excinfo:
        ai_config.load()

    message = str(excinfo.value)
    assert "no route to host" in message
    assert "not the same as 'no configuration is stored'" in message.lower()
    assert "db/migrate.py" in message          # the other cause, named


def test_the_two_failure_modes_do_not_look_alike(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stated as one assertion because it is one property: an empty table and an
    unreachable database must never produce the same value."""
    monkeypatch.setattr(ai_config.db, "DATABASE_URL", "")
    empty = ai_config.stored()
    ai_config.invalidate()

    monkeypatch.setattr(ai_config.db, "DATABASE_URL", "postgresql://configured/but-down")
    monkeypatch.setattr(ai_config, "get_conn", _boom(psycopg.OperationalError("down")))
    unreadable = ai_config.stored()

    assert empty.source == ai_config.SOURCE_DEFAULTS
    assert unreadable.source == ai_config.SOURCE_UNAVAILABLE
    assert empty.source != unreadable.source
    assert empty.store_readable is True and unreadable.store_readable is False


def test_the_routing_path_degrades_instead_of_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    """`stored()` is on the path of every model call. A dead configuration
    database must not take the deterministic engine down with it."""
    monkeypatch.setattr(ai_config.db, "DATABASE_URL", "postgresql://configured/but-down")
    monkeypatch.setattr(ai_config, "get_conn", _boom(psycopg.OperationalError("down")))

    assert ai_config.stored().source == ai_config.SOURCE_UNAVAILABLE


def test_an_unreadable_store_with_nothing_cached_is_reported_loudly(
        npr_logs: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ai_config.db, "DATABASE_URL", "postgresql://configured/but-down")
    monkeypatch.setattr(ai_config, "get_conn", _boom(psycopg.OperationalError("down")))

    ai_config.stored()

    (record,) = _events(npr_logs, "ai_config_unavailable")
    assert record.levelno == logging.ERROR
    assert record.name == "npr.api.aiconfig"
    assert "fallen back to the environment" in record.getMessage()


def test_a_configuration_already_read_survives_a_database_blip(
        npr_logs: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole point of separating the two. A brief outage is not an operator
    changing their mind, so the choice they made keeps being honoured -- and the
    result says `stale`, so nothing can mistake it for a fresh read either."""
    monkeypatch.setattr(ai_config.db, "DATABASE_URL", "postgresql://configured/ok")
    monkeypatch.setattr(ai_config, "load", lambda: AZURE_ROW)
    assert ai_config.stored() is AZURE_ROW                 # warm the cache

    monkeypatch.setattr(ai_config, "load", _raise(AiConfigUnavailable("pool exhausted")))
    ai_config._CACHE["checked_at"] = 0.0                   # expire it, do not clear it

    degraded = ai_config.stored()

    assert degraded.source == ai_config.SOURCE_STALE
    assert degraded.provider == "azure"
    assert degraded.azure_deployment == "Mistral-Large-3"   # still the operator's choice
    assert degraded.is_stored is True and degraded.store_readable is False
    (record,) = _events(npr_logs, "ai_config_stale")
    assert record.levelno == logging.WARNING


def test_a_dead_store_is_dialled_once_per_window_not_once_per_model_call(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """A dead database fails through psycopg_pool's 30-second connect timeout.
    Retrying that on every model call would turn "the config store is down" into
    "every capability hangs for half a minute", which is far worse than the
    degradation it is trying to detect."""
    monkeypatch.setattr(ai_config.db, "DATABASE_URL", "postgresql://configured/but-down")
    attempts = []

    def counting_get_conn():
        attempts.append(1)
        raise psycopg.OperationalError("down")

    monkeypatch.setattr(ai_config, "get_conn", counting_get_conn)

    for _ in range(20):
        assert ai_config.stored().source == ai_config.SOURCE_UNAVAILABLE

    assert len(attempts) == 1, f"dialled a dead database {len(attempts)} times"


def test_repointing_the_database_is_not_answered_from_the_old_cache(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The cache is keyed on the URL it was built against, so a process (or a
    test) that changes DATABASE_URL cannot be served the previous one's row."""
    monkeypatch.setattr(ai_config.db, "DATABASE_URL", "postgresql://first/db")
    monkeypatch.setattr(ai_config, "load", lambda: AZURE_ROW)
    assert ai_config.stored().provider == "azure"

    monkeypatch.setattr(ai_config.db, "DATABASE_URL", "postgresql://second/db")
    monkeypatch.setattr(ai_config, "load", lambda: ai_config.DEFAULTS)

    assert ai_config.stored().source == ai_config.SOURCE_DEFAULTS


# ==========================================================================
# 3. the resolution order
# ==========================================================================

def test_a_stored_provider_beats_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The documented winner. The row is a deliberate, attributable, in-product
    decision; ADVISORY_PROVIDER is a guess baked into a container spec -- and on
    the shipped deployment it is always set, so "environment wins" would make
    the Configuration page's Save button do nothing."""
    monkeypatch.setattr(settings_mod, "ADVISORY_PROVIDER", "openai")
    _stored(monkeypatch, AZURE_ROW)

    resolved = ai_config.resolve()

    assert resolved.provider == "azure"
    assert resolved.provider_origin == ai_config.ORIGIN_DATABASE
    assert settings_mod.active_provider() == "azure"


def test_the_environment_decides_when_nothing_is_stored(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every existing deployment behaves exactly as it did until someone
    deliberately configures it."""
    monkeypatch.setattr(settings_mod, "ADVISORY_PROVIDER", "anthropic")
    _stored(monkeypatch, None)

    resolved = ai_config.resolve()

    assert resolved.provider == "anthropic"
    assert resolved.provider_origin == ai_config.ORIGIN_ENVIRONMENT


def test_the_azure_block_comes_from_one_place_not_merged_field_by_field(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """A stored row is authoritative as a BLOCK. Merging would resurrect a
    client id the operator had just cleared, from a stale container variable,
    and the config page would then show a value the product is not using."""
    monkeypatch.setattr(settings_mod, "AZURE_AI_CLIENT_ID",
                        "11111111-2222-3333-4444-555555555555")
    monkeypatch.setattr(settings_mod, "AZURE_AI_DEPLOYMENT", "left-over-from-the-container-spec")
    _stored(monkeypatch, AZURE_ROW)                    # its azure_client_id is None

    resolved = ai_config.resolve()

    assert resolved.azure_client_id is None
    assert resolved.azure_deployment == "Mistral-Large-3"
    assert resolved.azure_origin == ai_config.ORIGIN_DATABASE


def test_the_environment_supplies_the_azure_block_when_nothing_is_stored(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings_mod, "AZURE_AI_ENDPOINT",
                        "https://acct.cognitiveservices.azure.com")
    monkeypatch.setattr(settings_mod, "AZURE_AI_DEPLOYMENT", "Kimi-K2.7-Code")
    _stored(monkeypatch, None)

    resolved = ai_config.resolve()

    assert resolved.azure_origin == ai_config.ORIGIN_ENVIRONMENT
    assert resolved.azure_deployment == "Kimi-K2.7-Code"
    # Normalised on the way out, so every consumer sees one form.
    assert resolved.azure_endpoint == "https://acct.cognitiveservices.azure.com/"


def test_a_stored_row_without_an_api_version_uses_the_application_default(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The column is nullable precisely so the default can move without a
    migration that rewrites every row."""
    _stored(monkeypatch, AiConfig(provider="azure", azure_endpoint="https://a.example.com/",
                                  azure_deployment="d", azure_api_version=None,
                                  source=ai_config.SOURCE_DATABASE))

    assert ai_config.resolve().azure_api_version == ai_config.DEFAULT_AZURE_API_VERSION


def test_the_break_glass_puts_the_environment_back_on_top(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """`AI_CONFIG_IGNORE_DB=true` is the recovery path for a stored
    configuration that is wrong on a deployment whose Configuration page cannot
    be reached: one variable and a restart, no psql into a private database."""
    monkeypatch.setattr(ai_config, "load", lambda: AZURE_ROW)
    monkeypatch.setattr(ai_config.db, "DATABASE_URL", "postgresql://configured/ok")
    monkeypatch.setattr(settings_mod, "ADVISORY_PROVIDER", "ollama")
    monkeypatch.setenv("AI_CONFIG_IGNORE_DB", "true")

    assert ai_config.stored().source == ai_config.SOURCE_IGNORED
    assert ai_config.resolve().provider == "ollama"
    assert settings_mod.active_provider() == "ollama"


def test_the_break_glass_is_read_at_call_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bound late, so its meaning is "what the environment says now" rather than
    "what it said when this module was first imported"."""
    monkeypatch.setattr(ai_config, "load", lambda: AZURE_ROW)
    monkeypatch.setattr(ai_config.db, "DATABASE_URL", "postgresql://configured/ok")
    assert ai_config.stored().source == ai_config.SOURCE_DATABASE

    monkeypatch.setenv("AI_CONFIG_IGNORE_DB", "1")
    assert ai_config.stored().source == ai_config.SOURCE_IGNORED


def test_secrets_are_taken_from_the_environment_and_nowhere_else(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The rule stated as behaviour: with a complete stored Azure configuration
    in key mode, whether the provider is usable depends ONLY on an environment
    variable, because there is no other place a key can come from."""
    _stored(monkeypatch, AiConfig(provider="azure", azure_endpoint="https://a.example.com/",
                                  azure_deployment="d", azure_auth_mode="key",
                                  source=ai_config.SOURCE_DATABASE))

    monkeypatch.setattr(settings_mod, "AZURE_AI_API_KEY", "")
    ready, why = ai_config.azure_ready(ai_config.resolve())
    assert ready is False and "AZURE_AI_API_KEY" in (why or "")

    monkeypatch.setattr(settings_mod, "AZURE_AI_API_KEY", "a-key-from-a-container-apps-secret")
    assert ai_config.azure_ready(ai_config.resolve())[0] is True


# ==========================================================================
# 4. what the store refuses to hold
# ==========================================================================

def test_an_unknown_provider_is_refused() -> None:
    with pytest.raises(AiConfigError, match="provider must be one of"):
        ai_config.validate(AiConfig(provider="gemini"))


def test_an_unknown_auth_mode_is_refused() -> None:
    with pytest.raises(AiConfigError, match="azure_auth_mode"):
        ai_config.validate(AiConfig(provider="auto", azure_auth_mode="sas-token"))


def test_azure_without_a_target_is_refused_before_the_database_sees_it() -> None:
    """The same condition as the table's CHECK, raised here so the API layer
    answers 400 with a sentence instead of leaking a constraint name."""
    with pytest.raises(AiConfigError, match="a model deployment"):
        ai_config.validate(AiConfig(provider="azure",
                                    azure_endpoint="https://a.cognitiveservices.azure.com/"))
    with pytest.raises(AiConfigError, match="an endpoint"):
        ai_config.validate(AiConfig(provider="azure", azure_deployment="d"))


def test_an_endpoint_carrying_a_key_is_refused_rather_than_silently_stripped() -> None:
    """The realistic accident: an operator pastes a URL out of a portal with
    `?api-key=...` on it. Stripping it quietly would leave them believing the key
    had been saved -- and the message has to say where a key actually goes."""
    with pytest.raises(AiConfigError) as excinfo:
        ai_config.validate(AiConfig(
            provider="azure", azure_deployment="d",
            azure_endpoint="https://acct.cognitiveservices.azure.com/?api-key=sk-secret"))
    assert "AZURE_AI_API_KEY" in str(excinfo.value)


def test_an_endpoint_embedding_credentials_is_refused() -> None:
    with pytest.raises(AiConfigError, match="must not embed credentials"):
        ai_config.validate(AiConfig(provider="azure", azure_deployment="d",
                                    azure_endpoint="https://user:pw@acct.example.com/"))


def test_plaintext_http_is_refused_for_a_remote_host_and_allowed_for_loopback() -> None:
    """The payloads are firewall rules, asset names and reachability paths.
    Loopback stays usable so the manual escape hatch can point at a local
    gateway during development."""
    with pytest.raises(AiConfigError, match="must use https"):
        ai_config.validate(AiConfig(provider="azure", azure_deployment="d",
                                    azure_endpoint="http://gateway.corp.example.com/"))

    ok = ai_config.validate(AiConfig(provider="azure", azure_deployment="d",
                                     azure_endpoint="http://localhost:8080/foundry"))
    assert ok.azure_endpoint == "http://localhost:8080/foundry/"


def test_a_deployment_name_that_is_really_a_path_is_refused() -> None:
    """The stored value is interpolated into a request path by the provider. A
    '/' or a '?' in it is not a typo, it is a request aimed somewhere else."""
    for bad in ("../../other", "d?api-version=x", "d/chat/completions", "with space"):
        with pytest.raises(AiConfigError, match="azure_deployment"):
            ai_config.validate(AiConfig(provider="azure", azure_deployment=bad,
                                        azure_endpoint="https://a.example.com/"))


def test_a_client_id_that_is_not_a_guid_is_refused() -> None:
    with pytest.raises(AiConfigError, match="azure_client_id"):
        ai_config.validate(AiConfig(provider="auto", azure_client_id="npr-acr-pull"))
    # The identity actually attached to the deployed apps, as a GUID.
    ok = ai_config.validate(AiConfig(provider="auto",
                                     azure_client_id="cf31bca1-7a3d-4bb9-9c62-5b18f7667c04"))
    assert ok.azure_client_id == "cf31bca1-7a3d-4bb9-9c62-5b18f7667c04"


def test_an_api_version_is_bounded_to_something_that_cannot_rewrite_a_url() -> None:
    with pytest.raises(AiConfigError, match="azure_api_version"):
        ai_config.validate(AiConfig(provider="auto",
                                    azure_api_version="2024-10-21&api-key=leak"))
    assert ai_config.validate(
        AiConfig(provider="auto", azure_api_version="2024-05-01-preview")
    ).azure_api_version == "2024-05-01-preview"


def test_saving_without_a_database_says_so_rather_than_pretending_it_worked(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ai_config.db, "DATABASE_URL", "")
    with pytest.raises(AiConfigUnavailable, match="nowhere to store"):
        ai_config.save(AiConfig(provider="ollama"))


def test_a_malformed_endpoint_degrades_the_provider_instead_of_every_request(
        npr_logs: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    """`resolve()` runs inside `active_provider()`, on every model call. A typo
    in a container spec's AZURE_AI_ENDPOINT must cost the advisory layer, not
    the product."""
    monkeypatch.setattr(settings_mod, "AZURE_AI_ENDPOINT", "acct.cognitiveservices.azure.com")
    monkeypatch.setattr(settings_mod, "AZURE_AI_DEPLOYMENT", "Mistral-Large-3")
    _stored(monkeypatch, None)

    resolved = ai_config.resolve()

    assert resolved.azure_endpoint == ""
    assert "http(s) URL" in (resolved.azure_endpoint_error or "")
    assert ai_config.azure_ready(resolved)[0] is False
    (record,) = _events(npr_logs, "ai_config_bad_endpoint")
    assert record.levelno == logging.ERROR


# ==========================================================================
# 5. where azure sits in `auto`
# ==========================================================================

def test_azure_is_an_explicit_provider_choice() -> None:
    """The vocabulary the whole feature rests on."""
    assert "azure" in settings_mod.EXPLICIT_PROVIDERS
    assert "azure" in ai_config.PROVIDERS


def test_auto_prefers_the_customers_own_azure_deployment_over_a_third_party_key(
        npr_logs: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    """Both are "hosted" -- the topology leaves the box either way -- but an
    Azure Foundry deployment is the customer's own resource in their own tenant
    and region, and it is the only one that needs no stored secret. `auto` picks
    the smaller disclosure. conftest already answers "no local model"."""
    monkeypatch.setattr(settings_mod, "ADVISORY_PROVIDER", "auto")
    monkeypatch.setattr(settings_mod, "OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(settings_mod, "ANTHROPIC_API_KEY", "sk-ant-test")
    _stored(monkeypatch, AiConfig(provider="auto", azure_endpoint="https://a.example.com/",
                                  azure_deployment="Mistral-Large-3",
                                  source=ai_config.SOURCE_DATABASE))
    assert settings_mod.ollama_available() is False

    assert settings_mod.active_provider() == "azure"

    (record,) = _events(npr_logs, "provider_route")
    assert record.levelno == logging.WARNING          # still off the box; still announced
    assert record.provider == "azure" and record.residency == "hosted"
    assert record.tool_calling is False


def test_auto_still_prefers_a_local_model_over_azure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Local-first is the product's residency claim and Azure does not displace
    it: an Azure deployment is the customer's own resource, but the topology
    still leaves the box to reach it."""
    monkeypatch.setattr(settings_mod, "ADVISORY_PROVIDER", "auto")
    monkeypatch.setattr(settings_mod, "ollama_probe", lambda: (True, ["qwen3-coder:30b"]))
    _stored(monkeypatch, AiConfig(provider="auto", azure_endpoint="https://a.example.com/",
                                  azure_deployment="d", source=ai_config.SOURCE_DATABASE))

    assert settings_mod.active_provider() == "ollama"


def test_auto_falls_through_to_openai_when_no_azure_target_is_configured(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The pre-existing behaviour, unchanged. Adding a provider must not move
    a deployment that has not configured it."""
    monkeypatch.setattr(settings_mod, "ADVISORY_PROVIDER", "auto")
    monkeypatch.setattr(settings_mod, "OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(settings_mod, "AZURE_AI_ENDPOINT", "")
    monkeypatch.setattr(settings_mod, "AZURE_AI_DEPLOYMENT", "")
    _stored(monkeypatch, None)

    assert settings_mod.active_provider() == "openai"


def test_auto_does_not_route_to_an_azure_target_that_cannot_authenticate(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Key auth with no key in the environment is configured and unusable.
    Routing to it would turn a missing secret into 401s that read to a user as a
    weak model, which is the failure this whole file is about."""
    monkeypatch.setattr(settings_mod, "ADVISORY_PROVIDER", "auto")
    monkeypatch.setattr(settings_mod, "OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(settings_mod, "AZURE_AI_API_KEY", "")
    _stored(monkeypatch, AiConfig(provider="auto", azure_endpoint="https://a.example.com/",
                                  azure_deployment="d", azure_auth_mode="key",
                                  source=ai_config.SOURCE_DATABASE))

    assert settings_mod.active_provider() == "openai"


def test_an_explicitly_selected_azure_that_cannot_work_is_honoured_and_announced(
        npr_logs: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit choice is not silently substituted -- swapping in a provider
    nobody chose is the exact failure `active_provider` was rewritten to stop --
    so it is said out loud instead, once per transition rather than per call."""
    monkeypatch.setattr(settings_mod, "AZURE_AI_API_KEY", "")
    _stored(monkeypatch, AiConfig(provider="azure", azure_endpoint="https://a.example.com/",
                                  azure_deployment="d", azure_auth_mode="key",
                                  source=ai_config.SOURCE_DATABASE))

    for _ in range(5):
        assert settings_mod.active_provider() == "azure"

    (record,) = _events(npr_logs, "provider_unusable")
    assert record.levelno == logging.WARNING
    assert record.provider == "azure" and "AZURE_AI_API_KEY" in record.reason
    assert record.config_source == ai_config.SOURCE_DATABASE


# ==========================================================================
# 6. against a real Postgres
# ==========================================================================

def _probe(url: str) -> str | None:
    try:
        with psycopg.connect(url, connect_timeout=2) as conn:
            conn.execute("SELECT 1")
        return None
    except Exception as exc:                       # any failure means "skip", not "fail"
        return f"{type(exc).__name__}: {exc}"


_URL = os.environ.get(TEST_DB_ENV, "").strip()
_DECISION, _REASON = collection_decision(_URL, _probe(_URL) if _URL else None)

# Asked for a database and could not get one -> fail collection, not skip. See
# tests/dbharness.py: a run that proved nothing must not exit 0.
if _DECISION == FAIL:
    raise RuntimeError(_REASON)

needs_db = pytest.mark.skipif(_DECISION == SKIP, reason=_REASON)


@pytest.fixture()
def conn() -> Iterator[Any]:
    """One connection, one transaction, always rolled back — the same shape as
    test_db_governance.py's, and for the same reason: a test that commits into
    the system of record is a test that damages it."""
    from psycopg.rows import dict_row

    connection = psycopg.connect(_URL, row_factory=dict_row, autocommit=False)
    try:
        connection.execute("SET search_path TO ztpa, public")
        yield connection
    finally:
        connection.rollback()
        connection.close()


@pytest.fixture()
def store(conn: Any, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """Point `ai_config`'s connection helper at the rolled-back transaction.

    This is what lets the REAL `save()` and `load()` run -- the UPSERT, the audit
    write and the SELECT, in one transaction -- instead of a test-only
    reimplementation of them that could agree with itself while disagreeing with
    the product. `nullcontext` yields the connection and, crucially, does not
    commit on exit the way `db.get_conn()` does.
    """
    monkeypatch.setattr(ai_config.db, "DATABASE_URL", _URL)
    monkeypatch.setattr(ai_config, "get_conn", lambda: contextlib.nullcontext(conn))
    ai_config.invalidate()
    yield conn


@needs_db
def test_the_database_refuses_a_second_configuration_row(store: Any) -> None:
    """The single-row rule, enforced by Postgres. `id boolean PRIMARY KEY
    DEFAULT true CHECK (id)` leaves a second insert nowhere to go: it either
    collides on the key or is rejected by the CHECK."""
    with store.cursor() as cur:
        cur.execute("INSERT INTO ztpa.ai_config (provider) VALUES ('ollama') "
                    "ON CONFLICT (id) DO UPDATE SET provider = 'ollama'")

        with pytest.raises(psycopg.errors.UniqueViolation):
            with store.transaction(force_rollback=True):
                cur.execute("INSERT INTO ztpa.ai_config (provider) VALUES ('openai')")

        with pytest.raises(psycopg.errors.CheckViolation):
            with store.transaction(force_rollback=True):
                cur.execute("INSERT INTO ztpa.ai_config (id, provider) VALUES (false, 'openai')")

        assert cur.execute("SELECT count(*) AS n FROM ztpa.ai_config").fetchone()["n"] == 1


@needs_db
def test_a_saved_configuration_reads_back_unchanged(store: Any) -> None:
    """The round trip, through the real SQL both ways."""
    saved = ai_config.save(AiConfig(
        provider="azure",
        azure_endpoint="https://api-endpoint-inference-resource.cognitiveservices.azure.com",
        azure_deployment="Mistral-Large-3",
        azure_api_version="2024-10-21",
        azure_auth_mode="identity",
        azure_client_id="cf31bca1-7a3d-4bb9-9c62-5b18f7667c04",
    ), actor="grace@example.com")

    loaded = ai_config.load()

    assert loaded.provider == saved.provider == "azure"
    assert loaded.azure_deployment == "Mistral-Large-3"
    # Normalised once, on the way in, so every later reader sees one form.
    assert loaded.azure_endpoint == (
        "https://api-endpoint-inference-resource.cognitiveservices.azure.com/")
    assert loaded.azure_api_version == "2024-10-21"
    assert loaded.azure_auth_mode == "identity"
    assert loaded.azure_client_id == "cf31bca1-7a3d-4bb9-9c62-5b18f7667c04"
    assert loaded.source == ai_config.SOURCE_DATABASE and loaded.is_stored is True


@needs_db
def test_saving_twice_updates_the_one_row_rather_than_adding_another(store: Any) -> None:
    ai_config.save(AiConfig(provider="ollama"), actor="a@example.com")
    ai_config.save(AiConfig(provider="anthropic"), actor="b@example.com")

    with store.cursor() as cur:
        assert cur.execute("SELECT count(*) AS n FROM ztpa.ai_config").fetchone()["n"] == 1
    assert ai_config.load().provider == "anthropic"
    assert ai_config.load().configured_by == "b@example.com"


@needs_db
def test_a_change_is_attributable_and_audited_in_the_same_transaction(store: Any) -> None:
    """Consistent with how Phase 2 made the audit trail carry a human identity:
    who changed the provider, and when, are part of the record -- and the audit
    row is written in the same transaction as the change, so the two can never
    disagree."""
    # The row this test wrote is identified by ID, not by position. A bare
    # SELECT has no order -- Postgres returns heap order, which moves with
    # updates and vacuum -- so `rows[-1]` was "some ai_config_saved row", and on
    # any developer database carrying rows from an earlier session it was
    # reliably the wrong one: 13 committed `subject='azure'` rows here made this
    # fail with `assert 'azure' == 'openai'` about a row it did not write. Same
    # class as everything else in this suite: an assertion whose green/red
    # depends on state the test does not control is not measuring the code.
    with store.cursor() as cur:
        before = {r["id"] for r in cur.execute(
            "SELECT id FROM ztpa.audit_log WHERE action = 'ai_config_saved'").fetchall()}

    saved = ai_config.save(AiConfig(provider="openai"), actor="grace@example.com")

    assert saved.configured_by == "grace@example.com"
    assert saved.updated_at is not None
    with store.cursor() as cur:
        rows = cur.execute(
            "SELECT id, action, subject, detail FROM ztpa.audit_log "
            "WHERE action = 'ai_config_saved'").fetchall()
        # Exactly one new row -- the claim `before + 1` was making, kept.
        written = [r for r in rows if r["id"] not in before]
        assert len(written) == 1, f"{len(written)} audit rows appeared, expected 1"
        row = written[0]
        assert row["subject"] == "openai"
        assert row["detail"]["provider"] == "openai"
        # The audit detail is as key-free as the table it describes.
        assert not any("key" in k for k in row["detail"])


@needs_db
def test_the_database_refuses_an_azure_row_with_no_target(store: Any) -> None:
    """`validate()` is not the only line of defence: the CHECK holds even for a
    hand-written INSERT that never goes through this module."""
    with store.cursor() as cur, pytest.raises(psycopg.errors.CheckViolation):
        with store.transaction(force_rollback=True):
            cur.execute("INSERT INTO ztpa.ai_config (provider, azure_endpoint) "
                        "VALUES ('azure', 'https://a.example.com/')")


@needs_db
def test_a_constraint_violation_is_reported_as_bad_input_not_as_an_outage(
        store: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """If `validate()` and the table's CHECKs ever drift apart, the honest answer
    is still "your input was rejected" (400), not "the store is unavailable"
    (503) -- the second sends an operator to look at the database instead of at
    the form they submitted. Forced by disabling validation."""
    monkeypatch.setattr(ai_config, "validate", lambda cfg: cfg)

    with pytest.raises(AiConfigError, match="drifted apart"):
        ai_config.save(AiConfig(provider="azure", azure_endpoint="https://a.example.com/"),
                       actor="grace@example.com")


@needs_db
def test_the_database_refuses_a_provider_it_does_not_serve(store: Any) -> None:
    with store.cursor() as cur, pytest.raises(psycopg.errors.CheckViolation):
        with store.transaction(force_rollback=True):
            cur.execute("INSERT INTO ztpa.ai_config (provider) VALUES ('gemini')")


@needs_db
def test_the_live_table_has_no_column_that_could_hold_a_secret(store: Any) -> None:
    """The same assertion as the static one, against the catalog -- which is
    what a `pg_dump` and an admin endpoint actually read."""
    with store.cursor() as cur:
        columns = [r["column_name"] for r in cur.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'ztpa' AND table_name = 'ai_config'").fetchall()]

    assert columns, "ztpa.ai_config is missing -- run `python db/migrate.py`"
    for column in columns:
        if column == "azure_client_id":
            continue
        for pattern in ai_config.SECRET_COLUMN_PATTERNS:
            assert pattern not in column, f"ztpa.ai_config.{column} looks like a secret column"


@needs_db
def test_the_migration_is_recorded_as_applied(store: Any) -> None:
    """The ledger check test_db_governance.py makes for the repo as a whole,
    stated for this migration so a developer whose database is behind gets an
    error naming the fix rather than an UndefinedTable from the routing path."""
    with store.cursor() as cur:
        row = cur.execute("SELECT filename FROM ztpa.schema_migrations "
                          "WHERE version = '0004'").fetchone()
    assert row is not None, "0004_ai_config.sql has never been applied -- run `python db/migrate.py`"
    assert row["filename"] == MIGRATION_0004.name
