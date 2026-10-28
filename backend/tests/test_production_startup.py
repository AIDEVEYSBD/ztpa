"""Production refuses to boot in a configuration that would fail open."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src import settings


@pytest.fixture()
def prod(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "NPR_ENV", "prod")
    monkeypatch.setattr(settings, "DATABASE_URL", "postgresql://x/y")
    monkeypatch.setenv("NPR_PROXY_SECRET", "s3cret")
    monkeypatch.setattr(settings, "NPR_STORAGE_URL", "gs://bucket/frr")
    monkeypatch.setattr(settings, "NPR_ARTIFACT_KEY", "k" * 32)


def test_dev_has_no_startup_requirements(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "NPR_ENV", "dev")
    monkeypatch.delenv("NPR_PROXY_SECRET", raising=False)
    assert settings.production_startup_errors() == []


def test_an_unset_env_on_a_cloud_platform_is_production(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "NPR_ENV", "")
    monkeypatch.setattr(settings, "NPR_PLATFORM", "gcp")
    assert settings.environment() == "prod" and settings.is_production()


def test_staging_is_held_to_production_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "NPR_ENV", "staging")
    assert settings.is_production()


def test_production_without_a_proxy_secret_is_refused(prod, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NPR_PROXY_SECRET")
    errors = settings.production_startup_errors()
    assert len(errors) == 1 and "NPR_PROXY_SECRET" in errors[0]


def test_production_without_a_database_is_refused(prod, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "DATABASE_URL", "")
    assert any("DATABASE_URL" in e for e in settings.production_startup_errors())


def test_a_complete_production_config_boots(prod) -> None:
    assert settings.production_startup_errors() == []


def test_the_app_will_not_start_when_refused(prod, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.main import app

    monkeypatch.delenv("NPR_PROXY_SECRET")
    with pytest.raises(settings.StartupRefused, match="NPR_PROXY_SECRET"):
        with TestClient(app):
            pass


def test_production_on_local_disk_storage_is_refused(prod, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "NPR_STORAGE_URL", "file:///tmp/x")
    assert any("NPR_STORAGE_URL" in e for e in settings.production_startup_errors())


def test_production_without_an_artifact_key_is_refused(prod, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "NPR_ARTIFACT_KEY", "short")
    assert any("NPR_ARTIFACT_KEY" in e for e in settings.production_startup_errors())


def test_preflight_exits_nonzero_when_refused(prod, monkeypatch: pytest.MonkeyPatch) -> None:
    from src import preflight
    assert preflight.main() == 0
    monkeypatch.delenv("NPR_PROXY_SECRET")
    assert preflight.main() == 1
