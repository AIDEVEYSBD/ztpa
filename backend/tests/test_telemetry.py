"""Tracing picks the host cloud's backend, is off by default, and never fails the API."""

from __future__ import annotations

import pytest

from src import telemetry


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for k in ("APPLICATIONINSIGHTS_CONNECTION_STRING", "NPR_OTEL", "OTEL_EXPORTER_OTLP_ENDPOINT"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(telemetry, "_STATE", {"configured": False, "backend": None})


def test_off_by_default() -> None:
    assert telemetry.backend() is None and telemetry.configure() is None


@pytest.mark.parametrize("env, expected", [
    ({"APPLICATIONINSIGHTS_CONNECTION_STRING": "InstrumentationKey=x"}, "azure_monitor"),
    ({"NPR_OTEL": "gcp"}, "gcp_cloud_trace"),
    ({"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318"}, "otlp"),
])
def test_backend_selection(monkeypatch, env, expected) -> None:
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert telemetry.backend() == expected


def test_an_exporter_that_cannot_start_does_not_fail_startup(monkeypatch) -> None:
    monkeypatch.setenv("NPR_OTEL", "gcp")
    import opentelemetry.exporter.cloud_trace as ct

    def broken(*_a, **_k):
        raise RuntimeError("no credentials")
    monkeypatch.setattr(ct, "CloudTraceSpanExporter", broken)
    assert telemetry.configure() is None
