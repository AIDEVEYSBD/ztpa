"""Distributed tracing (OpenTelemetry), exported to the host cloud's own backend.

    Azure   APPLICATIONINSIGHTS_CONNECTION_STRING set (Terraform sets it)
            -> Application Insights via the Azure Monitor distro
    GCP     NPR_OTEL=gcp (Terraform sets it) -> Cloud Trace, authenticated by
            the service account (ADC); no collector sidecar needed
    other   OTEL_EXPORTER_OTLP_ENDPOINT set -> any OTLP/HTTP collector
    none    tracing off; nothing is imported

FastAPI requests and psycopg queries are traced; the request id the API already
mints is attached to each request span (`npr.request_id`), so a trace and a log
line join on one value. NPR_OTEL_SAMPLE (default 0.1) bounds the cost: one in ten
traces, parent-based so a trace is never half-sampled.

Never fatal: an exporter that cannot start logs once and the API serves without
tracing, because losing traces must not take the service down.
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger("npr.api.telemetry")
_STATE = {"configured": False, "backend": None}


def backend() -> str | None:
    if os.environ.get("APPLICATIONINSIGHTS_CONNECTION_STRING", "").strip():
        return "azure_monitor"
    if os.environ.get("NPR_OTEL", "").strip().lower() == "gcp":
        return "gcp_cloud_trace"
    if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip():
        return "otlp"
    return None


def configure(app=None) -> str | None:
    """Idempotent. Returns the backend in use, or None when tracing is off."""
    if _STATE["configured"]:
        return _STATE["backend"]
    _STATE["configured"] = True
    kind = backend()
    if kind is None:
        return None
    rate = float(os.environ.get("NPR_OTEL_SAMPLE", "0.1"))
    service = os.environ.get("OTEL_SERVICE_NAME", "frr-api")
    try:
        from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
        # Cloud Run and load balancers send a trace parent marked NOT sampled
        # unless someone asked for a trace; obeying it would drop every request
        # span. Our own ratio applies then too; a sampled parent is honoured.
        ratio = TraceIdRatioBased(rate)
        sampler = ParentBased(root=ratio, remote_parent_not_sampled=ratio)
        if kind == "azure_monitor":
            from azure.monitor.opentelemetry import configure_azure_monitor
            configure_azure_monitor(sampling_ratio=rate, enable_live_metrics=False,
                                    resource_attributes={"service.name": service},
                                    instrumentation_options={"fastapi": {"enabled": True},
                                                             "psycopg2": {"enabled": False},
                                                             "requests": {"enabled": False}})
        else:
            from opentelemetry import trace
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
            provider = TracerProvider(sampler=sampler, resource=Resource.create({"service.name": service}))
            if kind == "gcp_cloud_trace":
                from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
                exporter = CloudTraceSpanExporter()
            else:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
                exporter = OTLPSpanExporter()
            provider.add_span_processor(BatchSpanProcessor(exporter))
            trace.set_tracer_provider(provider)
        from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor
        PsycopgInstrumentor().instrument(enable_commenter=False)
        if app is not None:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            FastAPIInstrumentor.instrument_app(app, excluded_urls="/api/live",
                                               server_request_hook=_tag_request)
    except Exception as exc:  # noqa: BLE001 — telemetry must never take the API down
        log.warning("tracing could not start; serving without it", exc_info=True,
                    extra={"event": "telemetry_unavailable", "backend": kind, "error": str(exc)})
        return None
    _STATE["backend"] = kind
    log.info("tracing enabled", extra={"event": "telemetry_enabled", "backend": kind, "sample": rate})
    return kind


def tag_request_id(request_id: str | None) -> None:
    """Put the API's request id on the current server span (called where the id
    is minted), so a trace and the log lines for that request join on it."""
    if not request_id or not _STATE["backend"]:
        return
    from opentelemetry import trace
    span = trace.get_current_span()
    if span.is_recording():
        span.set_attribute("npr.request_id", request_id)


def _tag_request(span, scope) -> None:
    if span is None or not span.is_recording():
        return
    for k, v in scope.get("headers") or []:
        if k == b"x-request-id":
            span.set_attribute("npr.request_id", v.decode(errors="replace")[:100])
            break
