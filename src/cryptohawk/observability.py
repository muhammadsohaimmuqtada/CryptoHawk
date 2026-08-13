from __future__ import annotations

import json
import logging
import re
import sys
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from opentelemetry import propagate, trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import SpanKind, Status, StatusCode
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, Info, generate_latest
from prometheus_client.exposition import CONTENT_TYPE_LATEST
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import JSONResponse, Response

from cryptohawk import __version__
from cryptohawk.config import settings

_request_id: ContextVar[str | None] = ContextVar("cryptohawk_request_id", default=None)
_trace_id: ContextVar[str | None] = ContextVar("cryptohawk_trace_id", default=None)
_job_id: ContextVar[str | None] = ContextVar("cryptohawk_job_id", default=None)
_component: ContextVar[str | None] = ContextVar("cryptohawk_component", default=None)

_CONFIG_LOCK = threading.Lock()
_LOGGING_CONFIGURED = False
_TRACING_CONFIGURED = False

_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:chs|chk)_[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:ghp_|github_pat_|glpat-)[A-Za-z0-9_-]{8,}\b", re.IGNORECASE),
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+"),
)

METRICS_REGISTRY = CollectorRegistry(auto_describe=True)
BUILD_INFO = Info(
    "cryptohawk_build",
    "CryptoHawk build and runtime information.",
    registry=METRICS_REGISTRY,
)
HTTP_REQUESTS = Counter(
    "cryptohawk_http_requests_total",
    "HTTP requests completed by method, route template, and status class.",
    ("method", "route", "status_class"),
    registry=METRICS_REGISTRY,
)
HTTP_REQUEST_DURATION = Histogram(
    "cryptohawk_http_request_duration_seconds",
    "HTTP request latency by method and route template.",
    ("method", "route"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
    registry=METRICS_REGISTRY,
)
HTTP_IN_PROGRESS = Gauge(
    "cryptohawk_http_requests_in_progress",
    "HTTP requests currently being served by method.",
    ("method",),
    registry=METRICS_REGISTRY,
)
SCAN_ATTEMPTS = Counter(
    "cryptohawk_scan_attempts_total",
    "Scan executions by kind, execution path, and outcome.",
    ("kind", "execution", "outcome"),
    registry=METRICS_REGISTRY,
)
SCAN_DURATION = Histogram(
    "cryptohawk_scan_duration_seconds",
    "Scan execution latency by kind, execution path, and outcome.",
    ("kind", "execution", "outcome"),
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120),
    registry=METRICS_REGISTRY,
)
WORKER_POLLS = Counter(
    "cryptohawk_worker_polls_total",
    "Durable worker polling outcomes.",
    ("outcome",),
    registry=METRICS_REGISTRY,
)
SCHEDULER_RUNS = Counter(
    "cryptohawk_scheduler_runs_total",
    "Scheduler polling outcomes.",
    ("outcome",),
    registry=METRICS_REGISTRY,
)
SCHEDULER_ENQUEUED = Counter(
    "cryptohawk_scheduler_jobs_enqueued_total",
    "Jobs enqueued by the continuous scheduler.",
    registry=METRICS_REGISTRY,
)
READINESS_CHECKS = Counter(
    "cryptohawk_readiness_checks_total",
    "Readiness dependency checks by dependency and outcome.",
    ("dependency", "outcome"),
    registry=METRICS_REGISTRY,
)

BUILD_INFO.info(
    {
        "version": __version__,
        "environment": settings.environment,
    }
)


def _redact(value: str) -> str:
    redacted = value
    for pattern in _TOKEN_PATTERNS:
        if pattern.pattern.lower().startswith("(?i)(authorization"):
            redacted = pattern.sub(r"\1<redacted>", redacted)
        else:
            redacted = pattern.sub("<redacted>", redacted)
    return redacted


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _redact(value)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            if any(token in name.lower() for token in ("secret", "token", "password", "credential")):
                result[name] = "<redacted>"
            else:
                result[name] = _json_safe(item)
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    return _redact(str(value))


class JsonLogFormatter(logging.Formatter):
    """Compact structured logs with request/trace/job correlation and secret redaction."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": _redact(record.getMessage()),
            "service": "cryptohawk",
            "environment": settings.environment,
        }
        context = {
            "component": _component.get(),
            "request_id": _request_id.get(),
            "trace_id": _trace_id.get(),
            "job_id": _job_id.get(),
        }
        payload.update({key: value for key, value in context.items() if value})
        fields = getattr(record, "structured_fields", None)
        if isinstance(fields, Mapping):
            payload.update(_json_safe(fields))
        if record.exc_info:
            exc_type, exc_value, _ = record.exc_info
            payload["exception"] = {
                "type": getattr(exc_type, "__name__", "Exception"),
                "message": _redact(str(exc_value)),
                "stack": _redact(self.formatException(record.exc_info)),
            }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def configure_logging() -> None:
    global _LOGGING_CONFIGURED
    if _LOGGING_CONFIGURED:
        return
    with _CONFIG_LOCK:
        if _LOGGING_CONFIGURED:
            return
        logger = logging.getLogger("cryptohawk")
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonLogFormatter())
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))
        logger.propagate = False
        _LOGGING_CONFIGURED = True


def configure_tracing() -> None:
    global _TRACING_CONFIGURED
    if _TRACING_CONFIGURED:
        return
    with _CONFIG_LOCK:
        if _TRACING_CONFIGURED:
            return
        resource = Resource.create(
            {
                "service.name": settings.otel_service_name,
                "service.version": __version__,
                "deployment.environment.name": settings.environment,
            }
        )
        provider = TracerProvider(resource=resource)
        endpoint = settings.otel_traces_endpoint.strip()
        if endpoint:
            exporter = OTLPSpanExporter(
                endpoint=endpoint,
                timeout=settings.otel_export_timeout_seconds,
            )
            provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _TRACING_CONFIGURED = True


def configure_observability() -> None:
    configure_logging()
    configure_tracing()


def current_trace_id() -> str | None:
    span_context = trace.get_current_span().get_span_context()
    if not span_context.is_valid:
        return None
    return f"{span_context.trace_id:032x}"


@contextmanager
def bind_context(
    *,
    request_id: str | None = None,
    trace_id: str | None = None,
    job_id: str | None = None,
    component: str | None = None,
) -> Iterator[None]:
    values = (
        (_request_id, request_id),
        (_trace_id, trace_id),
        (_job_id, job_id),
        (_component, component),
    )
    tokens = [(variable, variable.set(value)) for variable, value in values if value is not None]
    try:
        yield
    finally:
        for variable, token in reversed(tokens):
            variable.reset(token)


def log_event(
    logger: logging.Logger,
    level: int,
    event: str,
    *,
    exc_info: bool = False,
    **fields: Any,
) -> None:
    logger.log(
        level,
        event,
        exc_info=exc_info,
        extra={"structured_fields": {"event": event, **fields}},
    )


def extract_trace_context(headers: Mapping[str, str]):
    return propagate.extract(dict(headers))


def tracer(name: str = "cryptohawk"):
    configure_tracing()
    return trace.get_tracer(name, __version__)


@contextmanager
def traced_operation(
    name: str,
    *,
    attributes: Mapping[str, str | int | float | bool] | None = None,
    job_id: str | None = None,
    component: str | None = None,
) -> Iterator[trace.Span]:
    configure_observability()
    with tracer().start_as_current_span(name, kind=SpanKind.INTERNAL) as span:
        if attributes:
            for key, value in attributes.items():
                span.set_attribute(key, value)
        with bind_context(
            trace_id=current_trace_id(),
            job_id=job_id,
            component=component,
        ):
            try:
                yield span
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
                raise


def record_http_request(
    *,
    method: str,
    route: str,
    status_code: int,
    duration_seconds: float,
    trace_id: str | None = None,
) -> None:
    status_class = f"{status_code // 100}xx"
    exemplar = {"trace_id": trace_id} if trace_id else None
    HTTP_REQUESTS.labels(method, route, status_class).inc(exemplar=exemplar)
    HTTP_REQUEST_DURATION.labels(method, route).observe(
        duration_seconds,
        exemplar=exemplar,
    )


def record_scan_attempt(
    *,
    kind: str,
    execution: str,
    outcome: str,
    duration_seconds: float,
) -> None:
    trace_id = current_trace_id()
    exemplar = {"trace_id": trace_id} if trace_id else None
    SCAN_ATTEMPTS.labels(kind, execution, outcome).inc(exemplar=exemplar)
    SCAN_DURATION.labels(kind, execution, outcome).observe(
        duration_seconds,
        exemplar=exemplar,
    )


def liveness_response() -> JSONResponse:
    return JSONResponse(
        {
            "status": "ok",
            "service": "cryptohawk",
            "version": __version__,
        }
    )


def readiness_response(engine: Engine) -> JSONResponse:
    started = time.perf_counter()
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        READINESS_CHECKS.labels("database", "failed").inc()
        return JSONResponse(
            {
                "status": "not-ready",
                "service": "cryptohawk",
                "version": __version__,
                "checks": {"database": "unavailable"},
            },
            status_code=503,
        )
    READINESS_CHECKS.labels("database", "ready").inc()
    return JSONResponse(
        {
            "status": "ready",
            "service": "cryptohawk",
            "version": __version__,
            "checks": {"database": "ready"},
            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
        }
    )


def metrics_response() -> Response:
    return Response(
        generate_latest(METRICS_REGISTRY),
        headers={"Content-Type": CONTENT_TYPE_LATEST},
    )
