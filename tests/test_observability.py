from __future__ import annotations

import json
import logging
import re
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

import cryptohawk.api.middleware as middleware_module
from cryptohawk.api.middleware import SecurityAuditMiddleware
from cryptohawk.observability import JsonLogFormatter, bind_context
from cryptohawk.storage.audit import AuditRepository
from cryptohawk.storage.inventory import InventoryRepository

_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")


def _app(tmp_path, monkeypatch) -> TestClient:
    inventory = InventoryRepository(f"sqlite:///{tmp_path / 'observability.db'}")
    audit = AuditRepository(inventory)
    inventory.create_schema()
    audit.create_schema()
    monkeypatch.setattr(middleware_module, "audit_repo", audit)

    app = FastAPI()
    app.add_middleware(SecurityAuditMiddleware)

    @app.get("/hello/{name}")
    def hello(name: str) -> dict[str, str]:
        return {"hello": name}

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError("boom")

    return TestClient(app, raise_server_exceptions=False)


def test_liveness_emits_request_and_trace_correlation(tmp_path, monkeypatch) -> None:
    client = _app(tmp_path, monkeypatch)
    response = client.get("/health/live", headers={"X-Request-ID": "request-123"})

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["X-Request-ID"] == "request-123"
    assert _TRACE_ID.fullmatch(response.headers["X-Trace-ID"])


def test_incoming_traceparent_is_continued(tmp_path, monkeypatch) -> None:
    client = _app(tmp_path, monkeypatch)
    trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    response = client.get(
        "/hello/world",
        headers={
            "traceparent": f"00-{trace_id}-00f067aa0ba902b7-01",
        },
    )

    assert response.status_code == 200
    assert response.headers["X-Trace-ID"] == trace_id


def test_readiness_checks_database_without_exposing_failure_details(tmp_path, monkeypatch) -> None:
    client = _app(tmp_path, monkeypatch)
    ready = client.get("/health/ready")
    assert ready.status_code == 200
    assert ready.json()["checks"] == {"database": "ready"}

    bad_engine = create_engine(f"sqlite:///{tmp_path / 'missing' / 'db.sqlite'}")
    monkeypatch.setattr(
        middleware_module,
        "audit_repo",
        SimpleNamespace(inventory=SimpleNamespace(engine=bad_engine)),
    )
    unavailable = client.get("/health/ready")
    assert unavailable.status_code == 503
    assert unavailable.json()["checks"] == {"database": "unavailable"}
    assert "sqlite" not in unavailable.text.lower()
    assert str(tmp_path) not in unavailable.text


def test_metrics_use_route_templates_not_tenant_or_path_values(tmp_path, monkeypatch) -> None:
    client = _app(tmp_path, monkeypatch)
    response = client.get("/hello/alice")
    assert response.status_code == 200

    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    body = metrics.text
    assert "cryptohawk_http_requests_total" in body
    assert 'route="/hello/{name}"' in body
    assert "alice" not in body
    assert "cryptohawk_http_request_duration_seconds" in body
    assert "cryptohawk_build_info" in body


def test_failed_request_is_counted_without_breaking_error_response(tmp_path, monkeypatch) -> None:
    client = _app(tmp_path, monkeypatch)
    response = client.get("/boom")
    assert response.status_code == 500

    metrics = client.get("/metrics").text
    assert 'route="/boom"' in metrics
    assert 'status_class="5xx"' in metrics


def test_json_logs_redact_tokens_and_include_correlation_context() -> None:
    formatter = JsonLogFormatter()
    record = logging.LogRecord(
        name="cryptohawk.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="request used chk_abcdefghijklmnopqrstuvwxyz0123456789",
        args=(),
        exc_info=None,
    )
    record.structured_fields = {
        "event": "test.event",
        "token": "ghp_abcdefghijklmnopqrstuvwxyz",
    }

    with bind_context(
        request_id="request-abc",
        trace_id="f" * 32,
        job_id="job-123",
        component="test",
    ):
        payload = json.loads(formatter.format(record))

    assert payload["request_id"] == "request-abc"
    assert payload["trace_id"] == "f" * 32
    assert payload["job_id"] == "job-123"
    assert payload["component"] == "test"
    assert payload["token"] == "<redacted>"
    assert "chk_" not in payload["message"]
