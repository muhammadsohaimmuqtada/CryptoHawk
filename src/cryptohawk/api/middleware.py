from __future__ import annotations

import logging
import re
import time
from uuid import uuid4

from fastapi import Request, Response
from opentelemetry.trace import SpanKind, Status, StatusCode
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from cryptohawk.api.auth import inventory
from cryptohawk.config import settings
from cryptohawk.domain.audit import AuditEvent, AuditOutcome
from cryptohawk.domain.auth import Principal
from cryptohawk.observability import (
    HTTP_IN_PROGRESS,
    bind_context,
    configure_observability,
    current_trace_id,
    extract_trace_context,
    liveness_response,
    log_event,
    metrics_response,
    readiness_response,
    record_http_request,
    tracer,
)
from cryptohawk.storage.audit import AuditRepository

logger = logging.getLogger(__name__)
audit_repo = AuditRepository(inventory)
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_WORKSPACE_PATH = re.compile(r"^/api/v1/workspaces/([^/]+)")
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class SecurityAuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        configure_observability()
        request_id = self._request_id(request)
        request.state.request_id = request_id
        method = request.method.upper()
        started = time.perf_counter()
        HTTP_IN_PROGRESS.labels(method).inc()
        parent_context = extract_trace_context(request.headers)
        response: Response | None = None
        metric_route = "unmatched"
        trace_id: str | None = None

        try:
            with tracer("cryptohawk.api").start_as_current_span(
                "HTTP request",
                context=parent_context,
                kind=SpanKind.SERVER,
            ) as span:
                trace_id = current_trace_id()
                request.state.trace_id = trace_id
                with bind_context(
                    request_id=request_id,
                    trace_id=trace_id,
                    component="api",
                ):
                    try:
                        response = self._operational_response(request)
                        if response is None:
                            response = await call_next(request)
                    except Exception as exc:
                        metric_route = self._metric_route(request)
                        duration = time.perf_counter() - started
                        span.update_name(f"{method} {metric_route}")
                        self._set_span_http_attributes(
                            span,
                            request=request,
                            route=metric_route,
                            status_code=500,
                        )
                        span.record_exception(exc)
                        span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
                        record_http_request(
                            method=method,
                            route=metric_route,
                            status_code=500,
                            duration_seconds=duration,
                            trace_id=trace_id,
                        )
                        log_event(
                            logger,
                            logging.ERROR,
                            "http.request.failed",
                            exc_info=True,
                            method=method,
                            route=metric_route,
                            status_code=500,
                            duration_ms=round(duration * 1000, 3),
                            error_type=type(exc).__name__,
                        )
                        raise

                    metric_route = self._metric_route(request)
                    duration = time.perf_counter() - started
                    span.update_name(f"{method} {metric_route}")
                    self._set_span_http_attributes(
                        span,
                        request=request,
                        route=metric_route,
                        status_code=response.status_code,
                    )
                    if response.status_code >= 500:
                        span.set_status(Status(StatusCode.ERROR))

                    self._apply_security_headers(request, response, request_id, trace_id)
                    if self._should_audit(request):
                        self._write_audit_event(request, response, request_id)
                    record_http_request(
                        method=method,
                        route=metric_route,
                        status_code=response.status_code,
                        duration_seconds=duration,
                        trace_id=trace_id,
                    )
                    level = logging.WARNING if response.status_code >= 500 else logging.INFO
                    log_event(
                        logger,
                        level,
                        "http.request.completed",
                        method=method,
                        route=metric_route,
                        status_code=response.status_code,
                        duration_ms=round(duration * 1000, 3),
                    )
                    return response
        finally:
            HTTP_IN_PROGRESS.labels(method).dec()

    @staticmethod
    def _request_id(request: Request) -> str:
        supplied = request.headers.get("x-request-id", "")
        if _REQUEST_ID.fullmatch(supplied):
            return supplied
        return str(uuid4())

    @staticmethod
    def _operational_response(request: Request) -> Response | None:
        if request.method.upper() != "GET":
            return None
        path = request.url.path
        if path == "/health/live":
            return liveness_response()
        if path == "/health/ready":
            return readiness_response(audit_repo.inventory.engine)
        if settings.metrics_enabled and path == settings.metrics_path:
            return metrics_response()
        return None

    @staticmethod
    def _metric_route(request: Request) -> str:
        if request.url.path in {"/health/live", "/health/ready", settings.metrics_path}:
            return request.url.path
        route = request.scope.get("route")
        path = getattr(route, "path", None)
        return str(path) if path else "unmatched"

    @staticmethod
    def _set_span_http_attributes(
        span,
        *,
        request: Request,
        route: str,
        status_code: int,
    ) -> None:
        span.set_attribute("http.request.method", request.method.upper())
        span.set_attribute("http.route", route)
        span.set_attribute("http.response.status_code", status_code)
        span.set_attribute("url.scheme", request.url.scheme)
        if request.url.hostname:
            span.set_attribute("server.address", request.url.hostname)
        if request.url.port:
            span.set_attribute("server.port", request.url.port)

    @staticmethod
    def _apply_security_headers(
        request: Request,
        response: Response,
        request_id: str,
        trace_id: str | None,
    ) -> None:
        response.headers["X-Request-ID"] = request_id
        if trace_id:
            response.headers["X-Trace-ID"] = trace_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if request.url.path.startswith("/api/v1/auth"):
            response.headers["Cache-Control"] = "no-store"
        if not request.url.path.startswith(("/docs", "/redoc", "/openapi")):
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
            )
        if settings.environment.lower() == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

    @staticmethod
    def _should_audit(request: Request) -> bool:
        return (
            request.method.upper() in _MUTATING_METHODS
            and request.url.path.startswith("/api/v1/")
        )

    @staticmethod
    def _workspace_id(request: Request) -> str | None:
        if hasattr(request.state, "audit_workspace_id_override"):
            return request.state.audit_workspace_id_override
        match = _WORKSPACE_PATH.match(request.url.path)
        return match.group(1) if match else None

    @staticmethod
    def _outcome(status_code: int) -> AuditOutcome:
        if status_code in {401, 403, 429}:
            return AuditOutcome.DENIED
        if status_code < 400:
            return AuditOutcome.SUCCESS
        return AuditOutcome.FAILURE

    @staticmethod
    def _route_identity(request: Request) -> tuple[str, str]:
        route = request.scope.get("route")
        name = getattr(route, "name", "unmatched")
        path = getattr(route, "path", request.url.path)
        return str(name), str(path)

    def _write_audit_event(
        self,
        request: Request,
        response: Response,
        request_id: str,
    ) -> None:
        principal = getattr(request.state, "principal", None)
        route_name, route_path = self._route_identity(request)
        if isinstance(principal, Principal):
            actor_kind = principal.kind.value
            actor_id = principal.subject_id
            user_id = principal.user_id
        else:
            actor_kind = "anonymous"
            actor_id = None
            user_id = None
        event = AuditEvent(
            workspace_id=self._workspace_id(request),
            request_id=request_id,
            actor_kind=actor_kind,
            actor_id=actor_id,
            user_id=user_id,
            action=f"api.{request.method.lower()}.{route_name}",
            resource_type="api-route",
            resource_id=route_path,
            outcome=self._outcome(response.status_code),
            metadata={
                "method": request.method.upper(),
                "status_code": response.status_code,
            },
        )
        try:
            audit_repo.append(event)
        except Exception:
            log_event(
                logger,
                logging.ERROR,
                "audit.persist.failed",
                exc_info=True,
                audit_event_id=event.id,
            )
