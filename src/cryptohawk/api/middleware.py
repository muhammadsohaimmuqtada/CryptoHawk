from __future__ import annotations

import logging
import re
from uuid import uuid4

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from cryptohawk.api.auth import inventory
from cryptohawk.config import settings
from cryptohawk.domain.audit import AuditEvent, AuditOutcome
from cryptohawk.domain.auth import Principal
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
        request_id = self._request_id(request)
        request.state.request_id = request_id
        response = await call_next(request)
        self._apply_security_headers(request, response, request_id)
        if self._should_audit(request):
            self._write_audit_event(request, response, request_id)
        return response

    @staticmethod
    def _request_id(request: Request) -> str:
        supplied = request.headers.get("x-request-id", "")
        if _REQUEST_ID.fullmatch(supplied):
            return supplied
        return str(uuid4())

    @staticmethod
    def _apply_security_headers(request: Request, response: Response, request_id: str) -> None:
        response.headers["X-Request-ID"] = request_id
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
        match = _WORKSPACE_PATH.match(request.url.path)
        return match.group(1) if match else None

    @staticmethod
    def _outcome(status_code: int) -> AuditOutcome:
        if status_code in {401, 403}:
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
            logger.exception("failed to persist audit event %s", event.id)
