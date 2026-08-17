from __future__ import annotations

import hashlib
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from cryptohawk.api.auth import auth_repo, get_quota_repository, inventory
from cryptohawk.config import settings
from cryptohawk.domain.auth import IssuedToken
from cryptohawk.security.oidc import OidcTransactionCipher
from cryptohawk.services.oidc import OidcConfigurationError, OidcProviderError, OidcService
from cryptohawk.storage.oidc import OidcRepository

router = APIRouter()
_BINDING_COOKIE = "cryptohawk_oidc_binding"
_oidc_service: OidcService | None = None


class OidcExchangeRequest(BaseModel):
    code: str = Field(min_length=20, max_length=512)


def _service() -> OidcService:
    global _oidc_service
    if not settings.oidc_enabled:
        raise HTTPException(status_code=404, detail="OIDC is disabled")
    if _oidc_service is None:
        cipher = OidcTransactionCipher.from_spec(
            settings.connector_encryption_keys,
            active_version=settings.connector_encryption_active_version,
        )
        _oidc_service = OidcService(
            settings,
            OidcRepository(inventory, cipher=cipher),
        )
    return _oidc_service


def _rate_limit(request: Request, action: str) -> None:
    peer = request.client.host if request.client is not None else "unknown"
    scope = hashlib.sha256(peer.encode()).hexdigest()
    decision = get_quota_repository().consume(
        scope_key=f"oidc:{scope}",
        action=action,
        limit=settings.login_attempts_per_15_minutes,
        window_seconds=900,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail="OIDC authentication quota exceeded",
            headers={"Retry-After": str(max(1, decision.retry_after_seconds))},
        )


def _frontend_redirect(fragment: str) -> str:
    origin = settings.oidc_frontend_url.strip().rstrip("/")
    return f"{origin}/#{fragment}"


def _set_binding_cookie(response: Response, value: str, max_age: int) -> None:
    response.set_cookie(
        _BINDING_COOKIE,
        value,
        max_age=max_age,
        httponly=True,
        secure=settings.is_production,
        samesite="lax",
        path="/api/v1/auth/oidc",
    )


def _clear_binding_cookie(response: Response) -> None:
    response.delete_cookie(
        _BINDING_COOKIE,
        path="/api/v1/auth/oidc",
        httponly=True,
        secure=settings.is_production,
        samesite="lax",
    )


@router.get("/api/v1/auth/oidc/status")
def oidc_status() -> dict[str, bool]:
    return {"enabled": settings.oidc_enabled}


@router.get("/api/v1/auth/oidc/start")
async def oidc_start(request: Request) -> Response:
    _rate_limit(request, "start")
    try:
        started = await _service().begin_authorization()
    except OidcConfigurationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except OidcProviderError as exc:
        raise HTTPException(status_code=503, detail="OIDC provider unavailable") from exc

    response = RedirectResponse(
        started.authorization_url,
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    )
    _set_binding_cookie(
        response,
        started.browser_binding,
        settings.oidc_transaction_ttl_seconds,
    )
    return response


@router.get("/api/v1/auth/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> Response:
    browser_binding = request.cookies.get(_BINDING_COOKIE, "")
    if error or not code or not state or not browser_binding:
        response = RedirectResponse(
            _frontend_redirect("oidc_error=authentication_failed"),
            status_code=status.HTTP_303_SEE_OTHER,
        )
        _clear_binding_cookie(response)
        return response

    try:
        completion = await _service().complete_authorization(
            code=code,
            state=state,
            browser_binding=browser_binding,
        )
    except (PermissionError, OidcConfigurationError, OidcProviderError):
        response = RedirectResponse(
            _frontend_redirect("oidc_error=authentication_failed"),
            status_code=status.HTTP_303_SEE_OTHER,
        )
        _clear_binding_cookie(response)
        return response

    response = RedirectResponse(
        _frontend_redirect(f"oidc_code={quote(completion, safe='')}"),
        status_code=status.HTTP_303_SEE_OTHER,
    )
    _set_binding_cookie(
        response,
        browser_binding,
        settings.oidc_completion_ttl_seconds,
    )
    return response


@router.post("/api/v1/auth/oidc/exchange", response_model=IssuedToken)
def oidc_exchange(
    payload: OidcExchangeRequest,
    request: Request,
    response: Response,
) -> IssuedToken:
    _rate_limit(request, "exchange")
    browser_binding = request.cookies.get(_BINDING_COOKIE, "")
    if not browser_binding:
        raise HTTPException(status_code=401, detail="OIDC browser binding is missing")
    try:
        user_id = _service().consume_completion(
            code=payload.code,
            browser_binding=browser_binding,
        )
        issued = auth_repo.create_session(user_id, session_hours=settings.session_hours)
        user = auth_repo.get_user(user_id)
        if user is None:
            raise LookupError("SSO user is unavailable")
    except (PermissionError, LookupError, OidcConfigurationError) as exc:
        raise HTTPException(status_code=401, detail="OIDC completion is invalid") from exc

    _clear_binding_cookie(response)
    return issued.model_copy(update={"user": user})


__all__ = ["router"]
