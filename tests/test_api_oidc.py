from pathlib import Path

from fastapi.testclient import TestClient

import cryptohawk.api.app as api_module
import cryptohawk.api.middleware as middleware_module
import cryptohawk.api.oidc as oidc_api
from cryptohawk.services.oidc import OidcAuthorizationStart
from cryptohawk.storage.audit import AuditRepository
from cryptohawk.storage.auth import AuthRepository
from cryptohawk.storage.inventory import InventoryRepository


class _FakeOidcService:
    def __init__(self, user_id: str) -> None:
        self.user_id = user_id
        self.browser_binding = ""
        self.callback: tuple[str, str, str] | None = None
        self.exchange: tuple[str, str] | None = None

    async def begin_authorization(self, *, browser_binding: str) -> OidcAuthorizationStart:
        self.browser_binding = browser_binding
        return OidcAuthorizationStart(
            authorization_url="https://idp.example.com/authorize?client_id=cryptohawk"
        )

    async def complete_authorization(
        self,
        *,
        code: str,
        state: str,
        browser_binding: str,
    ) -> str:
        self.callback = (code, state, browser_binding)
        if browser_binding != self.browser_binding:
            raise PermissionError("binding mismatch")
        return "choc_completion-code-value"

    def consume_completion(self, *, code: str, browser_binding: str) -> str:
        self.exchange = (code, browser_binding)
        if code != "choc_completion-code-value" or browser_binding != self.browser_binding:
            raise PermissionError("invalid completion")
        return self.user_id


def test_oidc_http_flow_uses_browser_binding_and_normal_session(
    tmp_path: Path,
    monkeypatch,
) -> None:
    inventory = InventoryRepository(f"sqlite:///{tmp_path / 'api-oidc.db'}")
    inventory.create_schema()
    auth = AuthRepository(inventory)
    issued = auth.bootstrap(
        email="owner@example.com",
        display_name="Owner",
        password="correct-horse-battery-staple",
        workspace_name="Acme",
        workspace_slug="acme",
    )
    assert issued.user is not None

    audit = AuditRepository(inventory)
    fake = _FakeOidcService(issued.user.id)
    monkeypatch.setattr(oidc_api, "auth_repo", auth)
    monkeypatch.setattr(oidc_api, "_oidc_service", fake)
    monkeypatch.setattr(oidc_api, "_rate_limit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(oidc_api.settings, "oidc_enabled", True)
    monkeypatch.setattr(oidc_api.settings, "oidc_frontend_url", "https://app.example.com")
    monkeypatch.setattr(middleware_module, "audit_repo", audit)

    client = TestClient(api_module.app)

    status_response = client.get("/api/v1/auth/oidc/status")
    assert status_response.status_code == 200
    assert status_response.json() == {"enabled": True}

    start = client.get("/api/v1/auth/oidc/start", follow_redirects=False)
    assert start.status_code == 307
    assert start.headers["location"].startswith("https://idp.example.com/authorize")
    assert fake.browser_binding
    assert client.cookies.get("cryptohawk_oidc_binding") == fake.browser_binding

    callback = client.get(
        "/api/v1/auth/oidc/callback?code=provider-code&state=provider-state",
        follow_redirects=False,
    )
    assert callback.status_code == 303
    assert callback.headers["location"] == (
        "https://app.example.com/#oidc_code=choc_completion-code-value"
    )
    assert fake.callback == ("provider-code", "provider-state", fake.browser_binding)
    assert client.cookies.get("cryptohawk_oidc_binding") == fake.browser_binding

    exchange = client.post(
        "/api/v1/auth/oidc/exchange",
        json={"code": "choc_completion-code-value"},
    )
    assert exchange.status_code == 200
    body = exchange.json()
    assert body["user"]["id"] == issued.user.id
    assert body["token"].startswith("chs_")
    assert fake.exchange == ("choc_completion-code-value", fake.browser_binding)
    principal = auth.authenticate(body["token"])
    assert principal.user_id == issued.user.id
    assert client.cookies.get("cryptohawk_oidc_binding") is None
