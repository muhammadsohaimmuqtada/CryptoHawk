from __future__ import annotations

import argparse
import json
import os
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_EMAIL = "tester@cryptohawk.local"
DEFAULT_PASSWORD = "CryptoHawk-Eval-Only-2026!"
DEFAULT_WORKSPACE = "CryptoHawk Evaluation"
DEFAULT_SLUG = "cryptohawk-evaluation"


def _env(name: str, default: str) -> str:
    return os.getenv(name, default).strip()


def _require_evaluation_mode() -> None:
    if _env("CRYPTOHAWK_EVALUATION_MODE", "false").lower() != "true":
        raise SystemExit(
            "evaluation harness is disabled; set CRYPTOHAWK_EVALUATION_MODE=true"
        )


def _request(
    base_url: str,
    method: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    token: str | None = None,
    timeout: float = 15.0,
) -> Any:
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(
        f"{base_url.rstrip('/')}{path}",
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            data = response.read()
            if not data:
                return None
            content_type = response.headers.get("Content-Type", "")
            if "application/json" in content_type:
                return json.loads(data.decode("utf-8"))
            return data
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {path} failed with HTTP {exc.code}: {detail}") from exc


def _wait_for(url: str, path: str, *, attempts: int = 60) -> None:
    last_error: Exception | None = None
    for _ in range(attempts):
        try:
            _request(url, "GET", path, timeout=2.0)
            return
        except (RuntimeError, URLError, TimeoutError) as exc:
            last_error = exc
            time.sleep(1)
    raise RuntimeError(f"service did not become ready: {url}{path}: {last_error}")


def _login_or_bootstrap(api_url: str) -> tuple[str, dict[str, Any]]:
    email = _env("CRYPTOHAWK_EVALUATION_EMAIL", DEFAULT_EMAIL)
    password = _env("CRYPTOHAWK_EVALUATION_PASSWORD", DEFAULT_PASSWORD)
    status = _request(api_url, "GET", "/api/v1/auth/status")
    if status["bootstrap_required"]:
        issued = _request(
            api_url,
            "POST",
            "/api/v1/auth/bootstrap",
            payload={
                "email": email,
                "display_name": "Evaluation Owner",
                "password": password,
                "workspace_name": DEFAULT_WORKSPACE,
                "workspace_slug": DEFAULT_SLUG,
            },
        )
        return issued["token"], issued["workspace"]

    issued = _request(
        api_url,
        "POST",
        "/api/v1/auth/login",
        payload={"email": email, "password": password},
    )
    token = issued["token"]
    workspaces = _request(api_url, "GET", "/api/v1/workspaces", token=token)
    workspace = next((item for item in workspaces if item["slug"] == DEFAULT_SLUG), None)
    if workspace is None:
        raise RuntimeError(
            "evaluation database already contains a different bootstrap identity; "
            "run `make evaluation-down` before retrying"
        )
    return token, workspace


def _ensure_asset(
    api_url: str,
    token: str,
    workspace_id: str,
    *,
    name: str,
    locator: str,
    context: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    path = f"/api/v1/workspaces/{workspace_id}/assets"
    assets = _request(api_url, "GET", path, token=token)
    existing = next((item for item in assets if item["name"] == name), None)
    if existing is not None:
        return existing, False
    asset = _request(
        api_url,
        "POST",
        path,
        token=token,
        payload={
            "name": name,
            "kind": "source",
            "locator": locator,
            "context": context,
            "tags": {"evaluation": "synthetic", "owner": "security-platform"},
        },
    )
    return asset, True


def _scan_if_needed(
    api_url: str,
    token: str,
    workspace_id: str,
    asset: dict[str, Any],
    source: str,
) -> None:
    findings_path = f"/api/v1/workspaces/{workspace_id}/findings"
    findings = _request(api_url, "GET", findings_path, token=token)
    if any(item["observation"]["asset_name"] == asset["name"] for item in findings):
        return
    _request(
        api_url,
        "POST",
        f"/api/v1/workspaces/{workspace_id}/assets/{asset['id']}/scan",
        token=token,
        payload={"source": source, "filename": asset["locator"]},
    )


def seed() -> None:
    _require_evaluation_mode()
    api_url = _env("CRYPTOHAWK_EVALUATION_API_URL", "http://api:8000")
    _wait_for(api_url, "/health/ready")
    token, workspace = _login_or_bootstrap(api_url)
    workspace_id = workspace["id"]

    payments, _ = _ensure_asset(
        api_url,
        token,
        workspace_id,
        name="Payments Service",
        locator="evaluation/payments.py",
        context={
            "internet_exposed": True,
            "asset_criticality": 10,
            "data_lifetime_years": 8,
            "environment": "production",
        },
    )
    identity, _ = _ensure_asset(
        api_url,
        token,
        workspace_id,
        name="Identity Service",
        locator="evaluation/identity.py",
        context={
            "internet_exposed": False,
            "asset_criticality": 8,
            "data_lifetime_years": 5,
            "environment": "production",
        },
    )

    _scan_if_needed(
        api_url,
        token,
        workspace_id,
        payments,
        'legacy_hash = "SHA1"\nkey = "RSA-2048"\ncipher = "AES-128"\n',
    )
    _scan_if_needed(
        api_url,
        token,
        workspace_id,
        identity,
        'signing = "ECDSA"\nexchange = "ECDH"\npq_target = "ML-KEM"\n',
    )

    findings = _request(
        api_url,
        "GET",
        f"/api/v1/workspaces/{workspace_id}/findings",
        token=token,
    )
    if len(findings) < 5:
        raise RuntimeError("evaluation seed did not create the expected cryptographic findings")

    print(
        "evaluation seed ready:",
        f"workspace={workspace['slug']}",
        "assets=2",
        f"findings={len(findings)}",
    )


def smoke() -> None:
    _require_evaluation_mode()
    api_url = _env("CRYPTOHAWK_EVALUATION_API_URL", "http://api:8000")
    web_url = _env("CRYPTOHAWK_EVALUATION_WEB_URL", "http://web:8080")
    email = _env("CRYPTOHAWK_EVALUATION_EMAIL", DEFAULT_EMAIL)
    password = _env("CRYPTOHAWK_EVALUATION_PASSWORD", DEFAULT_PASSWORD)

    _wait_for(api_url, "/health/ready")
    _wait_for(web_url, "/health")

    issued = _request(
        web_url,
        "POST",
        "/api/v1/auth/login",
        payload={"email": email, "password": password},
    )
    token = issued["token"]
    workspaces = _request(web_url, "GET", "/api/v1/workspaces", token=token)
    workspace = next((item for item in workspaces if item["slug"] == DEFAULT_SLUG), None)
    if workspace is None:
        raise RuntimeError("evaluation workspace is missing")
    workspace_id = workspace["id"]

    probe_slug = "evaluation-workspace-create-probe"
    probe = _request(
        web_url,
        "POST",
        "/api/v1/workspaces",
        token=token,
        payload={"name": "Evaluation Workspace Create Probe", "slug": probe_slug},
    )
    if probe.get("slug") != probe_slug:
        raise RuntimeError("secondary workspace creation returned an unexpected workspace")
    listed = _request(web_url, "GET", "/api/v1/workspaces", token=token)
    if not any(item["id"] == probe["id"] for item in listed):
        raise RuntimeError("newly created workspace is not visible to its owner")
    _request(
        web_url,
        "DELETE",
        f"/api/v1/workspaces/{probe['id']}",
        token=token,
        payload={"confirm_slug": probe_slug},
    )
    listed_after_delete = _request(web_url, "GET", "/api/v1/workspaces", token=token)
    if any(item["id"] == probe["id"] for item in listed_after_delete):
        raise RuntimeError("workspace creation probe could not be deleted cleanly")

    assets = _request(
        web_url,
        "GET",
        f"/api/v1/workspaces/{workspace_id}/assets",
        token=token,
    )
    findings = _request(
        web_url,
        "GET",
        f"/api/v1/workspaces/{workspace_id}/findings",
        token=token,
    )
    executive = _request(
        web_url,
        "GET",
        f"/api/v1/workspaces/{workspace_id}/reports/executive",
        token=token,
    )
    cbom = _request(
        web_url,
        "GET",
        f"/api/v1/workspaces/{workspace_id}/reports/cbom",
        token=token,
    )
    evidence = _request(
        web_url,
        "GET",
        f"/api/v1/workspaces/{workspace_id}/reports/pilot-evidence.zip",
        token=token,
    )
    index = _request(web_url, "GET", "/")

    if len(assets) < 2 or len(findings) < 5:
        raise RuntimeError("evaluation estate is incomplete")
    if executive["summary"]["active_findings"] != len(findings):
        raise RuntimeError("executive report does not match active finding state")
    if cbom.get("specVersion") != "1.7":
        raise RuntimeError("CycloneDX CBOM is not version 1.7")
    if not isinstance(evidence, bytes) or not evidence.startswith(b"PK"):
        raise RuntimeError("pilot evidence ZIP could not be exported through the web proxy")
    if not isinstance(index, bytes) or b'id="root"' not in index:
        raise RuntimeError("compiled operator web application was not served")

    print(
        "evaluation smoke passed:",
        f"workspace={workspace['slug']}",
        f"assets={len(assets)}",
        f"findings={len(findings)}",
        "workspace-create=ok",
        "reports=ok",
        "cbom=1.7",
        "web=ok",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="CryptoHawk isolated evaluation harness")
    parser.add_argument("action", choices=("seed", "smoke"))
    args = parser.parse_args()
    if args.action == "seed":
        seed()
    else:
        smoke()


if __name__ == "__main__":
    main()
