import socket

import pytest
from fastapi.testclient import TestClient

from cryptohawk.api.app import app
from cryptohawk.security.network import NetworkTargetError, resolve_target


def test_blocks_loopback_literal_by_default() -> None:
    with pytest.raises(NetworkTargetError, match="non-global target"):
        resolve_target("127.0.0.1", 443)


def test_private_target_requires_explicit_opt_in() -> None:
    target = resolve_target("10.10.20.30", 443, allow_private=True)
    assert target.ip == "10.10.20.30"
    assert target.sockaddr == ("10.10.20.30", 443)


def test_blocks_hostname_if_any_answer_is_non_global(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: answers)

    with pytest.raises(NetworkTargetError, match="non-global address"):
        resolve_target("example.test", 443)


def test_resolution_returns_pinned_socket_address(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: answers)

    target = resolve_target("example.test", 443)
    assert target.ip == "93.184.216.34"
    assert target.sockaddr == ("93.184.216.34", 443)


def test_api_rejects_loopback_without_opening_socket() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scan/tls",
            json={"hostname": "127.0.0.1", "port": 443, "timeout": 1},
        )
    assert response.status_code == 422
    assert "non-global target is blocked" in response.json()["detail"]


def test_unspecified_target_is_blocked_even_with_private_opt_in() -> None:
    with pytest.raises(NetworkTargetError, match="unsafe target"):
        resolve_target("0.0.0.0", 443, allow_private=True)
