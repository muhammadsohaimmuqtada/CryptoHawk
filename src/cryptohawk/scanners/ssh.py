from __future__ import annotations

import base64
import hashlib
import socket

import paramiko

from cryptohawk.domain.models import (
    AssetType,
    CryptoAssetType,
    CryptoObservation,
    Evidence,
    Primitive,
)
from cryptohawk.security.network import resolve_target


class SSHScanner:
    """Discover SSH server host-key cryptography without authentication or commands."""

    def __init__(self, *, allow_private_targets: bool = False) -> None:
        self.allow_private_targets = allow_private_targets

    def scan(
        self,
        hostname: str,
        port: int = 22,
        timeout: float = 5.0,
    ) -> list[CryptoObservation]:
        target = resolve_target(hostname, port, allow_private=self.allow_private_targets)
        transport: paramiko.Transport | None = None
        with socket.socket(target.family, target.socktype, target.proto) as raw:
            raw.settimeout(timeout)
            raw.connect(target.sockaddr)
            try:
                transport = paramiko.Transport(raw)
                transport.banner_timeout = timeout
                transport.start_client(timeout=timeout)
                key = transport.get_remote_server_key()
                remote_version = transport.remote_version
            finally:
                if transport is not None:
                    transport.close()
        return [
            self.observation_from_key(
                key,
                locator=f"{hostname}:{port}",
                resolved_ip=target.ip,
                remote_version=remote_version,
            )
        ]

    @classmethod
    def observation_from_key(
        cls,
        key: paramiko.PKey,
        *,
        locator: str,
        resolved_ip: str | None = None,
        remote_version: str | None = None,
    ) -> CryptoObservation:
        key_name = key.get_name()
        bits = key.get_bits() or None
        family, parameter_set = cls._host_key_profile(key_name, bits)
        algorithm = cls._display_algorithm(family, parameter_set, bits, key_name)
        fingerprint = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        metadata = {
            "ssh_key_type": key_name,
            "sha256_fingerprint": f"SHA256:{fingerprint}",
            "authentication_performed": False,
            "remote_command_executed": False,
        }
        if resolved_ip:
            metadata["resolved_ip"] = resolved_ip
        if remote_version:
            metadata["remote_version"] = remote_version
        return CryptoObservation(
            asset_id=f"ssh:{locator}:{fingerprint[:16]}",
            asset_name=f"{locator} SSH host key",
            asset_type=AssetType.SSH_ENDPOINT,
            crypto_asset_type=CryptoAssetType.RELATED_CRYPTO_MATERIAL,
            algorithm=algorithm,
            family=family,
            primitive=Primitive.SIGNATURE,
            key_size=bits,
            parameter_set=parameter_set,
            confidence=1.0,
            evidence=Evidence(source="ssh-host-key", locator=locator, metadata=metadata),
        )

    @staticmethod
    def _host_key_profile(
        key_name: str,
        bits: int | None,
    ) -> tuple[str, str | None]:
        token = key_name.lower()
        if "ed25519" in token:
            return "ED25519", "Ed25519"
        if "ed448" in token:
            return "ED448", "Ed448"
        if "ecdsa-sha2-" in token:
            curve = token.split("ecdsa-sha2-", 1)[1].split("@", 1)[0]
            return "ECDSA", curve
        if "ssh-rsa" in token or "rsa-sha2-" in token:
            return "RSA", str(bits) if bits else None
        if "ssh-dss" in token:
            return "DSA", str(bits) if bits else None
        return key_name.upper(), str(bits) if bits else None

    @staticmethod
    def _display_algorithm(
        family: str,
        parameter_set: str | None,
        bits: int | None,
        key_name: str,
    ) -> str:
        if family in {"ED25519", "ED448"}:
            return family
        if family == "ECDSA" and parameter_set:
            return f"ECDSA-{parameter_set}"
        if family in {"RSA", "DSA"} and bits:
            return f"{family}-{bits}"
        return key_name
