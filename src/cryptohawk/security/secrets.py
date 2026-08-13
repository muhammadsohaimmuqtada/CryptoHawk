from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecretConfigurationError(RuntimeError):
    """Raised when connector secret encryption is not configured safely."""


class SecretDecryptionError(RuntimeError):
    """Raised when encrypted connector secret material cannot be authenticated."""


@dataclass(frozen=True)
class EncryptedSecret:
    ciphertext: bytes
    nonce: bytes
    key_version: int


class VersionedAesGcmCipher:
    def __init__(self, keys: Mapping[int, bytes], *, active_version: int) -> None:
        normalized = dict(keys)
        if not normalized:
            raise SecretConfigurationError("at least one connector encryption key is required")
        for version, key in normalized.items():
            if version < 1:
                raise SecretConfigurationError("connector key versions must be positive integers")
            if len(key) != 32:
                raise SecretConfigurationError("connector encryption keys must be exactly 32 bytes")
        if active_version not in normalized:
            raise SecretConfigurationError("active connector encryption key version is unavailable")
        self._keys = normalized
        self.active_version = active_version

    @classmethod
    def from_spec(cls, spec: str, *, active_version: int) -> "VersionedAesGcmCipher":
        keys: dict[int, bytes] = {}
        for entry in (part.strip() for part in spec.split(",")):
            if not entry:
                continue
            version_text, separator, encoded = entry.partition(":")
            if not separator:
                raise SecretConfigurationError(
                    "connector encryption keys must use VERSION:BASE64URL format"
                )
            try:
                version = int(version_text)
            except ValueError as exc:
                raise SecretConfigurationError(
                    "connector encryption key version must be an integer"
                ) from exc
            if version in keys:
                raise SecretConfigurationError("duplicate connector encryption key version")
            try:
                padding = "=" * (-len(encoded) % 4)
                key = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
            except Exception as exc:
                raise SecretConfigurationError(
                    "connector encryption key is not valid base64url"
                ) from exc
            keys[version] = key
        return cls(keys, active_version=active_version)

    @staticmethod
    def generate_key() -> str:
        return base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256)).decode().rstrip("=")

    @staticmethod
    def _aad(
        *,
        workspace_id: str,
        credential_id: str,
        kind: str,
        key_version: int,
    ) -> bytes:
        return (
            "cryptohawk.connector-credential|v1|"
            f"workspace:{workspace_id}|credential:{credential_id}|"
            f"kind:{kind}|key:{key_version}"
        ).encode("utf-8")

    def encrypt(
        self,
        secret: dict[str, str],
        *,
        workspace_id: str,
        credential_id: str,
        kind: str,
    ) -> EncryptedSecret:
        plaintext = json.dumps(
            secret,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        nonce = os.urandom(12)
        aad = self._aad(
            workspace_id=workspace_id,
            credential_id=credential_id,
            kind=kind,
            key_version=self.active_version,
        )
        ciphertext = AESGCM(self._keys[self.active_version]).encrypt(nonce, plaintext, aad)
        return EncryptedSecret(
            ciphertext=ciphertext,
            nonce=nonce,
            key_version=self.active_version,
        )

    def decrypt(
        self,
        encrypted: EncryptedSecret,
        *,
        workspace_id: str,
        credential_id: str,
        kind: str,
    ) -> dict[str, str]:
        key = self._keys.get(encrypted.key_version)
        if key is None:
            raise SecretDecryptionError("credential encryption key version is unavailable")
        aad = self._aad(
            workspace_id=workspace_id,
            credential_id=credential_id,
            kind=kind,
            key_version=encrypted.key_version,
        )
        try:
            plaintext = AESGCM(key).decrypt(encrypted.nonce, encrypted.ciphertext, aad)
        except (InvalidTag, ValueError) as exc:
            raise SecretDecryptionError(
                "credential ciphertext failed authentication"
            ) from exc
        try:
            decoded = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecretDecryptionError("credential plaintext is invalid") from exc
        if not isinstance(decoded, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in decoded.items()
        ):
            raise SecretDecryptionError("credential plaintext has an invalid structure")
        return decoded
