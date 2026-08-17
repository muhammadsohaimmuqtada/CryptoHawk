from __future__ import annotations

from dataclasses import dataclass

from cryptohawk.security.secrets import EncryptedSecret, VersionedAesGcmCipher


@dataclass(frozen=True)
class OidcTransactionSecret:
    code_verifier: str
    nonce: str


class OidcTransactionCipher:
    """Reuse CryptoHawk's versioned AES-GCM keyring for short-lived OIDC state."""

    def __init__(self, cipher: VersionedAesGcmCipher) -> None:
        self._cipher = cipher

    @classmethod
    def from_spec(cls, spec: str, *, active_version: int) -> "OidcTransactionCipher":
        return cls(VersionedAesGcmCipher.from_spec(spec, active_version=active_version))

    def encrypt(self, secret: OidcTransactionSecret, *, transaction_id: str) -> EncryptedSecret:
        return self._cipher.encrypt(
            {
                "code_verifier": secret.code_verifier,
                "nonce": secret.nonce,
            },
            workspace_id="__oidc__",
            credential_id=transaction_id,
            kind="oidc-transaction",
        )

    def decrypt(
        self,
        payload: EncryptedSecret,
        *,
        transaction_id: str,
    ) -> OidcTransactionSecret:
        values = self._cipher.decrypt(
            payload,
            workspace_id="__oidc__",
            credential_id=transaction_id,
            kind="oidc-transaction",
        )
        verifier = values.get("code_verifier")
        nonce = values.get("nonce")
        if not verifier or not nonce:
            raise ValueError("OIDC transaction secret is incomplete")
        return OidcTransactionSecret(code_verifier=verifier, nonce=nonce)


__all__ = ["OidcTransactionCipher", "OidcTransactionSecret"]
