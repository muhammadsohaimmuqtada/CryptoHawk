# Connector Credential Security

CryptoHawk connector credentials are security-sensitive infrastructure secrets. The platform treats them as encrypted execution inputs, not application data.

## Storage contract

- Connector secret values are encrypted before persistence with AES-256-GCM.
- Each encryption operation uses a fresh 96-bit nonce.
- Authenticated additional data binds ciphertext to the workspace, credential ID, connector kind, and key version. Copying ciphertext into another tenant or credential record does not produce valid plaintext.
- Only ciphertext, nonce, key version, secret-field names, and non-secret metadata are persisted.
- Secret values are never returned by list, create, replace, rotate, or delete APIs.
- Credential-management APIs require workspace `admin` or `owner` authorization.
- Worker/collector code must obtain secret material only through `ConnectorCredentialRepository.resolve_for_use`; there is intentionally no HTTP endpoint that returns plaintext.

## Master keys

Runtime keys are supplied through:

```text
CRYPTOHAWK_CONNECTOR_ENCRYPTION_KEYS=1:<base64url-32-byte-key>,2:<base64url-32-byte-key>
CRYPTOHAWK_CONNECTOR_ENCRYPTION_ACTIVE_VERSION=2
```

Every key must decode to exactly 32 random bytes. The active version must exist in the configured keyring. Production startup refuses to enable the API when the keyring is absent.

Generate key material with a cryptographically secure generator. For example, the Python API exposes `VersionedAesGcmCipher.generate_key()` for operator tooling. Do not commit generated keys to Git, bake them into container images, or reuse development examples.

In a managed deployment the environment variables should be populated from the deployment secret manager/KMS integration rather than a checked-in environment file.

## Rotation

1. Add the new key version while retaining the previous decrypt key.
2. Set `CRYPTOHAWK_CONNECTOR_ENCRYPTION_ACTIVE_VERSION` to the new version.
3. Re-encrypt stored credentials through the rotate-encryption operation.
4. Verify all credentials report the new key version and can be used successfully.
5. Remove the retired key only after no credential references it.

Removing an old key before re-encryption intentionally makes those records undecryptable rather than silently falling back to unsafe behavior.

## Logging and audit

API mutation audit events record route identity, actor, status, and request ID. They do not record request bodies. Secret values must never be added to structured logs, exception messages, metrics labels, audit metadata, traces, or finding evidence.

Credential creation, replacement, rotation, and deletion are auditable API mutations. Collector execution that resolves a credential must emit only the credential ID and connector identity when execution-level audit events are added; it must never emit resolved fields or values.

## Incident response

If a master key or connector credential is suspected compromised:

1. Revoke/rotate the upstream connector credential.
2. Introduce a new CryptoHawk encryption key version.
3. Re-encrypt surviving credentials.
4. Review workspace audit events for credential mutations and connector activity.
5. Remove the compromised master-key version only after all stored records have migrated.
