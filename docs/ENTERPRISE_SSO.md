# Enterprise OpenID Connect SSO

CryptoHawk supports optional deployment-wide OpenID Connect (OIDC) single sign-on for commercial-pilot and enterprise deployments. OIDC is disabled by default and local high-entropy CryptoHawk sessions remain the authorization boundary after authentication.

## Security model

CryptoHawk uses the OIDC Authorization Code flow with PKCE S256. The login transaction uses server-generated `state`, `nonce`, PKCE verifier and a browser-binding cookie.

The PKCE verifier and nonce are stored only in short-lived server-side transaction state and are encrypted at rest with CryptoHawk's existing versioned AES-256-GCM keyring. The raw `state`, browser binding and one-time completion code are stored only as SHA-256 hashes.

After the IdP callback succeeds, CryptoHawk does **not** expose the provider access token to the frontend. Instead it issues a short-lived, one-time CryptoHawk completion code in the URL fragment. The browser exchanges that code, together with the HttpOnly browser-binding cookie, for a normal CryptoHawk session token. The completion record is then deleted.

CryptoHawk does not persist IdP access or refresh tokens.

## Identity and authorization boundary

OIDC authentication does not create a workspace, membership or role.

A user must already exist in CryptoHawk with the same normalized email address before their first successful SSO login. On that first login, CryptoHawk links the user to the immutable `(issuer, subject)` OIDC identity. Later logins use that immutable identity and do not relink access merely because an email claim changed.

The link is one-to-one for a configured issuer. A CryptoHawk user already linked to one subject cannot silently be linked to another subject for the same issuer.

Workspace RBAC remains entirely authoritative inside CryptoHawk. IdP groups or roles are not automatically converted into CryptoHawk roles in the 0.9 pilot line.

## ID token requirements

CryptoHawk validates:

- a cryptographic ID-token signature using provider JWKS;
- exact configured issuer;
- CryptoHawk client ID as the token audience;
- `exp`, `iat`, `sub` and transaction `nonce`;
- `azp` when present;
- email syntax;
- `email_verified=true` by default.

Permitted asymmetric signing algorithms are:

- RS256 / RS384 / RS512;
- PS256 / PS384 / PS512;
- ES256 / ES384 / ES512;
- EdDSA.

Symmetric `HS*` ID-token signatures and `alg=none` are not accepted.

## Provider discovery and outbound network boundary

CryptoHawk fetches the provider's OIDC discovery document from:

```text
{issuer}/.well-known/openid-configuration
```

The returned issuer must exactly match the configured issuer. Authorization, token and JWKS endpoint URLs are validated before use. Redirect following is disabled for discovery, token and JWKS requests.

Production OIDC URLs must use HTTPS and cannot use loopback hosts. Public-address validation is enabled by default. A deployment that intentionally operates an internal/private IdP must explicitly set:

```text
CRYPTOHAWK_OIDC_ALLOW_PRIVATE_PROVIDER=true
```

Do not enable that option for an Internet-facing public IdP.

## IdP application configuration

Register CryptoHawk as a confidential OIDC web application at the IdP.

Required flow/capabilities:

- Authorization Code;
- PKCE S256;
- OpenID Connect;
- `openid`, `profile`, `email` scopes;
- a client secret;
- `client_secret_basic` or `client_secret_post` token endpoint authentication;
- an ID token with a stable `sub` and email claim.

Register exactly one CryptoHawk callback URL matching:

```text
https://<cryptohawk-host>/api/v1/auth/oidc/callback
```

## CryptoHawk configuration

Example production configuration:

```text
CRYPTOHAWK_OIDC_ENABLED=true
CRYPTOHAWK_OIDC_ISSUER=https://idp.example.com
CRYPTOHAWK_OIDC_CLIENT_ID=<client-id>
CRYPTOHAWK_OIDC_CLIENT_SECRET=<client-secret>
CRYPTOHAWK_OIDC_REDIRECT_URI=https://cryptohawk.example.com/api/v1/auth/oidc/callback
CRYPTOHAWK_OIDC_FRONTEND_URL=https://cryptohawk.example.com
CRYPTOHAWK_OIDC_SCOPES=openid profile email
CRYPTOHAWK_OIDC_TOKEN_ENDPOINT_AUTH_METHOD=client_secret_basic
CRYPTOHAWK_OIDC_REQUIRE_VERIFIED_EMAIL=true
CRYPTOHAWK_OIDC_ALLOW_PRIVATE_PROVIDER=false
```

OIDC transaction encryption also requires the normal CryptoHawk connector keyring:

```text
CRYPTOHAWK_CONNECTOR_ENCRYPTION_KEYS=<versioned AES-256-GCM keyring>
CRYPTOHAWK_CONNECTOR_ENCRYPTION_ACTIVE_VERSION=1
```

Production startup fails closed when required OIDC configuration is incomplete, uses unsafe URL forms, omits required scopes, or lacks the encryption keyring.

After changing OIDC configuration, restart the API service.

## User provisioning

Before a user's first SSO login:

1. create/provision the CryptoHawk user with the email address asserted by the IdP;
2. assign the intended workspace membership and CryptoHawk role;
3. then allow the user to select **Sign in with enterprise SSO**.

An unknown IdP identity receives no CryptoHawk access and no workspace membership.

## Browser flow

The web application checks whether OIDC is enabled. When enabled and initial bootstrap has already been completed, the login surface exposes **Sign in with enterprise SSO**.

The browser flow is:

```text
CryptoHawk login
    → /api/v1/auth/oidc/start
    → IdP authorization endpoint
    → /api/v1/auth/oidc/callback
    → frontend URL fragment with one-time completion code
    → /api/v1/auth/oidc/exchange
    → normal CryptoHawk session
```

The browser-binding cookie is HttpOnly and SameSite=Lax; in production it is also Secure.

## Operational checks before enabling for a customer

- confirm the IdP's discovery issuer exactly equals `CRYPTOHAWK_OIDC_ISSUER`;
- confirm the registered callback URI exactly equals `CRYPTOHAWK_OIDC_REDIRECT_URI`;
- confirm expected email verification behavior;
- pre-provision a non-admin test user and verify tenant isolation;
- verify logout revokes the CryptoHawk session;
- verify an unknown IdP identity cannot auto-provision access;
- verify changing an IdP email does not move an existing linked identity to another CryptoHawk account;
- retain local break-glass owner access according to the deployment's operating policy.

SAML is not implemented in the 0.9 pilot line. Enterprises that expose SAML through an OIDC-capable identity broker can use that broker while CryptoHawk remains an OIDC relying party.
