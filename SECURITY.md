# Security Policy

CryptoHawk is security software and security reports are treated as product-critical engineering work.

## Supported versions

| Version | Security support |
| --- | --- |
| `0.9.x` | Supported commercial-pilot release line |
| `< 0.9.0` | Pre-release engineering builds; upgrade before reporting deployment-specific issues |

CryptoHawk 0.9 is a commercial-pilot candidate, not a generally available enterprise release. See `docs/RELEASE_QUALIFICATION.md` for the release claim boundary.

## Reporting a vulnerability

Please use **GitHub's private vulnerability reporting / Security Advisory workflow** for this repository when available. Do not open a public GitHub issue for an unpatched vulnerability, credential exposure or exploit chain.

A useful report includes:

- affected CryptoHawk version or commit SHA;
- deployment model and relevant configuration with secrets removed;
- affected endpoint/component/collector;
- clear reproduction steps;
- expected versus observed security boundary;
- impact and attacker prerequisites;
- minimal proof material that does not contain customer secrets or unauthorized third-party data.

Do not include production credentials, connector tokens, encryption keys, private repository contents, customer scan databases or unrelated personal data in a report.

## Scope priorities

High-priority security boundaries include:

- workspace/tenant isolation and RBAC bypass;
- authentication, session and API-key handling;
- connector credential encryption, decryption and redaction;
- repository acquisition sandbox/URL/network restrictions;
- private-target network policy and DNS-rebinding resistance;
- container/archive path traversal, decompression limits and unintended execution;
- unsafe deserialization or code execution;
- stored/reflected injection through evidence, reports or operator UI;
- audit/evidence integrity;
- queue/concurrency failures that cross tenant boundaries;
- production configuration bypasses that silently weaken documented invariants.

## Safe research expectations

Only test systems, repositories, images and endpoints you own or are explicitly authorized to assess. Avoid denial-of-service, destructive testing, social engineering and access to unrelated customer data.

If research reveals a live secret, stop using it, preserve only the minimum evidence necessary to report the issue and do not rotate or modify third-party credentials unless you are authorized to do so.

## Disclosure process

Security fixes should land through a private or minimally disclosed patch path when premature publication would create material risk. Once a fix is available, maintainers may publish an advisory with affected versions, impact, mitigation and upgrade guidance.

Security-related release changes must pass the same exact-head backend, frontend, PostgreSQL reliability, release-qualification and container-build gates as other release changes.
