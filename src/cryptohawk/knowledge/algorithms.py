from __future__ import annotations

from dataclasses import dataclass

from cryptohawk.domain.models import Primitive, QuantumStatus


@dataclass(frozen=True, slots=True)
class AlgorithmProfile:
    family: str
    primitive: Primitive
    quantum_status: QuantumStatus
    deprecated: bool = False
    migration_target: str | None = None
    migration_strategy: str | None = None
    security_bits: int | None = None
    weakness_weight: int = 0


def _profile(
    family: str,
    primitive: Primitive,
    quantum_status: QuantumStatus,
    *,
    deprecated: bool = False,
    migration_target: str | None = None,
    migration_strategy: str | None = None,
    security_bits: int | None = None,
    weakness_weight: int = 0,
) -> AlgorithmProfile:
    return AlgorithmProfile(
        family=family,
        primitive=primitive,
        quantum_status=quantum_status,
        deprecated=deprecated,
        migration_target=migration_target,
        migration_strategy=migration_strategy,
        security_bits=security_bits,
        weakness_weight=weakness_weight,
    )


PROFILES: dict[str, AlgorithmProfile] = {
    "MD5": _profile(
        "MD5",
        Primitive.HASH,
        QuantumStatus.VULNERABLE,
        deprecated=True,
        migration_target="SHA-256",
        migration_strategy="Replace immediately",
        security_bits=0,
        weakness_weight=40,
    ),
    "SHA-1": _profile(
        "SHA-1",
        Primitive.HASH,
        QuantumStatus.VULNERABLE,
        deprecated=True,
        migration_target="SHA-256",
        migration_strategy="Replace collision-sensitive uses",
        security_bits=80,
        weakness_weight=35,
    ),
    "DES": _profile(
        "DES",
        Primitive.BLOCK_CIPHER,
        QuantumStatus.VULNERABLE,
        deprecated=True,
        migration_target="AES-256-GCM",
        migration_strategy="Replace immediately",
        security_bits=56,
        weakness_weight=40,
    ),
    "3DES": _profile(
        "3DES",
        Primitive.BLOCK_CIPHER,
        QuantumStatus.VULNERABLE,
        deprecated=True,
        migration_target="AES-256-GCM",
        migration_strategy="Replace immediately",
        security_bits=112,
        weakness_weight=38,
    ),
    "RC4": _profile(
        "RC4",
        Primitive.STREAM_CIPHER,
        QuantumStatus.VULNERABLE,
        deprecated=True,
        migration_target="AES-256-GCM",
        migration_strategy="Replace immediately",
        security_bits=0,
        weakness_weight=40,
    ),
    "RSA": _profile(
        "RSA",
        Primitive.PKE,
        QuantumStatus.VULNERABLE,
        migration_target="ML-KEM",
        migration_strategy=(
            "Use hybrid classical + ML-KEM for key establishment; "
            "ML-DSA for signatures"
        ),
        security_bits=112,
        weakness_weight=18,
    ),
    "DSA": _profile(
        "DSA",
        Primitive.SIGNATURE,
        QuantumStatus.VULNERABLE,
        deprecated=True,
        migration_target="ML-DSA",
        migration_strategy="Replace signature scheme",
        security_bits=112,
        weakness_weight=32,
    ),
    "ECDSA": _profile(
        "ECDSA",
        Primitive.SIGNATURE,
        QuantumStatus.VULNERABLE,
        migration_target="ML-DSA",
        migration_strategy=(
            "Migrate signatures to ML-DSA; retain hybrid verification "
            "during transition"
        ),
        security_bits=128,
        weakness_weight=18,
    ),
    "ED25519": _profile(
        "ED25519",
        Primitive.SIGNATURE,
        QuantumStatus.VULNERABLE,
        migration_target="ML-DSA",
        migration_strategy="Migrate signatures to ML-DSA with a controlled hybrid transition",
        security_bits=128,
        weakness_weight=18,
    ),
    "ED448": _profile(
        "ED448",
        Primitive.SIGNATURE,
        QuantumStatus.VULNERABLE,
        migration_target="ML-DSA",
        migration_strategy="Migrate signatures to ML-DSA with a controlled hybrid transition",
        security_bits=224,
        weakness_weight=18,
    ),
    "ECDH": _profile(
        "ECDH",
        Primitive.KEY_AGREE,
        QuantumStatus.VULNERABLE,
        migration_target="ML-KEM",
        migration_strategy="Adopt hybrid ECDH + ML-KEM during transition",
        security_bits=128,
        weakness_weight=18,
    ),
    "DH": _profile(
        "DH",
        Primitive.KEY_AGREE,
        QuantumStatus.VULNERABLE,
        migration_target="ML-KEM",
        migration_strategy="Adopt hybrid finite-field DH + ML-KEM during transition",
        security_bits=112,
        weakness_weight=22,
    ),
    "AES": _profile(
        "AES",
        Primitive.BLOCK_CIPHER,
        QuantumStatus.TRANSITION,
        migration_target="AES-256-GCM",
        migration_strategy=(
            "Prefer 256-bit keys for long-lived post-quantum confidentiality"
        ),
        security_bits=128,
        weakness_weight=4,
    ),
    "CHACHA20": _profile(
        "ChaCha20",
        Primitive.STREAM_CIPHER,
        QuantumStatus.TRANSITION,
        migration_target="ChaCha20-Poly1305",
        migration_strategy="Retain with strong key management",
        security_bits=128,
        weakness_weight=3,
    ),
    "SHA-256": _profile(
        "SHA-256",
        Primitive.HASH,
        QuantumStatus.TRANSITION,
        migration_target="SHA-384",
        migration_strategy=(
            "Acceptable for most uses; consider wider hashes for long-lived PQ assurance"
        ),
        security_bits=128,
        weakness_weight=2,
    ),
    "SHA-384": _profile(
        "SHA-384",
        Primitive.HASH,
        QuantumStatus.SAFE,
        security_bits=192,
    ),
    "SHA-512": _profile(
        "SHA-512",
        Primitive.HASH,
        QuantumStatus.SAFE,
        security_bits=256,
    ),
    "ML-KEM": _profile(
        "ML-KEM",
        Primitive.KEM,
        QuantumStatus.SAFE,
        security_bits=128,
    ),
    "ML-DSA": _profile(
        "ML-DSA",
        Primitive.SIGNATURE,
        QuantumStatus.SAFE,
        security_bits=128,
    ),
    "SLH-DSA": _profile(
        "SLH-DSA",
        Primitive.SIGNATURE,
        QuantumStatus.SAFE,
        security_bits=128,
    ),
}


ALIASES: dict[str, str] = {
    "SHA1": "SHA-1",
    "SHA256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA512": "SHA-512",
    "TRIPLEDES": "3DES",
    "DES3": "3DES",
    "ARC4": "RC4",
    "KYBER": "ML-KEM",
    "CRYSTALS-KYBER": "ML-KEM",
    "DILITHIUM": "ML-DSA",
    "CRYSTALS-DILITHIUM": "ML-DSA",
    "SPHINCS+": "SLH-DSA",
    "SSH-ED25519": "ED25519",
}


def normalize_family(value: str) -> str:
    token = value.strip().upper().replace("_", "-")
    if token in ALIASES:
        return ALIASES[token]
    if token.startswith("AES-"):
        return "AES"
    if token.startswith("RSA"):
        return "RSA"
    if token.startswith("ECDSA"):
        return "ECDSA"
    if token.startswith("ECDH"):
        return "ECDH"
    if token.startswith("ED25519"):
        return "ED25519"
    if token.startswith("ED448"):
        return "ED448"
    if token.startswith("ML-KEM"):
        return "ML-KEM"
    if token.startswith("ML-DSA"):
        return "ML-DSA"
    if token.startswith("SLH-DSA"):
        return "SLH-DSA"
    if token.startswith("CHACHA20"):
        return "CHACHA20"
    return token


def get_profile(family: str) -> AlgorithmProfile | None:
    return PROFILES.get(normalize_family(family))
