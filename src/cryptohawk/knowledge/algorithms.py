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


PROFILES: dict[str, AlgorithmProfile] = {
    "MD5": AlgorithmProfile("MD5", Primitive.HASH, QuantumStatus.VULNERABLE, True, "SHA-256", "Replace immediately", 0, 40),
    "SHA-1": AlgorithmProfile("SHA-1", Primitive.HASH, QuantumStatus.VULNERABLE, True, "SHA-256", "Replace collision-sensitive uses", 80, 35),
    "DES": AlgorithmProfile("DES", Primitive.BLOCK_CIPHER, QuantumStatus.VULNERABLE, True, "AES-256-GCM", "Replace immediately", 56, 40),
    "3DES": AlgorithmProfile("3DES", Primitive.BLOCK_CIPHER, QuantumStatus.VULNERABLE, True, "AES-256-GCM", "Replace immediately", 112, 38),
    "RC4": AlgorithmProfile("RC4", Primitive.STREAM_CIPHER, QuantumStatus.VULNERABLE, True, "AES-256-GCM", "Replace immediately", 0, 40),
    "RSA": AlgorithmProfile("RSA", Primitive.PKE, QuantumStatus.VULNERABLE, False, "ML-KEM", "Use hybrid classical + ML-KEM for key establishment; ML-DSA for signatures", 112, 18),
    "DSA": AlgorithmProfile("DSA", Primitive.SIGNATURE, QuantumStatus.VULNERABLE, True, "ML-DSA", "Replace signature scheme", 112, 32),
    "ECDSA": AlgorithmProfile("ECDSA", Primitive.SIGNATURE, QuantumStatus.VULNERABLE, False, "ML-DSA", "Migrate signatures to ML-DSA; retain hybrid verification during transition", 128, 18),
    "ECDH": AlgorithmProfile("ECDH", Primitive.KEY_AGREE, QuantumStatus.VULNERABLE, False, "ML-KEM", "Adopt hybrid ECDH + ML-KEM during transition", 128, 18),
    "DH": AlgorithmProfile("DH", Primitive.KEY_AGREE, QuantumStatus.VULNERABLE, False, "ML-KEM", "Adopt hybrid finite-field DH + ML-KEM during transition", 112, 22),
    "AES": AlgorithmProfile("AES", Primitive.BLOCK_CIPHER, QuantumStatus.TRANSITION, False, "AES-256-GCM", "Prefer 256-bit keys for long-lived post-quantum confidentiality", 128, 4),
    "CHACHA20": AlgorithmProfile("ChaCha20", Primitive.STREAM_CIPHER, QuantumStatus.TRANSITION, False, "ChaCha20-Poly1305", "Retain with strong key management", 128, 3),
    "SHA-256": AlgorithmProfile("SHA-256", Primitive.HASH, QuantumStatus.TRANSITION, False, "SHA-384", "Acceptable for most uses; consider wider hashes for long-lived PQ assurance", 128, 2),
    "SHA-384": AlgorithmProfile("SHA-384", Primitive.HASH, QuantumStatus.SAFE, False, None, None, 192, 0),
    "SHA-512": AlgorithmProfile("SHA-512", Primitive.HASH, QuantumStatus.SAFE, False, None, None, 256, 0),
    "ML-KEM": AlgorithmProfile("ML-KEM", Primitive.KEM, QuantumStatus.SAFE, False, None, None, 128, 0),
    "ML-DSA": AlgorithmProfile("ML-DSA", Primitive.SIGNATURE, QuantumStatus.SAFE, False, None, None, 128, 0),
    "SLH-DSA": AlgorithmProfile("SLH-DSA", Primitive.SIGNATURE, QuantumStatus.SAFE, False, None, None, 128, 0),
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
