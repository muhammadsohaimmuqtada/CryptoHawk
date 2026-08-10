from __future__ import annotations

from cryptohawk.domain.models import (
    CryptoAssetType,
    CryptoObservation,
    Finding,
    QuantumStatus,
    RiskAssessment,
    ScanContext,
    Severity,
)
from cryptohawk.knowledge.algorithms import get_profile


def severity_for(score: int) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 35:
        return Severity.MEDIUM
    if score >= 15:
        return Severity.LOW
    return Severity.INFO


class RiskEngine:
    """Deterministic, explainable cryptographic risk scoring.

    Score components intentionally sum to 100:
      cryptographic weakness: 0..40
      quantum exposure:       0..25
      internet exposure:      0..15
      data lifetime:          0..10
      asset criticality:      0..10
    """

    def assess(self, observation: CryptoObservation, context: ScanContext | None = None) -> Finding:
        context = context or ScanContext()
        profile = get_profile(observation.family)
        reasons: list[str] = []

        weakness = 12
        quantum = 10
        migration_target = None
        migration_strategy = None
        security_bits = None
        quantum_status = QuantumStatus.UNKNOWN

        if observation.crypto_asset_type == CryptoAssetType.PROTOCOL:
            version = (observation.protocol_version or "").replace("TLSv", "")
            quantum_status = QuantumStatus.TRANSITION
            weakness = 2
            quantum = 4
            if version in {"1", "1.0", "1.1"}:
                weakness = 35
                migration_target = "TLS 1.3"
                migration_strategy = "Disable legacy TLS and require TLS 1.2+; prefer TLS 1.3"
                reasons.append(f"TLS {version} is a legacy protocol version")
            elif version == "1.2":
                reasons.append(
                    "TLS 1.2 security depends on negotiated cipher suite and key exchange"
                )
            elif version == "1.3":
                reasons.append(
                    "TLS 1.3 protocol baseline is modern; assess key exchange and "
                    "certificates separately"
                )
            else:
                reasons.append("Protocol version requires review")

        if profile:
            weakness = profile.weakness_weight
            quantum_status = profile.quantum_status
            migration_target = profile.migration_target
            migration_strategy = profile.migration_strategy
            security_bits = profile.security_bits
            if profile.deprecated:
                reasons.append(
                    f"{profile.family} is deprecated or unsuitable for new security designs"
                )
            if profile.quantum_status == QuantumStatus.VULNERABLE:
                quantum = 25
                reasons.append(
                    f"{profile.family} is not resistant to a cryptographically relevant "
                    "quantum computer"
                )
            elif profile.quantum_status == QuantumStatus.TRANSITION:
                quantum = 8
                reasons.append(f"{profile.family} needs post-quantum parameter and usage review")
            elif profile.quantum_status == QuantumStatus.SAFE:
                quantum = 0
                reasons.append(
                    f"{profile.family} is a post-quantum or high-margin primitive in this policy"
                )

        # Parameter-sensitive rules override family defaults where evidence is stronger.
        if observation.family == "RSA" and observation.key_size:
            if observation.key_size < 2048:
                weakness = 40
                reasons.append(f"RSA key size {observation.key_size} is below modern minimums")
            elif observation.key_size < 3072:
                weakness = max(weakness, 24)
                reasons.append(f"RSA-{observation.key_size} has limited classical security margin")

        if observation.family == "AES" and observation.key_size:
            if observation.key_size < 128:
                weakness = 40
                reasons.append(f"AES key size {observation.key_size} is insufficient")
            elif observation.key_size == 128:
                quantum = max(quantum, 10)
                reasons.append(
                    "AES-128 has reduced effective security margin under Grover-style search"
                )
            elif observation.key_size >= 256:
                quantum = min(quantum, 3)
                reasons.append("AES-256 retains a strong post-quantum security margin")

        internet = 15 if context.internet_exposed else 0
        if internet:
            reasons.append("Asset is marked internet-exposed")

        lifetime = min(context.data_lifetime_years, 10)
        if lifetime >= 5 and quantum_status == QuantumStatus.VULNERABLE:
            reasons.append(
                "Long confidentiality lifetime increases harvest-now-decrypt-later exposure"
            )

        criticality = context.asset_criticality
        score = min(100, weakness + quantum + internet + lifetime + criticality)

        if observation.confidence < 0.75:
            reasons.append(
                "Detection confidence is below high-confidence threshold; verify before remediation"
            )

        risk = RiskAssessment(
            observation_id=observation.id,
            score=score,
            severity=severity_for(score),
            quantum_status=quantum_status,
            reasons=reasons or ["No policy-specific risk rule matched"],
            migration_target=migration_target,
            migration_strategy=migration_strategy,
            security_bits=security_bits,
        )
        return Finding(observation=observation, risk=risk)
