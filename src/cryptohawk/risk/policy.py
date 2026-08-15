from __future__ import annotations

from cryptohawk.domain.models import CryptoAssetType, Finding, QuantumStatus, ScanContext
from cryptohawk.domain.policy import EffectiveCryptoPolicy, PolicyDisposition
from cryptohawk.knowledge.algorithms import get_profile, normalize_family

_STATUS_ORDER: dict[PolicyDisposition, int] = {"pass": 0, "review": 1, "fail": 2}


def _max_status(
    current: PolicyDisposition,
    candidate: PolicyDisposition,
) -> PolicyDisposition:
    return candidate if _STATUS_ORDER[candidate] > _STATUS_ORDER[current] else current


def _tls_rank(value: str | None) -> int | None:
    if value is None:
        return None
    normalized = value.strip().upper().replace("TLSV", "").replace("TLS ", "")
    if normalized in {"1", "1.0"}:
        return 10
    if normalized == "1.1":
        return 11
    if normalized == "1.2":
        return 12
    if normalized == "1.3":
        return 13
    return None


class CryptoPolicyEvaluator:
    """Evaluate an immutable organization baseline without changing core risk scoring."""

    def apply(
        self,
        finding: Finding,
        context: ScanContext,
        policy: EffectiveCryptoPolicy,
    ) -> Finding:
        rules = policy.version.rules
        observation = finding.observation
        family = normalize_family(observation.family)
        status: PolicyDisposition = "pass"
        reasons: list[str] = []
        controls: list[str] = []

        disallowed = {normalize_family(value) for value in rules.disallowed_families}
        if family in disallowed:
            status = "fail"
            controls.append("disallowed-family")
            reasons.append(f"{family} is disallowed by this organization baseline")

        if family == "RSA":
            if observation.key_size is None:
                status = _max_status(status, "review")
                controls.append("minimum-rsa-bits")
                reasons.append(
                    "RSA key size is unknown; minimum-key-size compliance is unproven"
                )
            elif observation.key_size < rules.minimum_rsa_bits:
                status = "fail"
                controls.append("minimum-rsa-bits")
                reasons.append(
                    f"RSA-{observation.key_size} is below the policy minimum of "
                    f"{rules.minimum_rsa_bits} bits"
                )

        if family == "AES":
            if observation.key_size is None:
                status = _max_status(status, "review")
                controls.append("minimum-aes-bits")
                reasons.append(
                    "AES key size is unknown; minimum-key-size compliance is unproven"
                )
            elif observation.key_size < rules.minimum_aes_bits:
                status = "fail"
                controls.append("minimum-aes-bits")
                reasons.append(
                    f"AES-{observation.key_size} is below the policy minimum of "
                    f"{rules.minimum_aes_bits} bits"
                )

        if observation.crypto_asset_type == CryptoAssetType.PROTOCOL:
            observed_tls = _tls_rank(observation.protocol_version)
            required_tls = _tls_rank(rules.minimum_tls_version)
            if observed_tls is None:
                status = _max_status(status, "review")
                controls.append("minimum-tls-version")
                reasons.append(
                    "TLS protocol version is unknown; baseline compliance is unproven"
                )
            elif required_tls is not None and observed_tls < required_tls:
                status = "fail"
                controls.append("minimum-tls-version")
                reasons.append(
                    f"TLS {observation.protocol_version} is below the policy minimum of "
                    f"TLS {rules.minimum_tls_version}"
                )

        if finding.risk.quantum_status == QuantumStatus.VULNERABLE:
            status = _max_status(status, rules.quantum_vulnerable_default)
            controls.append("quantum-vulnerable")
            reasons.append(
                "Quantum-vulnerable cryptography requires "
                f"{rules.quantum_vulnerable_default} under this baseline"
            )
            if context.internet_exposed:
                status = _max_status(status, rules.internet_exposed_quantum_action)
                controls.append("internet-quantum-exposure")
                reasons.append(
                    "Internet-exposed quantum-vulnerable cryptography requires "
                    f"{rules.internet_exposed_quantum_action} under this baseline"
                )
            if context.data_lifetime_years >= rules.long_lived_data_years:
                status = "fail"
                controls.append("harvest-now-decrypt-later")
                reasons.append(
                    f"Data lifetime of {context.data_lifetime_years} years meets the policy "
                    f"HNDL threshold of {rules.long_lived_data_years} years"
                )

        if (
            observation.crypto_asset_type == CryptoAssetType.ALGORITHM
            and get_profile(family) is None
        ):
            status = _max_status(status, rules.unknown_family_action)
            controls.append("unknown-family")
            reasons.append(
                f"{family} is not in the CryptoHawk algorithm knowledge base and requires "
                f"{rules.unknown_family_action} under this baseline"
            )

        if observation.confidence < rules.minimum_detection_confidence:
            status = _max_status(status, "review")
            controls.append("detection-confidence")
            reasons.append(
                f"Detection confidence {observation.confidence:.2f} is below the policy "
                f"minimum of {rules.minimum_detection_confidence:.2f}"
            )

        if not reasons:
            reasons.append(
                "Observed cryptography satisfies the selected organization baseline"
            )

        policy_risk = finding.risk.model_copy(
            update={
                "policy_id": policy.pack.id,
                "policy_version": policy.version.version,
                "policy_name": policy.pack.name,
                "policy_status": status,
                "policy_reasons": reasons,
                "policy_controls": sorted(set(controls)),
                "policy_rules_hash": policy.version.rules_hash,
            }
        )
        return finding.model_copy(update={"risk": policy_risk})
