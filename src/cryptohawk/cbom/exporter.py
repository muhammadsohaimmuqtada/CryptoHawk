from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from cryptohawk.domain.models import CryptoAssetType, Finding


class CycloneDXExporter:
    """Export CryptoHawk findings as CycloneDX 1.7 cryptographic assets."""

    def export(self, findings: list[Finding]) -> dict:
        components: list[dict] = []
        for finding in findings:
            obs = finding.observation
            props = {
                "assetType": obs.crypto_asset_type.value,
            }
            if obs.crypto_asset_type == CryptoAssetType.ALGORITHM:
                algorithm_props: dict[str, object] = {
                    "primitive": obs.primitive.value,
                    "algorithmFamily": obs.family,
                }
                if obs.parameter_set:
                    algorithm_props["parameterSetIdentifier"] = obs.parameter_set
                props["algorithmProperties"] = algorithm_props
            elif obs.crypto_asset_type == CryptoAssetType.PROTOCOL:
                props["protocolProperties"] = {
                    "type": "tls" if obs.family == "TLS" else "other",
                    "version": obs.protocol_version or "unknown",
                }

            components.append(
                {
                    "type": "cryptographic-asset",
                    "bom-ref": f"crypto:{obs.id}",
                    "name": self._component_name(finding),
                    "cryptoProperties": props,
                    "properties": [
                        {"name": "cryptohawk:risk:score", "value": str(finding.risk.score)},
                        {"name": "cryptohawk:risk:severity", "value": finding.risk.severity.value},
                        {
                            "name": "cryptohawk:pqc:status",
                            "value": finding.risk.quantum_status.value,
                        },
                        {"name": "cryptohawk:asset:id", "value": obs.asset_id},
                        {"name": "cryptohawk:evidence:source", "value": obs.evidence.source},
                    ],
                }
            )

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "serialNumber": f"urn:uuid:{uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(UTC).isoformat(),
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "CryptoHawk",
                            "version": "0.1.0",
                        }
                    ]
                },
            },
            "components": components,
        }

    @staticmethod
    def _component_name(finding: Finding) -> str:
        obs = finding.observation
        if obs.key_size and str(obs.key_size) not in obs.algorithm:
            return f"{obs.family}-{obs.key_size}"
        return obs.algorithm or obs.family
