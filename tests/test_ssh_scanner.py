from cryptohawk.domain.models import CryptoAssetType, Primitive, QuantumStatus
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.ssh import SSHScanner


class FakeKey:
    def __init__(self, name: str, bits: int, payload: bytes) -> None:
        self._name = name
        self._bits = bits
        self._payload = payload

    def get_name(self) -> str:
        return self._name

    def get_bits(self) -> int:
        return self._bits

    def asbytes(self) -> bytes:
        return self._payload


def test_ssh_rsa_host_key_is_signature_material_and_never_authenticates() -> None:
    observation = SSHScanner.observation_from_key(
        FakeKey("ssh-rsa", 2048, b"host-key"),
        locator="bastion.example.com:22",
        resolved_ip="203.0.113.20",
        remote_version="SSH-2.0-OpenSSH_9.9",
    )

    assert observation.family == "RSA"
    assert observation.algorithm == "RSA-2048"
    assert observation.primitive == Primitive.SIGNATURE
    assert observation.crypto_asset_type == CryptoAssetType.RELATED_CRYPTO_MATERIAL
    assert observation.evidence.metadata["authentication_performed"] is False
    assert observation.evidence.metadata["remote_command_executed"] is False
    assert observation.evidence.metadata["sha256_fingerprint"].startswith("SHA256:")

    finding = RiskEngine().assess(observation)
    assert finding.risk.quantum_status == QuantumStatus.VULNERABLE
    assert finding.risk.migration_target == "ML-DSA"


def test_ssh_ed25519_host_key_is_classified_as_quantum_vulnerable_signature() -> None:
    observation = SSHScanner.observation_from_key(
        FakeKey("ssh-ed25519", 256, b"ed25519-host-key"),
        locator="git.example.com:22",
    )

    assert observation.family == "ED25519"
    assert observation.algorithm == "ED25519"
    assert observation.parameter_set == "Ed25519"
    finding = RiskEngine().assess(observation)
    assert finding.risk.quantum_status == QuantumStatus.VULNERABLE
    assert finding.risk.migration_target == "ML-DSA"


def test_ssh_ecdsa_key_preserves_curve_parameter_set() -> None:
    observation = SSHScanner.observation_from_key(
        FakeKey("ecdsa-sha2-nistp256", 256, b"ecdsa-host-key"),
        locator="git.example.com:22",
    )

    assert observation.family == "ECDSA"
    assert observation.algorithm == "ECDSA-nistp256"
    assert observation.parameter_set == "nistp256"
