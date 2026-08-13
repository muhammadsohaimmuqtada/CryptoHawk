from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cryptohawk.domain.models import Primitive, QuantumStatus
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.certificates import CertificateScanner


def _certificate_der() -> bytes:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.example.com")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("api.example.com"), x509.DNSName("www.example.com")]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(x509.Encoding.DER)


def test_certificate_estate_inventory_preserves_identity_and_crypto_metadata() -> None:
    scanner = CertificateScanner()
    observations = scanner.scan_der(
        _certificate_der(),
        locator="api.example.com:443",
        resolved_ip="203.0.113.10",
        tls_version="TLSv1.3",
    )

    assert len(observations) == 2
    public_key, signature_hash = observations
    assert public_key.family == "RSA"
    assert public_key.key_size == 2048
    assert public_key.primitive == Primitive.SIGNATURE
    assert public_key.evidence.metadata["trust_validation"] == "not-performed"
    assert public_key.evidence.metadata["self_issued"] is True
    assert public_key.evidence.metadata["subject_alt_names"] == [
        "api.example.com",
        "www.example.com",
    ]
    assert public_key.evidence.metadata["resolved_ip"] == "203.0.113.10"
    assert public_key.evidence.metadata["tls_version"] == "TLSv1.3"
    assert signature_hash.family == "SHA-256"
    assert signature_hash.asset_id == public_key.asset_id


def test_rsa_certificate_signature_migrates_to_ml_dsa() -> None:
    observation = CertificateScanner().scan_der(
        _certificate_der(),
        locator="api.example.com:443",
    )[0]
    finding = RiskEngine().assess(observation)

    assert finding.risk.quantum_status == QuantumStatus.VULNERABLE
    assert finding.risk.migration_target == "ML-DSA"
