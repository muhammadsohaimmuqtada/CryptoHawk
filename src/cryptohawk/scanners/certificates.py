from __future__ import annotations

import socket
import ssl
from datetime import UTC
from ipaddress import IPv4Address, IPv6Address

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

from cryptohawk.domain.models import (
    AssetType,
    CryptoAssetType,
    CryptoObservation,
    Evidence,
    Primitive,
)
from cryptohawk.security.network import resolve_target


class CertificateScanner:
    """Inventory the leaf X.509 certificate exposed by a TLS endpoint."""

    def __init__(self, *, allow_private_targets: bool = False) -> None:
        self.allow_private_targets = allow_private_targets

    def scan(
        self,
        hostname: str,
        port: int = 443,
        timeout: float = 5.0,
    ) -> list[CryptoObservation]:
        target = resolve_target(hostname, port, allow_private=self.allow_private_targets)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.socket(target.family, target.socktype, target.proto) as raw:
            raw.settimeout(timeout)
            raw.connect(target.sockaddr)
            with context.wrap_socket(raw, server_hostname=hostname) as tls:
                der = tls.getpeercert(binary_form=True)
                tls_version = tls.version()
        if not der:
            return []
        return self.scan_der(
            der,
            locator=f"{hostname}:{port}",
            resolved_ip=target.ip,
            tls_version=tls_version,
        )

    def scan_der(
        self,
        der: bytes,
        *,
        locator: str,
        resolved_ip: str | None = None,
        tls_version: str | None = None,
    ) -> list[CryptoObservation]:
        cert = x509.load_der_x509_certificate(der)
        family, primitive, key_size, parameter_set = self._public_key_profile(cert)
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        metadata = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": str(cert.serial_number),
            "not_valid_before": cert.not_valid_before_utc.astimezone(UTC).isoformat(),
            "not_valid_after": cert.not_valid_after_utc.astimezone(UTC).isoformat(),
            "sha256_fingerprint": fingerprint,
            "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
            "self_issued": cert.subject == cert.issuer,
            "subject_alt_names": self._subject_alt_names(cert),
            "trust_validation": "not-performed",
        }
        if resolved_ip:
            metadata["resolved_ip"] = resolved_ip
        if tls_version:
            metadata["tls_version"] = tls_version

        algorithm = family
        if parameter_set:
            algorithm = f"{family}-{parameter_set}"
        elif key_size:
            algorithm = f"{family}-{key_size}"

        asset_id = f"certificate:{locator}:{fingerprint[:16]}"
        observations = [
            CryptoObservation(
                asset_id=asset_id,
                asset_name=f"{locator} certificate public key",
                asset_type=AssetType.CERTIFICATE,
                crypto_asset_type=CryptoAssetType.CERTIFICATE,
                algorithm=algorithm,
                family=family,
                primitive=primitive,
                key_size=key_size,
                parameter_set=parameter_set,
                confidence=1.0,
                evidence=Evidence(
                    source="x509-certificate-estate",
                    locator=locator,
                    metadata=metadata,
                ),
            )
        ]
        signature_hash = cert.signature_hash_algorithm
        if signature_hash is not None:
            hash_family = self._normalize_hash(signature_hash.name)
            observations.append(
                CryptoObservation(
                    asset_id=asset_id,
                    asset_name=f"{locator} certificate signature hash",
                    asset_type=AssetType.CERTIFICATE,
                    crypto_asset_type=CryptoAssetType.CERTIFICATE,
                    algorithm=hash_family,
                    family=hash_family,
                    primitive=Primitive.HASH,
                    confidence=1.0,
                    evidence=Evidence(
                        source="x509-certificate-estate",
                        locator=locator,
                        metadata={
                            "sha256_fingerprint": fingerprint,
                            "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
                            **({"resolved_ip": resolved_ip} if resolved_ip else {}),
                        },
                    ),
                )
            )
        return observations

    @staticmethod
    def _public_key_profile(
        cert: x509.Certificate,
    ) -> tuple[str, Primitive, int | None, str | None]:
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            primitive = CertificateScanner._rsa_certificate_primitive(cert)
            return "RSA", primitive, public_key.key_size, str(public_key.key_size)
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return "ECDSA", Primitive.SIGNATURE, public_key.key_size, public_key.curve.name
        if isinstance(public_key, dsa.DSAPublicKey):
            return "DSA", Primitive.SIGNATURE, public_key.key_size, str(public_key.key_size)
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            return "ED25519", Primitive.SIGNATURE, 256, "Ed25519"
        if isinstance(public_key, ed448.Ed448PublicKey):
            return "ED448", Primitive.SIGNATURE, 448, "Ed448"
        return "UNKNOWN", Primitive.UNKNOWN, getattr(public_key, "key_size", None), None

    @staticmethod
    def _rsa_certificate_primitive(cert: x509.Certificate) -> Primitive:
        try:
            usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            return Primitive.PKE
        if usage.digital_signature and not usage.key_encipherment:
            return Primitive.SIGNATURE
        return Primitive.PKE

    @staticmethod
    def _subject_alt_names(cert: x509.Certificate) -> list[str]:
        try:
            names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            return []
        values: list[str] = []
        values.extend(names.get_values_for_type(x509.DNSName))
        for address in names.get_values_for_type(x509.IPAddress):
            if isinstance(address, (IPv4Address, IPv6Address)):
                values.append(str(address))
        return values[:200]

    @staticmethod
    def _normalize_hash(name: str) -> str:
        token = name.upper().replace("_", "-")
        if token.startswith("SHA") and not token.startswith("SHA-"):
            token = token.replace("SHA", "SHA-", 1)
        return token
