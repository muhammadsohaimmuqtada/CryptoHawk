from __future__ import annotations

import socket
import ssl
from datetime import UTC
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from cryptohawk.domain.models import AssetType, CryptoAssetType, CryptoObservation, Evidence, Primitive


class TLSScanner:
    def scan(self, hostname: str, port: int = 443, timeout: float = 5.0) -> list[CryptoObservation]:
        context = ssl.create_default_context()
        asset_id = f"tls:{hostname}:{port}"
        observations: list[CryptoObservation] = []

        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as tls:
                der = tls.getpeercert(binary_form=True)
                version = tls.version() or "unknown"
                cipher = tls.cipher()

        observations.append(
            CryptoObservation(
                asset_id=asset_id,
                asset_name=f"{hostname}:{port}",
                asset_type=AssetType.TLS_ENDPOINT,
                crypto_asset_type=CryptoAssetType.PROTOCOL,
                algorithm=f"TLS {version}",
                family="TLS",
                primitive=Primitive.OTHER,
                protocol_version=version.replace("TLSv", ""),
                confidence=1.0,
                evidence=Evidence(source="tls-handshake", locator=f"{hostname}:{port}", metadata={"cipher_suite": cipher[0] if cipher else None}),
            )
        )

        if not der:
            return observations

        cert = x509.load_der_x509_certificate(der)
        public_key = cert.public_key()
        family = "UNKNOWN"
        primitive = Primitive.UNKNOWN
        key_size = getattr(public_key, "key_size", None)
        if isinstance(public_key, rsa.RSAPublicKey):
            family, primitive = "RSA", Primitive.PKE
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            family, primitive = "ECDSA", Primitive.SIGNATURE
        elif isinstance(public_key, dsa.DSAPublicKey):
            family, primitive = "DSA", Primitive.SIGNATURE

        observations.append(
            CryptoObservation(
                id=str(uuid4()),
                asset_id=asset_id,
                asset_name=f"{hostname}:{port} certificate public key",
                asset_type=AssetType.CERTIFICATE,
                algorithm=f"{family}-{key_size}" if key_size else family,
                family=family,
                primitive=primitive,
                key_size=key_size,
                parameter_set=str(key_size) if key_size else None,
                confidence=1.0,
                evidence=Evidence(
                    source="x509-certificate",
                    locator=f"{hostname}:{port}",
                    metadata={
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "serial_number": str(cert.serial_number),
                        "not_valid_before": cert.not_valid_before_utc.astimezone(UTC).isoformat(),
                        "not_valid_after": cert.not_valid_after_utc.astimezone(UTC).isoformat(),
                    },
                ),
            )
        )

        sig_hash = cert.signature_hash_algorithm
        if sig_hash:
            normalized = sig_hash.name.upper().replace("SHA", "SHA-") if sig_hash.name.lower().startswith("sha") else sig_hash.name.upper()
            observations.append(
                CryptoObservation(
                    asset_id=asset_id,
                    asset_name=f"{hostname}:{port} certificate signature hash",
                    asset_type=AssetType.CERTIFICATE,
                    algorithm=normalized,
                    family=normalized,
                    primitive=Primitive.HASH,
                    confidence=1.0,
                    evidence=Evidence(source="x509-certificate", locator=f"{hostname}:{port}"),
                )
            )
        return observations
