from cryptohawk.scanners.source import SourceScanner


def test_detects_crypto_and_key_size() -> None:
    source = '''
from cryptography.hazmat.primitives.asymmetric import rsa
legacy = "SHA1"
key = RSA-2048
cipher = AES-256
pqc = "ML-KEM-768"
'''
    results = SourceScanner().scan_text(source, asset_name="example.py")
    families = {item.family for item in results}
    assert {"SHA-1", "RSA", "AES", "ML-KEM"}.issubset(families)
    assert next(item for item in results if item.family == "RSA").key_size == 2048
    assert next(item for item in results if item.family == "AES").key_size == 256
