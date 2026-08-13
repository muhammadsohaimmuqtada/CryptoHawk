from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from cryptohawk.domain.models import AssetType, CryptoObservation, Evidence, Primitive
from cryptohawk.knowledge.algorithms import get_profile, normalize_family


@dataclass(frozen=True, slots=True)
class Detector:
    pattern: re.Pattern[str]
    family: str
    confidence: float
    key_size_group: str | None = None


DETECTORS: tuple[Detector, ...] = (
    Detector(re.compile(r"\b(?:MD5|md5)\s*\("), "MD5", 0.98),
    Detector(re.compile(r"\b(?:SHA1|sha1|SHA-1)\b"), "SHA-1", 0.95),
    Detector(re.compile(r"\b(?:SHA256|sha256|SHA-256)\b"), "SHA-256", 0.94),
    Detector(re.compile(r"\b(?:SHA384|sha384|SHA-384)\b"), "SHA-384", 0.94),
    Detector(re.compile(r"\b(?:SHA512|sha512|SHA-512)\b"), "SHA-512", 0.94),
    Detector(re.compile(r"\b(?:TripleDES|3DES|DES3)\b"), "3DES", 0.96),
    Detector(re.compile(r"\b(?:ARC4|RC4)\b"), "RC4", 0.96),
    Detector(re.compile(r"\bDES\b"), "DES", 0.90),
    Detector(
        re.compile(r"\bAES(?:[-_ ]?(?P<bits>128|192|256))?\b", re.I),
        "AES",
        0.90,
        "bits",
    ),
    Detector(
        re.compile(r"\bRSA(?:[-_ ]?(?P<bits>1024|2048|3072|4096|8192))?\b", re.I),
        "RSA",
        0.90,
        "bits",
    ),
    Detector(re.compile(r"\bECDSA\b", re.I), "ECDSA", 0.92),
    Detector(re.compile(r"\bECDH\b", re.I), "ECDH", 0.92),
    Detector(re.compile(r"\b(?:DiffieHellman|Diffie-Hellman|\bDH\b)\b", re.I), "DH", 0.83),
    Detector(re.compile(r"\b(?:ChaCha20|CHACHA20)\b"), "ChaCha20", 0.94),
    Detector(re.compile(r"\b(?:ML[-_]?KEM|Kyber|CRYSTALS[-_]?Kyber)\b", re.I), "ML-KEM", 0.97),
    Detector(
        re.compile(r"\b(?:ML[-_]?DSA|Dilithium|CRYSTALS[-_]?Dilithium)\b", re.I),
        "ML-DSA",
        0.97,
    ),
    Detector(re.compile(r"\b(?:SLH[-_]?DSA|SPHINCS\+?)\b", re.I), "SLH-DSA", 0.97),
)

SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rs",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".cs",
    ".rb",
    ".php",
    ".swift",
    ".kt",
    ".kts",
    ".scala",
    ".sh",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".xml",
    ".properties",
    ".conf",
    ".ini",
    ".env",
    ".pem",
}
IGNORED_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    ".next",
    "coverage",
}


class SourceScanner:
    def scan_text(
        self,
        text: str,
        *,
        asset_name: str = "inline",
        locator: str = "inline",
    ) -> list[CryptoObservation]:
        asset_id = f"src:{uuid4()}"
        observations: list[CryptoObservation] = []
        seen: set[tuple[int, str, int | None]] = set()
        for line_no, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            # Imports describe available libraries, not proof that an algorithm is used.
            # Dependency inventory will be modeled separately; suppress these low-signal hits.
            import_only = stripped.startswith(("import ", "from ")) and not any(
                token in stripped for token in ("=", "(", ")")
            )
            if import_only:
                continue
            for detector in DETECTORS:
                for match in detector.pattern.finditer(line):
                    family = normalize_family(detector.family)
                    key_size = None
                    if detector.key_size_group and match.groupdict().get(detector.key_size_group):
                        key_size = int(match.group(detector.key_size_group))
                    fingerprint = (line_no, family, key_size)
                    if fingerprint in seen:
                        continue
                    seen.add(fingerprint)
                    profile = get_profile(family)
                    primitive = profile.primitive if profile else Primitive.UNKNOWN
                    observations.append(
                        CryptoObservation(
                            asset_id=asset_id,
                            asset_name=asset_name,
                            asset_type=AssetType.SOURCE,
                            algorithm=family,
                            family=family,
                            primitive=primitive,
                            key_size=key_size,
                            parameter_set=str(key_size) if key_size else None,
                            confidence=detector.confidence,
                            evidence=Evidence(
                                source="source-code",
                                locator=locator,
                                line=line_no,
                                snippet=line.strip()[:240],
                            ),
                        )
                    )
        return observations

    def scan_path(self, root: str | Path) -> list[CryptoObservation]:
        root = Path(root).resolve()
        if not root.exists():
            raise FileNotFoundError(root)
        if root.is_file():
            return self.scan_text(
                root.read_text(errors="ignore"),
                asset_name=root.name,
                locator=str(root),
            )

        results: list[CryptoObservation] = []
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue
            if any(part in IGNORED_DIRS for part in path.parts):
                continue
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            if len(text) > 2_000_000:
                continue
            results.extend(self.scan_text(text, asset_name=path.name, locator=str(path)))
        return results
