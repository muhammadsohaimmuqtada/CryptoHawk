from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from cryptohawk.domain.policy import (
    CryptoPolicyPack,
    CryptoPolicyPackWithVersions,
    CryptoPolicyRules,
    CryptoPolicyVersion,
    EffectiveCryptoPolicy,
)
from cryptohawk.storage.database import Base
from cryptohawk.storage.inventory import InventoryRepository, WorkspaceRecord
from cryptohawk.storage.time import as_utc

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,79}$")


class CryptoPolicyPackRecord(Base):
    __tablename__ = "crypto_policy_packs"
    __table_args__ = (
        UniqueConstraint(
            "workspace_id",
            "slug",
            name="uq_crypto_policy_pack_workspace_slug",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        index=True,
    )
    slug: Mapped[str] = mapped_column(String(80), index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    built_in: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_by: Mapped[str] = mapped_column(String(200), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class CryptoPolicyVersionRecord(Base):
    __tablename__ = "crypto_policy_versions"
    __table_args__ = (
        UniqueConstraint(
            "policy_id",
            "version",
            name="uq_crypto_policy_version_number",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    policy_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("crypto_policy_packs.id", ondelete="CASCADE"),
        index=True,
    )
    workspace_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        index=True,
    )
    version: Mapped[int] = mapped_column(Integer)
    rules_json: Mapped[str] = mapped_column(Text)
    rules_hash: Mapped[str] = mapped_column(String(64), index=True)
    created_by: Mapped[str] = mapped_column(String(200), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class WorkspacePolicyAssignmentRecord(Base):
    __tablename__ = "workspace_policy_assignments"

    workspace_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        primary_key=True,
    )
    policy_version_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("crypto_policy_versions.id", ondelete="RESTRICT"),
        index=True,
    )
    assigned_by: Mapped[str] = mapped_column(String(200))
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


def _utc(value: datetime | None = None) -> datetime:
    normalized = as_utc(value or datetime.now(UTC))
    if normalized is None:
        raise ValueError("datetime value is required")
    return normalized


def _rules_payload(rules: CryptoPolicyRules) -> str:
    return json.dumps(
        rules.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    )


def _rules_hash(rules: CryptoPolicyRules) -> str:
    return hashlib.sha256(_rules_payload(rules).encode("utf-8")).hexdigest()


def _stable_id(workspace_id: str, value: str) -> str:
    return hashlib.sha256(f"{workspace_id}|{value}".encode("utf-8")).hexdigest()


_BUILTIN_PACKS: tuple[tuple[str, str, str, CryptoPolicyRules], ...] = (
    (
        "cryptohawk-recommended",
        "CryptoHawk Recommended",
        "Balanced modern cryptography and post-quantum transition baseline.",
        CryptoPolicyRules(),
    ),
    (
        "strict-modern",
        "Strict Modern",
        "High-assurance baseline for new systems and aggressively modernized estates.",
        CryptoPolicyRules(
            minimum_rsa_bits=3072,
            minimum_aes_bits=256,
            minimum_tls_version="1.3",
            quantum_vulnerable_default="fail",
            internet_exposed_quantum_action="fail",
            long_lived_data_years=3,
            unknown_family_action="fail",
            minimum_detection_confidence=0.85,
        ),
    ),
    (
        "long-lived-confidentiality",
        "Long-Lived Confidentiality",
        (
            "HNDL-focused baseline for data that must remain confidential through "
            "the PQ transition."
        ),
        CryptoPolicyRules(
            minimum_rsa_bits=3072,
            minimum_aes_bits=256,
            minimum_tls_version="1.2",
            quantum_vulnerable_default="review",
            internet_exposed_quantum_action="fail",
            long_lived_data_years=3,
            unknown_family_action="review",
            minimum_detection_confidence=0.8,
        ),
    ),
)


class PolicyRepository:
    def __init__(self, inventory: InventoryRepository) -> None:
        self.inventory = inventory
        self.engine = inventory.engine
        self.SessionLocal = inventory.SessionLocal

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def ensure_builtins(
        self,
        workspace_id: str,
        *,
        now: datetime | None = None,
    ) -> None:
        current = _utc(now)
        try:
            with self.SessionLocal() as session:
                if session.get(WorkspaceRecord, workspace_id) is None:
                    raise LookupError("workspace not found")
                recommended_version_id: str | None = None
                for slug, name, description, rules in _BUILTIN_PACKS:
                    policy_id = _stable_id(workspace_id, f"builtin-policy:{slug}")
                    version_id = _stable_id(
                        workspace_id,
                        f"builtin-policy:{slug}:v1",
                    )
                    pack = session.get(CryptoPolicyPackRecord, policy_id)
                    if pack is None:
                        session.add(
                            CryptoPolicyPackRecord(
                                id=policy_id,
                                workspace_id=workspace_id,
                                slug=slug,
                                name=name,
                                description=description,
                                built_in=True,
                                created_by="system:builtin-policy",
                                created_at=current,
                            )
                        )
                    version = session.get(CryptoPolicyVersionRecord, version_id)
                    if version is None:
                        session.add(
                            CryptoPolicyVersionRecord(
                                id=version_id,
                                policy_id=policy_id,
                                workspace_id=workspace_id,
                                version=1,
                                rules_json=_rules_payload(rules),
                                rules_hash=_rules_hash(rules),
                                created_by="system:builtin-policy",
                                created_at=current,
                            )
                        )
                    if slug == "cryptohawk-recommended":
                        recommended_version_id = version_id

                assignment = session.get(
                    WorkspacePolicyAssignmentRecord,
                    workspace_id,
                )
                if assignment is None:
                    if recommended_version_id is None:
                        raise RuntimeError("recommended policy definition is missing")
                    session.add(
                        WorkspacePolicyAssignmentRecord(
                            workspace_id=workspace_id,
                            policy_version_id=recommended_version_id,
                            assigned_by="system:default-policy",
                            assigned_at=current,
                        )
                    )
                session.commit()
        except IntegrityError:
            # Deterministic built-in identities make a concurrent winner safe. Validate
            # the complete result after rollback instead of creating duplicate policy rows.
            with self.SessionLocal() as session:
                slugs = set(
                    session.scalars(
                        select(CryptoPolicyPackRecord.slug).where(
                            CryptoPolicyPackRecord.workspace_id == workspace_id,
                            CryptoPolicyPackRecord.built_in.is_(True),
                        )
                    ).all()
                )
                expected = {definition[0] for definition in _BUILTIN_PACKS}
                assignment = session.get(
                    WorkspacePolicyAssignmentRecord,
                    workspace_id,
                )
                if slugs != expected or assignment is None:
                    raise

    def create_pack(
        self,
        *,
        workspace_id: str,
        slug: str,
        name: str,
        description: str,
        rules: CryptoPolicyRules,
        created_by: str,
        activate: bool = False,
        now: datetime | None = None,
    ) -> CryptoPolicyPackWithVersions:
        current = _utc(now)
        normalized_slug = slug.strip().lower()
        if not _SLUG_RE.fullmatch(normalized_slug):
            raise ValueError(
                "policy slug must contain lowercase letters, digits, and hyphens"
            )
        if not name.strip():
            raise ValueError("policy name is required")
        if not created_by.strip():
            raise ValueError("created_by is required")
        self.ensure_builtins(workspace_id, now=current)
        policy_id = str(uuid4())
        version_id = str(uuid4())
        with self.SessionLocal() as session:
            pack = CryptoPolicyPackRecord(
                id=policy_id,
                workspace_id=workspace_id,
                slug=normalized_slug,
                name=name.strip()[:200],
                description=description.strip(),
                built_in=False,
                created_by=created_by.strip()[:200],
                created_at=current,
            )
            version = CryptoPolicyVersionRecord(
                id=version_id,
                policy_id=policy_id,
                workspace_id=workspace_id,
                version=1,
                rules_json=_rules_payload(rules),
                rules_hash=_rules_hash(rules),
                created_by=created_by.strip()[:200],
                created_at=current,
            )
            session.add_all([pack, version])
            if activate:
                assignment = session.get(
                    WorkspacePolicyAssignmentRecord,
                    workspace_id,
                )
                if assignment is None:
                    session.add(
                        WorkspacePolicyAssignmentRecord(
                            workspace_id=workspace_id,
                            policy_version_id=version_id,
                            assigned_by=created_by.strip()[:200],
                            assigned_at=current,
                        )
                    )
                else:
                    assignment.policy_version_id = version_id
                    assignment.assigned_by = created_by.strip()[:200]
                    assignment.assigned_at = current
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise ValueError("policy slug already exists in workspace") from exc
        result = self.get_pack(workspace_id=workspace_id, policy_id=policy_id)
        if result is None:
            raise RuntimeError("policy pack disappeared after creation")
        return result

    def create_version(
        self,
        *,
        workspace_id: str,
        policy_id: str,
        rules: CryptoPolicyRules,
        created_by: str,
        activate: bool = False,
        now: datetime | None = None,
    ) -> CryptoPolicyVersion:
        current = _utc(now)
        if not created_by.strip():
            raise ValueError("created_by is required")
        try:
            with self.SessionLocal() as session:
                pack = session.scalar(
                    select(CryptoPolicyPackRecord).where(
                        CryptoPolicyPackRecord.id == policy_id,
                        CryptoPolicyPackRecord.workspace_id == workspace_id,
                    )
                )
                if pack is None:
                    raise LookupError("policy pack not found in workspace")
                if pack.built_in:
                    raise ValueError("built-in policy packs are immutable")
                latest = session.scalar(
                    select(CryptoPolicyVersionRecord)
                    .where(CryptoPolicyVersionRecord.policy_id == policy_id)
                    .order_by(CryptoPolicyVersionRecord.version.desc())
                )
                version_number = (latest.version if latest else 0) + 1
                rules_hash = _rules_hash(rules)
                if latest is not None and latest.rules_hash == rules_hash:
                    raise ValueError(
                        "new policy version must change at least one rule"
                    )
                record = CryptoPolicyVersionRecord(
                    id=str(uuid4()),
                    policy_id=policy_id,
                    workspace_id=workspace_id,
                    version=version_number,
                    rules_json=_rules_payload(rules),
                    rules_hash=rules_hash,
                    created_by=created_by.strip()[:200],
                    created_at=current,
                )
                session.add(record)
                session.flush()
                if activate:
                    assignment = session.get(
                        WorkspacePolicyAssignmentRecord,
                        workspace_id,
                    )
                    if assignment is None:
                        session.add(
                            WorkspacePolicyAssignmentRecord(
                                workspace_id=workspace_id,
                                policy_version_id=record.id,
                                assigned_by=created_by.strip()[:200],
                                assigned_at=current,
                            )
                        )
                    else:
                        assignment.policy_version_id = record.id
                        assignment.assigned_by = created_by.strip()[:200]
                        assignment.assigned_at = current
                session.commit()
                session.refresh(record)
                return self._version(record)
        except IntegrityError as exc:
            raise ValueError(
                "policy version changed concurrently; reload the policy and retry"
            ) from exc

    def activate(
        self,
        *,
        workspace_id: str,
        policy_id: str,
        version: int,
        assigned_by: str,
        now: datetime | None = None,
    ) -> EffectiveCryptoPolicy:
        current = _utc(now)
        if not assigned_by.strip():
            raise ValueError("assigned_by is required")
        self.ensure_builtins(workspace_id, now=current)
        with self.SessionLocal() as session:
            record = session.scalar(
                select(CryptoPolicyVersionRecord).where(
                    CryptoPolicyVersionRecord.workspace_id == workspace_id,
                    CryptoPolicyVersionRecord.policy_id == policy_id,
                    CryptoPolicyVersionRecord.version == version,
                )
            )
            if record is None:
                raise LookupError("policy version not found in workspace")
            assignment = session.get(
                WorkspacePolicyAssignmentRecord,
                workspace_id,
            )
            if assignment is None:
                assignment = WorkspacePolicyAssignmentRecord(
                    workspace_id=workspace_id,
                    policy_version_id=record.id,
                    assigned_by=assigned_by.strip()[:200],
                    assigned_at=current,
                )
                session.add(assignment)
            else:
                assignment.policy_version_id = record.id
                assignment.assigned_by = assigned_by.strip()[:200]
                assignment.assigned_at = current
            session.commit()
        return self.effective_policy(workspace_id)

    def effective_policy(self, workspace_id: str) -> EffectiveCryptoPolicy:
        self.ensure_builtins(workspace_id)
        with self.SessionLocal() as session:
            assignment = session.get(
                WorkspacePolicyAssignmentRecord,
                workspace_id,
            )
            if assignment is None:
                raise RuntimeError("workspace has no effective cryptographic policy")
            version = session.get(
                CryptoPolicyVersionRecord,
                assignment.policy_version_id,
            )
            if version is None:
                raise RuntimeError(
                    "workspace policy assignment points to a missing version"
                )
            pack = session.get(CryptoPolicyPackRecord, version.policy_id)
            if pack is None or pack.workspace_id != workspace_id:
                raise RuntimeError(
                    "workspace policy assignment crosses tenant boundary"
                )
            return EffectiveCryptoPolicy(
                pack=self._pack(pack),
                version=self._version(version),
                assigned_by=assignment.assigned_by,
                assigned_at=_utc(assignment.assigned_at),
            )

    def list_packs(
        self,
        *,
        workspace_id: str,
    ) -> list[CryptoPolicyPackWithVersions]:
        self.ensure_builtins(workspace_id)
        with self.SessionLocal() as session:
            assignment = session.get(
                WorkspacePolicyAssignmentRecord,
                workspace_id,
            )
            active_id = assignment.policy_version_id if assignment else None
            packs = session.scalars(
                select(CryptoPolicyPackRecord)
                .where(CryptoPolicyPackRecord.workspace_id == workspace_id)
                .order_by(
                    CryptoPolicyPackRecord.built_in.desc(),
                    CryptoPolicyPackRecord.name,
                )
            ).all()
            results: list[CryptoPolicyPackWithVersions] = []
            for pack in packs:
                versions = session.scalars(
                    select(CryptoPolicyVersionRecord)
                    .where(CryptoPolicyVersionRecord.policy_id == pack.id)
                    .order_by(CryptoPolicyVersionRecord.version.desc())
                ).all()
                active_version = next(
                    (
                        version.version
                        for version in versions
                        if version.id == active_id
                    ),
                    None,
                )
                results.append(
                    CryptoPolicyPackWithVersions(
                        pack=self._pack(pack),
                        versions=[self._version(version) for version in versions],
                        active_version=active_version,
                    )
                )
            return results

    def get_pack(
        self,
        *,
        workspace_id: str,
        policy_id: str,
    ) -> CryptoPolicyPackWithVersions | None:
        self.ensure_builtins(workspace_id)
        with self.SessionLocal() as session:
            pack = session.scalar(
                select(CryptoPolicyPackRecord).where(
                    CryptoPolicyPackRecord.id == policy_id,
                    CryptoPolicyPackRecord.workspace_id == workspace_id,
                )
            )
            if pack is None:
                return None
            versions = session.scalars(
                select(CryptoPolicyVersionRecord)
                .where(CryptoPolicyVersionRecord.policy_id == policy_id)
                .order_by(CryptoPolicyVersionRecord.version.desc())
            ).all()
            assignment = session.get(
                WorkspacePolicyAssignmentRecord,
                workspace_id,
            )
            active_id = assignment.policy_version_id if assignment else None
            active_version = next(
                (
                    version.version
                    for version in versions
                    if version.id == active_id
                ),
                None,
            )
            return CryptoPolicyPackWithVersions(
                pack=self._pack(pack),
                versions=[self._version(version) for version in versions],
                active_version=active_version,
            )

    @staticmethod
    def _pack(row: CryptoPolicyPackRecord) -> CryptoPolicyPack:
        return CryptoPolicyPack(
            id=row.id,
            workspace_id=row.workspace_id,
            slug=row.slug,
            name=row.name,
            description=row.description,
            built_in=row.built_in,
            created_by=row.created_by,
            created_at=_utc(row.created_at),
        )

    @staticmethod
    def _version(row: CryptoPolicyVersionRecord) -> CryptoPolicyVersion:
        return CryptoPolicyVersion(
            id=row.id,
            policy_id=row.policy_id,
            workspace_id=row.workspace_id,
            version=row.version,
            rules=CryptoPolicyRules.model_validate_json(row.rules_json),
            rules_hash=row.rules_hash,
            created_by=row.created_by,
            created_at=_utc(row.created_at),
        )
