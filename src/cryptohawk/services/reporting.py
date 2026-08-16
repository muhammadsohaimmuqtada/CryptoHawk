from __future__ import annotations

import csv
import html
from collections import Counter
from datetime import UTC, datetime, timedelta
from io import StringIO

from sqlalchemy import func, select

from cryptohawk.cbom.exporter import CycloneDXExporter
from cryptohawk.domain.models import Finding
from cryptohawk.domain.remediation import RemediationStatus
from cryptohawk.domain.reporting import (
    EngineeringFinding,
    EngineeringReport,
    ExecutivePriority,
    ExecutiveReport,
    ExecutiveSummary,
    ReportMetadata,
    ReportPolicyRef,
)
from cryptohawk.storage.continuous import DriftEventRecord, ObservationStateRecord
from cryptohawk.storage.inventory import InventoryRepository, ManagedAssetRecord
from cryptohawk.storage.policy import PolicyRepository
from cryptohawk.storage.remediation import RemediationRepository
from cryptohawk.storage.time import as_utc

_TERMINAL_REMEDIATION = {
    RemediationStatus.VERIFIED,
    RemediationStatus.ACCEPTED_RISK,
}
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@")


def _utc(value: datetime | None = None) -> datetime:
    return as_utc(value or datetime.now(UTC)) or datetime.now(UTC)


def _csv_safe(value: object | None) -> str:
    if value is None:
        return ""
    text = str(value)
    if text.lstrip().startswith(_CSV_FORMULA_PREFIXES):
        return f"'{text}"
    return text


class ReportingService:
    def __init__(self, inventory: InventoryRepository) -> None:
        self.inventory = inventory
        self.SessionLocal = inventory.SessionLocal
        self.policies = PolicyRepository(inventory)
        self.remediation = RemediationRepository(inventory)

    def _metadata(self, workspace_id: str, generated_at: datetime) -> ReportMetadata:
        workspace = self.inventory.get_workspace(workspace_id)
        if workspace is None:
            raise LookupError("workspace not found")
        policy = self.policies.effective_policy(workspace_id)
        return ReportMetadata(
            generated_at=generated_at,
            workspace_id=workspace.id,
            workspace_name=workspace.name,
            workspace_slug=workspace.slug,
            policy=ReportPolicyRef(
                name=policy.pack.name,
                version=policy.version.version,
                rules_hash=policy.version.rules_hash,
                provenance_ref=policy.provenance_ref,
            ),
        )

    def _current_rows(
        self,
        workspace_id: str,
    ) -> tuple[list[ManagedAssetRecord], list[tuple[ObservationStateRecord, Finding]]]:
        with self.SessionLocal() as session:
            assets = session.scalars(
                select(ManagedAssetRecord)
                .where(ManagedAssetRecord.workspace_id == workspace_id)
                .order_by(ManagedAssetRecord.name, ManagedAssetRecord.id)
            ).all()
            states = session.scalars(
                select(ObservationStateRecord)
                .where(
                    ObservationStateRecord.workspace_id == workspace_id,
                    ObservationStateRecord.active.is_(True),
                )
                .order_by(
                    ObservationStateRecord.risk_score.desc(),
                    ObservationStateRecord.last_seen.desc(),
                    ObservationStateRecord.fingerprint,
                )
            ).all()
        return list(assets), [
            (state, Finding.model_validate_json(state.finding_payload)) for state in states
        ]

    def engineering_report(
        self,
        workspace_id: str,
        *,
        now: datetime | None = None,
    ) -> EngineeringReport:
        generated_at = _utc(now)
        metadata = self._metadata(workspace_id, generated_at)
        assets, current = self._current_rows(workspace_id)
        assets_by_id = {asset.id: asset for asset in assets}
        migration_items = self.remediation.list_items(workspace_id=workspace_id, limit=1000)
        remediation_by_fingerprint = {
            (item.asset_id, item.observation_fingerprint): item for item in migration_items
        }

        rows: list[EngineeringFinding] = []
        for state, finding in current:
            asset = assets_by_id.get(state.asset_id)
            if asset is None:
                continue
            observation = finding.observation
            risk = finding.risk
            remediation = remediation_by_fingerprint.get((state.asset_id, state.fingerprint))
            rows.append(
                EngineeringFinding(
                    fingerprint=state.fingerprint,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    asset_kind=asset.kind,
                    locator=asset.locator,
                    environment=asset.environment,
                    internet_exposed=asset.internet_exposed,
                    asset_criticality=asset.asset_criticality,
                    data_lifetime_years=asset.data_lifetime_years,
                    algorithm=observation.algorithm,
                    family=observation.family,
                    primitive=observation.primitive.value,
                    crypto_asset_type=observation.crypto_asset_type.value,
                    parameter_set=observation.parameter_set,
                    key_size=observation.key_size,
                    protocol_version=observation.protocol_version,
                    confidence=observation.confidence,
                    risk_score=risk.score,
                    severity=risk.severity.value,
                    quantum_status=risk.quantum_status.value,
                    risk_reasons=list(risk.reasons),
                    migration_target=risk.migration_target,
                    migration_strategy=risk.migration_strategy,
                    policy_name=risk.policy_name,
                    policy_version=risk.policy_version,
                    policy_status=risk.policy_status,
                    policy_controls=list(risk.policy_controls),
                    policy_reasons=list(risk.policy_reasons),
                    policy_rules_hash=risk.policy_rules_hash,
                    evidence_source=observation.evidence.source,
                    evidence_locator=observation.evidence.locator,
                    evidence_hash=state.evidence_hash,
                    first_seen=state.first_seen,
                    last_seen=state.last_seen,
                    occurrence_count=state.occurrence_count,
                    remediation_id=remediation.id if remediation else None,
                    remediation_status=remediation.status.value if remediation else None,
                    remediation_priority=remediation.priority.value if remediation else None,
                    remediation_owner=remediation.owner if remediation else None,
                    remediation_due_date=(
                        remediation.due_date.isoformat()
                        if remediation and remediation.due_date
                        else None
                    ),
                    remediation_target=(
                        remediation.target_algorithm if remediation else None
                    ),
                )
            )
        return EngineeringReport(metadata=metadata, findings=rows)

    def executive_report(
        self,
        workspace_id: str,
        *,
        now: datetime | None = None,
    ) -> ExecutiveReport:
        generated_at = _utc(now)
        engineering = self.engineering_report(workspace_id, now=generated_at)
        assets = self.inventory.list_assets(workspace_id=workspace_id)
        migration_items = self.remediation.list_items(workspace_id=workspace_id, limit=1000)

        severity = Counter(row.severity for row in engineering.findings)
        quantum = Counter(row.quantum_status for row in engineering.findings)
        policy = Counter(row.policy_status or "unassessed" for row in engineering.findings)
        remediation = Counter(item.status.value for item in migration_items)
        current_date = generated_at.date()
        active_items = [
            item for item in migration_items if item.status not in _TERMINAL_REMEDIATION
        ]
        overdue = sum(
            1 for item in active_items if item.due_date is not None and item.due_date < current_date
        )
        unowned = sum(1 for item in active_items if not item.owner)

        since = generated_at - timedelta(days=30)
        with self.SessionLocal() as session:
            drift = Counter(
                dict(
                    session.execute(
                        select(DriftEventRecord.event_type, func.count())
                        .where(
                            DriftEventRecord.workspace_id == workspace_id,
                            DriftEventRecord.occurred_at >= since,
                        )
                        .group_by(DriftEventRecord.event_type)
                    ).all()
                )
            )

        priorities = [
            ExecutivePriority(
                asset_id=row.asset_id,
                asset_name=row.asset_name,
                asset_kind=row.asset_kind,
                algorithm=row.algorithm,
                family=row.family,
                risk_score=row.risk_score,
                severity=row.severity,
                quantum_status=row.quantum_status,
                policy_status=row.policy_status,
                migration_target=row.migration_target,
                remediation_status=row.remediation_status,
                remediation_owner=row.remediation_owner,
                due_date=row.remediation_due_date,
            )
            for row in engineering.findings[:10]
        ]
        summary = ExecutiveSummary(
            assets_total=len(assets),
            assets_enabled=sum(1 for asset in assets if asset.enabled),
            active_findings=len(engineering.findings),
            severity={name: severity.get(name, 0) for name in (
                "critical", "high", "medium", "low", "info"
            )},
            quantum={name: quantum.get(name, 0) for name in (
                "vulnerable", "transition", "safe", "unknown"
            )},
            policy={name: policy.get(name, 0) for name in (
                "fail", "review", "pass", "unassessed"
            )},
            remediation=dict(sorted(remediation.items())),
            overdue_remediation=overdue,
            unowned_remediation=unowned,
            drift_30d=dict(sorted(drift.items())),
        )
        return ExecutiveReport(
            metadata=engineering.metadata,
            summary=summary,
            top_priorities=priorities,
        )

    def engineering_csv(self, workspace_id: str, *, now: datetime | None = None) -> str:
        report = self.engineering_report(workspace_id, now=now)
        buffer = StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        headers = list(EngineeringFinding.model_fields)
        writer.writerow(headers)
        for finding in report.findings:
            data = finding.model_dump(mode="json")
            writer.writerow(
                _csv_safe("; ".join(value) if isinstance(value, list) else value)
                for value in (data[header] for header in headers)
            )
        return buffer.getvalue()

    def executive_csv(self, workspace_id: str, *, now: datetime | None = None) -> str:
        report = self.executive_report(workspace_id, now=now)
        buffer = StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(["section", "metric", "value"])
        summary = report.summary
        scalar = {
            "assets_total": summary.assets_total,
            "assets_enabled": summary.assets_enabled,
            "active_findings": summary.active_findings,
            "overdue_remediation": summary.overdue_remediation,
            "unowned_remediation": summary.unowned_remediation,
        }
        for metric, value in scalar.items():
            writer.writerow(["summary", metric, value])
        for section, values in (
            ("severity", summary.severity),
            ("quantum", summary.quantum),
            ("policy", summary.policy),
            ("remediation", summary.remediation),
            ("drift_30d", summary.drift_30d),
        ):
            for metric, value in values.items():
                writer.writerow([section, _csv_safe(metric), value])
        return buffer.getvalue()

    def executive_html(self, workspace_id: str, *, now: datetime | None = None) -> str:
        report = self.executive_report(workspace_id, now=now)
        metadata = report.metadata
        summary = report.summary
        priority_rows = "".join(
            "<tr>"
            f"<td>{html.escape(item.asset_name)}</td>"
            f"<td>{html.escape(item.algorithm)}</td>"
            f"<td>{item.risk_score}</td>"
            f"<td>{html.escape(item.severity)}</td>"
            f"<td>{html.escape(item.quantum_status)}</td>"
            f"<td>{html.escape(item.remediation_status or 'not-tracked')}</td>"
            "</tr>"
            for item in report.top_priorities
        )
        cards = (
            ("Managed assets", summary.assets_total),
            ("Active findings", summary.active_findings),
            ("Quantum vulnerable", summary.quantum.get("vulnerable", 0)),
            ("Policy failures", summary.policy.get("fail", 0)),
            ("Overdue remediation", summary.overdue_remediation),
            ("Unowned remediation", summary.unowned_remediation),
        )
        card_html = "".join(
            f'<div class="card"><strong>{value}</strong><span>{html.escape(label)}</span></div>'
            for label, value in cards
        )
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>CryptoHawk Executive Report</title>
<style>
body{{font-family:Arial,sans-serif;color:#18212f;margin:40px;line-height:1.45}}
h1{{margin:0}} .meta{{color:#5d6878;margin:8px 0 28px}} .grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}}
.card{{border:1px solid #d9dee7;border-radius:10px;padding:16px}} .card strong{{font-size:26px;display:block}} .card span{{color:#5d6878}}
table{{width:100%;border-collapse:collapse;margin-top:12px}} th,td{{padding:9px;border-bottom:1px solid #e5e9ef;text-align:left;font-size:13px}}
h2{{margin-top:30px;font-size:18px}} code{{font-size:11px;word-break:break-all}} @media print{{body{{margin:20px}}}}
</style></head><body>
<h1>CryptoHawk Executive Cryptographic Posture</h1>
<div class="meta">{html.escape(metadata.workspace_name)} · generated {metadata.generated_at.isoformat()}</div>
<div class="grid">{card_html}</div>
<h2>Active cryptographic policy</h2>
<p><strong>{html.escape(metadata.policy.name)} v{metadata.policy.version}</strong><br><code>{html.escape(metadata.policy.rules_hash)}</code></p>
<h2>Top migration priorities</h2>
<table><thead><tr><th>Asset</th><th>Algorithm</th><th>Risk</th><th>Severity</th><th>PQ status</th><th>Remediation</th></tr></thead><tbody>{priority_rows}</tbody></table>
<h2>30-day cryptographic drift</h2>
<p>{html.escape(', '.join(f'{key}: {value}' for key, value in summary.drift_30d.items()) or 'No recorded drift events.')}</p>
<p class="meta">This report is generated deterministically from CryptoHawk active observation state, retained remediation records, and the effective workspace policy. Historical source snippets and connector secrets are not included.</p>
</body></html>"""

    def current_cbom(self, workspace_id: str) -> dict:
        _, current = self._current_rows(workspace_id)
        return CycloneDXExporter().export([finding for _, finding in current])
