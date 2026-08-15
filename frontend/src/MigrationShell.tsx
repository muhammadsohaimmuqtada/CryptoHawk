import { FormEvent, useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ClipboardCheck,
  Clock3,
  ListChecks,
  Play,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldAlert,
  Target,
  X,
} from 'lucide-react'
import HistoryShell from './HistoryShell'
import { createClient } from './api'
import type {
  Finding,
  ManagedAsset,
  MigrationItem,
  RemediationPriority,
  RemediationStatus,
  ScanJob,
  Workspace,
} from './types'
import './migration.css'

const TERMINAL = new Set<RemediationStatus>(['verified', 'accepted-risk'])

type QueueFilter = 'all' | 'active' | RemediationStatus

function humanize(value: string) {
  return value.replaceAll('-', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function short(value: string) {
  return value.slice(0, 8)
}

function formatDate(value?: string) {
  if (!value) return '—'
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(new Date(`${value}T00:00:00`))
}

function priorityFromFinding(finding: Finding): RemediationPriority {
  if (finding.risk.severity === 'critical') return 'critical'
  if (finding.risk.severity === 'high') return 'high'
  if (finding.risk.severity === 'medium') return 'medium'
  return 'low'
}

function nextActions(status: RemediationStatus): Array<{ label: string; target: RemediationStatus }> {
  switch (status) {
    case 'open':
      return [
        { label: 'Plan work', target: 'planned' },
        { label: 'Start now', target: 'in-progress' },
      ]
    case 'planned':
      return [
        { label: 'Start work', target: 'in-progress' },
        { label: 'Mark blocked', target: 'blocked' },
      ]
    case 'in-progress':
      return [
        { label: 'Ready to verify', target: 'ready-for-verification' },
        { label: 'Mark blocked', target: 'blocked' },
      ]
    case 'blocked':
      return [{ label: 'Resume work', target: 'in-progress' }]
    case 'ready-for-verification':
      return [
        { label: 'Back to work', target: 'in-progress' },
        { label: 'Mark blocked', target: 'blocked' },
      ]
    case 'verified':
      return [{ label: 'Reopen', target: 'open' }]
    case 'accepted-risk':
      return [{ label: 'Reopen', target: 'open' }]
  }
}

export default function MigrationShell() {
  return (
    <>
      <HistoryShell />
      <MigrationConsole />
    </>
  )
}

function MigrationConsole() {
  const [credential, setCredential] = useState(() => sessionStorage.getItem('cryptohawk_session'))
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [workspaces, setWorkspaces] = useState<Workspace[]>([])
  const [workspaceId, setWorkspaceId] = useState('')
  const [items, setItems] = useState<MigrationItem[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [jobs, setJobs] = useState<ScanJob[]>([])
  const [assets, setAssets] = useState<ManagedAsset[]>([])
  const [selectedId, setSelectedId] = useState('')
  const [filter, setFilter] = useState<QueueFilter>('active')
  const [query, setQuery] = useState('')

  useEffect(() => {
    const interval = window.setInterval(() => {
      const current = sessionStorage.getItem('cryptohawk_session')
      setCredential((previous) => (previous === current ? previous : current))
    }, 1000)
    return () => window.clearInterval(interval)
  }, [])

  const client = useMemo(
    () =>
      credential
        ? createClient(credential, () => {
            sessionStorage.removeItem('cryptohawk_session')
            setCredential(null)
            setOpen(false)
          })
        : null,
    [credential],
  )

  useEffect(() => {
    if (!open || !client) return
    void loadWorkspaces()
  }, [open, client])

  useEffect(() => {
    if (!open || !client || !workspaceId) return
    void refresh()
  }, [open, client, workspaceId])

  async function loadWorkspaces() {
    if (!client) return
    try {
      const available = await client.listWorkspaces()
      setWorkspaces(available)
      setWorkspaceId((current) =>
        available.some((workspace) => workspace.id === current)
          ? current
          : available[0]?.id || '',
      )
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to load workspaces')
    }
  }

  async function refresh() {
    if (!client || !workspaceId) return
    setBusy(true)
    try {
      const [nextItems, nextFindings, nextJobs, nextAssets] = await Promise.all([
        client.migrationItems(workspaceId),
        client.findings(workspaceId),
        client.jobs(workspaceId),
        client.assets(workspaceId),
      ])
      setItems(nextItems)
      setFindings(nextFindings)
      setJobs(nextJobs)
      setAssets(nextAssets)
      setSelectedId((current) =>
        current && nextItems.some((item) => item.id === current) ? current : nextItems[0]?.id || '',
      )
      setMessage(`Loaded ${nextItems.length} migration item${nextItems.length === 1 ? '' : 's'}`)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to load migration queue')
    } finally {
      setBusy(false)
    }
  }

  async function createFromFinding(finding: Finding) {
    if (!client || !workspaceId) return
    setBusy(true)
    try {
      const item = await client.createMigrationItem(workspaceId, {
        finding_id: finding.observation.id,
        priority: priorityFromFinding(finding),
        target_algorithm: finding.risk.migration_target || undefined,
      })
      setItems((current) => [item, ...current])
      setSelectedId(item.id)
      setMessage(`Migration work created for ${finding.observation.algorithm}`)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to create migration work')
    } finally {
      setBusy(false)
    }
  }

  async function updateItem(item: MigrationItem, changes: Record<string, unknown>) {
    if (!client || !workspaceId) return
    setBusy(true)
    try {
      const updated = await client.updateMigrationItem(workspaceId, item.id, changes)
      setItems((current) => current.map((candidate) => (candidate.id === updated.id ? updated : candidate)))
      setMessage(`${updated.title} updated`)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to update migration work')
    } finally {
      setBusy(false)
    }
  }

  async function queueVerificationScan(item: MigrationItem) {
    if (!client || !workspaceId) return
    const asset = assets.find((candidate) => candidate.id === item.asset_id)
    if (!asset?.enabled) {
      setMessage('The managed asset is unavailable or disabled')
      return
    }
    setBusy(true)
    try {
      const job = await client.queueScan(workspaceId, item.asset_id)
      setJobs((current) => [job, ...current])
      setMessage(`Verification scan ${short(job.id)} queued for ${asset.name}`)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to queue verification scan')
    } finally {
      setBusy(false)
    }
  }

  async function verify(item: MigrationItem) {
    if (!client || !workspaceId) return
    const latest = jobs
      .filter((job) => job.asset_id === item.asset_id && job.status === 'succeeded')
      .sort((a, b) => new Date(b.finished_at || b.requested_at).getTime() - new Date(a.finished_at || a.requested_at).getTime())[0]
    if (!latest) {
      setMessage('No successful evidence scan is available for this asset yet')
      return
    }
    setBusy(true)
    try {
      const result = await client.verifyMigrationItem(workspaceId, item.id, latest.id)
      setItems((current) => current.map((candidate) => (candidate.id === item.id ? result.item : candidate)))
      setMessage(
        result.verified
          ? `Verified: exposure absent in scan ${short(latest.id)}`
          : `Verification failed: exposure still present in scan ${short(latest.id)}`,
      )
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to verify migration work')
    } finally {
      setBusy(false)
    }
  }

  const assetsById = useMemo(() => new Map(assets.map((asset) => [asset.id, asset])), [assets])
  const selected = items.find((item) => item.id === selectedId)
  const activeCount = items.filter((item) => !TERMINAL.has(item.status)).length
  const overdueCount = items.filter(
    (item) => !TERMINAL.has(item.status) && item.due_date && new Date(`${item.due_date}T23:59:59`).getTime() < Date.now(),
  ).length
  const verifiedCount = items.filter((item) => item.status === 'verified').length

  const filteredItems = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    return items.filter((item) => {
      if (filter === 'active' && TERMINAL.has(item.status)) return false
      if (filter !== 'all' && filter !== 'active' && item.status !== filter) return false
      if (!normalized) return true
      const asset = assetsById.get(item.asset_id)
      return [
        item.title,
        item.owner || '',
        item.status,
        item.priority,
        item.target_algorithm || '',
        item.source_finding.observation.algorithm,
        asset?.name || '',
        asset?.locator || '',
      ]
        .join(' ')
        .toLowerCase()
        .includes(normalized)
    })
  }, [items, filter, query, assetsById])

  const candidateFindings = findings
    .filter((finding) => finding.risk.migration_target || finding.risk.quantum_status === 'vulnerable')
    .slice(0, 12)

  if (!credential) return null

  return (
    <>
      <button className="migration-launcher" onClick={() => setOpen(true)} title="Open migration queue">
        <ListChecks size={16} />
        <span>Migration queue</span>
        {activeCount > 0 && <b>{activeCount}</b>}
      </button>

      {open && (
        <div className="migration-backdrop" role="presentation">
          <section className="migration-console" role="dialog" aria-modal="true" aria-label="Migration queue">
            <header className="migration-header">
              <div>
                <span className="eyebrow">POST-QUANTUM REMEDIATION</span>
                <h2>Migration queue</h2>
                <p>Own, execute and prove cryptographic remediation against retained scan evidence.</p>
              </div>
              <div className="migration-header-actions">
                <label>
                  <span>Workspace</span>
                  <select value={workspaceId} onChange={(event) => setWorkspaceId(event.target.value)}>
                    {workspaces.map((workspace) => (
                      <option key={workspace.id} value={workspace.id}>{workspace.name}</option>
                    ))}
                  </select>
                </label>
                <button disabled={busy || !workspaceId} onClick={() => void refresh()} title="Refresh queue">
                  <RefreshCw size={15} className={busy ? 'spin' : ''} />
                </button>
                <button onClick={() => setOpen(false)} title="Close migration queue"><X size={17} /></button>
              </div>
            </header>

            <div className="migration-summary">
              <div><span>Total work</span><strong>{items.length}</strong></div>
              <div><span>Active</span><strong>{activeCount}</strong></div>
              <div className={overdueCount ? 'migration-alert' : ''}><span>Overdue</span><strong>{overdueCount}</strong></div>
              <div><span>Verified</span><strong>{verifiedCount}</strong></div>
            </div>

            <div className="migration-toolbar">
              <label className="migration-search">
                <Search size={14} />
                <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search owner, asset, algorithm, target or status" />
              </label>
              <div className="migration-filters">
                {(['active', 'all', 'open', 'planned', 'in-progress', 'blocked', 'ready-for-verification', 'verified', 'accepted-risk'] as QueueFilter[]).map((value) => (
                  <button key={value} className={filter === value ? 'active' : ''} onClick={() => setFilter(value)}>
                    {humanize(value)}
                  </button>
                ))}
              </div>
            </div>

            <div className="migration-body">
              <section className="migration-list">
                <div className="migration-list-head">
                  <div><span className="eyebrow">ACCOUNTABLE WORK</span><h3>Remediation backlog</h3></div>
                  <strong>{filteredItems.length}</strong>
                </div>
                <div className="migration-cards">
                  {filteredItems.map((item) => {
                    const asset = assetsById.get(item.asset_id)
                    return (
                      <button
                        key={item.id}
                        className={`migration-card ${selectedId === item.id ? 'selected' : ''}`}
                        onClick={() => setSelectedId(item.id)}
                      >
                        <div className="migration-card-top">
                          <span className={`priority-dot ${item.priority}`} />
                          <strong>{item.source_finding.observation.algorithm}</strong>
                          <span className={`migration-status ${item.status}`}>{humanize(item.status)}</span>
                        </div>
                        <h4>{asset?.name || item.source_finding.observation.asset_name}</h4>
                        <p>{item.target_algorithm || 'Migration target not assigned'}</p>
                        <div className="migration-card-meta">
                          <span>{item.owner || 'Unassigned'}</span>
                          <span>{item.due_date ? formatDate(item.due_date) : 'No due date'}</span>
                        </div>
                      </button>
                    )
                  })}
                  {filteredItems.length === 0 && (
                    <div className="migration-empty"><ClipboardCheck size={23} /><strong>No migration work matches this view.</strong></div>
                  )}
                </div>
              </section>

              <aside className="migration-detail">
                {selected ? (
                  <MigrationDetail
                    item={selected}
                    asset={assetsById.get(selected.asset_id)}
                    busy={busy}
                    onUpdate={(changes) => void updateItem(selected, changes)}
                    onQueueScan={() => void queueVerificationScan(selected)}
                    onVerify={() => void verify(selected)}
                  />
                ) : (
                  <CandidateFindings findings={candidateFindings} busy={busy} onCreate={(finding) => void createFromFinding(finding)} />
                )}
              </aside>

              <aside className="migration-candidates">
                <CandidateFindings findings={candidateFindings} busy={busy} onCreate={(finding) => void createFromFinding(finding)} compact />
              </aside>
            </div>

            <footer className="migration-footer">
              <span>{message || 'Verification can only be proven by the newest successful scan of the same managed asset.'}</span>
              <span>Manual state changes cannot set an item to Verified.</span>
            </footer>
          </section>
        </div>
      )}
    </>
  )
}

function MigrationDetail({
  item,
  asset,
  busy,
  onUpdate,
  onQueueScan,
  onVerify,
}: {
  item: MigrationItem
  asset?: ManagedAsset
  busy: boolean
  onUpdate: (changes: Record<string, unknown>) => void
  onQueueScan: () => void
  onVerify: () => void
}) {
  const [owner, setOwner] = useState(item.owner || '')
  const [target, setTarget] = useState(item.target_algorithm || '')
  const [dueDate, setDueDate] = useState(item.due_date || '')
  const [priority, setPriority] = useState<RemediationPriority>(item.priority)
  const [notes, setNotes] = useState(item.notes || '')
  const [acceptanceReason, setAcceptanceReason] = useState(item.acceptance_reason || '')

  useEffect(() => {
    setOwner(item.owner || '')
    setTarget(item.target_algorithm || '')
    setDueDate(item.due_date || '')
    setPriority(item.priority)
    setNotes(item.notes || '')
    setAcceptanceReason(item.acceptance_reason || '')
  }, [item.id, item.updated_at])

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    onUpdate({
      owner: owner || null,
      target_algorithm: target || null,
      due_date: dueDate || null,
      priority,
      notes: notes || null,
      ...(item.status === 'accepted-risk' ? { acceptance_reason: acceptanceReason || null } : {}),
    })
  }

  function acceptRisk() {
    if (acceptanceReason.trim().length < 5) return
    onUpdate({ status: 'accepted-risk', acceptance_reason: acceptanceReason.trim() })
  }

  const risk = item.source_finding.risk
  const observation = item.source_finding.observation

  return (
    <div className="migration-detail-inner">
      <div className="migration-detail-head">
        <div>
          <span className="eyebrow">MIGRATION RECORD</span>
          <h3>{item.title}</h3>
          <code>{short(item.observation_fingerprint)}</code>
        </div>
        <span className={`migration-status ${item.status}`}>{humanize(item.status)}</span>
      </div>

      <div className="migration-risk-card">
        <div><ShieldAlert size={17} /><strong>{risk.score}/100</strong><span>{humanize(risk.severity)} risk</span></div>
        <p>{risk.reasons?.[0] || 'Cryptographic migration required by the current risk policy.'}</p>
      </div>

      <dl className="migration-evidence-grid">
        <div><dt>Asset</dt><dd>{asset?.name || observation.asset_name}</dd></div>
        <div><dt>Locator</dt><dd>{observation.evidence.locator || asset?.locator || '—'}</dd></div>
        <div><dt>Current crypto</dt><dd>{observation.algorithm}{observation.key_size ? ` ${observation.key_size}` : ''}</dd></div>
        <div><dt>Quantum status</dt><dd>{humanize(risk.quantum_status)}</dd></div>
        <div><dt>Source scan</dt><dd>{short(item.source_scan_job_id)}</dd></div>
        <div><dt>Verified by</dt><dd>{item.verification_job_id ? short(item.verification_job_id) : '—'}</dd></div>
      </dl>

      <form className="migration-form" onSubmit={submit}>
        <label><span>Owner</span><input value={owner} onChange={(event) => setOwner(event.target.value)} placeholder="Platform Security" /></label>
        <label><span>Priority</span><select value={priority} onChange={(event) => setPriority(event.target.value as RemediationPriority)}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
        <label className="wide"><span>Migration target</span><input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="ML-KEM hybrid deployment" /></label>
        <label><span>Due date</span><input type="date" value={dueDate} onChange={(event) => setDueDate(event.target.value)} /></label>
        <label className="wide"><span>Operator notes</span><textarea value={notes} onChange={(event) => setNotes(event.target.value)} rows={3} placeholder="Dependencies, rollout plan, blockers or change reference" /></label>
        {(item.status === 'accepted-risk' || ['open', 'planned', 'in-progress', 'blocked'].includes(item.status)) && (
          <label className="wide"><span>Risk acceptance rationale</span><textarea value={acceptanceReason} onChange={(event) => setAcceptanceReason(event.target.value)} rows={2} placeholder="Required before risk can be accepted" /></label>
        )}
        <button className="migration-save" disabled={busy} type="submit">Save ownership & plan</button>
      </form>

      <div className="migration-workflow-actions">
        {nextActions(item.status).map((action) => (
          <button key={action.target} disabled={busy} onClick={() => onUpdate({ status: action.target })}>
            <ArrowRight size={14} />{action.label}
          </button>
        ))}
        {!TERMINAL.has(item.status) && item.status !== 'ready-for-verification' && (
          <button className="risk-accept" disabled={busy || acceptanceReason.trim().length < 5} onClick={acceptRisk}>
            <AlertTriangle size={14} />Accept risk
          </button>
        )}
      </div>

      <div className="verification-panel">
        <div className="verification-title"><Target size={16} /><div><strong>Evidence verification</strong><span>Only the latest successful scan can close this item.</span></div></div>
        <div className="verification-actions">
          <button disabled={busy || !asset?.enabled} onClick={onQueueScan}><Play size={14} />Queue verification scan</button>
          <button className="verify-button" disabled={busy || item.status !== 'ready-for-verification'} onClick={onVerify}><CheckCircle2 size={14} />Verify latest evidence</button>
        </div>
        {item.verification_evidence.outcome && (
          <div className={`verification-result ${String(item.verification_evidence.outcome)}`}>
            {item.verification_evidence.outcome === 'resolved' ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}
            <span>{humanize(String(item.verification_evidence.outcome))}</span>
          </div>
        )}
      </div>
    </div>
  )
}

function CandidateFindings({
  findings,
  busy,
  onCreate,
  compact = false,
}: {
  findings: Finding[]
  busy: boolean
  onCreate: (finding: Finding) => void
  compact?: boolean
}) {
  return (
    <div className={`candidate-findings ${compact ? 'compact' : ''}`}>
      <div className="candidate-head">
        <div><span className="eyebrow">UNPLANNED EXPOSURE</span><h3>Candidate findings</h3></div>
        <Clock3 size={17} />
      </div>
      <p>Promote an evidence-backed finding into accountable migration work.</p>
      <div className="candidate-list">
        {findings.map((finding) => (
          <div className="candidate-item" key={finding.observation.id}>
            <div>
              <strong>{finding.observation.algorithm}</strong>
              <span>{finding.observation.asset_name}</span>
              <small>{finding.risk.migration_target || humanize(finding.risk.quantum_status)}</small>
            </div>
            <b>{finding.risk.score}</b>
            <button disabled={busy} onClick={() => onCreate(finding)}>Create work <ArrowRight size={12} /></button>
          </div>
        ))}
        {findings.length === 0 && <div className="candidate-empty">No migration candidates in the current finding set.</div>}
      </div>
    </div>
  )
}
