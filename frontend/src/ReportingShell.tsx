import { useEffect, useMemo, useState } from 'react'
import {
  BarChart3,
  Download,
  FileCode2,
  FileSpreadsheet,
  FileText,
  RefreshCw,
  ShieldAlert,
  X,
} from 'lucide-react'
import PolicyShell from './PolicyShell'
import { createClient } from './api'
import type { ExecutiveReport, Workspace } from './types'
import './reporting.css'

const ARTIFACTS = [
  { key: 'executive.html', label: 'Executive report', detail: 'Print-ready HTML', icon: FileText },
  { key: 'executive.csv', label: 'Executive metrics', detail: 'CSV summary', icon: FileSpreadsheet },
  { key: 'engineering.csv', label: 'Engineering evidence', detail: 'CSV findings', icon: FileCode2 },
  { key: 'cbom', label: 'CycloneDX CBOM', detail: 'Current-state JSON', icon: Download },
] as const

function formatNumber(value: number) {
  return new Intl.NumberFormat().format(value)
}

export default function ReportingShell() {
  const [credential, setCredential] = useState(() => sessionStorage.getItem('cryptohawk_session'))
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [workspaces, setWorkspaces] = useState<Workspace[]>([])
  const [workspaceId, setWorkspaceId] = useState('')
  const [report, setReport] = useState<ExecutiveReport | null>(null)

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
    void refreshReport()
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

  async function refreshReport() {
    if (!client || !workspaceId) return
    setBusy(true)
    try {
      const next = await client.executiveReport(workspaceId)
      setReport(next)
      setMessage(`Posture refreshed ${new Date(next.metadata.generated_at).toLocaleString()}`)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to build report')
    } finally {
      setBusy(false)
    }
  }

  async function downloadArtifact(artifact: (typeof ARTIFACTS)[number]['key']) {
    if (!client || !workspaceId) return
    const workspace = workspaces.find((item) => item.id === workspaceId)
    setBusy(true)
    try {
      const blob = await client.downloadReport(workspaceId, artifact)
      const extension = artifact === 'cbom' ? 'cbom.json' : artifact
      const filename = `cryptohawk-${workspace?.slug || 'workspace'}-${extension}`
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
      setMessage(`${filename} exported from current retained evidence`)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to export report')
    } finally {
      setBusy(false)
    }
  }

  if (!credential) {
    return <PolicyShell />
  }

  const summary = report?.summary

  return (
    <>
      <PolicyShell />
      <button className="reporting-launcher" onClick={() => setOpen(true)} title="Open reporting">
        <BarChart3 size={16} />
        <span>Reports</span>
      </button>

      {open && (
        <div className="reporting-backdrop" role="presentation">
          <section className="reporting-console" role="dialog" aria-modal="true" aria-label="Reports">
            <header className="reporting-header">
              <div>
                <span className="eyebrow">EVIDENCE EXPORT</span>
                <h2>Executive & engineering reports</h2>
                <p>Current cryptographic posture, migration accountability, policy context and portable evidence.</p>
              </div>
              <div className="reporting-header-actions">
                <label>
                  <span>Workspace</span>
                  <select value={workspaceId} onChange={(event) => setWorkspaceId(event.target.value)}>
                    {workspaces.map((workspace) => (
                      <option key={workspace.id} value={workspace.id}>{workspace.name}</option>
                    ))}
                  </select>
                </label>
                <button disabled={busy || !workspaceId} onClick={() => void refreshReport()} title="Refresh report">
                  <RefreshCw size={15} className={busy ? 'spin' : ''} />
                </button>
                <button onClick={() => setOpen(false)} title="Close reports"><X size={17} /></button>
              </div>
            </header>

            {report && summary ? (
              <div className="reporting-body">
                <section className="reporting-trust">
                  <ShieldAlert size={18} />
                  <div>
                    <strong>{report.metadata.policy.name} v{report.metadata.policy.version}</strong>
                    <span>All figures below are derived from active retained observation state. Historical source snippets and connector secrets are excluded.</span>
                  </div>
                  <code>{report.metadata.policy.rules_hash.slice(0, 16)}…</code>
                </section>

                <section className="reporting-kpis">
                  <Kpi label="Managed assets" value={summary.assets_total} />
                  <Kpi label="Active findings" value={summary.active_findings} />
                  <Kpi label="Critical" value={summary.severity.critical || 0} attention />
                  <Kpi label="Quantum vulnerable" value={summary.quantum.vulnerable || 0} attention />
                  <Kpi label="Policy failures" value={summary.policy.fail || 0} attention />
                  <Kpi label="Overdue work" value={summary.overdue_remediation} attention />
                </section>

                <div className="reporting-grid">
                  <section className="reporting-panel">
                    <div className="reporting-panel-head">
                      <div><span className="eyebrow">EXPORT BUNDLE</span><h3>Portable artifacts</h3></div>
                    </div>
                    <div className="artifact-list">
                      {ARTIFACTS.map(({ key, label, detail, icon: Icon }) => (
                        <button key={key} disabled={busy} onClick={() => void downloadArtifact(key)}>
                          <span className="artifact-icon"><Icon size={17} /></span>
                          <span><strong>{label}</strong><small>{detail}</small></span>
                          <Download size={15} />
                        </button>
                      ))}
                    </div>
                  </section>

                  <section className="reporting-panel priority-panel">
                    <div className="reporting-panel-head">
                      <div><span className="eyebrow">TOP EXPOSURES</span><h3>Migration priorities</h3></div>
                      <span>{report.top_priorities.length} shown</span>
                    </div>
                    <div className="priority-list">
                      {report.top_priorities.length ? report.top_priorities.map((item) => (
                        <article key={`${item.asset_id}-${item.algorithm}-${item.risk_score}`}>
                          <div className="risk-score">{item.risk_score}</div>
                          <div>
                            <strong>{item.asset_name}</strong>
                            <span>{item.algorithm} · {item.quantum_status} · {item.policy_status || 'unassessed'}</span>
                          </div>
                          <div className="priority-state">
                            <b>{item.severity}</b>
                            <small>{item.remediation_status || 'not tracked'}</small>
                          </div>
                        </article>
                      )) : <div className="reporting-empty">No active cryptographic findings.</div>}
                    </div>
                  </section>
                </div>

                <section className="reporting-foot-metrics">
                  <div><span>Unowned migration work</span><strong>{formatNumber(summary.unowned_remediation)}</strong></div>
                  <div><span>Introduced / 30d</span><strong>{formatNumber(summary.drift_30d.introduced || 0)}</strong></div>
                  <div><span>Resolved / 30d</span><strong>{formatNumber(summary.drift_30d.resolved || 0)}</strong></div>
                  <div><span>Verified migrations</span><strong>{formatNumber(summary.remediation.verified || 0)}</strong></div>
                </section>
              </div>
            ) : (
              <div className="reporting-loading">{busy ? 'Building current-state report…' : 'Select a workspace to build a report.'}</div>
            )}

            <footer className="reporting-footer">
              <span>{message || 'Exports are generated on demand from workspace-scoped evidence.'}</span>
              <span>Executive HTML · Executive CSV · Engineering CSV · CycloneDX 1.7</span>
            </footer>
          </section>
        </div>
      )}
    </>
  )
}

function Kpi({ label, value, attention = false }: { label: string; value: number; attention?: boolean }) {
  return (
    <div className={`reporting-kpi ${attention && value > 0 ? 'attention' : ''}`}>
      <strong>{formatNumber(value)}</strong>
      <span>{label}</span>
    </div>
  )
}
