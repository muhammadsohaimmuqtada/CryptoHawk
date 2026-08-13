import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  CalendarClock,
  CheckCircle2,
  Clock3,
  History,
  RefreshCw,
  RotateCcw,
  Search,
  X,
} from 'lucide-react'
import App from './App'
import { createClient } from './api'
import type { ManagedAsset, ScanJob, Workspace } from './types'
import './history.css'

type HistoryFilter = 'all' | 'active' | 'failed' | 'succeeded' | 'canceled'

function duration(job: ScanJob) {
  if (!job.started_at) return 'Not started'
  const start = new Date(job.started_at).getTime()
  const end = job.finished_at ? new Date(job.finished_at).getTime() : Date.now()
  const seconds = Math.max(0, Math.round((end - start) / 1000))
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  const remainder = seconds % 60
  return `${minutes}m ${remainder}s`
}

function timestamp(value?: string) {
  if (!value) return '—'
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(new Date(value))
}

function statusLabel(status: ScanJob['status']) {
  return status.charAt(0).toUpperCase() + status.slice(1)
}

function isTerminal(job: ScanJob) {
  return ['succeeded', 'failed', 'canceled'].includes(job.status)
}

export default function HistoryShell() {
  return (
    <>
      <App />
      <HistoryConsole />
    </>
  )
}

function HistoryConsole() {
  const [credential, setCredential] = useState(() => sessionStorage.getItem('cryptohawk_session'))
  const [open, setOpen] = useState(false)
  const [workspaces, setWorkspaces] = useState<Workspace[]>([])
  const [workspaceId, setWorkspaceId] = useState('')
  const [jobs, setJobs] = useState<ScanJob[]>([])
  const [assets, setAssets] = useState<ManagedAsset[]>([])
  const [selectedJobId, setSelectedJobId] = useState('')
  const [filter, setFilter] = useState<HistoryFilter>('all')
  const [query, setQuery] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

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
      const [nextJobs, nextAssets] = await Promise.all([
        client.jobs(workspaceId),
        client.assets(workspaceId),
      ])
      setJobs(nextJobs)
      setAssets(nextAssets)
      setSelectedJobId((current) =>
        current && nextJobs.some((job) => job.id === current) ? current : nextJobs[0]?.id || '',
      )
      setMessage(`Loaded ${nextJobs.length} job${nextJobs.length === 1 ? '' : 's'}`)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to load job history')
    } finally {
      setBusy(false)
    }
  }

  async function rerun(job: ScanJob) {
    if (!client || !workspaceId || !isTerminal(job)) return
    const asset = assets.find((candidate) => candidate.id === job.asset_id)
    if (!asset || !asset.enabled) {
      setMessage('The original asset is unavailable or disabled')
      return
    }
    setBusy(true)
    try {
      const next = await client.queueScan(workspaceId, asset.id)
      setMessage(`Rerun ${next.id.slice(0, 8)} queued for ${asset.name}`)
      await refresh()
      setSelectedJobId(next.id)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to queue rerun')
    } finally {
      setBusy(false)
    }
  }

  const assetsById = useMemo(
    () => new Map(assets.map((asset) => [asset.id, asset])),
    [assets],
  )

  const filteredJobs = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    return jobs.filter((job) => {
      if (filter === 'active' && !['queued', 'running'].includes(job.status)) return false
      if (filter !== 'all' && filter !== 'active' && job.status !== filter) return false
      if (!normalized) return true
      const asset = assetsById.get(job.asset_id)
      return [
        job.id,
        job.kind,
        job.status,
        asset?.name || '',
        asset?.locator || '',
      ]
        .join(' ')
        .toLowerCase()
        .includes(normalized)
    })
  }, [jobs, filter, query, assetsById])

  const selected = jobs.find((job) => job.id === selectedJobId)
  const selectedAsset = selected ? assetsById.get(selected.asset_id) : undefined
  const failed = jobs.filter((job) => job.status === 'failed').length
  const active = jobs.filter((job) => ['queued', 'running'].includes(job.status)).length

  if (!credential) return null

  return (
    <>
      <button
        className="history-launcher"
        onClick={() => setOpen(true)}
        title="Open job history"
      >
        <History size={16} />
        <span>Job history</span>
        {failed > 0 && <b>{failed}</b>}
      </button>

      {open && (
        <div className="history-backdrop" role="presentation">
          <section className="history-console" role="dialog" aria-modal="true" aria-label="Job history">
            <header className="history-header">
              <div>
                <span className="eyebrow">OPERATIONS EVIDENCE</span>
                <h2>Job history & diagnostics</h2>
                <p>Trace execution state, failure evidence, timing, findings and explicit reruns.</p>
              </div>
              <div className="history-header-actions">
                <label>
                  <span>Workspace</span>
                  <select value={workspaceId} onChange={(event) => setWorkspaceId(event.target.value)}>
                    {workspaces.map((workspace) => (
                      <option key={workspace.id} value={workspace.id}>{workspace.name}</option>
                    ))}
                  </select>
                </label>
                <button disabled={busy || !workspaceId} onClick={() => void refresh()} title="Refresh history">
                  <RefreshCw size={15} className={busy ? 'spin' : ''} />
                </button>
                <button onClick={() => setOpen(false)} title="Close history"><X size={17} /></button>
              </div>
            </header>

            <div className="history-summary">
              <div><span>Total jobs</span><strong>{jobs.length}</strong></div>
              <div><span>Active</span><strong>{active}</strong></div>
              <div className={failed ? 'history-alert' : ''}><span>Failed</span><strong>{failed}</strong></div>
              <div><span>Visible results</span><strong>{filteredJobs.length}</strong></div>
            </div>

            <div className="history-toolbar">
              <label className="history-search">
                <Search size={14} />
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search asset, locator, kind or job ID"
                />
              </label>
              <div className="history-filters">
                {(['all', 'active', 'failed', 'succeeded', 'canceled'] as HistoryFilter[]).map((value) => (
                  <button
                    key={value}
                    className={filter === value ? 'active' : ''}
                    onClick={() => setFilter(value)}
                  >
                    {value}
                  </button>
                ))}
              </div>
            </div>

            <div className="history-body">
              <div className="history-table-wrap">
                <table className="history-table">
                  <thead>
                    <tr>
                      <th>Asset</th>
                      <th>Kind</th>
                      <th>Status</th>
                      <th>Requested</th>
                      <th>Duration</th>
                      <th>Findings</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredJobs.map((job) => {
                      const asset = assetsById.get(job.asset_id)
                      return (
                        <tr
                          key={job.id}
                          className={selectedJobId === job.id ? 'selected' : ''}
                          onClick={() => setSelectedJobId(job.id)}
                        >
                          <td>
                            <strong>{asset?.name || 'Deleted asset'}</strong>
                            <small>{job.id.slice(0, 8)}</small>
                          </td>
                          <td>{job.kind}</td>
                          <td><span className={`status-pill ${job.status}`}>{statusLabel(job.status)}</span></td>
                          <td>{timestamp(job.requested_at)}</td>
                          <td>{duration(job)}</td>
                          <td>{job.findings_count}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
                {filteredJobs.length === 0 && (
                  <div className="history-empty"><History size={20} />No jobs match the current filters.</div>
                )}
              </div>

              <aside className="history-detail">
                {selected ? (
                  <>
                    <div className="history-detail-head">
                      <div>
                        <span className="eyebrow">EXECUTION RECORD</span>
                        <h3>{selectedAsset?.name || 'Deleted asset'}</h3>
                        <code>{selected.id}</code>
                      </div>
                      <span className={`status-pill ${selected.status}`}>{statusLabel(selected.status)}</span>
                    </div>

                    <dl className="history-metadata">
                      <div><dt>Collector</dt><dd>{selected.kind}</dd></div>
                      <div><dt>Locator</dt><dd>{selectedAsset?.locator || 'Asset removed'}</dd></div>
                      <div><dt>Requested</dt><dd>{timestamp(selected.requested_at)}</dd></div>
                      <div><dt>Started</dt><dd>{timestamp(selected.started_at)}</dd></div>
                      <div><dt>Finished</dt><dd>{timestamp(selected.finished_at)}</dd></div>
                      <div><dt>Duration</dt><dd>{duration(selected)}</dd></div>
                      <div><dt>Findings</dt><dd>{selected.findings_count}</dd></div>
                      <div><dt>Asset status</dt><dd>{selectedAsset?.enabled === false ? 'Disabled' : 'Enabled'}</dd></div>
                    </dl>

                    {selected.status === 'failed' && (
                      <div className="failure-diagnostic">
                        <div><AlertTriangle size={16} /><strong>Failure diagnostic</strong></div>
                        <p>{selected.error_message || 'No worker error message was retained for this failure.'}</p>
                      </div>
                    )}

                    {selected.status === 'running' && (
                      <div className="active-diagnostic">
                        <Clock3 size={16} />
                        <div><strong>Execution in progress</strong><span>Elapsed {duration(selected)}</span></div>
                      </div>
                    )}

                    {selected.status === 'queued' && (
                      <div className="active-diagnostic">
                        <CalendarClock size={16} />
                        <div><strong>Waiting for a worker lease</strong><span>Queued {timestamp(selected.requested_at)}</span></div>
                      </div>
                    )}

                    {selected.status === 'succeeded' && (
                      <div className="success-diagnostic">
                        <CheckCircle2 size={16} />
                        <div><strong>Completed successfully</strong><span>{selected.findings_count} findings persisted</span></div>
                      </div>
                    )}

                    <div className="history-detail-actions">
                      <button
                        disabled={busy || !isTerminal(selected) || !selectedAsset?.enabled}
                        onClick={() => void rerun(selected)}
                      >
                        <RotateCcw size={15} />Run again
                      </button>
                      {!isTerminal(selected) && <span>Active jobs cannot be duplicated from history.</span>}
                    </div>
                  </>
                ) : (
                  <div className="history-empty-detail"><History size={24} />Select a job to inspect its evidence.</div>
                )}
              </aside>
            </div>

            <footer className="history-footer">
              <span>{message || 'History is workspace-scoped and read from durable job records.'}</span>
              <span>Auto-refresh remains controlled by the main workspace session.</span>
            </footer>
          </section>
        </div>
      )}
    </>
  )
}
