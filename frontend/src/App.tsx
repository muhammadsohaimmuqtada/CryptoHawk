import React, { FormEvent, ReactNode, useEffect, useMemo, useState } from 'react'
import {
  Activity,
  ArrowRight,
  Box,
  CheckCircle2,
  Database,
  FileCode2,
  Globe2,
  KeyRound,
  LockKeyhole,
  LogOut,
  Plus,
  Radar,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Terminal,
  TriangleAlert,
  UserRound,
  Zap,
} from 'lucide-react'
import { ApiError, bootstrap, createClient, login, publicJson } from './api'
import type {
  AssetKind,
  AuthMode,
  Finding,
  IssuedToken,
  ManagedAsset,
  OperatorView,
  ScanJob,
  ScannableAssetKind,
  Summary,
  Workspace,
} from './types'

const initialSummary: Summary = {
  total_findings: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  quantum_vulnerable: 0,
  pqc_ready: 0,
}

const SCANNABLE_KINDS: ScannableAssetKind[] = [
  'tls-endpoint',
  'certificate-endpoint',
  'ssh-endpoint',
  'repository',
  'container',
]

const ASSET_OPTIONS: Array<{
  kind: ScannableAssetKind
  label: string
  short: string
  example: string
  icon: ReactNode
}> = [
  {
    kind: 'tls-endpoint',
    label: 'TLS endpoint',
    short: 'Protocol + certificate posture',
    example: 'api.example.com:443',
    icon: <Globe2 size={18} />,
  },
  {
    kind: 'certificate-endpoint',
    label: 'Certificate endpoint',
    short: 'X.509 estate inventory',
    example: 'login.example.com:443',
    icon: <KeyRound size={18} />,
  },
  {
    kind: 'ssh-endpoint',
    label: 'SSH endpoint',
    short: 'Server host-key exposure',
    example: 'bastion.example.com:22',
    icon: <Terminal size={18} />,
  },
  {
    kind: 'repository',
    label: 'Git repository',
    short: 'Source crypto + commit drift',
    example: 'https://github.com/org/repo.git',
    icon: <FileCode2 size={18} />,
  },
  {
    kind: 'container',
    label: 'Container image',
    short: 'Effective image filesystem',
    example: '/ingress/payments-api.tar',
    icon: <Box size={18} />,
  },
]

function isScannable(kind: AssetKind): kind is ScannableAssetKind {
  return SCANNABLE_KINDS.includes(kind as ScannableAssetKind)
}

function displayKind(kind: AssetKind) {
  return kind.replaceAll('-', ' ').replace(/\b\w/g, (value) => value.toUpperCase())
}

function shortId(value: string) {
  return value.slice(0, 8)
}

function App() {
  const [authMode, setAuthMode] = useState<AuthMode>('checking')
  const [bootstrapRequired, setBootstrapRequired] = useState(false)
  const [token, setToken] = useState<string | null>(null)
  const [identity, setIdentity] = useState('Authenticated operator')
  const [workspaces, setWorkspaces] = useState<Workspace[]>([])
  const [workspaceId, setWorkspaceId] = useState('')
  const [summary, setSummary] = useState<Summary>(initialSummary)
  const [findings, setFindings] = useState<Finding[]>([])
  const [assets, setAssets] = useState<ManagedAsset[]>([])
  const [jobs, setJobs] = useState<ScanJob[]>([])
  const [view, setView] = useState<OperatorView>('command')
  const [assetSearch, setAssetSearch] = useState('')
  const [kindFilter, setKindFilter] = useState<'all' | AssetKind>('all')
  const [showWorkspaceForm, setShowWorkspaceForm] = useState(false)
  const [showAssetWizard, setShowAssetWizard] = useState(false)
  const [busy, setBusy] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [message, setMessage] = useState('Secure session initializing')

  function expireSession() {
    sessionStorage.removeItem('cryptohawk_session')
    setToken(null)
    setWorkspaceId('')
    setWorkspaces([])
    setAssets([])
    setFindings([])
    setJobs([])
    setSummary(initialSummary)
    setAuthMode(bootstrapRequired ? 'bootstrap' : 'login')
    setMessage('Session expired. Sign in again.')
  }

  const client = useMemo(
    () => (token ? createClient(token, expireSession) : null),
    [token, bootstrapRequired],
  )

  useEffect(() => {
    void initialize()
  }, [])

  useEffect(() => {
    if (authMode !== 'ready' || !client || !workspaceId) return
    void refreshWorkspace(client, workspaceId)
    const interval = window.setInterval(() => {
      void refreshWorkspace(client, workspaceId, true)
    }, 5000)
    return () => window.clearInterval(interval)
  }, [authMode, client, workspaceId])

  async function initialize() {
    try {
      const status = await publicJson<{ bootstrap_required: boolean }>('/api/v1/auth/status')
      setBootstrapRequired(status.bootstrap_required)
      const storedToken = sessionStorage.getItem('cryptohawk_session')
      if (storedToken) {
        try {
          const storedClient = createClient(storedToken, expireSession)
          const me = await storedClient.me()
          setIdentity(me.user_id ? `User ${shortId(me.user_id)}` : 'API principal')
          await enterAuthenticated(storedToken)
          return
        } catch {
          sessionStorage.removeItem('cryptohawk_session')
        }
      }
      setAuthMode(status.bootstrap_required ? 'bootstrap' : 'login')
      setMessage(status.bootstrap_required ? 'Create the first CryptoHawk owner' : 'Authentication required')
    } catch {
      setAuthMode('login')
      setMessage('CryptoHawk API unavailable')
    }
  }

  async function enterAuthenticated(credential: string, preferredWorkspace?: string) {
    const authenticated = createClient(credential, expireSession)
    const accessible = await authenticated.listWorkspaces()
    sessionStorage.setItem('cryptohawk_session', credential)
    setToken(credential)
    setWorkspaces(accessible)
    const selected =
      accessible.find((workspace) => workspace.id === preferredWorkspace)?.id ||
      accessible[0]?.id ||
      ''
    setWorkspaceId(selected)
    setAuthMode('ready')
    setShowWorkspaceForm(accessible.length === 0)
    setMessage(accessible.length ? 'Workspace boundary active' : 'Create your first workspace')
  }

  async function refreshWorkspace(
    activeClient = client,
    selectedWorkspace = workspaceId,
    quiet = false,
  ) {
    if (!activeClient || !selectedWorkspace) return
    if (!quiet) setRefreshing(true)
    try {
      const [workspaceSummary, workspaceFindings, workspaceAssets, workspaceJobs] =
        await Promise.all([
          activeClient.summary(selectedWorkspace),
          activeClient.findings(selectedWorkspace),
          activeClient.assets(selectedWorkspace),
          activeClient.jobs(selectedWorkspace),
        ])
      setSummary(workspaceSummary)
      setFindings(workspaceFindings)
      setAssets(workspaceAssets)
      setJobs(workspaceJobs)
      if (!quiet) setMessage('Workspace data synchronized')
    } catch (error) {
      if (!quiet) setMessage(error instanceof Error ? error.message : 'Workspace refresh failed')
    } finally {
      if (!quiet) setRefreshing(false)
    }
  }

  async function submitBootstrap(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    setBusy(true)
    setMessage('Creating owner identity…')
    try {
      const issued = await bootstrap({
        email: String(data.get('email') || ''),
        display_name: String(data.get('display_name') || ''),
        password: String(data.get('password') || ''),
        workspace_name: String(data.get('workspace_name') || ''),
      })
      setIdentity(issued.user?.display_name || issued.user?.email || 'Workspace owner')
      setBootstrapRequired(false)
      await enterAuthenticated(issued.token, issued.workspace?.id)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Bootstrap failed')
    } finally {
      setBusy(false)
    }
  }

  async function submitLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    setBusy(true)
    setMessage('Verifying identity…')
    try {
      const email = String(data.get('email') || '')
      const issued = await login(email, String(data.get('password') || ''))
      setIdentity(issued.user?.display_name || issued.user?.email || email)
      await enterAuthenticated(issued.token)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Login failed')
    } finally {
      setBusy(false)
    }
  }

  async function logout() {
    if (client) await client.logout().catch(() => undefined)
    sessionStorage.removeItem('cryptohawk_session')
    setToken(null)
    setWorkspaces([])
    setWorkspaceId('')
    setFindings([])
    setJobs([])
    setAssets([])
    setSummary(initialSummary)
    setAuthMode('login')
    setMessage('Signed out')
  }

  async function createWorkspace(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!client) return
    const data = new FormData(event.currentTarget)
    setBusy(true)
    try {
      const created = await client.createWorkspace(
        String(data.get('name') || ''),
        String(data.get('slug') || '') || undefined,
      )
      const accessible = await client.listWorkspaces()
      setWorkspaces(accessible)
      setWorkspaceId(created.id)
      setShowWorkspaceForm(false)
      setShowAssetWizard(true)
      setMessage(`${created.name} created. Register the first asset.`)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Workspace creation failed')
    } finally {
      setBusy(false)
    }
  }

  async function createAsset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!client || !workspaceId) return
    const data = new FormData(event.currentTarget)
    const kind = String(data.get('kind')) as ScannableAssetKind
    const name = String(data.get('name') || '').trim()
    const locator = String(data.get('locator') || '').trim()
    const context = {
      internet_exposed: data.get('internet_exposed') === 'on',
      asset_criticality: Number(data.get('asset_criticality') || 5),
      data_lifetime_years: Number(data.get('data_lifetime_years') || 1),
      environment: String(data.get('environment') || 'unknown'),
    }
    const tags = { source: 'operator-onboarding' }
    const queueImmediately = data.get('queue_immediately') === 'on'

    setBusy(true)
    setMessage(`Registering ${name || locator}…`)
    try {
      let asset: ManagedAsset
      if (kind === 'repository') {
        const result = await client.createRepository(workspaceId, {
          name,
          repository_url: locator,
          ref: String(data.get('ref') || 'HEAD'),
          context,
          tags,
        })
        asset = result.asset
      } else {
        asset = await client.createAsset(workspaceId, {
          name,
          kind,
          locator,
          context,
          tags,
        })
      }

      if (queueImmediately) {
        const job = await client.queueScan(workspaceId, asset.id)
        setMessage(`${asset.name} registered; scan ${shortId(job.id)} queued`)
      } else {
        setMessage(`${asset.name} registered in managed inventory`)
      }
      setShowAssetWizard(false)
      await refreshWorkspace(client, workspaceId, true)
      setView('inventory')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Asset registration failed')
    } finally {
      setBusy(false)
    }
  }

  async function queueAssetScan(asset: ManagedAsset) {
    if (!client || !workspaceId || !isScannable(asset.kind)) return
    setBusy(true)
    try {
      const job = await client.queueScan(workspaceId, asset.id)
      setMessage(`${displayKind(asset.kind)} scan ${shortId(job.id)} queued for ${asset.name}`)
      await refreshWorkspace(client, workspaceId, true)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Scan submission failed')
    } finally {
      setBusy(false)
    }
  }

  const workspace = workspaces.find((candidate) => candidate.id === workspaceId)
  const activeJobs = jobs.filter((job) => ['queued', 'running'].includes(job.status)).length
  const readiness = summary.total_findings
    ? Math.round((summary.pqc_ready / summary.total_findings) * 100)
    : 0
  const latestJobsByAsset = useMemo(() => {
    const latest = new Map<string, ScanJob>()
    for (const job of jobs) {
      if (!latest.has(job.asset_id)) latest.set(job.asset_id, job)
    }
    return latest
  }, [jobs])
  const filteredAssets = useMemo(() => {
    const query = assetSearch.trim().toLowerCase()
    return assets.filter((asset) => {
      if (kindFilter !== 'all' && asset.kind !== kindFilter) return false
      if (!query) return true
      return [asset.name, asset.locator, asset.kind]
        .join(' ')
        .toLowerCase()
        .includes(query)
    })
  }, [assets, assetSearch, kindFilter])

  if (authMode !== 'ready') {
    return (
      <AuthScreen
        mode={authMode}
        busy={busy}
        message={message}
        onBootstrap={submitBootstrap}
        onLogin={submitLogin}
      />
    )
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="mark"><Radar size={21} /></div>
          <div><strong>CRYPTOHAWK</strong><span>Exposure Command</span></div>
        </div>
        <nav>
          <button className={view === 'command' ? 'active' : ''} onClick={() => setView('command')}>
            <Activity size={17} />Command Center
          </button>
          <button className={view === 'inventory' ? 'active' : ''} onClick={() => setView('inventory')}>
            <Database size={17} />Inventory
          </button>
        </nav>
        <div className="side-card">
          <span className="eyebrow">SECURITY BOUNDARY</span>
          <strong>Authenticated workspace mode</strong>
          <p>Inventory, findings and scan jobs stay inside the authorized tenant boundary.</p>
        </div>
      </aside>

      <main>
        <header>
          <div>
            <span className="eyebrow">CRYPTOGRAPHIC EXPOSURE MANAGEMENT</span>
            <h1>{view === 'command' ? 'Command Center' : 'Managed Inventory'}</h1>
            <p>
              {view === 'command'
                ? 'Find cryptography. Quantify quantum risk. Build the migration path.'
                : 'Register assets once, preserve identity, and run repeatable cryptographic discovery.'}
            </p>
          </div>
          <div className="header-actions">
            {workspaces.length > 0 && (
              <label className="workspace-picker">
                <span>Workspace</span>
                <select value={workspaceId} onChange={(event) => setWorkspaceId(event.target.value)}>
                  {workspaces.map((candidate) => (
                    <option key={candidate.id} value={candidate.id}>{candidate.name}</option>
                  ))}
                </select>
              </label>
            )}
            <button className="secondary-button compact" onClick={() => setShowWorkspaceForm(true)}>
              <Plus size={15} />Workspace
            </button>
            <div className="operator-chip"><UserRound size={15} /><span>{identity}</span></div>
            <button className="icon-button" onClick={() => void logout()} title="Sign out">
              <LogOut size={16} />
            </button>
          </div>
        </header>

        <div className="workspace-strip">
          <div><span className="pulse" /><strong>{workspace?.name || 'Workspace setup required'}</strong></div>
          <span>{message}</span>
          <div className="strip-actions">
            <span className="job-live">{activeJobs} active job{activeJobs === 1 ? '' : 's'}</span>
            {workspaceId && (
              <button
                className="refresh-button"
                disabled={refreshing}
                onClick={() => client && void refreshWorkspace(client, workspaceId)}
                title="Refresh workspace"
              >
                <RefreshCw size={14} className={refreshing ? 'spin' : ''} />
              </button>
            )}
          </div>
        </div>

        {!workspaceId ? (
          <EmptyWorkspace onCreate={() => setShowWorkspaceForm(true)} />
        ) : view === 'command' ? (
          <CommandCenter
            summary={summary}
            findings={findings}
            jobs={jobs}
            assets={assets}
            readiness={readiness}
            onAddAsset={() => setShowAssetWizard(true)}
            onOpenInventory={() => setView('inventory')}
          />
        ) : (
          <Inventory
            assets={filteredAssets}
            allAssets={assets}
            latestJobsByAsset={latestJobsByAsset}
            search={assetSearch}
            kindFilter={kindFilter}
            busy={busy}
            onSearch={setAssetSearch}
            onKindFilter={setKindFilter}
            onAddAsset={() => setShowAssetWizard(true)}
            onQueueScan={(asset) => void queueAssetScan(asset)}
          />
        )}
      </main>

      {showWorkspaceForm && (
        <WorkspaceDialog
          busy={busy}
          canClose={workspaces.length > 0}
          onClose={() => setShowWorkspaceForm(false)}
          onSubmit={createWorkspace}
        />
      )}
      {showAssetWizard && workspaceId && (
        <AssetWizard busy={busy} onClose={() => setShowAssetWizard(false)} onSubmit={createAsset} />
      )}
    </div>
  )
}

function CommandCenter({
  summary,
  findings,
  jobs,
  assets,
  readiness,
  onAddAsset,
  onOpenInventory,
}: {
  summary: Summary
  findings: Finding[]
  jobs: ScanJob[]
  assets: ManagedAsset[]
  readiness: number
  onAddAsset: () => void
  onOpenInventory: () => void
}) {
  const migrationQueue = findings.filter((finding) => finding.risk.migration_target).slice(0, 5)
  const recentJobs = jobs.slice(0, 6)

  if (assets.length === 0) {
    return (
      <section className="first-run">
        <div className="first-run-graphic">
          <Radar size={34} />
          <span className="ring ring-one" />
          <span className="ring ring-two" />
        </div>
        <div>
          <span className="eyebrow">FIRST DISCOVERY</span>
          <h2>Build a durable cryptographic inventory</h2>
          <p>
            Start with an internet endpoint, repository, or image. CryptoHawk will preserve the
            asset identity across scans so evidence, drift and migration work remain traceable.
          </p>
          <div className="first-run-actions">
            <button onClick={onAddAsset}><Plus size={16} />Register first asset</button>
            <span>Five production collectors available</span>
          </div>
        </div>
      </section>
    )
  }

  return (
    <>
      <section className="metric-grid">
        <Metric label="Managed assets" value={assets.length} icon={<Database size={18} />} />
        <Metric
          label="Quantum vulnerable"
          value={summary.quantum_vulnerable}
          tone="danger"
          icon={<TriangleAlert size={18} />}
        />
        <Metric label="Critical exposure" value={summary.critical} tone="danger" icon={<Zap size={18} />} />
        <Metric label="PQC ready" value={`${readiness}%`} tone="good" icon={<ShieldCheck size={18} />} />
      </section>

      <section className="two-col operator-grid">
        <div className="panel">
          <div className="panel-head">
            <div><span className="eyebrow">MANAGED ESTATE</span><h2>Discovery coverage</h2></div>
            <button className="text-button" onClick={onOpenInventory}>Open inventory <ArrowRight size={14} /></button>
          </div>
          <div className="coverage-list">
            {ASSET_OPTIONS.map((option) => {
              const count = assets.filter((asset) => asset.kind === option.kind).length
              return (
                <div className="coverage-row" key={option.kind}>
                  <span className="coverage-icon">{option.icon}</span>
                  <div><strong>{option.label}</strong><small>{option.short}</small></div>
                  <b>{count}</b>
                </div>
              )
            })}
          </div>
          <button className="wide-secondary" onClick={onAddAsset}><Plus size={16} />Register another asset</button>
        </div>

        <div className="panel readiness-panel">
          <div className="panel-head">
            <div><span className="eyebrow">POST-QUANTUM POSTURE</span><h2>Readiness signal</h2></div>
            <ShieldCheck size={22} />
          </div>
          <div className="readiness-number">{readiness}<span>%</span></div>
          <div className="progress"><span style={{ width: `${readiness}%` }} /></div>
          <div className="readiness-stats">
            <div><span>PQC ready</span><strong>{summary.pqc_ready}</strong></div>
            <div><span>Vulnerable</span><strong>{summary.quantum_vulnerable}</strong></div>
            <div><span>Observed crypto</span><strong>{summary.total_findings}</strong></div>
          </div>
          <p>Readiness is based on observed cryptographic evidence, not dependency presence alone.</p>
        </div>
      </section>

      <section className="two-col">
        <div className="panel">
          <div className="panel-head"><div><span className="eyebrow">DURABLE EXECUTION</span><h2>Recent scan jobs</h2></div></div>
          {recentJobs.length ? (
            <div className="job-list">
              {recentJobs.map((job) => (
                <div className="job-row" key={job.id}>
                  <div><strong>{shortId(job.id)}</strong><span>{job.kind}</span></div>
                  <StatusPill status={job.status} />
                  <span>{job.findings_count} findings</span>
                </div>
              ))}
            </div>
          ) : <EmptyLine text="No scans have been queued yet." />}
        </div>

        <div className="panel">
          <div className="panel-head"><div><span className="eyebrow">MIGRATION SIGNALS</span><h2>Highest-priority replacements</h2></div></div>
          {migrationQueue.length ? (
            <div className="migration-list">
              {migrationQueue.map((finding) => (
                <div className="migration-row" key={finding.observation.id}>
                  <div>
                    <strong>{finding.observation.asset_name}</strong>
                    <span>{finding.observation.family} · risk {finding.risk.score}</span>
                  </div>
                  <div className="migration-target">
                    <span>Move toward</span><strong>{finding.risk.migration_target}</strong>
                  </div>
                </div>
              ))}
            </div>
          ) : <EmptyLine text="No migration-target findings are present in this workspace." />}
        </div>
      </section>
    </>
  )
}

function Inventory({
  assets,
  allAssets,
  latestJobsByAsset,
  search,
  kindFilter,
  busy,
  onSearch,
  onKindFilter,
  onAddAsset,
  onQueueScan,
}: {
  assets: ManagedAsset[]
  allAssets: ManagedAsset[]
  latestJobsByAsset: Map<string, ScanJob>
  search: string
  kindFilter: 'all' | AssetKind
  busy: boolean
  onSearch: (value: string) => void
  onKindFilter: (value: 'all' | AssetKind) => void
  onAddAsset: () => void
  onQueueScan: (asset: ManagedAsset) => void
}) {
  const kinds = Array.from(new Set(allAssets.map((asset) => asset.kind))).sort()
  return (
    <section className="inventory-panel panel">
      <div className="inventory-toolbar">
        <div>
          <span className="eyebrow">WORKSPACE ASSET REGISTRY</span>
          <h2>{allAssets.length} managed asset{allAssets.length === 1 ? '' : 's'}</h2>
        </div>
        <div className="inventory-actions">
          <label className="search-box">
            <Search size={15} />
            <input value={search} onChange={(event) => onSearch(event.target.value)} placeholder="Search assets or locators" />
          </label>
          <select value={kindFilter} onChange={(event) => onKindFilter(event.target.value as 'all' | AssetKind)}>
            <option value="all">All types</option>
            {kinds.map((kind) => <option key={kind} value={kind}>{displayKind(kind)}</option>)}
          </select>
          <button onClick={onAddAsset}><Plus size={16} />Register asset</button>
        </div>
      </div>

      {assets.length ? (
        <div className="asset-table-wrap">
          <table className="asset-table">
            <thead>
              <tr><th>Asset</th><th>Type</th><th>Environment</th><th>Latest scan</th><th>Locator</th><th /></tr>
            </thead>
            <tbody>
              {assets.map((asset) => {
                const latest = latestJobsByAsset.get(asset.id)
                return (
                  <tr key={asset.id}>
                    <td>
                      <div className="asset-name"><span className="asset-dot" /><div><strong>{asset.name}</strong><small>{shortId(asset.id)}</small></div></div>
                    </td>
                    <td><span className="kind-chip">{displayKind(asset.kind)}</span></td>
                    <td>{asset.context?.environment || 'unknown'}</td>
                    <td>{latest ? <StatusPill status={latest.status} /> : <span className="muted">Never scanned</span>}</td>
                    <td className="locator-cell" title={asset.locator}>{asset.locator}</td>
                    <td className="table-action">
                      {isScannable(asset.kind) ? (
                        <button
                          className="scan-action"
                          disabled={busy || latest?.status === 'queued' || latest?.status === 'running'}
                          onClick={() => onQueueScan(asset)}
                        >
                          <Radar size={14} />Scan
                        </button>
                      ) : <span className="inventory-only">Inventory only</span>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-inventory">
          <Database size={28} />
          <h3>No matching assets</h3>
          <p>{allAssets.length ? 'Adjust the search or type filter.' : 'Register a scan-capable asset to start discovery.'}</p>
          {!allAssets.length && <button onClick={onAddAsset}><Plus size={16} />Register first asset</button>}
        </div>
      )}
    </section>
  )
}

function AssetWizard({
  busy,
  onClose,
  onSubmit,
}: {
  busy: boolean
  onClose: () => void
  onSubmit: (event: FormEvent<HTMLFormElement>) => void
}) {
  const [kind, setKind] = useState<ScannableAssetKind>('tls-endpoint')
  const selected = ASSET_OPTIONS.find((option) => option.kind === kind) || ASSET_OPTIONS[0]
  return (
    <div className="dialog-backdrop" role="presentation">
      <section className="dialog asset-dialog" role="dialog" aria-modal="true" aria-labelledby="asset-dialog-title">
        <div className="dialog-head">
          <div><span className="eyebrow">MANAGED DISCOVERY</span><h2 id="asset-dialog-title">Register a scan-capable asset</h2></div>
          <button className="dialog-close" onClick={onClose} aria-label="Close">×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="asset-kind-grid">
            {ASSET_OPTIONS.map((option) => (
              <label className={kind === option.kind ? 'asset-kind selected' : 'asset-kind'} key={option.kind}>
                <input type="radio" name="kind" value={option.kind} checked={kind === option.kind} onChange={() => setKind(option.kind)} />
                <span>{option.icon}</span>
                <strong>{option.label}</strong>
                <small>{option.short}</small>
              </label>
            ))}
          </div>

          <div className="form-grid two">
            <label><span>Asset name</span><input name="name" required maxLength={200} placeholder="Payments production" /></label>
            <label>
              <span>{kind === 'repository' ? 'Repository URL' : kind === 'container' ? 'Ingress archive path' : 'Endpoint'}</span>
              <input name="locator" required maxLength={1000} placeholder={selected.example} />
            </label>
            {kind === 'repository' && (
              <label><span>Git ref</span><input name="ref" defaultValue="HEAD" maxLength={200} /></label>
            )}
            <label>
              <span>Environment</span>
              <select name="environment" defaultValue="production">
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
                <option value="unknown">Unknown</option>
              </select>
            </label>
            <label><span>Asset criticality · 1–10</span><input name="asset_criticality" type="number" min="1" max="10" defaultValue="5" /></label>
            <label><span>Data lifetime · years</span><input name="data_lifetime_years" type="number" min="0" max="50" defaultValue="3" /></label>
          </div>

          <div className="wizard-flags">
            <label className="check-row"><input type="checkbox" name="internet_exposed" defaultChecked={kind !== 'container'} /><span><strong>Internet exposed</strong><small>Raises risk weighting for externally reachable assets.</small></span></label>
            <label className="check-row"><input type="checkbox" name="queue_immediately" defaultChecked /><span><strong>Queue first scan immediately</strong><small>Uses the durable worker queue and workspace concurrency limits.</small></span></label>
          </div>

          {kind === 'container' && (
            <div className="callout"><LockKeyhole size={16} /><span>Container locators must point inside the server-configured read-only image ingress root.</span></div>
          )}
          {kind === 'repository' && (
            <div className="callout"><ShieldCheck size={16} /><span>Public HTTPS repositories work directly. Private GitHub/GitLab repositories require an encrypted connector credential configured through the API.</span></div>
          )}

          <div className="dialog-actions">
            <button type="button" className="secondary-button" onClick={onClose}>Cancel</button>
            <button disabled={busy}>{busy ? 'Registering…' : 'Register asset'}<ArrowRight size={15} /></button>
          </div>
        </form>
      </section>
    </div>
  )
}

function WorkspaceDialog({
  busy,
  canClose,
  onClose,
  onSubmit,
}: {
  busy: boolean
  canClose: boolean
  onClose: () => void
  onSubmit: (event: FormEvent<HTMLFormElement>) => void
}) {
  return (
    <div className="dialog-backdrop">
      <section className="dialog workspace-dialog" role="dialog" aria-modal="true" aria-labelledby="workspace-dialog-title">
        <div className="dialog-head">
          <div><span className="eyebrow">TENANT SETUP</span><h2 id="workspace-dialog-title">Create a workspace</h2></div>
          {canClose && <button className="dialog-close" onClick={onClose} aria-label="Close">×</button>}
        </div>
        <p>A workspace is the authorization, inventory and evidence boundary for one organization or environment.</p>
        <form onSubmit={onSubmit}>
          <label><span>Workspace name</span><input name="name" required maxLength={200} placeholder="Acme Security" /></label>
          <label><span>Slug <em>optional</em></span><input name="slug" minLength={2} maxLength={80} pattern="[a-z0-9][a-z0-9-]*" placeholder="acme-security" /></label>
          <div className="dialog-actions">
            {canClose && <button type="button" className="secondary-button" onClick={onClose}>Cancel</button>}
            <button disabled={busy}>{busy ? 'Creating…' : 'Create workspace'}<ArrowRight size={15} /></button>
          </div>
        </form>
      </section>
    </div>
  )
}

function EmptyWorkspace({ onCreate }: { onCreate: () => void }) {
  return (
    <section className="first-run workspace-empty">
      <div className="first-run-graphic"><Database size={34} /><span className="ring ring-one" /><span className="ring ring-two" /></div>
      <div>
        <span className="eyebrow">ONBOARDING</span>
        <h2>Create the first workspace boundary</h2>
        <p>Workspaces isolate assets, findings, scan capacity, credentials and audit history.</p>
        <button onClick={onCreate}><Plus size={16} />Create workspace</button>
      </div>
    </section>
  )
}

function Metric({
  label,
  value,
  icon,
  tone = 'neutral',
}: {
  label: string
  value: string | number
  icon: ReactNode
  tone?: 'neutral' | 'danger' | 'good'
}) {
  return (
    <div className={`metric ${tone}`}>
      <div><span>{label}</span>{icon}</div>
      <strong>{value}</strong>
    </div>
  )
}

function StatusPill({ status }: { status: ScanJob['status'] }) {
  return <span className={`status-pill ${status}`}>{status}</span>
}

function EmptyLine({ text }: { text: string }) {
  return <div className="empty-line"><CheckCircle2 size={16} /><span>{text}</span></div>
}

function AuthScreen({
  mode,
  busy,
  message,
  onBootstrap,
  onLogin,
}: {
  mode: AuthMode
  busy: boolean
  message: string
  onBootstrap: (event: FormEvent<HTMLFormElement>) => void
  onLogin: (event: FormEvent<HTMLFormElement>) => void
}) {
  const checking = mode === 'checking'
  const firstRun = mode === 'bootstrap'
  return (
    <div className="auth-shell">
      <section className="auth-brand-panel">
        <div className="brand auth-brand">
          <div className="mark"><Radar size={21} /></div>
          <div><strong>CRYPTOHAWK</strong><span>Exposure Command</span></div>
        </div>
        <div className="auth-copy">
          <span className="eyebrow">CRYPTOGRAPHIC EXPOSURE MANAGEMENT</span>
          <h1>Know what cryptography you run before quantum migration becomes an outage.</h1>
          <p>Discover evidence, retain asset identity, prioritize breakage risk, and prove migration progress from one workspace-scoped control plane.</p>
        </div>
        <div className="auth-proof">
          <span><ShieldCheck size={16} />Tenant-scoped RBAC</span>
          <span><KeyRound size={16} />Encrypted connector secrets</span>
          <span><Activity size={16} />Durable evidence + drift</span>
        </div>
      </section>
      <section className="auth-form-panel">
        <div className="auth-card">
          {checking ? (
            <div className="auth-loading"><Radar size={26} /><h2>Initializing secure session</h2><p>{message}</p></div>
          ) : (
            <>
              <span className="eyebrow">{firstRun ? 'FIRST-RUN SETUP' : 'OPERATOR ACCESS'}</span>
              <h2>{firstRun ? 'Create the workspace owner' : 'Sign in to CryptoHawk'}</h2>
              <p>{message}</p>
              <form onSubmit={firstRun ? onBootstrap : onLogin}>
                {firstRun && <label><span>Display name</span><input name="display_name" required maxLength={200} autoComplete="name" /></label>}
                <label><span>Email</span><input name="email" type="email" required maxLength={320} autoComplete="email" /></label>
                <label><span>Password</span><input name="password" type="password" required minLength={firstRun ? 12 : 1} autoComplete={firstRun ? 'new-password' : 'current-password'} /></label>
                {firstRun && <label><span>First workspace</span><input name="workspace_name" required maxLength={200} placeholder="Acme Security" /></label>}
                <button disabled={busy}>{busy ? 'Working…' : firstRun ? 'Create secure workspace' : 'Sign in'}<ArrowRight size={15} /></button>
              </form>
            </>
          )}
        </div>
      </section>
    </div>
  )
}

export default App
