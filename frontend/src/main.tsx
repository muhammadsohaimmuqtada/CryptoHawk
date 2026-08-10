import React, { FormEvent, useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  Activity,
  ArrowUpRight,
  Database,
  FileCode2,
  KeyRound,
  LogOut,
  Radar,
  ShieldCheck,
  TriangleAlert,
  UserRound,
  Zap,
} from 'lucide-react'
import './styles.css'

type Summary = {
  total_findings: number
  critical: number
  high: number
  medium: number
  low: number
  quantum_vulnerable: number
  pqc_ready: number
}

type Finding = {
  observation: {
    id: string
    asset_name: string
    algorithm: string
    family: string
    primitive: string
    key_size?: number
    evidence: { source: string; locator?: string; line?: number }
  }
  risk: {
    score: number
    severity: string
    quantum_status: string
    migration_target?: string
    migration_strategy?: string
  }
}

type Workspace = { id: string; name: string; slug: string }
type ManagedAsset = {
  id: string
  workspace_id: string
  name: string
  kind: string
  locator: string
  enabled: boolean
}
type ScanJob = {
  id: string
  workspace_id: string
  asset_id: string
  kind: string
  status: string
  requested_at: string
  started_at?: string
  finished_at?: string
  findings_count: number
  error_message?: string
}
type IssuedToken = {
  token: string
  expires_at: string
  user?: { id: string; email: string; display_name: string }
  workspace?: Workspace
}

type AuthMode = 'checking' | 'bootstrap' | 'login' | 'ready'

const initialSummary: Summary = {
  total_findings: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  quantum_vulnerable: 0,
  pqc_ready: 0,
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
  const [host, setHost] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('Secure session initializing')

  useEffect(() => {
    void initialize()
  }, [])

  useEffect(() => {
    if (authMode !== 'ready' || !token || !workspaceId) return
    void refreshWorkspace(token, workspaceId).catch((error) => {
      setMessage(error instanceof Error ? error.message : 'Workspace refresh failed')
    })
    const interval = window.setInterval(() => {
      void refreshWorkspace(token, workspaceId).catch(() => undefined)
    }, 4000)
    return () => window.clearInterval(interval)
  }, [authMode, token, workspaceId])

  async function initialize() {
    try {
      const statusRes = await fetch('/api/v1/auth/status')
      const statusBody = statusRes.ok ? await statusRes.json() : { bootstrap_required: false }
      const needsBootstrap = Boolean(statusBody.bootstrap_required)
      setBootstrapRequired(needsBootstrap)

      const storedToken = sessionStorage.getItem('cryptohawk_session')
      if (storedToken) {
        const meRes = await fetch('/api/v1/auth/me', {
          headers: { Authorization: `Bearer ${storedToken}` },
        })
        if (meRes.ok) {
          const me = await meRes.json()
          setIdentity(me.user_id ? `User ${String(me.user_id).slice(0, 8)}` : 'API principal')
          await enterAuthenticated(storedToken)
          return
        }
        sessionStorage.removeItem('cryptohawk_session')
      }
      setAuthMode(needsBootstrap ? 'bootstrap' : 'login')
      setMessage(needsBootstrap ? 'Create the first CryptoHawk owner' : 'Authentication required')
    } catch {
      setAuthMode('login')
      setMessage('CryptoHawk API unavailable')
    }
  }

  async function enterAuthenticated(credential: string, preferredWorkspace?: string) {
    sessionStorage.setItem('cryptohawk_session', credential)
    setToken(credential)
    const workspaceRes = await request('/api/v1/workspaces', {}, credential)
    const accessible: Workspace[] = await workspaceRes.json()
    setWorkspaces(accessible)
    const selected =
      accessible.find((workspace) => workspace.id === preferredWorkspace)?.id ||
      accessible[0]?.id ||
      ''
    setWorkspaceId(selected)
    setAuthMode('ready')
    setMessage(accessible.length ? 'Tenant boundary active' : 'Create a workspace to continue')
  }

  async function request(path: string, options: RequestInit = {}, credential = token) {
    if (!credential) throw new Error('Authentication required')
    const headers = new Headers(options.headers)
    headers.set('Authorization', `Bearer ${credential}`)
    if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
    const response = await fetch(path, { ...options, headers })
    if (response.status === 401) {
      sessionStorage.removeItem('cryptohawk_session')
      setToken(null)
      setAuthMode(bootstrapRequired ? 'bootstrap' : 'login')
      throw new Error('Session expired. Sign in again.')
    }
    return response
  }

  async function refreshWorkspace(credential = token, selectedWorkspace = workspaceId) {
    if (!credential || !selectedWorkspace) return
    const base = `/api/v1/workspaces/${selectedWorkspace}`
    const [summaryRes, findingsRes, assetsRes, jobsRes] = await Promise.all([
      request(`${base}/dashboard/summary`, {}, credential),
      request(`${base}/findings?limit=100`, {}, credential),
      request(`${base}/assets`, {}, credential),
      request(`${base}/scan-jobs?limit=50`, {}, credential),
    ])
    for (const response of [summaryRes, findingsRes, assetsRes, jobsRes]) {
      if (!response.ok) {
        const body = await response.json().catch(() => ({}))
        throw new Error(body.detail || 'Unable to load workspace')
      }
    }
    setSummary(await summaryRes.json())
    setFindings(await findingsRes.json())
    setAssets(await assetsRes.json())
    setJobs(await jobsRes.json())
  }

  async function submitBootstrap(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    setBusy(true)
    setMessage('Creating encrypted owner identity…')
    try {
      const response = await fetch('/api/v1/auth/bootstrap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: String(data.get('email') || ''),
          display_name: String(data.get('display_name') || ''),
          password: String(data.get('password') || ''),
          workspace_name: String(data.get('workspace_name') || ''),
        }),
      })
      const body = await response.json()
      if (!response.ok) throw new Error(body.detail || 'Bootstrap failed')
      const issued = body as IssuedToken
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
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: String(data.get('password') || '') }),
      })
      const body = await response.json()
      if (!response.ok) throw new Error(body.detail || 'Login failed')
      const issued = body as IssuedToken
      setIdentity(issued.user?.display_name || issued.user?.email || email)
      await enterAuthenticated(issued.token)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Login failed')
    } finally {
      setBusy(false)
    }
  }

  async function logout() {
    if (token) await request('/api/v1/auth/logout', { method: 'POST' }).catch(() => undefined)
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

  async function scanTls(event: FormEvent) {
    event.preventDefault()
    const locator = host.trim().toLowerCase()
    if (!locator || !workspaceId) return
    setBusy(true)
    setMessage(`Registering ${locator}…`)
    try {
      let asset = assets.find(
        (candidate) => candidate.kind === 'tls-endpoint' && candidate.locator === locator,
      )
      if (!asset) {
        const createRes = await request(`/api/v1/workspaces/${workspaceId}/assets`, {
          method: 'POST',
          body: JSON.stringify({
            name: locator,
            kind: 'tls-endpoint',
            locator,
            context: {
              internet_exposed: true,
              asset_criticality: 5,
              data_lifetime_years: 3,
              environment: 'production',
            },
            tags: { source: 'command-center' },
          }),
        })
        if (createRes.ok) {
          asset = await createRes.json()
        } else if (createRes.status === 409) {
          const assetsRes = await request(`/api/v1/workspaces/${workspaceId}/assets`)
          if (!assetsRes.ok) throw new Error('Unable to resolve existing managed asset')
          const currentAssets: ManagedAsset[] = await assetsRes.json()
          setAssets(currentAssets)
          asset = currentAssets.find(
            (candidate) => candidate.kind === 'tls-endpoint' && candidate.locator === locator,
          )
        } else {
          const body = await createRes.json().catch(() => ({}))
          throw new Error(body.detail || 'Asset registration failed')
        }
      }
      if (!asset) throw new Error('Managed TLS asset could not be resolved')

      const queueRes = await request(
        `/api/v1/workspaces/${workspaceId}/assets/${asset.id}/scan-jobs`,
        { method: 'POST', body: JSON.stringify({ max_attempts: 3 }) },
      )
      const queueBody = await queueRes.json()
      if (!queueRes.ok) throw new Error(queueBody.detail || 'Unable to queue scan')
      setMessage(`Scan ${String(queueBody.id).slice(0, 8)} queued for durable execution`)
      setHost('')
      await refreshWorkspace()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Scan submission failed')
    } finally {
      setBusy(false)
    }
  }

  const migrationQueue = useMemo(
    () => findings.filter((finding) => finding.risk.migration_target).slice(0, 5),
    [findings],
  )
  const recentJobs = jobs.slice(0, 6)
  const activeJobs = jobs.filter((job) => ['queued', 'running'].includes(job.status)).length
  const workspace = workspaces.find((candidate) => candidate.id === workspaceId)
  const readiness = summary.total_findings
    ? Math.round((summary.pqc_ready / summary.total_findings) * 100)
    : 0

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
          <a className="active"><Activity size={17} />Command Center</a>
          <a><Database size={17} />Inventory</a>
          <a><FileCode2 size={17} />Discovery</a>
          <a><ShieldCheck size={17} />Migration</a>
        </nav>
        <div className="side-card">
          <span className="eyebrow">SECURITY BOUNDARY</span>
          <strong>Authenticated workspace mode</strong>
          <p>All inventory, findings, CBOM and scan jobs are scoped to an authorized tenant.</p>
        </div>
      </aside>
      <main>
        <header>
          <div>
            <span className="eyebrow">CRYPTOGRAPHIC EXPOSURE MANAGEMENT</span>
            <h1>Command Center</h1>
            <p>Find cryptography. Quantify quantum risk. Build the migration path.</p>
          </div>
          <div className="header-actions">
            <label className="workspace-picker">
              <span>Workspace</span>
              <select value={workspaceId} onChange={(event) => setWorkspaceId(event.target.value)}>
                {workspaces.map((candidate) => (
                  <option key={candidate.id} value={candidate.id}>{candidate.name}</option>
                ))}
              </select>
            </label>
            <div className="operator-chip"><UserRound size={15} /><span>{identity}</span></div>
            <button className="icon-button" onClick={() => void logout()} title="Sign out">
              <LogOut size={16} />
            </button>
          </div>
        </header>

        <div className="workspace-strip">
          <div><span className="pulse" /><strong>{workspace?.name || 'No workspace'}</strong></div>
          <span>{message}</span>
          <span className="job-live">{activeJobs} active job{activeJobs === 1 ? '' : 's'}</span>
        </div>

        <section className="metric-grid">
          <Metric label="Crypto assets" value={summary.total_findings} icon={<Database size={18} />} />
          <Metric label="Quantum vulnerable" value={summary.quantum_vulnerable} tone="danger" icon={<TriangleAlert size={18} />} />
          <Metric label="Critical exposure" value={summary.critical} tone="danger" icon={<Zap size={18} />} />
          <Metric label="PQC ready" value={summary.pqc_ready} tone="good" icon={<ShieldCheck size={18} />} />
        </section>

        <section className="two-col">
          <div className="panel scan-panel">
            <div className="panel-head">
              <div><span className="eyebrow">MANAGED DISCOVERY</span><h2>Register + scan a TLS endpoint</h2></div>
              <Radar size={22} />
            </div>
            <p>The endpoint becomes a durable asset, then a leased worker performs the scan with retry and crash recovery.</p>
            <form onSubmit={scanTls}>
              <input
                aria-label="TLS hostname"
                placeholder="api.example.com"
                value={host}
                onChange={(event) => setHost(event.target.value)}
              />
              <button disabled={busy || !workspaceId}>
                {busy ? 'Submitting…' : 'Queue scan'}<ArrowUpRight size={16} />
              </button>
            </form>
            <div className="mini-row"><span>Managed assets</span><b>{assets.length} registered</b></div>
            <div className="mini-row"><span>Execution model</span><b>DB lease + retry + recovery</b></div>
          </div>
          <div className="panel posture">
            <div className="panel-head">
              <div><span className="eyebrow">MIGRATION POSTURE</span><h2>Quantum readiness</h2></div>
              <ShieldCheck size={22} />
            </div>
            <div className="ring" style={{ '--pct': `${readiness}%` } as React.CSSProperties}>
              <div><strong>{readiness}%</strong><span>ready</span></div>
            </div>
            <div className="legend">
              <span><i className="dot bad" />Quantum vulnerable <b>{summary.quantum_vulnerable}</b></span>
              <span><i className="dot good" />PQC ready <b>{summary.pqc_ready}</b></span>
            </div>
          </div>
        </section>

        <section className="panel job-panel">
          <div className="panel-head">
            <div><span className="eyebrow">DURABLE EXECUTION</span><h2>Recent scan jobs</h2></div>
            <span className="count">worker-backed</span>
          </div>
          <div className="job-grid">
            {recentJobs.length === 0 ? (
              <div className="empty">No managed scan jobs yet.</div>
            ) : recentJobs.map((job) => {
              const asset = assets.find((candidate) => candidate.id === job.asset_id)
              return (
                <div className="job-card" key={job.id}>
                  <div><strong>{asset?.name || job.asset_id.slice(0, 8)}</strong><small>{job.kind}</small></div>
                  <span className={`job-state ${job.status}`}>{job.status}</span>
                  <div className="job-meta">
                    <span>{job.findings_count} findings</span>
                    <span>{new Date(job.requested_at).toLocaleString()}</span>
                  </div>
                  {job.error_message && <p>{job.error_message}</p>}
                </div>
              )
            })}
          </div>
        </section>

        <section className="panel inventory">
          <div className="panel-head">
            <div><span className="eyebrow">PRIORITIZED INVENTORY</span><h2>Highest-risk cryptographic assets</h2></div>
            <span className="count">{findings.length} shown</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Asset</th><th>Primitive</th><th>Algorithm</th><th>PQ status</th><th>Risk</th><th>Migration</th></tr></thead>
              <tbody>
                {findings.length === 0 ? (
                  <tr><td colSpan={6} className="empty">No findings yet. Register an endpoint to begin inventory discovery.</td></tr>
                ) : findings.slice(0, 12).map((finding) => (
                  <tr key={finding.observation.id}>
                    <td><strong>{finding.observation.asset_name}</strong><small>{finding.observation.evidence.locator || finding.observation.evidence.source}</small></td>
                    <td>{finding.observation.primitive}</td>
                    <td><code>{finding.observation.algorithm}</code></td>
                    <td><span className={`pill ${finding.risk.quantum_status}`}>{finding.risk.quantum_status}</span></td>
                    <td><span className={`risk ${finding.risk.severity}`}>{finding.risk.score}</span></td>
                    <td>{finding.risk.migration_target ? <span className="target">→ {finding.risk.migration_target}</span> : <span className="muted">retain</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel migration">
          <div className="panel-head">
            <div><span className="eyebrow">ACTION QUEUE</span><h2>Migration candidates</h2></div>
            <span className="count">ranked by exposure</span>
          </div>
          <div className="queue">
            {migrationQueue.length === 0 ? (
              <div className="empty">Migration recommendations appear here as evidence is collected.</div>
            ) : migrationQueue.map((finding, index) => (
              <div className="queue-item" key={finding.observation.id}>
                <span className="rank">0{index + 1}</span>
                <div><strong>{finding.observation.family} on {finding.observation.asset_name}</strong><p>{finding.risk.migration_strategy}</p></div>
                <div className="move"><span>{finding.observation.family}</span><ArrowUpRight size={15} /><b>{finding.risk.migration_target}</b></div>
              </div>
            ))}
          </div>
        </section>
      </main>
    </div>
  )
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
  onBootstrap: (event: FormEvent<HTMLFormElement>) => Promise<void>
  onLogin: (event: FormEvent<HTMLFormElement>) => Promise<void>
}) {
  const bootstrap = mode === 'bootstrap'
  return (
    <div className="auth-shell">
      <div className="auth-orbit auth-orbit-one" />
      <div className="auth-orbit auth-orbit-two" />
      <section className="auth-card">
        <div className="auth-brand">
          <div className="mark"><Radar size={24} /></div>
          <div><span className="eyebrow">CRYPTOGRAPHIC EXPOSURE MANAGEMENT</span><h1>CryptoHawk</h1></div>
        </div>
        {mode === 'checking' ? (
          <div className="auth-loading"><span className="pulse" />Establishing secure control plane…</div>
        ) : (
          <>
            <div className="auth-copy">
              <KeyRound size={22} />
              <div>
                <h2>{bootstrap ? 'Initialize your secure workspace' : 'Sign in to Exposure Command'}</h2>
                <p>{bootstrap ? 'The first account becomes the workspace owner. Passwords are scrypt-hashed and sessions are opaque.' : 'Use your CryptoHawk operator identity. The session remains in this browser tab only.'}</p>
              </div>
            </div>
            <form className="auth-form" onSubmit={bootstrap ? onBootstrap : onLogin}>
              {bootstrap && <label><span>Display name</span><input name="display_name" required placeholder="Security Lead" /></label>}
              <label><span>Email</span><input name="email" type="email" autoComplete="email" required placeholder="operator@company.com" /></label>
              <label><span>Password</span><input name="password" type="password" autoComplete={bootstrap ? 'new-password' : 'current-password'} minLength={12} required placeholder="12+ characters" /></label>
              {bootstrap && <label><span>Workspace</span><input name="workspace_name" required placeholder="Acme Security" /></label>}
              <button className="auth-submit" disabled={busy}>
                {busy ? 'Working…' : bootstrap ? 'Create secure workspace' : 'Authenticate'}
                <ArrowUpRight size={16} />
              </button>
            </form>
            <div className="auth-status"><ShieldCheck size={15} /><span>{message}</span></div>
          </>
        )}
      </section>
      <div className="auth-foot">Tenant-scoped inventory · hashed credentials · explainable PQC decisions</div>
    </div>
  )
}

function Metric({
  label,
  value,
  icon,
  tone = 'normal',
}: {
  label: string
  value: number
  icon: React.ReactNode
  tone?: string
}) {
  return (
    <div className={`metric ${tone}`}>
      <div className="metric-top"><span>{label}</span><span className="metric-icon">{icon}</span></div>
      <strong>{value.toLocaleString()}</strong><small>live inventory</small>
    </div>
  )
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode><App /></React.StrictMode>,
)
