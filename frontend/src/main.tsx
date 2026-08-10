import React, { FormEvent, useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { Activity, ArrowUpRight, Database, FileCode2, Radar, ShieldCheck, TriangleAlert, Zap } from 'lucide-react'
import './styles.css'

type Summary = { total_findings:number; critical:number; high:number; medium:number; low:number; quantum_vulnerable:number; pqc_ready:number }
type Finding = {
  observation: { id:string; asset_name:string; algorithm:string; family:string; primitive:string; key_size?:number; evidence:{source:string; locator?:string; line?:number} }
  risk: { score:number; severity:string; quantum_status:string; migration_target?:string; migration_strategy?:string }
}

const initialSummary: Summary = { total_findings:0, critical:0, high:0, medium:0, low:0, quantum_vulnerable:0, pqc_ready:0 }

function App() {
  const [summary, setSummary] = useState<Summary>(initialSummary)
  const [findings, setFindings] = useState<Finding[]>([])
  const [host, setHost] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('Inventory connected')

  async function refresh() {
    const [summaryRes, findingsRes] = await Promise.all([fetch('/api/v1/dashboard/summary'), fetch('/api/v1/findings?limit=100')])
    if (summaryRes.ok) setSummary(await summaryRes.json())
    if (findingsRes.ok) setFindings(await findingsRes.json())
  }

  useEffect(() => { refresh().catch(() => setMessage('API unavailable')) }, [])

  async function scanTls(event: FormEvent) {
    event.preventDefault()
    if (!host.trim()) return
    setBusy(true)
    setMessage(`Inspecting ${host.trim()}…`)
    try {
      const res = await fetch('/api/v1/scan/tls', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({hostname:host.trim(), persist:true}),
      })
      const body = await res.json()
      if (!res.ok) throw new Error(body.detail || 'Scan failed')
      setMessage(`${body.findings.length} cryptographic assets observed`)
      await refresh()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Scan failed')
    } finally { setBusy(false) }
  }

  const migrationQueue = useMemo(() => findings.filter(f => f.risk.migration_target).slice(0, 5), [findings])

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="mark"><Radar size={21}/></div><div><strong>CRYPTOHAWK</strong><span>Exposure Command</span></div></div>
      <nav><a className="active"><Activity size={17}/>Command Center</a><a><Database size={17}/>Inventory</a><a><FileCode2 size={17}/>Discovery</a><a><ShieldCheck size={17}/>Migration</a></nav>
      <div className="side-card"><span className="eyebrow">Policy baseline</span><strong>NIST PQC + CycloneDX 1.7</strong><p>Deterministic rules with evidence attached to every decision.</p></div>
    </aside>
    <main>
      <header><div><span className="eyebrow">CRYPTOGRAPHIC EXPOSURE MANAGEMENT</span><h1>Command Center</h1><p>Find cryptography. Quantify quantum risk. Build the migration path.</p></div><div className="status"><span className="pulse"/> {message}</div></header>
      <section className="metric-grid">
        <Metric label="Crypto assets" value={summary.total_findings} icon={<Database size={18}/>} />
        <Metric label="Quantum vulnerable" value={summary.quantum_vulnerable} tone="danger" icon={<TriangleAlert size={18}/>} />
        <Metric label="Critical exposure" value={summary.critical} tone="danger" icon={<Zap size={18}/>} />
        <Metric label="PQC ready" value={summary.pqc_ready} tone="good" icon={<ShieldCheck size={18}/>} />
      </section>
      <section className="two-col">
        <div className="panel scan-panel"><div className="panel-head"><div><span className="eyebrow">ACTIVE DISCOVERY</span><h2>Inspect a TLS endpoint</h2></div><Radar size={22}/></div><p>Pull live certificate, public-key, protocol and cipher evidence into the inventory.</p><form onSubmit={scanTls}><input aria-label="TLS hostname" placeholder="api.example.com" value={host} onChange={e => setHost(e.target.value)} /><button disabled={busy}>{busy ? 'Scanning…' : 'Scan endpoint'}<ArrowUpRight size={16}/></button></form><div className="mini-row"><span>Network scanner</span><b>Leaf X.509 + negotiated TLS</b></div><div className="mini-row"><span>Decision engine</span><b>Explainable / deterministic</b></div></div>
        <div className="panel posture"><div className="panel-head"><div><span className="eyebrow">MIGRATION POSTURE</span><h2>Quantum readiness</h2></div><ShieldCheck size={22}/></div><div className="ring" style={{'--pct': `${summary.total_findings ? Math.round(summary.pqc_ready / summary.total_findings * 100) : 0}%`} as React.CSSProperties}><div><strong>{summary.total_findings ? Math.round(summary.pqc_ready / summary.total_findings * 100) : 0}%</strong><span>ready</span></div></div><div className="legend"><span><i className="dot bad"/>Quantum vulnerable <b>{summary.quantum_vulnerable}</b></span><span><i className="dot good"/>PQC ready <b>{summary.pqc_ready}</b></span></div></div>
      </section>
      <section className="panel inventory"><div className="panel-head"><div><span className="eyebrow">PRIORITIZED INVENTORY</span><h2>Highest-risk cryptographic assets</h2></div><span className="count">{findings.length} shown</span></div><div className="table-wrap"><table><thead><tr><th>Asset</th><th>Primitive</th><th>Algorithm</th><th>PQ status</th><th>Risk</th><th>Migration</th></tr></thead><tbody>{findings.length === 0 ? <tr><td colSpan={6} className="empty">No findings yet. Scan an endpoint or use the source scanner.</td></tr> : findings.slice(0,12).map(f => <tr key={f.observation.id}><td><strong>{f.observation.asset_name}</strong><small>{f.observation.evidence.locator || f.observation.evidence.source}</small></td><td>{f.observation.primitive}</td><td><code>{f.observation.algorithm}</code></td><td><span className={`pill ${f.risk.quantum_status}`}>{f.risk.quantum_status}</span></td><td><span className={`risk ${f.risk.severity}`}>{f.risk.score}</span></td><td>{f.risk.migration_target ? <span className="target">→ {f.risk.migration_target}</span> : <span className="muted">retain</span>}</td></tr>)}</tbody></table></div></section>
      <section className="panel migration"><div className="panel-head"><div><span className="eyebrow">ACTION QUEUE</span><h2>Migration candidates</h2></div><span className="count">ranked by exposure</span></div><div className="queue">{migrationQueue.length === 0 ? <div className="empty">Migration recommendations appear here as evidence is collected.</div> : migrationQueue.map((f,i) => <div className="queue-item" key={f.observation.id}><span className="rank">0{i+1}</span><div><strong>{f.observation.family} on {f.observation.asset_name}</strong><p>{f.risk.migration_strategy}</p></div><div className="move"><span>{f.observation.family}</span><ArrowUpRight size={15}/><b>{f.risk.migration_target}</b></div></div>)}</div></section>
    </main>
  </div>
}

function Metric({label,value,icon,tone='normal'}:{label:string;value:number;icon:React.ReactNode;tone?:string}) { return <div className={`metric ${tone}`}><div className="metric-top"><span>{label}</span><span className="metric-icon">{icon}</span></div><strong>{value.toLocaleString()}</strong><small>live inventory</small></div> }

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
