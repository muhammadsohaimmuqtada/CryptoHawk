import { FormEvent, useEffect, useMemo, useState } from 'react'
import {
  BadgeCheck,
  BookOpenCheck,
  Check,
  CopyPlus,
  FileLock2,
  Fingerprint,
  Plus,
  RefreshCw,
  Save,
  ShieldCheck,
  SlidersHorizontal,
  X,
} from 'lucide-react'
import MigrationShell from './MigrationShell'
import { createClient } from './api'
import type {
  CryptoPolicyPackWithVersions,
  CryptoPolicyRules,
  CryptoPolicyVersion,
  EffectiveCryptoPolicy,
  PolicyDisposition,
  Workspace,
} from './types'
import './policy.css'

const DEFAULT_RULES: CryptoPolicyRules = {
  minimum_rsa_bits: 2048,
  minimum_aes_bits: 128,
  minimum_tls_version: '1.2',
  disallowed_families: ['MD5', 'SHA-1', 'DES', '3DES', 'RC4', 'DSA'],
  quantum_vulnerable_default: 'review',
  internet_exposed_quantum_action: 'review',
  long_lived_data_years: 5,
  unknown_family_action: 'review',
  minimum_detection_confidence: 0.75,
}

function shortHash(value: string) {
  return `${value.slice(0, 12)}…${value.slice(-8)}`
}

function humanize(value: string) {
  return value.replaceAll('-', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function copyRules(rules: CryptoPolicyRules): CryptoPolicyRules {
  return {
    ...rules,
    disallowed_families: [...rules.disallowed_families],
  }
}

export default function PolicyShell() {
  return (
    <>
      <MigrationShell />
      <PolicyConsole />
    </>
  )
}

function PolicyConsole() {
  const [credential, setCredential] = useState(() => sessionStorage.getItem('cryptohawk_session'))
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [workspaces, setWorkspaces] = useState<Workspace[]>([])
  const [workspaceId, setWorkspaceId] = useState('')
  const [packs, setPacks] = useState<CryptoPolicyPackWithVersions[]>([])
  const [effective, setEffective] = useState<EffectiveCryptoPolicy | null>(null)
  const [selectedPolicyId, setSelectedPolicyId] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [editingVersion, setEditingVersion] = useState(false)

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
    void refreshPolicy()
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

  async function refreshPolicy() {
    if (!client || !workspaceId) return
    setBusy(true)
    try {
      const [nextPacks, nextEffective] = await Promise.all([
        client.policyPacks(workspaceId),
        client.effectivePolicy(workspaceId),
      ])
      setPacks(nextPacks)
      setEffective(nextEffective)
      setSelectedPolicyId((current) =>
        nextPacks.some((item) => item.pack.id === current)
          ? current
          : nextEffective.pack.id,
      )
      setMessage(
        `${nextEffective.pack.name} v${nextEffective.version.version} is active for new scans`,
      )
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to load policy baseline')
    } finally {
      setBusy(false)
    }
  }

  async function activate(pack: CryptoPolicyPackWithVersions, version: CryptoPolicyVersion) {
    if (!client || !workspaceId) return
    setBusy(true)
    try {
      const next = await client.activatePolicyVersion(workspaceId, pack.pack.id, version.version)
      setEffective(next)
      setPacks((current) =>
        current.map((candidate) => ({
          ...candidate,
          active_version:
            candidate.pack.id === pack.pack.id ? version.version : undefined,
        })),
      )
      setMessage(
        `${next.pack.name} v${next.version.version} activated. Existing scan evidence is unchanged.`,
      )
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to activate policy version')
    } finally {
      setBusy(false)
    }
  }

  async function createPack(event: FormEvent<HTMLFormElement>, rules: CryptoPolicyRules) {
    event.preventDefault()
    if (!client || !workspaceId) return
    const form = new FormData(event.currentTarget)
    setBusy(true)
    try {
      const created = await client.createPolicyPack(workspaceId, {
        slug: String(form.get('slug') || '').trim(),
        name: String(form.get('name') || '').trim(),
        description: String(form.get('description') || '').trim(),
        rules,
        activate: form.get('activate') === 'on',
      })
      setShowCreate(false)
      setSelectedPolicyId(created.pack.id)
      await refreshPolicy()
      setMessage(`${created.pack.name} created as immutable version 1`)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to create policy pack')
    } finally {
      setBusy(false)
    }
  }

  async function createVersion(pack: CryptoPolicyPackWithVersions, rules: CryptoPolicyRules) {
    if (!client || !workspaceId) return
    setBusy(true)
    try {
      const created = await client.createPolicyVersion(workspaceId, pack.pack.id, {
        rules,
        activate: true,
      })
      setEditingVersion(false)
      await refreshPolicy()
      setMessage(
        `${pack.pack.name} v${created.version} created and activated; prior versions remain immutable`,
      )
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to create policy version')
    } finally {
      setBusy(false)
    }
  }

  const selected = packs.find((item) => item.pack.id === selectedPolicyId) || null
  const selectedVersion = selected?.versions[0] || null
  const policyRef = effective
    ? `policy:${effective.pack.id}@${effective.version.version}:${effective.version.rules_hash.slice(0, 16)}`
    : ''

  if (!credential) return null

  return (
    <>
      <button className="policy-launcher" onClick={() => setOpen(true)} title="Open policy baselines">
        <ShieldCheck size={16} />
        <span>Policy baseline</span>
        {effective && <b>v{effective.version.version}</b>}
      </button>

      {open && (
        <div className="policy-backdrop" role="presentation">
          <section className="policy-console" role="dialog" aria-modal="true" aria-label="Policy baselines">
            <header className="policy-header">
              <div>
                <span className="eyebrow">ORGANIZATION CRYPTO STANDARD</span>
                <h2>Policy baselines</h2>
                <p>Versioned compliance rules layered on top of CryptoHawk’s deterministic risk engine.</p>
              </div>
              <div className="policy-header-actions">
                <label>
                  <span>Workspace</span>
                  <select value={workspaceId} onChange={(event) => setWorkspaceId(event.target.value)}>
                    {workspaces.map((workspace) => (
                      <option key={workspace.id} value={workspace.id}>{workspace.name}</option>
                    ))}
                  </select>
                </label>
                <button disabled={busy || !workspaceId} onClick={() => void refreshPolicy()} title="Refresh policies">
                  <RefreshCw size={15} className={busy ? 'spin' : ''} />
                </button>
                <button onClick={() => setOpen(false)} title="Close policies"><X size={17} /></button>
              </div>
            </header>

            <div className="policy-trust-banner">
              <FileLock2 size={18} />
              <div>
                <strong>Risk and policy are intentionally separate.</strong>
                <span>Organization rules can produce Pass / Review / Fail, but never lower CryptoHawk’s underlying risk score or rewrite historical scan evidence.</span>
              </div>
            </div>

            {effective && (
              <section className="effective-policy">
                <div className="effective-icon"><BadgeCheck size={22} /></div>
                <div>
                  <span className="eyebrow">ACTIVE FOR NEW SCANS</span>
                  <h3>{effective.pack.name} <small>v{effective.version.version}</small></h3>
                  <p>{effective.pack.description}</p>
                </div>
                <dl>
                  <div><dt>Rules hash</dt><dd>{shortHash(effective.version.rules_hash)}</dd></div>
                  <div><dt>Assigned by</dt><dd>{effective.assigned_by}</dd></div>
                </dl>
                <code>{policyRef}</code>
              </section>
            )}

            <div className="policy-body">
              <aside className="policy-pack-list">
                <div className="policy-list-head">
                  <div><span className="eyebrow">BASELINE LIBRARY</span><h3>Policy packs</h3></div>
                  <button onClick={() => setShowCreate(true)}><Plus size={14} />Custom</button>
                </div>
                <div className="policy-pack-cards">
                  {packs.map((item) => {
                    const latest = item.versions[0]
                    const active = item.active_version !== undefined
                    return (
                      <button
                        key={item.pack.id}
                        className={`policy-pack-card ${selectedPolicyId === item.pack.id ? 'selected' : ''}`}
                        onClick={() => {
                          setSelectedPolicyId(item.pack.id)
                          setEditingVersion(false)
                        }}
                      >
                        <div className="policy-pack-top">
                          {item.pack.built_in ? <BookOpenCheck size={14} /> : <SlidersHorizontal size={14} />}
                          <span>{item.pack.built_in ? 'Built-in' : 'Custom'}</span>
                          {active && <b><Check size={11} />Active v{item.active_version}</b>}
                        </div>
                        <strong>{item.pack.name}</strong>
                        <p>{item.pack.description || 'Organization-specific cryptographic baseline.'}</p>
                        <div className="policy-pack-meta">
                          <span>{item.versions.length} version{item.versions.length === 1 ? '' : 's'}</span>
                          <code>{latest ? shortHash(latest.rules_hash) : '—'}</code>
                        </div>
                      </button>
                    )
                  })}
                </div>
              </aside>

              <main className="policy-detail">
                {selected && selectedVersion ? (
                  <PolicyDetail
                    pack={selected}
                    activePolicyId={effective?.pack.id}
                    busy={busy}
                    editingVersion={editingVersion}
                    onEdit={() => setEditingVersion(true)}
                    onCancelEdit={() => setEditingVersion(false)}
                    onActivate={(version) => void activate(selected, version)}
                    onCreateVersion={(rules) => void createVersion(selected, rules)}
                  />
                ) : (
                  <div className="policy-empty"><ShieldCheck size={28} /><strong>Select a policy pack.</strong></div>
                )}
              </main>
            </div>

            <footer className="policy-footer">
              <span>{message || 'Policy changes affect only scans executed after activation.'}</span>
              <span>Historical versions and rules hashes are retained for reproducibility.</span>
            </footer>
          </section>
        </div>
      )}

      {showCreate && (
        <CreatePolicyDialog
          busy={busy}
          onClose={() => setShowCreate(false)}
          onSubmit={createPack}
        />
      )}
    </>
  )
}

function PolicyDetail({
  pack,
  activePolicyId,
  busy,
  editingVersion,
  onEdit,
  onCancelEdit,
  onActivate,
  onCreateVersion,
}: {
  pack: CryptoPolicyPackWithVersions
  activePolicyId?: string
  busy: boolean
  editingVersion: boolean
  onEdit: () => void
  onCancelEdit: () => void
  onActivate: (version: CryptoPolicyVersion) => void
  onCreateVersion: (rules: CryptoPolicyRules) => void
}) {
  const latest = pack.versions[0]
  const [rules, setRules] = useState(() => copyRules(latest.rules))

  useEffect(() => {
    setRules(copyRules(pack.versions[0].rules))
  }, [pack.pack.id, pack.versions[0].id])

  if (editingVersion && !pack.pack.built_in) {
    return (
      <div className="policy-editor-wrap">
        <div className="policy-detail-head">
          <div><span className="eyebrow">NEW IMMUTABLE VERSION</span><h3>{pack.pack.name}</h3></div>
          <button className="policy-text-button" onClick={onCancelEdit}><X size={13} />Cancel</button>
        </div>
        <RuleEditor rules={rules} onChange={setRules} />
        <button className="policy-primary" disabled={busy} onClick={() => onCreateVersion(rules)}>
          <Save size={14} />Create & activate v{latest.version + 1}
        </button>
      </div>
    )
  }

  return (
    <div className="policy-detail-inner">
      <div className="policy-detail-head">
        <div>
          <span className="eyebrow">{pack.pack.built_in ? 'IMMUTABLE BUILT-IN' : 'VERSIONED CUSTOM BASELINE'}</span>
          <h3>{pack.pack.name}</h3>
          <p>{pack.pack.description}</p>
        </div>
        {!pack.pack.built_in && (
          <button className="policy-text-button" onClick={onEdit}><CopyPlus size={13} />New version</button>
        )}
      </div>

      <div className="policy-version-list">
        {pack.versions.map((version) => {
          const active = pack.active_version === version.version && activePolicyId === pack.pack.id
          return (
            <article className={`policy-version ${active ? 'active' : ''}`} key={version.id}>
              <div className="policy-version-head">
                <div><strong>Version {version.version}</strong>{active && <span><Check size={11} />Effective</span>}</div>
                <code>{shortHash(version.rules_hash)}</code>
              </div>
              <RuleSummary rules={version.rules} />
              <div className="policy-version-actions">
                <span>Created by {version.created_by}</span>
                {!active && (
                  <button disabled={busy} onClick={() => onActivate(version)}>
                    <ShieldCheck size={13} />Activate this version
                  </button>
                )}
              </div>
            </article>
          )
        })}
      </div>
    </div>
  )
}

function RuleSummary({ rules }: { rules: CryptoPolicyRules }) {
  return (
    <div className="rule-summary">
      <Rule label="RSA minimum" value={`${rules.minimum_rsa_bits} bits`} />
      <Rule label="AES minimum" value={`${rules.minimum_aes_bits} bits`} />
      <Rule label="TLS minimum" value={`TLS ${rules.minimum_tls_version}`} />
      <Rule label="Quantum vulnerable" value={humanize(rules.quantum_vulnerable_default)} />
      <Rule label="Internet + quantum" value={humanize(rules.internet_exposed_quantum_action)} />
      <Rule label="HNDL threshold" value={`${rules.long_lived_data_years} years`} />
      <Rule label="Unknown algorithms" value={humanize(rules.unknown_family_action)} />
      <Rule label="Min confidence" value={`${Math.round(rules.minimum_detection_confidence * 100)}%`} />
      <div className="rule-wide"><span>Disallowed families</span><strong>{rules.disallowed_families.join(', ') || 'None'}</strong></div>
    </div>
  )
}

function Rule({ label, value }: { label: string; value: string }) {
  return <div><span>{label}</span><strong>{value}</strong></div>
}

function RuleEditor({
  rules,
  onChange,
}: {
  rules: CryptoPolicyRules
  onChange: (rules: CryptoPolicyRules) => void
}) {
  function set<K extends keyof CryptoPolicyRules>(key: K, value: CryptoPolicyRules[K]) {
    onChange({ ...rules, [key]: value })
  }

  return (
    <div className="rule-editor">
      <label><span>Minimum RSA bits</span><input type="number" min="1024" max="16384" step="256" value={rules.minimum_rsa_bits} onChange={(event) => set('minimum_rsa_bits', Number(event.target.value))} /></label>
      <label><span>Minimum AES bits</span><select value={rules.minimum_aes_bits} onChange={(event) => set('minimum_aes_bits', Number(event.target.value))}><option value="128">128</option><option value="192">192</option><option value="256">256</option></select></label>
      <label><span>Minimum TLS</span><select value={rules.minimum_tls_version} onChange={(event) => set('minimum_tls_version', event.target.value as '1.2' | '1.3')}><option value="1.2">TLS 1.2</option><option value="1.3">TLS 1.3</option></select></label>
      <label><span>Quantum-vulnerable default</span><ActionSelect value={rules.quantum_vulnerable_default} onChange={(value) => set('quantum_vulnerable_default', value as 'review' | 'fail')} pass={false} /></label>
      <label><span>Internet + quantum</span><ActionSelect value={rules.internet_exposed_quantum_action} onChange={(value) => set('internet_exposed_quantum_action', value as 'review' | 'fail')} pass={false} /></label>
      <label><span>HNDL data lifetime</span><input type="number" min="0" max="50" value={rules.long_lived_data_years} onChange={(event) => set('long_lived_data_years', Number(event.target.value))} /></label>
      <label><span>Unknown algorithms</span><ActionSelect value={rules.unknown_family_action} onChange={(value) => set('unknown_family_action', value)} /></label>
      <label><span>Minimum detection confidence</span><input type="number" min="0" max="1" step="0.05" value={rules.minimum_detection_confidence} onChange={(event) => set('minimum_detection_confidence', Number(event.target.value))} /></label>
      <label className="rule-editor-wide"><span>Disallowed families</span><input value={rules.disallowed_families.join(', ')} onChange={(event) => set('disallowed_families', event.target.value.split(',').map((value) => value.trim()).filter(Boolean))} placeholder="MD5, SHA-1, DES, 3DES, RC4, DSA" /></label>
    </div>
  )
}

function ActionSelect({
  value,
  onChange,
  pass = true,
}: {
  value: PolicyDisposition | 'review' | 'fail'
  onChange: (value: PolicyDisposition) => void
  pass?: boolean
}) {
  return (
    <select value={value} onChange={(event) => onChange(event.target.value as PolicyDisposition)}>
      {pass && <option value="pass">Pass</option>}
      <option value="review">Review</option>
      <option value="fail">Fail</option>
    </select>
  )
}

function CreatePolicyDialog({
  busy,
  onClose,
  onSubmit,
}: {
  busy: boolean
  onClose: () => void
  onSubmit: (event: FormEvent<HTMLFormElement>, rules: CryptoPolicyRules) => void
}) {
  const [rules, setRules] = useState(() => copyRules(DEFAULT_RULES))
  return (
    <div className="policy-dialog-backdrop">
      <form className="policy-dialog" onSubmit={(event) => onSubmit(event, rules)}>
        <div className="policy-dialog-head">
          <div><span className="eyebrow">CUSTOM ORGANIZATION BASELINE</span><h3>Create policy pack</h3></div>
          <button type="button" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="policy-dialog-fields">
          <label><span>Name</span><input name="name" required maxLength={200} placeholder="Payments Production" /></label>
          <label><span>Slug</span><input name="slug" required pattern="[a-z0-9][a-z0-9-]*" placeholder="payments-production" /></label>
          <label className="wide"><span>Description</span><textarea name="description" rows={2} maxLength={4000} placeholder="Cryptographic baseline for production payment workloads" /></label>
        </div>
        <RuleEditor rules={rules} onChange={setRules} />
        <label className="policy-activate-check"><input type="checkbox" name="activate" defaultChecked /><span>Activate version 1 immediately for new scans</span></label>
        <div className="policy-dialog-actions">
          <button type="button" className="secondary" onClick={onClose}>Cancel</button>
          <button disabled={busy} type="submit"><Fingerprint size={14} />Create immutable v1</button>
        </div>
      </form>
    </div>
  )
}
