export type Summary = {
  total_findings: number
  critical: number
  high: number
  medium: number
  low: number
  quantum_vulnerable: number
  pqc_ready: number
}

export type PolicyDisposition = 'pass' | 'review' | 'fail'

export type Finding = {
  observation: {
    id: string
    asset_id: string
    asset_name: string
    asset_type: string
    algorithm: string
    family: string
    primitive: string
    key_size?: number
    protocol_version?: string
    confidence?: number
    evidence: {
      source: string
      locator?: string
      line?: number
      metadata?: Record<string, unknown>
    }
  }
  risk: {
    score: number
    severity: string
    quantum_status: string
    reasons?: string[]
    migration_target?: string
    migration_strategy?: string
    policy_id?: string
    policy_version?: number
    policy_name?: string
    policy_status?: PolicyDisposition
    policy_reasons?: string[]
    policy_controls?: string[]
    policy_rules_hash?: string
  }
}

export type Workspace = {
  id: string
  name: string
  slug: string
  created_at?: string
}

export type ScanContext = {
  internet_exposed?: boolean
  asset_criticality?: number
  data_lifetime_years?: number
  environment?: string
}

export type AssetKind =
  | 'source'
  | 'repository'
  | 'tls-endpoint'
  | 'certificate-endpoint'
  | 'ssh-endpoint'
  | 'host'
  | 'container'
  | 'kubernetes'
  | 'cloud-resource'

export type ManagedAsset = {
  id: string
  workspace_id: string
  name: string
  kind: AssetKind
  locator: string
  context: ScanContext
  tags: Record<string, string>
  enabled: boolean
  created_at?: string
  updated_at?: string
}

export type ScanJob = {
  id: string
  workspace_id: string
  asset_id: string
  kind: string
  status: 'queued' | 'running' | 'succeeded' | 'failed' | 'canceled'
  requested_at: string
  started_at?: string
  finished_at?: string
  findings_count: number
  error_message?: string
}

export type RemediationStatus =
  | 'open'
  | 'planned'
  | 'in-progress'
  | 'blocked'
  | 'ready-for-verification'
  | 'verified'
  | 'accepted-risk'

export type RemediationPriority = 'critical' | 'high' | 'medium' | 'low'

export type MigrationItem = {
  id: string
  workspace_id: string
  asset_id: string
  observation_fingerprint: string
  source_finding_id: string
  source_scan_job_id: string
  title: string
  owner?: string
  status: RemediationStatus
  priority: RemediationPriority
  target_algorithm?: string
  due_date?: string
  notes?: string
  acceptance_reason?: string
  verification_job_id?: string
  verified_at?: string
  verification_evidence: Record<string, string | number | boolean | null>
  source_finding: Finding
  created_by: string
  created_at: string
  updated_at: string
}

export type RemediationVerification = {
  item: MigrationItem
  verified: boolean
  outcome: string
}

export type CryptoPolicyRules = {
  minimum_rsa_bits: number
  minimum_aes_bits: number
  minimum_tls_version: '1.2' | '1.3'
  disallowed_families: string[]
  quantum_vulnerable_default: 'review' | 'fail'
  internet_exposed_quantum_action: 'review' | 'fail'
  long_lived_data_years: number
  unknown_family_action: PolicyDisposition
  minimum_detection_confidence: number
}

export type CryptoPolicyPack = {
  id: string
  workspace_id: string
  slug: string
  name: string
  description: string
  built_in: boolean
  created_by: string
  created_at: string
}

export type CryptoPolicyVersion = {
  id: string
  policy_id: string
  workspace_id: string
  version: number
  rules: CryptoPolicyRules
  rules_hash: string
  created_by: string
  created_at: string
}

export type CryptoPolicyPackWithVersions = {
  pack: CryptoPolicyPack
  versions: CryptoPolicyVersion[]
  active_version?: number
}

export type EffectiveCryptoPolicy = {
  pack: CryptoPolicyPack
  version: CryptoPolicyVersion
  assigned_by: string
  assigned_at: string
}

export type IssuedToken = {
  token: string
  expires_at: string
  user?: { id: string; email: string; display_name: string }
  workspace?: Workspace
}

export type AuthMode = 'checking' | 'bootstrap' | 'login' | 'ready'
export type OperatorView = 'command' | 'inventory' | 'history' | 'migration' | 'policy'

export type ScannableAssetKind =
  | 'tls-endpoint'
  | 'certificate-endpoint'
  | 'ssh-endpoint'
  | 'repository'
  | 'container'
