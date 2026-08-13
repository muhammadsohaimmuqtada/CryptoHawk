export type Summary = {
  total_findings: number
  critical: number
  high: number
  medium: number
  low: number
  quantum_vulnerable: number
  pqc_ready: number
}

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

export type IssuedToken = {
  token: string
  expires_at: string
  user?: { id: string; email: string; display_name: string }
  workspace?: Workspace
}

export type AuthMode = 'checking' | 'bootstrap' | 'login' | 'ready'
export type OperatorView = 'command' | 'inventory' | 'history'

export type ScannableAssetKind =
  | 'tls-endpoint'
  | 'certificate-endpoint'
  | 'ssh-endpoint'
  | 'repository'
  | 'container'
