import type {
  Finding,
  IssuedToken,
  ManagedAsset,
  ScanJob,
  Summary,
  Workspace,
} from './types'

export class ApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function readError(response: Response, fallback: string): Promise<never> {
  const body = await response.json().catch(() => ({}))
  throw new ApiError(String(body.detail || fallback), response.status)
}

export async function publicJson<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, options)
  if (!response.ok) return readError(response, 'Request failed')
  return response.json() as Promise<T>
}

export function createClient(token: string, onUnauthorized: () => void) {
  async function request(path: string, options: RequestInit = {}) {
    const headers = new Headers(options.headers)
    headers.set('Authorization', `Bearer ${token}`)
    if (options.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json')
    }
    const response = await fetch(path, { ...options, headers })
    if (response.status === 401) onUnauthorized()
    return response
  }

  async function json<T>(path: string, options: RequestInit = {}, fallback = 'Request failed') {
    const response = await request(path, options)
    if (!response.ok) return readError(response, fallback)
    return response.json() as Promise<T>
  }

  return {
    me: () => json<{ user_id?: string; kind?: string }>('/api/v1/auth/me'),
    logout: () => request('/api/v1/auth/logout', { method: 'POST' }),
    listWorkspaces: () => json<Workspace[]>('/api/v1/workspaces'),
    createWorkspace: (name: string, slug?: string) =>
      json<Workspace>(
        '/api/v1/workspaces',
        {
          method: 'POST',
          body: JSON.stringify({ name, slug: slug || undefined }),
        },
        'Workspace creation failed',
      ),
    summary: (workspaceId: string) =>
      json<Summary>(`/api/v1/workspaces/${workspaceId}/dashboard/summary`),
    findings: (workspaceId: string) =>
      json<Finding[]>(`/api/v1/workspaces/${workspaceId}/findings?limit=200`),
    assets: (workspaceId: string) =>
      json<ManagedAsset[]>(`/api/v1/workspaces/${workspaceId}/assets`),
    jobs: (workspaceId: string) =>
      json<ScanJob[]>(`/api/v1/workspaces/${workspaceId}/scan-jobs?limit=100`),
    createAsset: (workspaceId: string, body: Record<string, unknown>) =>
      json<ManagedAsset>(
        `/api/v1/workspaces/${workspaceId}/assets`,
        { method: 'POST', body: JSON.stringify(body) },
        'Asset registration failed',
      ),
    createRepository: (workspaceId: string, body: Record<string, unknown>) =>
      json<{ asset: ManagedAsset }>(
        `/api/v1/workspaces/${workspaceId}/repositories`,
        { method: 'POST', body: JSON.stringify(body) },
        'Repository registration failed',
      ),
    queueScan: (workspaceId: string, assetId: string, maxAttempts = 3) =>
      json<ScanJob>(
        `/api/v1/workspaces/${workspaceId}/assets/${assetId}/scan-jobs`,
        { method: 'POST', body: JSON.stringify({ max_attempts: maxAttempts }) },
        'Unable to queue scan',
      ),
  }
}

export async function bootstrap(body: Record<string, string>): Promise<IssuedToken> {
  return publicJson<IssuedToken>('/api/v1/auth/bootstrap', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

export async function login(email: string, password: string): Promise<IssuedToken> {
  return publicJson<IssuedToken>('/api/v1/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
}
