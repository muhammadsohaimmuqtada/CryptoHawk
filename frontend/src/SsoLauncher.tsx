import { useEffect, useState } from 'react'
import { KeyRound } from 'lucide-react'
import { oidcStatus, publicJson } from './api'
import './oidc.css'

export default function SsoLauncher() {
  const [enabled, setEnabled] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    const message = sessionStorage.getItem('cryptohawk_oidc_error') || ''
    if (message) {
      setError(message)
      sessionStorage.removeItem('cryptohawk_oidc_error')
    }

    if (sessionStorage.getItem('cryptohawk_session')) return
    void Promise.all([
      oidcStatus(),
      publicJson<{ bootstrap_required: boolean }>('/api/v1/auth/status'),
    ])
      .then(([oidc, auth]) => setEnabled(oidc.enabled && !auth.bootstrap_required))
      .catch(() => setEnabled(false))
  }, [])

  if (!enabled && !error) return null

  return (
    <aside className="oidc-launcher" aria-live="polite">
      {error && <span className="oidc-error">{error}</span>}
      {enabled && (
        <a className="oidc-button" href="/api/v1/auth/oidc/start">
          <KeyRound size={16} />
          Sign in with enterprise SSO
        </a>
      )}
    </aside>
  )
}
