import React from 'react'
import { createRoot } from 'react-dom/client'
import ReportingShell from './ReportingShell'
import SsoLauncher from './SsoLauncher'
import { exchangeOidc } from './api'
import './styles.css'

async function completeOidcRedirect() {
  const fragment = new URLSearchParams(window.location.hash.replace(/^#/, ''))
  const code = fragment.get('oidc_code')
  const error = fragment.get('oidc_error')
  if (!code && !error) return

  window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}`)
  if (error) {
    sessionStorage.setItem('cryptohawk_oidc_error', 'Enterprise SSO authentication failed.')
    return
  }

  try {
    const issued = await exchangeOidc(code || '')
    sessionStorage.setItem('cryptohawk_session', issued.token)
    sessionStorage.removeItem('cryptohawk_oidc_error')
  } catch {
    sessionStorage.removeItem('cryptohawk_session')
    sessionStorage.setItem('cryptohawk_oidc_error', 'Enterprise SSO session exchange failed.')
  }
}

void completeOidcRedirect().finally(() => {
  createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
      <ReportingShell />
      <SsoLauncher />
    </React.StrictMode>,
  )
})
