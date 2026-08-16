import React from 'react'
import { createRoot } from 'react-dom/client'
import PolicyShell from './PolicyShell'
import './styles.css'

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <PolicyShell />
  </React.StrictMode>,
)
