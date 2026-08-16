import React from 'react'
import { createRoot } from 'react-dom/client'
import ReportingShell from './ReportingShell'
import './styles.css'

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ReportingShell />
  </React.StrictMode>,
)
