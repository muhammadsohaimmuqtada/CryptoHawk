import React from 'react'
import { createRoot } from 'react-dom/client'
import MigrationShell from './MigrationShell'
import './styles.css'

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <MigrationShell />
  </React.StrictMode>,
)
