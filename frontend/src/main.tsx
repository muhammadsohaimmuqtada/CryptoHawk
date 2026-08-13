import React from 'react'
import { createRoot } from 'react-dom/client'
import HistoryShell from './HistoryShell'
import './styles.css'

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <HistoryShell />
  </React.StrictMode>,
)
