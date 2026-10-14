import React from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import 'antd/dist/reset.css'
import './styles.css'
import './app/cockpit.css'
import './standalone-cockpit.css'
import { CockpitPage } from './app/CockpitPage.jsx'

// The cockpit is intentionally mounted outside FeatureApp so its canvas owns the full viewport.
window.__STANDALONE_COCKPIT__ = true

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/cockpit" element={<CockpitPage />} />
        <Route path="/dashboard" element={<CockpitPage />} />
        <Route path="*" element={<Navigate to="/cockpit" replace />} />
      </Routes>
    </BrowserRouter>
  </React.StrictMode>,
)
