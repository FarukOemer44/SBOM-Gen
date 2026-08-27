import React from 'react'
import { useStore } from './store.jsx'

const sbomIcon = (c) => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
    <path d="M12 3.5 21 8l-9 4.5L3 8l9-4.5Z" stroke={c} strokeWidth="1.7" strokeLinejoin="round" />
    <path d="M3 12.5 12 17l9-4.5M3 17l9 4.5 9-4.5" stroke={c} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
)

export default function Shell({ children }) {
  const { dbStatus } = useStore()
  return (
    <div className="shell">
      <aside className="sidebar sc">
        <div className="sidebar-logo">
          <b><img src="/assets/logo.svg" height="18" alt="" />TrustSpace</b>
        </div>
        <nav className="sidenav">
          <div className="nav-caption">CRA</div>
          <div className="nl active">
            <span className="lab">{sbomIcon('#1298ff')}SBOM &amp; Komponenten</span>
          </div>
        </nav>
        <div className="nav-footer">
          <div className="nl" style={{ padding: '4px 10px', pointerEvents: 'none' }}>
            <span className="lab" style={{ fontSize: 11, color: dbStatus === 'SQLite' ? '#3EC556' : '#F5A623' }}>● Datenbank: {dbStatus}</span>
          </div>
          <div className="nl" style={{ padding: '4px 10px', pointerEvents: 'none' }}>
            <span className="lab" style={{ fontSize: 11, color: '#B6C1CD' }}>CRA-Modul · SBOM-Gen</span>
          </div>
        </div>
      </aside>
      <div className="col">
        <header className="header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 22, flex: '0 0 auto', marginLeft: 'auto' }}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" style={{ cursor: 'pointer' }}>
              <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9Z" stroke="#495057" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
              <path d="M13.73 21a2 2 0 0 1-3.46 0" stroke="#495057" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, cursor: 'pointer' }}>
              <div style={{ width: 42, height: 42, borderRadius: '50%', background: '#F4640E', color: '#fff', fontSize: 14, fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>ÖF</div>
              <span style={{ fontSize: 17, fontWeight: 600, color: '#1F1F1F' }}>Ömer Faruk Yildiz</span>
            </div>
          </div>
        </header>
        {children}
      </div>
    </div>
  )
}
