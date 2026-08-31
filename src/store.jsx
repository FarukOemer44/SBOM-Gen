import React, { createContext, useContext, useEffect, useState } from 'react'
import { useT } from './i18n.jsx'

const Ctx = createContext(null)

async function j(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status)
  return data
}

// Persistenz: ausschließlich SQLite über /api (server/index.mjs, Port 5178).
// Produkte/Versionen/Komponenten/SBOMs/Funde liegen relational getrennt in der DB;
// nur die aktuelle Auswahl (Produkt + Version) ist lokaler UI-Zustand.
export function StoreProvider({ children }) {
  const t = useT()
  const [products, setProducts] = useState(null)
  const [dbStatus, setDbStatus] = useState('lädt')
  const [sel, setSelRaw] = useState(() => {
    try { return JSON.parse(localStorage.getItem('sbomgen-sel')) || {} } catch { return {} }
  })
  const [data, setData] = useState(null)   // Versionsdaten: components, sboms, findings, scans
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState(null)

  const setSel = (s) => { setSelRaw(s); try { localStorage.setItem('sbomgen-sel', JSON.stringify(s)) } catch {} }

  const loadProducts = () =>
    j('GET', '/api/bootstrap')
      .then(({ products }) => { setProducts(products); setDbStatus('SQLite'); return products })
      .catch(() => { setDbStatus('fehler'); return null })

  useEffect(() => { loadProducts() }, [])

  // Auswahl validieren, sobald Produkte da sind
  useEffect(() => {
    if (!products) return
    const prod = products.find(p => p.id === sel.pid) || products[0]
    if (!prod) { if (sel.pid) setSel({}); setData(null); return }
    const ver = prod.versions.find(v => v.id === sel.vid) || prod.versions[prod.versions.length - 1]
    if (prod.id !== sel.pid || ver?.id !== sel.vid) setSel({ pid: prod.id, vid: ver?.id })
  }, [products])

  // Versionsdaten laden, wenn die Auswahl wechselt
  useEffect(() => {
    if (!sel.vid) { setData(null); return }
    j('GET', '/api/versions/' + sel.vid)
      .then(setData)
      .catch(() => {
        // Die gemerkte Version gibt es nicht mehr (etwa nach einem Zuruecksetzen der
        // Datenbank). Auswahl verwerfen und aus den vorhandenen Produkten neu waehlen.
        setData(null)
        setSel({})
        loadProducts()
      })
  }, [sel.vid])

  if (dbStatus === 'fehler' && !products) return <DbError onRetry={() => { setDbStatus('lädt'); loadProducts() }} />
  if (!products) return (
    <div style={{ height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontFamily: 'DM Sans, sans-serif', fontSize: 13, color: '#8B95A3' }}>● {t('verbinde …')}</div>
  )

  const product = products.find(p => p.id === sel.pid) || null
  const version = product?.versions.find(v => v.id === sel.vid) || null

  // Mutationen: API-Aufruf; Antworten mit Versionsdaten aktualisieren den Zustand direkt.
  const call = async (method, url, body, { reloadProducts = false } = {}) => {
    setBusy(true)
    try {
      const res = await j(method, url, body)
      if (res.components) setData({ components: res.components, sboms: res.sboms, findings: res.findings, scans: res.scans })
      if (reloadProducts) await loadProducts()
      return res
    } catch (e) {
      setNotice({ err: true, msg: e.message })
      throw e
    } finally { setBusy(false) }
  }

  const api = {
    products, product, version, sel, setSel, data, dbStatus, busy, notice, setNotice, call,
    reloadProducts: loadProducts,
  }
  return <Ctx.Provider value={api}>{children}</Ctx.Provider>
}

function DbError({ onRetry }) {
  const t = useT()
  return (
    <div style={{ height: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 10, fontFamily: 'DM Sans, sans-serif' }}>
      <div style={{ fontSize: 16, fontWeight: 600, color: '#0B1928' }}>{t('Datenbank nicht erreichbar')}</div>
      <div style={{ fontSize: 13, color: '#69778E' }}>{t('API-Server starten:')} <b>npm run server</b> (Port 5178)</div>
      <button className="ab" onClick={onRetry}>{t('Erneut verbinden')}</button>
    </div>
  )
}

export const useStore = () => useContext(Ctx)
