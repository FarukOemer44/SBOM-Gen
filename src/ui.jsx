import React from 'react'
import { useT, getLang } from './i18n.jsx'

export const Pill = ({ kind = 'neutral', children, title }) => <span className={'pill ' + kind} title={title}>{children}</span>

export const Toggle = ({ on, onChange }) => (
  <span className={'toggle' + (on ? '' : ' off')} onClick={() => onChange(!on)} />
)

export const CloseX = ({ onClick }) => (
  <span style={{ cursor: 'pointer', color: '#8B95A3', fontSize: 20, lineHeight: 1, padding: '2px 6px' }} onClick={onClick}>×</span>
)

export function Drawer({ children, onClose }) {
  return (
    <div className="overlay">
      <div className="dim" onClick={onClose} />
      <div className="drawer sc">{children}</div>
    </div>
  )
}

export function Modal({ children, onClose, width = 640 }) {
  return (
    <div className="modal-dim" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal sc" style={{ width }}>{children}</div>
    </div>
  )
}

export function TitleBar({ title, children }) {
  return (
    <div className="titlebar">
      <h2>{title}</h2>
      <div className="actions">{children}</div>
    </div>
  )
}

export function SearchBox({ value, onChange }) {
  const t = useT()
  return (
    <span className="searchbox">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none"><circle cx="11" cy="11" r="7" stroke="#9AA4B2" strokeWidth="1.8" /><path d="M20 20l-3.5-3.5" stroke="#9AA4B2" strokeWidth="1.8" strokeLinecap="round" /></svg>
      <input placeholder={t('Suchen …')} value={value} onChange={e => onChange(e.target.value)} />
    </span>
  )
}

// Datum folgt der gewaehlten Sprache: TT.MM.JJJJ deutsch, DD/MM/YYYY englisch.
export const fmtDT = (iso) => {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d)) return iso
  const p = n => String(n).padStart(2, '0')
  const tag = getLang() === 'en'
    ? `${p(d.getDate())}/${p(d.getMonth() + 1)}/${d.getFullYear()}`
    : `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()}`
  return `${tag} ${p(d.getHours())}:${p(d.getMinutes())}`
}
export const fmtD = (iso) => {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d)) return iso
  const p = n => String(n).padStart(2, '0')
  return getLang() === 'en'
    ? `${p(d.getDate())}/${p(d.getMonth() + 1)}/${d.getFullYear()}`
    : `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()}`
}
// Monatswerte (YYYY-MM) nie roh anzeigen: MM/JJJJ.
export const fmtM = (ym) => {
  if (!ym) return '—'
  const m = String(ym).match(/^(\d{4})-(\d{2})$/)
  return m ? `${m[2]}/${m[1]}` : ym
}
// purl lesbar machen: %40types → @types, %C3%BC → ü.
export const pshow = (s) => { try { return decodeURIComponent(String(s)) } catch { return s } }
// Kleiner Fragezeichen-Kreis: Erklaerung in Alltagssprache beim Darueberfahren (D-037).
export const HelpDot = ({ text }) => (
  <span className="helpdot" title={text}>?</span>
)
