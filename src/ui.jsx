import React from 'react'

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
  return (
    <span className="searchbox">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none"><circle cx="11" cy="11" r="7" stroke="#9AA4B2" strokeWidth="1.8" /><path d="M20 20l-3.5-3.5" stroke="#9AA4B2" strokeWidth="1.8" strokeLinecap="round" /></svg>
      <input placeholder="Suchen …" value={value} onChange={e => onChange(e.target.value)} />
    </span>
  )
}

export const fmtDT = (iso) => {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d)) return iso
  const p = n => String(n).padStart(2, '0')
  return `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}`
}
export const fmtD = (iso) => {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d)) return iso
  const p = n => String(n).padStart(2, '0')
  return `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()}`
}
