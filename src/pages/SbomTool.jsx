import React, { useRef, useState } from 'react'
import { useStore } from '../store.jsx'
import { useT, useI18n } from '../i18n.jsx'
import { TitleBar, SearchBox, Pill, Toggle, Drawer, Modal, CloseX, fmtDT, fmtD } from '../ui.jsx'

// Komponententypen (Dokument Abschnitt 1.6): Hardware steht im Inventar, nicht in der SBOM.
const KINDS = [
  ['hardware', 'Hardware', 'neutral'],
  ['software_eigen', 'Software (eigen)', 'blue'],
  ['software_oss', 'Open Source', 'violet'],
  ['software_zukauf', 'Software (Zukauf)', 'amber'],
]
const kindMeta = k => KINDS.find(x => x[0] === k) || ['?', k, 'neutral']

const SEVS = [
  ['KRITISCH', 'Kritisch', '#E44817'],
  ['HOCH', 'Hoch', '#F6A13C'],
  ['MITTEL', 'Mittel', '#E3C500'],
  ['NIEDRIG', 'Niedrig', '#27AE60'],
  ['—', 'Unbewertet', '#8B95A3'],
]
const VEX_STATI = [
  ['under_investigation', 'In Prüfung', 'amber'],
  ['affected', 'Betroffen', 'red'],
  ['not_affected', 'Nicht betroffen', 'green'],
  ['fixed', 'Behoben', 'green'],
]
// Triage-Entscheidung nach ENISA 4.13: fix now / mitigate / accept (befristet) / defer (mit Begründung)
const DECISIONS = [
  ['', '— offen —'],
  ['fix_now', 'Sofort beheben'],
  ['mitigate', 'Mitigieren'],
  ['accept', 'Risiko akzeptieren (befristet)'],
  ['defer', 'Zurückstellen'],
]

// Eingangskanäle (ENISA 4.13: Intake-Kanäle festhalten; D-020: Mail-Eingang beim Kunden)
const INTAKE = [
  ['osv_scan', 'OSV-Abgleich'],
  ['cvd_mail', 'Meldung per Mail (CVD-Kontaktadresse)'],
  ['advisory', 'Lieferanten-Advisory'],
  ['test', 'Eigene Tests'],
  ['csirt', 'Hinweis von außen'],
  ['other', 'Sonstiges'],
]
const intakeLabel = v => (INTAKE.find(x => x[0] === v) || [v, v])[1]

// Automatisches Speichern: Auswahl sofort, Freitext nach kurzer Pause.
// Kein Speichern-Knopf, kein Abbrechen — was man aendert, ist gespeichert.
function useAutoSave(url, initial, call) {
  const [f, setF] = useState(initial)
  const [saved, setSaved] = useState(false)
  const timer = useRef(null)
  const flash = () => { setSaved(true); setTimeout(() => setSaved(false), 1400) }
  const set = (k, v, { debounce = false } = {}) => {
    setF(prev => {
      const next = { ...prev, [k]: v }
      clearTimeout(timer.current)
      const send = () => call('PATCH', url, next).then(flash).catch(() => {})
      if (debounce) timer.current = setTimeout(send, 700)
      else send()
      return next
    })
  }
  React.useEffect(() => () => clearTimeout(timer.current), [])
  return [f, set, saved]
}

function SavedHint({ on }) {
  const t = useT()
  return <span className="muted" style={{ opacity: on ? 1 : 0, transition: 'opacity .25s', fontSize: 12 }}>{t('Gespeichert')}</span>
}

function SevPill({ f }) {
  const t = useT()
  const sc = f.score != null ? ' · CVSS ' + Number(f.score).toFixed(1) : ''
  const [label, kind] = f.severity === 'KRITISCH' ? ['Kritisch', 'red']
    : f.severity === 'HOCH' ? ['Hoch', 'red']
      : f.severity === 'MITTEL' ? ['Mittel', 'amber']
        : f.severity === 'NIEDRIG' ? ['Niedrig', 'green']
          : ['Unbewertet', 'neutral']
  return <Pill kind={kind}>{t(label)}{f.severity !== '—' ? sc : ''}</Pill>
}
function VexPill({ v }) {
  const t = useT()
  const [, label, kind] = VEX_STATI.find(x => x[0] === v) || [null, v || '—', 'neutral']
  return <Pill kind={kind}>{t(label)}</Pill>
}

const toLocal = iso => { if (!iso) return ''; const d = new Date(iso); if (isNaN(d)) return ''; const p = n => String(n).padStart(2, '0'); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}` }
const fromLocal = v => v ? new Date(v).toISOString() : ''

// ---------- Modale: Neues Produkt / Neue Version ----------
function NewProductModal({ onClose }) {
  const t = useT()
  const { call, setSel } = useStore()
  const [name, setName] = useState(''); const [hersteller, setHersteller] = useState(''); const [version, setVersion] = useState('1.0.0')
  const save = async () => {
    const res = await call('POST', '/api/products', { name, hersteller, version }, { reloadProducts: true })
    setSel({ pid: res.productId, vid: res.versionId }); onClose()
  }
  return (
    <Modal onClose={onClose} width={480}>
      <div style={{ display: 'flex', alignItems: 'center' }}><span className="dtitle" style={{ flex: 1 }}>{t('Neues Produkt')}</span><CloseX onClick={onClose} /></div>
      <div className="dsub">{t('Die Zusammensetzung wird je Version geführt.')}</div>
      <div className="fieldlab">{t('Produktname')}</div>
      <input className="field" value={name} onChange={e => setName(e.target.value)} placeholder="z. B. SmartPanel 3000" autoFocus />
      <div className="fieldlab">{t('Hersteller')}</div>
      <input className="field" value={hersteller} onChange={e => setHersteller(e.target.value)} placeholder="z. B. Muster GmbH" />
      <div className="fieldlab">{t('Erste Version')}</div>
      <input className="field" value={version} onChange={e => setVersion(e.target.value)} />
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 18 }}>
        <button className="hb" onClick={onClose}>{t('Abbrechen')}</button>
        <button className="ab" disabled={!name.trim()} onClick={save}>{t('Anlegen')}</button>
      </div>
    </Modal>
  )
}

function NewVersionModal({ onClose }) {
  const t = useT()
  const { call, setSel, sel, product, version } = useStore()
  const [ver, setVer] = useState('')
  const [mode, setMode] = useState('unchanged')      // unchanged | new_sbom
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(null)
  const fileRef = useRef(null)

  const save = async () => {
    setBusy(true); setErr(null)
    try {
      const res = await call('POST', '/api/products/' + product.id + '/versions',
        { version: ver, copyFrom: sel.vid, mode }, { reloadProducts: true })

      if (mode === 'new_sbom' && file) {
        // Neue SBOM direkt in die frisch angelegte Version importieren
        const text = await file.text()
        const jx = JSON.parse(text)
        const raw = jx.components || jx.packages || []
        if (!raw.length) throw new Error(t('Keine Komponenten gefunden — CycloneDX (components[]) oder SPDX (packages[]) erwartet.'))
        // Direkte Abhaengigkeiten aus dem Abhaengigkeitsgraph (CycloneDX) bzw. den
        // SPDX-Relationships bestimmen — nur fuer sie ist die Sorgfaltspruefung sinnvoll.
        const rootRef = jx.metadata?.component?.['bom-ref'] || jx.metadata?.component?.purl
        const directRefs = new Set(
          (jx.dependencies || []).filter(d => d.ref === rootRef).flatMap(d => d.dependsOn || [])
        )
        const spdxDirect = new Set(
          (jx.relationships || []).filter(r => r.relationshipType === 'DEPENDS_ON'
            && r.spdxElementId === (jx.documentDescribes?.[0] || 'SPDXRef-DOCUMENT'))
            .map(r => r.relatedSpdxElement)
        )
        const list = raw.map(c => ({
          name: c.name || '?', version: c.version || c.versionInfo || '',
          purl: c.purl || (c.externalRefs || []).find(r => r.referenceType === 'purl')?.referenceLocator || '',
          supplier: c.supplier?.name || c.publisher || (typeof c.supplier === 'string' ? c.supplier.replace(/^Organization: /, '') : '') || '',
          license: (c.licenses && (c.licenses[0]?.license?.id || c.licenses[0]?.expression)) || c.licenseConcluded || '',
          is_direct: directRefs.has(c['bom-ref']) || spdxDirect.has(c.SPDXID) ? 1 : 0,
        }))
        const fmt = jx.bomFormat ? 'CycloneDX ' + (jx.specVersion || '') : jx.spdxVersion ? 'SPDX ' + jx.spdxVersion : 'SBOM'
        await call('POST', '/api/versions/' + res.versionId + '/sboms', {
          fileName: file.name, format: fmt, depth: 'top_level',
          generatedAt: jx.metadata?.timestamp || jx.creationInfo?.created || '',
          components: list, content: text,
        })
      }
      setSel({ pid: product.id, vid: res.versionId })
      onClose()
    } catch (e) {
      setErr(String(e.message || e))
    } finally { setBusy(false) }
  }

  const ready = ver.trim() && (mode === 'unchanged' || file)
  return (
    <Modal onClose={onClose} width={560}>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <span className="dtitle" style={{ flex: 1 }}>{t('Neue Version —')} {product.name}</span><CloseX onClick={onClose} />
      </div>
      <div className="dsub">{t('Jede Version führt Komponenten, SBOMs und Funde getrennt.')}</div>

      <div className="fieldlab">{t('Versionsbezeichnung')}</div>
      <input className="field" value={ver} onChange={e => setVer(e.target.value)} placeholder="z. B. 1.1.0" autoFocus />

      <div className="fieldlab">{t('Hat sich die Softwarezusammensetzung geändert?')}</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {[
          ['unchanged', t('Nein — SBOM unverändert'), t('Komponenten und der SBOM-Stand aus') + ' ' + (version?.version || '') + ' ' + t('werden übernommen.')],
          ['new_sbom', t('Ja — neue SBOM hochladen'), t('Hardware wird übernommen (steht nicht in der SBOM), die Software kommt aus der neuen Datei.')],
        ].map(([v, label, hint]) => (
          <div key={v} onClick={() => setMode(v)}
            style={{ display: 'flex', gap: 10, alignItems: 'flex-start', padding: '10px 12px', cursor: 'pointer',
              border: '1px solid ' + (mode === v ? '#1298ff' : '#E3E8ED'), borderRadius: 10,
              background: mode === v ? 'rgba(18,152,255,0.04)' : '#fff' }}>
            <span style={{ width: 16, height: 16, borderRadius: '50%', flex: '0 0 auto', marginTop: 2,
              border: '2px solid ' + (mode === v ? '#1298ff' : '#C2CCD8'),
              boxShadow: mode === v ? 'inset 0 0 0 3px #fff, inset 0 0 0 8px #1298ff' : 'none' }} />
            <span style={{ minWidth: 0 }}>
              <span style={{ display: 'block', fontSize: 13.5, fontWeight: 600, color: '#0B1928' }}>{label}</span>
              <span style={{ display: 'block', fontSize: 12, color: '#69778E', lineHeight: 1.5 }}>{hint}</span>
            </span>
          </div>
        ))}
      </div>

      {mode === 'new_sbom' && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 12 }}>
          <button className="hb sm" onClick={() => fileRef.current?.click()}>{t('Datei wählen')}</button>
          <input ref={fileRef} type="file" accept=".json" style={{ display: 'none' }}
            onChange={e => { setFile(e.target.files[0] || null); setErr(null) }} />
          <span className="muted">{file ? file.name : t('CycloneDX- oder SPDX-JSON')}</span>
        </div>
      )}

      {err && <div style={{ marginTop: 12 }}><Pill kind="red">{err}</Pill></div>}

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 18 }}>
        <button className="hb" onClick={onClose}>{t('Abbrechen')}</button>
        <button className="ab" disabled={!ready || busy} onClick={save}>
          {busy ? t('Bitte warten …') : t('Anlegen')}
        </button>
      </div>
    </Modal>
  )
}

// ---------- Komponenten-Drawer (anlegen/bearbeiten) ----------
function ComponentDrawer({ comp, onClose }) {
  const t = useT()
  const { call, sel } = useStore()
  const blank = {
    kind: 'software_oss', name: '', version: '', supplier: '', purl: '', cpe: '', license: '',
    is_core_function: 0, dd_status: 'offen', dd_note: '',
  }
  // Bestehende Komponente speichert automatisch; eine neue braucht den Anlegen-Schritt.
  const [auto, setAuto, saved] = useAutoSave(comp ? '/api/components/' + comp.id : '', comp ? { ...comp } : blank, call)
  const [draft, setDraft] = useState(blank)
  const f = comp ? auto : draft
  const set = comp
    ? (k, v, o) => setAuto(k, v, o)
    : (k, v) => setDraft(x => ({ ...x, [k]: v }))
  const isHw = f.kind === 'hardware'
  const isOwn = f.kind === 'software_eigen'
  const create = async () => { await call('POST', '/api/versions/' + sel.vid + '/components', draft); onClose() }
  const del = async () => { if (confirm(t('Komponente löschen? Zugehörige Funde werden mit entfernt.'))) { await call('DELETE', '/api/components/' + comp.id); onClose() } }
  return (
    <Drawer onClose={onClose}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span className="dtitle" style={{ flex: 1 }}>{comp ? f.name || 'Komponente' : 'Komponente hinzufügen'}</span>
        {comp?.source === 'sbom_import' && <Pill kind="blue">{t('aus SBOM-Import')}</Pill>}
        <CloseX onClick={onClose} />
      </div>
      <div className="dsub">{t('Hardware und Software stehen im Inventar; in die SBOM gehört nur Software.')}</div>

      <div className="fieldlab">{t('Typ')}</div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {KINDS.map(([k, label]) => (
          <span key={k} className={'tabpill' + (f.kind === k ? ' active' : '')} onClick={() => set('kind', k)}>{t(label)}</span>
        ))}
      </div>

      <div style={{ display: 'flex', gap: 12 }}>
        <div style={{ flex: 2 }}><div className="fieldlab">{t('Name')}</div><input className="field" value={f.name} onChange={e => set('name', e.target.value, { debounce: true })} /></div>
        <div style={{ flex: 1 }}><div className="fieldlab">{t('Version')}</div><input className="field" value={f.version} onChange={e => set('version', e.target.value, { debounce: true })} /></div>
      </div>
      <div className="fieldlab">{t('Lieferant')} <span className="fund">{isOwn ? t('— entfällt bei Eigenentwicklung') : t('(Verknüpfung ins Lieferantenmanagement)')}</span></div>
      <input className="field" value={f.supplier} onChange={e => set('supplier', e.target.value, { debounce: true })} disabled={isOwn} />
      {!isHw && <>
        <div className="fieldlab">purl <span className="fund">{t('(Package URL — Schlüssel für den OSV-Abgleich)')}</span></div>
        <input className="field" value={f.purl} onChange={e => set('purl', e.target.value, { debounce: true })} placeholder="pkg:npm/lodash@4.17.21" />
      </>}
      <div className="fieldlab">cpe <span className="fund">{t('(für Hardware/Firmware — NVD-Identifikation, optional)')}</span></div>
      <input className="field" value={f.cpe} onChange={e => set('cpe', e.target.value, { debounce: true })} placeholder="cpe:2.3:h:…" />
      <div className="fieldlab">{t('Lizenz')} <span className="fund">{t('(nur mitgespeichert — keine Lizenzanalyse, D-006)')}</span></div>
      <input className="field" value={f.license} onChange={e => set('license', e.target.value, { debounce: true })} />

      <div className="fieldlab">{t('Kernfunktion des Produkts?')}</div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Toggle on={!!f.is_core_function} onChange={v => set('is_core_function', v ? 1 : 0)} />
        <span className="muted">{f.is_core_function ? 'Ja — Unterstützungszeitraum des Lieferanten berücksichtigen' : 'Nein'}</span>
      </div>

      {!isOwn && <>
        <div className="fieldlab">{t('Sorgfaltsnachweis')}</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
          <Toggle on={f.dd_status === 'geprueft'} onChange={v => set('dd_status', v ? 'geprueft' : 'offen')} />
          {f.dd_status === 'geprueft' ? <Pill kind="green">{t('Geprüft')}</Pill> : <Pill kind="amber">{t('Offen')}</Pill>}
        </div>
        <textarea className="field" rows={3} value={f.dd_note} onChange={e => set('dd_note', e.target.value, { debounce: true })}
          placeholder={t('z. B. Lieferanten-Baseline 2026 (Security-Kontakt, Patch-Zusagen) im Lieferantenmanagement abgelegt')} />
      </>}

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 20 }}>
        {comp && <button className="hb" style={{ color: '#DC2626' }} onClick={del}>{t('Löschen')}</button>}
        <span style={{ flex: 1 }} />
        {comp ? <SavedHint on={saved} />
              : <button className="ab" disabled={!draft.name.trim()} onClick={create}>{t('Anlegen')}</button>}
      </div>
    </Drawer>
  )
}

// ---------- Funde: Triage-Drawer ----------
function FindingDrawer({ finding, onClose }) {
  const { t, lang } = useI18n()
  const T = (de, en) => (lang === 'en' ? en : de)
  const { call, product, version } = useStore()
  const [f, set, saved] = useAutoSave('/api/findings/' + finding.id, { ...finding }, call)
  const advisory = () => {
    // Advisory-Entwurf (Anhang I Teil II Nr. 4) — Entwurf herunterladen; veröffentlichen muss der Hersteller.
    const md = [
      T('# Sicherheitshinweis (ENTWURF) — ', '# Security advisory (DRAFT) — ') + product.name + ' ' + version.version,
      '',
      T('> Entwurf nach Anhang I Teil II Nr. 4 CRA — Veröffentlichung erst nach Bereitstellung der Sicherheitsaktualisierung.',
        '> Draft under Annex I Part II No. 4 CRA — publish only once the security update is available.'),
      '',
      T('## Betroffenes Produkt', '## Affected product'),
      T('- Produkt: ', '- Product: ') + product.name + (product.hersteller ? ' (' + product.hersteller + ')' : ''),
      T('- Betroffene Version(en): ', '- Affected version(s): ') + version.version,
      T('- Betroffene Komponente: ', '- Affected component: ') + (f.component_name || '—') + (f.component_purl ? ' (`' + f.component_purl + '`)' : ''),
      '',
      T('## Schwachstelle', '## Vulnerability'),
      T('- Kennung: ', '- Identifier: ') + f.vuln_id + (f.aliases ? ' (' + f.aliases + ')' : ''),
      T('- Schwere: ', '- Severity: ') + f.severity + (f.score != null ? ' (CVSS ' + Number(f.score).toFixed(1) + ')' : ''),
      T('- Beschreibung: ', '- Description: ') + (f.summary || '—'),
      '',
      T('## Auswirkungen und Abhilfe', '## Impact and remedy'),
      T('- Status: behoben (VEX: fixed)', '- Status: fixed (VEX: fixed)'),
      T('- Abhilfe: ', '- Remedy: ') + (f.fix_version ? f.component_name + ' ' + f.fix_version
          : f.fixed_versions ? T('Version ', 'version ') + f.fixed_versions
            : T('[Sicherheitsaktualisierung eintragen]', '[enter the security update]')),
      T('- Maßnahmen für Nutzer: [eindeutige, verständliche Anleitung ergänzen]',
        '- Action for users: [add clear, understandable instructions]'),
      '',
      ...(f.refs_json ? ['', T('## Quellen', '## Sources'), ...(() => { try { return JSON.parse(f.refs_json).map(r => '- ' + r.label + ': ' + r.url) } catch { return [] } })()] : []),
      '',
      T('_Entwurf erzeugt am ', '_Draft generated on ') + new Date().toLocaleDateString(lang === 'en' ? 'en-GB' : 'de-DE')
        + T('. Vor Veröffentlichung fachlich prüfen und vervollständigen._', '. Review and complete before publishing._'),
    ].join('\n')
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([md], { type: 'text/markdown' }))
    a.download = (lang === 'en' ? 'advisory-draft-' : 'advisory-entwurf-') + f.vuln_id + '.md'
    a.click()
    URL.revokeObjectURL(a.href)
  }
  return (
    <Drawer onClose={onClose}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span className="dtitle" style={{ flex: 1 }}>{f.vuln_id} — {f.component_name || '—'}</span>
        {!!f.actively_exploited && <Pill kind="red" >{t('Aktiv ausgenutzt')}</Pill>}
        <CloseX onClick={onClose} />
      </div>
      <div style={{ marginTop: 6, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <SevPill f={f} />
        {f.aliases && f.aliases.split(', ').filter(a => a.startsWith('CVE-')).map(a => <Pill key={a} kind="blue">{a}</Pill>)}
        {f.cwe_ids && f.cwe_ids.split(', ').slice(0, 4).map(c => <Pill key={c} kind="neutral" title={t('Schwachstellenklasse')}>{c}</Pill>)}
      </div>
      <div className="dsub">{f.component_purl ? f.component_purl + ' · ' : ''}{f.summary}</div>
      <div className="dsub">
        {t('Eingang:')} {t(intakeLabel(f.intake_channel))}
        {f.published ? ' · ' + t('Advisory veröffentlicht:') + ' ' + fmtD(f.published) : ''}
      </div>

      {/* Behebung und Quellen — automatisch beim Abgleich aus OSV übernommen */}
      <div className="fieldlab">{t('Behebung')} <span className="fund">(aus dem Advisory, {'affected[].ranges'})</span></div>
      {f.fixed_versions
        ? (f.fixed_versions.startsWith('kein Fix')
            ? <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Pill kind="red">{t('Keine feste Version')}</Pill>
                <span className="muted">{f.fixed_versions}</span></div>
            : <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span className="muted">{t('Behoben in:')}</span>
                {f.fixed_versions.split(', ').map(v => (
                  <button key={v} className={'hb sm' + (f.fix_version === v ? ' active' : '')}
                    style={f.fix_version === v ? { borderColor: '#1298ff', color: '#1298ff' } : {}}
                    title={t('Als Zielversion uebernehmen und Entscheidung auf Sofort beheben setzen')}
                    onClick={() => setF(x => ({ ...x, fix_version: v, decision: x.decision || 'fix_now' }))}>
                    {f.component_name} {v}
                  </button>
                ))}
                {f.fix_version && <Pill kind="green">Zielversion: {f.fix_version}</Pill>}
              </div>)
        : <span className="muted">{t('Keine Versionsangabe im Advisory.')}</span>}

      {f.refs_json && (() => {
        let refs = []
        try { refs = JSON.parse(f.refs_json) } catch { /* nichts anzeigen */ }
        if (!refs.length) return null
        return (
          <>
            <div className="fieldlab">{t('Quellen')} <span className="fund">{t('(Advisory, Fix-Commit, Projektseite)')}</span></div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {refs.map((r, i) => (
                <a key={i} className="chip blue" href={r.url} target="_blank" rel="noreferrer noopener"
                   style={{ textDecoration: 'none' }} title={r.url}>
                  {r.label} ↗
                </a>
              ))}
            </div>
          </>
        )
      })()}

      <div className="fieldlab">{t('Betroffenheit (VEX-Status)')}</div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {VEX_STATI.map(([v, label]) => (
          <span key={v} className={'tabpill' + (f.vex_status === v ? ' active' : '')} onClick={() => set('vex_status', v)}>{t(label)}</span>
        ))}
      </div>
      <div className="fieldlab">{t('Begründung')}</div>
      <textarea className="field" rows={2} value={f.vex_justification}
        placeholder={f.vex_status === 'not_affected' ? 'z. B. die verwundbare Funktion wird nicht aufgerufen (code_not_reachable)' : 'Einschätzung, Analyse-Stand'}
        onChange={e => set('vex_justification', e.target.value, { debounce: true })} />

      <div className="fieldlab">{t('Entscheidung')}</div>
      <div style={{ display: 'flex', gap: 12 }}>
        <select className="field" style={{ flex: 1 }} value={f.decision} onChange={e => set('decision', e.target.value)}>
          {DECISIONS.map(([v, label]) => <option key={v} value={v}>{t(label)}</option>)}
        </select>
        {f.decision === 'accept' && (
          <input type="date" className="field" style={{ flex: 1 }} value={f.accept_until} onChange={e => set('accept_until', e.target.value)} title={t('Befristung (Pflicht bei accept)')} />
        )}
      </div>
      {(f.decision === 'accept' || f.decision === 'defer') && (
        <textarea className="field" rows={2} style={{ marginTop: 8 }} value={f.decision_rationale}
          placeholder={t('Begründung (Pflicht bei accept/defer)')} onChange={e => set('decision_rationale', e.target.value, { debounce: true })} />
      )}

      <div style={{ display: 'flex', gap: 12 }}>
        <div style={{ flex: 1 }}>
          <div className="fieldlab">{t('Verantwortlich')}</div>
          <input className="field" value={f.owner} onChange={e => set('owner', e.target.value, { debounce: true })} placeholder={t('Name')} />
        </div>
        <div style={{ flex: 1 }}>
          <div className="fieldlab">{t('Kenntnis am')}</div>
          <input type="datetime-local" className="field" value={toLocal(f.became_known_at)} onChange={e => set('became_known_at', fromLocal(e.target.value))} />
        </div>
      </div>

      <div className="fieldlab">{t('Aktiv ausgenutzt?')}</div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Toggle on={!!f.actively_exploited} onChange={v => set('actively_exploited', v ? 1 : 0)} />
        <span className="muted">{f.actively_exploited ? t('Ja — verlässliche Nachweise erforderlich') : t('Nein / keine Nachweise')}</span>
      </div>
      {!!f.actively_exploited && <>
        <textarea className="field" rows={2} style={{ marginTop: 8 }} value={f.exploit_evidence}
          placeholder={t('Nachweis: worauf stützt sich die Einstufung?')} onChange={e => set('exploit_evidence', e.target.value, { debounce: true })} />
      </>}

      <div className="fieldlab">{t('Upstream-Meldung')}</div>
      <div style={{ display: 'flex', gap: 12 }}>
        <input className="field" style={{ flex: 2 }} value={f.upstream_reported_to} placeholder={t('Gemeldet an (Hersteller/Wartende)')} onChange={e => set('upstream_reported_to', e.target.value, { debounce: true })} />
        <input type="date" className="field" style={{ flex: 1 }} value={f.upstream_reported_at} onChange={e => set('upstream_reported_at', e.target.value)} />
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 8 }}>
        <Toggle on={!!f.upstream_fix_shared} onChange={v => set('upstream_fix_shared', v ? 1 : 0)} />
        <span className="muted">{t('Fix-Code oder Unterlagen geteilt')}</span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 20 }}>
        {f.vex_status === 'fixed' && <button className="hb" onClick={advisory}>{t('Advisory-Entwurf ↓')}</button>}
        <span style={{ flex: 1 }} />
        <SavedHint on={saved} />
      </div>
    </Drawer>
  )
}

// ---------- SBOM-Drawer ----------
function SbomDrawer({ sbom, onClose }) {
  const t = useT()
  const { call } = useStore()
  const patch = (body) => call('PATCH', '/api/sboms/' + sbom.id, body)
  const del = async () => { if (confirm(t('SBOM-Stand löschen? (Komponenten bleiben im Inventar)'))) { await call('DELETE', '/api/sboms/' + sbom.id); onClose() } }
  return (
    <Drawer onClose={onClose}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span className="dtitle" style={{ flex: 1 }}>{sbom.file_name}</span>
        <Pill kind="blue">{sbom.format}</Pill>
        <CloseX onClick={onClose} />
      </div>
      <div className="dsub">{sbom.component_count} {t('Komponenten · erstellt')} {sbom.generated_at ? fmtDT(sbom.generated_at) : '—'} {t('· importiert')} {fmtDT(sbom.imported_at)} · {(sbom.bytes / 1024).toFixed(1)} KB</div>

      <div className="fieldlab">{t('Tiefe')}</div>
      <div style={{ display: 'flex', gap: 8 }}>
        <span className={'tabpill' + (sbom.depth === 'top_level' ? ' active' : '')} onClick={() => patch({ depth: 'top_level' })}>{t('Oberste Abhängigkeiten')}</span>
        <span className={'tabpill' + (sbom.depth === 'full' ? ' active' : '')} onClick={() => patch({ depth: 'full' })}>{t('Vollständig aufgelöst')}</span>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 20 }}>
        <button className="hb" style={{ color: '#DC2626', marginRight: 'auto' }} onClick={del}>{t('Löschen')}</button>
        <a className="ab" style={{ textDecoration: 'none' }} href={'/api/sboms/' + sbom.id + '/download'}>{t('Herunterladen')}</a>
      </div>
    </Drawer>
  )
}

// ---------- Manuelle Fund-Erfassung (D-020): Eingang kommt per Mail/Advisory, hier wird nur dokumentiert ----------
// ---------- Änderungen zur Vorversion (D-019): automatisch berechnet, nichts wird gepflegt ----------
function DiffTab({ versionLabel }) {
  const t = useT()
  const { sel } = useStore()
  const [diff, setDiff] = useState(null)
  const [err, setErr] = useState(null)
  React.useEffect(() => {
    setDiff(null); setErr(null)
    fetch('/api/versions/' + sel.vid + '/diff')
      .then(r => r.json())
      .then(d => d.error ? setErr(d.error) : setDiff(d))
      .catch(e => setErr(String(e.message || e)))
  }, [sel.vid])

  if (err) return <div className="hintbox" style={{ margin: 16 }}>{err}</div>
  if (!diff) return <div className="hintbox" style={{ margin: 16 }}>{t('Vergleich wird berechnet …')}</div>
  if (!diff.base) return (
    <div className="hintbox" style={{ margin: 16 }}>
      <b style={{ color: '#0B1928' }}>{t('Erste Version')}</b> — es gibt keine Vorversion zum Vergleichen.
      Sobald eine weitere Version existiert, erscheint hier automatisch der Unterschied der Komponenteninventare.
    </div>
  )
  const kindLabel = k => kindMeta(k)[1]
  const Section = ({ title, kind, rows, render }) => (
    <React.Fragment>
      <tr><td colSpan={4} style={{ background: 'transparent', border: 'none', padding: '14px 6px 2px', fontSize: 13, fontWeight: 600, color: '#808E9C' }}>
        {title} <Pill kind={kind}>{rows.length}</Pill>
      </td></tr>
      {rows.map((c, i) => render(c, i))}
      {!rows.length && <tr><td colSpan={4} style={{ color: '#B6C1CD', padding: '8px 14px' }}>{t('keine')}</td></tr>}
    </React.Fragment>
  )
  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px 0', flexWrap: 'wrap' }}>
        <Pill kind="blue">{t('Vergleich:')} {diff.base.version} → {versionLabel}</Pill>
        <span className="muted">{diff.added.length} {t('neu ·')} {diff.removed.length} {t('entfernt ·')} {diff.changed.length} {t('Version geändert ·')} {diff.unchanged} {t('unverändert — automatisch aus den Inventaren berechnet')}</span>
      </div>
      <div className="tblwrap sc">
        <table className="tbl">
          <thead><tr><th style={{ width: '34%' }}>{t('Komponente')}</th><th>{t('Typ')}</th><th>{t('Version')}</th><th>{t('Lieferant')}</th></tr></thead>
          <tbody>
            <Section title={t('Neu hinzugekommen')} kind="green" rows={diff.added}
              render={(c, i) => (
                <tr key={'a' + i}>
                  <td><span style={{ fontWeight: 500, color: '#0B1928' }}>{c.name}</span>
                    <span style={{ display: 'block', fontSize: 11.5, color: '#8B95A3' }}>{c.purl || '—'}</span></td>
                  <td>{t(kindLabel(c.kind))}</td>
                  <td><Pill kind="green">{c.version || '—'}</Pill></td>
                  <td>{c.supplier || '—'}</td>
                </tr>
              )} />
            <Section title={t('Version geändert')} kind="amber" rows={diff.changed}
              render={(c, i) => (
                <tr key={'c' + i}>
                  <td><span style={{ fontWeight: 500, color: '#0B1928' }}>{c.name}</span>
                    <span style={{ display: 'block', fontSize: 11.5, color: '#8B95A3' }}>{c.purl || '—'}</span></td>
                  <td>{t(kindLabel(c.kind))}</td>
                  <td><Pill kind="amber">{c.from} → {c.to}</Pill></td>
                  <td>{c.supplier || '—'}</td>
                </tr>
              )} />
            <Section title={t('Entfernt')} kind="red" rows={diff.removed}
              render={(c, i) => (
                <tr key={'r' + i}>
                  <td><span style={{ fontWeight: 500, color: '#0B1928' }}>{c.name}</span>
                    <span style={{ display: 'block', fontSize: 11.5, color: '#8B95A3' }}>{c.purl || '—'}</span></td>
                  <td>{t(kindLabel(c.kind))}</td>
                  <td><Pill kind="red">{c.version || '—'}</Pill></td>
                  <td>{c.supplier || '—'}</td>
                </tr>
              )} />
          </tbody>
        </table>
      </div>
    </>
  )
}

// ---------- Filter als eigener Bereich ----------
function FilterRow({ label, children }) {
  return (
    <div style={{ marginTop: 16 }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: '#808E9C', textTransform: 'uppercase', letterSpacing: '.04em', marginBottom: 8 }}>{label}</div>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>{children}</div>
    </div>
  )
}

function Chip({ active, count, disabled, dot, onClick, children }) {
  return (
    <span className={'sevchip' + (active ? ' active' : '') + (disabled ? ' off' : '')}
      onClick={disabled ? undefined : onClick}>
      {dot && <span className="dot" style={{ background: dot }} />}
      {children}{count !== undefined && <b>{count}</b>}
    </span>
  )
}

function FilterDrawer({ tab, f, set, counts, onClose }) {
  const t = useT()
  const reset = () => set({ kind: null, compSev: null, compDd: false, compDirect: null, sev: null, vex: null, fix: null })
  const activeCount = Object.values(f).filter(v => v !== null && v !== false).length
  return (
    <Drawer onClose={onClose}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span className="dtitle" style={{ flex: 1 }}>{t('Filter')}</span>
        {activeCount > 0 && <span className="link" style={{ fontSize: 13 }} onClick={reset}>{t('Zurücksetzen')}</span>}
        <CloseX onClick={onClose} />
      </div>

      {tab === 'komponenten' && <>
        <FilterRow label={t('Typ')}>
          <Chip active={!f.kind} onClick={() => set({ kind: null })}>{t('Alle')} </Chip>
          {KINDS.map(([k, label]) => (
            <Chip key={k} active={f.kind === k} count={counts.kind[k]} disabled={!counts.kind[k]}
              onClick={() => set({ kind: f.kind === k ? null : k })}>{t(label)} </Chip>
          ))}
        </FilterRow>
        <FilterRow label={t('Herkunft')}>
          <Chip active={!f.compDirect} onClick={() => set({ compDirect: null })}>{t('Alle')} </Chip>
          <Chip active={f.compDirect === 'direct'} count={counts.direct} disabled={!counts.direct}
            onClick={() => set({ compDirect: f.compDirect === 'direct' ? null : 'direct' })}>{t('Direkt eingebunden')} </Chip>
          <Chip active={f.compDirect === 'transitive'} count={counts.transitive} disabled={!counts.transitive}
            onClick={() => set({ compDirect: f.compDirect === 'transitive' ? null : 'transitive' })}>{t('Transitiv')} </Chip>
        </FilterRow>
        <FilterRow label={t('Schwachstellen an der Komponente')}>
          <Chip active={!f.compSev} onClick={() => set({ compSev: null })}>{t('Alle')} </Chip>
          {SEVS.filter(([k]) => k !== '—').map(([k, label, col]) => (
            <Chip key={k} active={f.compSev === k} count={counts.compSev[k]} disabled={!counts.compSev[k]} dot={col}
              onClick={() => set({ compSev: f.compSev === k ? null : k })}>{t(label)} </Chip>
          ))}
          <Chip active={f.compSev === 'none'} count={counts.compSev.none}
            onClick={() => set({ compSev: f.compSev === 'none' ? null : 'none' })}>{t('Ohne Funde')} </Chip>
        </FilterRow>
        <FilterRow label={t('Sorgfalt')}>
          <Chip active={!f.compDd} onClick={() => set({ compDd: false })}>{t('Alle')} </Chip>
          <Chip active={f.compDd} count={counts.ddOpen} disabled={!counts.ddOpen}
            onClick={() => set({ compDd: !f.compDd })}>{t('Sorgfalt offen')} </Chip>
        </FilterRow>
      </>}

      {tab === 'funde' && <>
        {selected.size > 0 && (
          <BulkBar count={selected.size} busy={bulkBusy} onClear={() => setSelected(new Set())}
            onApply={async (vex, just) => {
              setBulkBusy(true)
              try {
                await call('PATCH', '/api/versions/' + sel.vid + '/findings/bulk',
                  { ids: [...selected], vex_status: vex, vex_justification: just })
                setSelected(new Set())
              } finally { setBulkBusy(false) }
            }} />
        )}
        <FilterRow label={t('Schwere')}>
          <Chip active={!f.sev} onClick={() => set({ sev: null })}>{t('Alle')} </Chip>
          {SEVS.map(([k, label, col]) => (
            <Chip key={k} active={f.sev === k} count={counts.sev[k]} disabled={!counts.sev[k]} dot={col}
              onClick={() => set({ sev: f.sev === k ? null : k })}>{t(label)} </Chip>
          ))}
        </FilterRow>
        <FilterRow label={t('Betroffenheit')}>
          <Chip active={!f.vex} onClick={() => set({ vex: null })}>{t('Alle')} </Chip>
          {VEX_STATI.map(([v, label]) => (
            <Chip key={v} active={f.vex === v} count={counts.vex[v]} disabled={!counts.vex[v]}
              onClick={() => set({ vex: f.vex === v ? null : v })}>{t(label)} </Chip>
          ))}
        </FilterRow>
        <FilterRow label={t('Behebung')}>
          <Chip active={!f.fix} onClick={() => set({ fix: null })}>{t('Alle')} </Chip>
          <Chip active={f.fix === 'has'} count={counts.fixHas} disabled={!counts.fixHas}
            onClick={() => set({ fix: f.fix === 'has' ? null : 'has' })}>{t('Fix verfügbar')} </Chip>
          <Chip active={f.fix === 'none'} count={counts.fixNone} disabled={!counts.fixNone}
            onClick={() => set({ fix: f.fix === 'none' ? null : 'none' })}>{t('Kein Fix')} </Chip>
        </FilterRow>
      </>}
    </Drawer>
  )
}

// ---------- Massen-Bewertung der Betroffenheit ----------
function BulkBar({ count, onApply, onClear, busy }) {
  const t = useT()
  const [just, setJust] = useState('')
  return (
    <div className="bulkbar">
      <b style={{ color: '#0B1928' }}>{count}</b>
      <span>{t('Funde ausgewählt')}</span>
      <input className="field" style={{ flex: 1, minWidth: 180, height: 32 }} value={just}
        onChange={e => setJust(e.target.value)} placeholder={t('Begründung (gilt für alle ausgewählten)')} />
      {VEX_STATI.filter(([v]) => v !== 'under_investigation').map(([v, label]) => (
        <button key={v} className="hb sm" disabled={busy} onClick={() => onApply(v, just)}>{t(label)}</button>
      ))}
      <span className="link" style={{ fontSize: 12.5 }} onClick={onClear}>{t('Auswahl aufheben')}</span>
    </div>
  )
}

// ---------- Scan-Historie ----------
function ScanHistoryModal({ scans, onClose }) {
  const t = useT()
  return (
    <Modal onClose={onClose} width={620}>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <span className="dtitle" style={{ flex: 1 }}>{t('Scan-Historie')}</span><CloseX onClick={onClose} />
      </div>
      <div className="dsub">{t('Jeder Abgleich wird protokolliert — wann er lief, wie viele Komponenten geprüft wurden und was dabei herauskam.')}</div>
      {scans.length ? (
        <table className="tbl" style={{ marginTop: 12 }}>
          <thead><tr><th>{t('Zeitpunkt')}</th><th>{t('Quelle')}</th><th>{t('Geprüft')}</th><th>{t('Neu')}</th><th>{t('Aktualisiert')}</th></tr></thead>
          <tbody>
            {scans.map(sc => (
              <tr key={sc.id}>
                <td>{fmtDT(sc.ran_at)}</td>
                <td>{sc.source}</td>
                <td>{sc.components_scanned}</td>
                <td>{sc.findings_new ? <Pill kind="amber">+{sc.findings_new}</Pill> : <span className="muted">0</span>}</td>
                <td><span className="muted">{sc.findings_updated}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : <div className="muted" style={{ marginTop: 14 }}>{t('Noch kein Abgleich für diese Version')}</div>}
    </Modal>
  )
}

// ---------- Versionsauswahl: umschalten und einzelne Versionen loeschen ----------
function VersionPicker() {
  const t = useT()
  const { product, version, setSel, call } = useStore()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  React.useEffect(() => {
    if (!open) return
    const away = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', away)
    return () => document.removeEventListener('mousedown', away)
  }, [open])

  const versions = product?.versions || []
  const del = async (v, e) => {
    e.stopPropagation()
    if (!confirm(t('Version löschen?') + ' ' + v.version)) return
    await call('DELETE', '/api/versions/' + v.id, undefined, { reloadProducts: true })
    if (v.id === version?.id) {
      const rest = versions.filter(x => x.id !== v.id)
      setSel({ pid: product.id, vid: rest[rest.length - 1]?.id })
    }
    setOpen(false)
  }

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button className="hb" onClick={() => setOpen(o => !o)} style={{ height: 36 }}>
        {t('Version:')} <b style={{ fontWeight: 600 }}>{version?.version || '—'}</b>
        <span style={{ color: '#B6C1CD', fontSize: 11 }}>▾</span>
      </button>
      {open && (
        <div className="popmenu">
          {versions.map(v => (
            <div key={v.id} className={'popitem' + (v.id === version?.id ? ' active' : '')}
              onClick={() => { setSel({ pid: product.id, vid: v.id }); setOpen(false) }}>
              <span style={{ flex: 1 }}>{v.version}</span>
              {versions.length > 1 && (
                <span className="popdel" title={t('Version löschen?')} onClick={e => del(v, e)}>
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none">
                    <path d="M6 7h12M9 7V5.5h6V7M8 7l.7 12h6.6L16 7" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ---------- Hauptseite ----------
export default function SbomTool() {
  const t = useT()
  const { products, product, version, sel, setSel, data, call, busy, notice, setNotice, reloadProducts } = useStore()
  const [q, setQ] = useState('')
  const [tab, setTab] = useState('komponenten')
  const EMPTY_FILTER = { kind: null, compSev: null, compDd: false, compDirect: null, sev: null, vex: null, fix: null }
  const [filter, setFilterRaw] = useState(EMPTY_FILTER)
  const setFilter = patchObj => setFilterRaw(f => ({ ...f, ...patchObj }))
  const activeFilters = Object.values(filter).filter(v => v !== null && v !== false).length
  const [selected, setSelected] = useState(() => new Set())
  const [bulkBusy, setBulkBusy] = useState(false)
  const [modal, setModal] = useState(null)        // 'produkt' | 'version'
  const [compOpen, setCompOpen] = useState(null)  // component | 'neu'
  const [findOpen, setFindOpen] = useState(null)
  const [sbomOpen, setSbomOpen] = useState(null)
  const [scanBanner, setScanBanner] = useState(null)
  const fileRef = useRef(null)

  const components = data?.components || []
  const sboms = data?.sboms || []
  const findings = data?.findings || []
  const lastScan = data?.scans?.[0]

  // ---------- SBOM-Import: Datei clientseitig lesen (CycloneDX/SPDX-JSON), Server speichert + übernimmt Komponenten
  const importSbom = (file) => {
    const reader = new FileReader()
    reader.onload = async () => {
      try {
        const jx = JSON.parse(reader.result)
        const raw = jx.components || jx.packages || []
        // Direkte Abhaengigkeiten aus dem Abhaengigkeitsgraph (CycloneDX) bzw. den
        // SPDX-Relationships bestimmen — nur fuer sie ist die Sorgfaltspruefung sinnvoll.
        const rootRef = jx.metadata?.component?.['bom-ref'] || jx.metadata?.component?.purl
        const directRefs = new Set(
          (jx.dependencies || []).filter(d => d.ref === rootRef).flatMap(d => d.dependsOn || [])
        )
        const spdxDirect = new Set(
          (jx.relationships || []).filter(r => r.relationshipType === 'DEPENDS_ON'
            && r.spdxElementId === (jx.documentDescribes?.[0] || 'SPDXRef-DOCUMENT'))
            .map(r => r.relatedSpdxElement)
        )
        const list = raw.map(c => ({
          name: c.name || '?', version: c.version || c.versionInfo || '',
          purl: c.purl || (c.externalRefs || []).find(r => r.referenceType === 'purl')?.referenceLocator || '',
          supplier: c.supplier?.name || c.publisher || (typeof c.supplier === 'string' ? c.supplier.replace(/^Organization: /, '') : '') || '',
          license: (c.licenses && (c.licenses[0]?.license?.id || c.licenses[0]?.expression)) || c.licenseConcluded || '',
          is_direct: directRefs.has(c['bom-ref']) || spdxDirect.has(c.SPDXID) ? 1 : 0,
        }))
        if (!list.length) { setNotice({ err: true, msg: t('Keine Komponenten gefunden — CycloneDX (components[]) oder SPDX (packages[]) erwartet.') }); return }
        const fmt = jx.bomFormat ? 'CycloneDX ' + (jx.specVersion || '') : jx.spdxVersion ? 'SPDX ' + jx.spdxVersion : 'SBOM'
        const res = await call('POST', '/api/versions/' + sel.vid + '/sboms', {
          fileName: file.name, format: fmt, depth: 'top_level',
          generatedAt: jx.metadata?.timestamp || jx.creationInfo?.created || '',
          components: list, content: reader.result,
        })
        const noPurl = list.filter(c => !c.purl).length
        setNotice({ err: false, msg: fmt + ' · ' + list.length + ' ' + t('Komponenten importiert') + ' (' + res.imported.added + ' ' + t('neu,') + ' ' + res.imported.updated + ' ' + t('aktualisiert), Original archiviert') + (noPurl ? ' · ' + noPurl + ' ' + t('ohne purl') : '') })
        setTab('komponenten')
      } catch (e) { if (!notice) setNotice({ err: true, msg: t('Datei konnte nicht gelesen werden:') + ' ' + e.message }) }
    }
    reader.readAsText(file)
  }

  const runScan = async () => {
    setScanBanner(null)
    try {
      const res = await call('POST', '/api/versions/' + sel.vid + '/scan')
      setScanBanner(res.scan)
      setTab('funde')
    } catch { /* Fehlermeldung kommt über notice */ }
  }

  const delVersion = async () => {
    if (!confirm(t('Version löschen') + ': ' + version.version + '?')) return
    await call('DELETE', '/api/versions/' + version.id, undefined, { reloadProducts: true })
    setSel({ pid: product.id })
  }
  const delProduct = async () => {
    if (!confirm(t('Produkt löschen') + ': ' + product.name + '?')) return
    await call('DELETE', '/api/products/' + product.id, undefined, { reloadProducts: true })
    setSel({})
  }

  // ---------- Abgeleitete Daten ----------
  const findingsByComp = {}
  findings.forEach(f => { (findingsByComp[f.component_id] = findingsByComp[f.component_id] || []).push(f) })
  const sevCounts = { KRITISCH: 0, HOCH: 0, MITTEL: 0, NIEDRIG: 0, '—': 0 }
  findings.forEach(f => { sevCounts[f.severity in sevCounts ? f.severity : '—']++ })
  const hw = components.filter(c => c.kind === 'hardware').length
  const ddPool = components.filter(c => c.kind === 'hardware' || c.kind === 'software_zukauf' || !!c.is_direct)
  const geprueft = ddPool.filter(c => c.dd_status === 'geprueft').length
  const triaged = findings.filter(f => f.vex_status !== 'under_investigation').length

  const compFindings = c => findingsByComp[c.id] || []
  // Sorgfaltspflicht betrifft die Komponenten, die man auswaehlt: Hardware, Zukauf
  // und direkte Abhaengigkeiten. Transitive Pakete waehlt niemand aus.
  const ddRelevant = c => c.kind === 'hardware' || c.kind === 'software_zukauf' || !!c.is_direct
  const ddOpen = c => ddRelevant(c) && c.dd_status !== 'geprueft'
  const hasFix = f => !!f.fixed_versions && !f.fixed_versions.startsWith('kein Fix')
  const filterCounts = {
    kind: Object.fromEntries(KINDS.map(([k]) => [k, components.filter(c => c.kind === k).length])),
    direct: components.filter(c => !!c.is_direct).length,
    transitive: components.filter(c => !c.is_direct).length,
    compSev: {
      ...Object.fromEntries(SEVS.map(([k]) => [k, components.filter(c => (findingsByComp[c.id] || [])
        .some(f => (f.severity in sevCounts ? f.severity : '—') === k)).length])),
      none: components.filter(c => !(findingsByComp[c.id] || []).length).length,
    },
    ddOpen: components.filter(c => (c.kind === 'hardware' || c.kind === 'software_zukauf' || !!c.is_direct) && c.dd_status !== 'geprueft').length,
    sev: sevCounts,
    vex: Object.fromEntries(VEX_STATI.map(([v]) => [v, findings.filter(f => f.vex_status === v).length])),
    fixHas: findings.filter(f => !!f.fixed_versions && !f.fixed_versions.startsWith('kein Fix')).length,
    fixNone: findings.filter(f => !f.fixed_versions || f.fixed_versions.startsWith('kein Fix')).length,
  }
  const compRows = components
    .filter(c => !filter.kind || c.kind === filter.kind)
    .filter(c => !filter.compDirect || (filter.compDirect === 'direct' ? !!c.is_direct : !c.is_direct))
    .filter(c => !filter.compSev || (filter.compSev === 'none' ? compFindings(c).length === 0
      : compFindings(c).some(f => (f.severity in sevCounts ? f.severity : '—') === filter.compSev)))
    .filter(c => !filter.compDd || ddOpen(c))
    .filter(c => !q || (c.name + ' ' + c.purl + ' ' + c.supplier).toLowerCase().includes(q.toLowerCase()))
  const findRows = findings
    .filter(f => !filter.sev || (f.severity in sevCounts ? f.severity : '—') === filter.sev)
    .filter(f => !filter.vex || f.vex_status === filter.vex)
    .filter(f => !filter.fix || (filter.fix === 'has' ? hasFix(f) : !hasFix(f)))
    .filter(f => !q || (f.vuln_id + ' ' + (f.component_name || '') + ' ' + f.summary).toLowerCase().includes(q.toLowerCase()))

  // ---------- Leerer Zustand ----------
  if (!products.length) return (
    <main className="main">
      <TitleBar title={t('SBOM & Komponenten')} />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 12 }}>
        <div style={{ fontSize: 17, fontWeight: 700, color: '#0B1928' }}>{t('Noch kein Produkt angelegt')}</div>
        <div className="muted" style={{ maxWidth: 500, textAlign: 'center', lineHeight: 1.7 }}>{t('Komponenten, SBOMs und Funde hängen an der Produktversion. Lege ein Produkt mit seiner ersten Version an und importiere anschließend die SBOM, die dein Build erzeugt hat — eine Beispiel-SBOM liegt im Ordner')}<code>sboms/</code>.
        </div>
        <div style={{ display: 'flex', gap: 10, marginTop: 6 }}>
          <button className="ab" onClick={() => setModal('produkt')}>{t('Neues Produkt anlegen')}</button>
        </div>
      </div>
      {modal === 'produkt' && <NewProductModal onClose={() => setModal(null)} />}
    </main>
  )

  return (
    <main className="main">
      <TitleBar title={t('SBOM & Komponenten')}>
        <SearchBox value={q} onChange={setQ} />
        {(tab === 'komponenten' || tab === 'funde') && (
          <button className={'hb' + (activeFilters ? ' on' : '')} onClick={() => setModal('filter')}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M4 6h16M7 12h10M10 18h4" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" /></svg>
            {t('Filter')}{activeFilters ? ' (' + activeFilters + ')' : ''}
          </button>
        )}
        <button className="hb" onClick={runScan} disabled={busy || !components.some(c => c.purl && c.kind !== 'hardware')}>
          {busy ? t('Bitte warten …') : t('CVE-Abgleich (OSV)')}
        </button>
        <button className="hb" onClick={() => setModal('scans')} disabled={!version}>{t('Scan-Historie')}</button>
        <button className="ab" onClick={() => fileRef.current?.click()} disabled={!version}>{t('SBOM importieren')}</button>
        <input ref={fileRef} type="file" accept=".json" style={{ display: 'none' }}
          onChange={e => { if (e.target.files[0]) importSbom(e.target.files[0]); e.target.value = '' }} />
      </TitleBar>

      {/* Produkt- und Versionsauswahl — Daten liegen je Version getrennt in der DB */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '14px 16px 0', flexWrap: 'wrap' }}>
        <select className="field" style={{ width: 'auto', height: 36, padding: '0 12px', borderRadius: 10 }}
          value={product?.id || ''} onChange={e => { const p = products.find(x => x.id === e.target.value); setSel({ pid: p.id, vid: p.versions[p.versions.length - 1]?.id }) }}>
          {products.map(p => <option key={p.id} value={p.id}>{t('Produkt:')} {p.name}</option>)}
        </select>
        <VersionPicker />
        <button className="hb sm" onClick={() => setModal('version')}>{t('+ Version')}</button>
        <span style={{ flex: 1 }} />
        {scanBanner && <Pill kind="green">{t('Abgleich abgeschlossen — SBOM-Komponenten:')} {scanBanner.scanned} · {t('neu:')} {scanBanner.added} · {t('aktualisiert:')} {scanBanner.updated}</Pill>}
        {!scanBanner && lastScan && <span className="muted">{t('Letzter Abgleich:')} {fmtDT(lastScan.ran_at)} · {lastScan.source} · {lastScan.components_scanned} {t('Komponenten geprüft')}</span>}
        {!scanBanner && !lastScan && <span className="muted">{t('Noch kein Abgleich für diese Version')}</span>}
      </div>

      {/* Kennzahlen je Version */}
      <div style={{ display: 'flex', gap: 14, padding: '14px 16px 0', flexWrap: 'wrap' }}>
        <div className="kpi">
          <div className="l">{t('Komponenteninventar (HW + SW)')}</div>
          <div className="v">{components.length}</div>
          <div className="s">{hw} {t('Hardware ·')} {components.length - hw} {t('Software (SBOM)')}</div>
        </div>
        <div className="kpi">
          <div className="l">{t('Sorgfalt')}</div>
          <div className="v">{geprueft}<span style={{ fontSize: 13, fontWeight: 500, color: '#8B95A3' }}> / {ddPool.length}</span></div>
          <div className="progress" style={{ marginTop: 7 }}><div style={{ width: (ddPool.length ? geprueft / ddPool.length * 100 : 0) + '%', background: '#27AE60' }} /></div>
          <div className="s">{t('Drittkomponenten geprüft bzw. Eigenentwicklung')}</div>
        </div>
        <div className="kpi">
          <div className="l">{t('Schwachstellen (offene Funde)')}</div>
          <div className="v">{findings.length}</div>
          <div className="sevbar">
            {SEVS.map(([k, , c]) => sevCounts[k] > 0 && <div key={k} style={{ flex: sevCounts[k], background: c }} title={k + ': ' + sevCounts[k]} />)}
            {!findings.length && <div style={{ flex: 1, background: '#EFF3F8' }} />}
          </div>
          <div className="s">{sevCounts.KRITISCH} {t('kritisch ·')} {sevCounts.HOCH} {t('hoch ·')} {sevCounts.MITTEL} {t('mittel ·')} {sevCounts.NIEDRIG} {t('niedrig')}</div>
        </div>
        <div className="kpi">
          <div className="l">{t('Triage (Betroffenheit bewertet)')}</div>
          <div className="v">{triaged}<span style={{ fontSize: 13, fontWeight: 500, color: '#8B95A3' }}> / {findings.length}</span></div>
          <div className="progress" style={{ marginTop: 7 }}><div style={{ width: (findings.length ? triaged / findings.length * 100 : 0) + '%', background: '#1298ff' }} /></div>
          <div className="s">{findings.filter(f => f.actively_exploited).length} {t('aktiv ausgenutzt')}</div>
        </div>
      </div>

      {notice && <div style={{ padding: '10px 16px 0' }}><Pill kind={notice.err ? 'red' : 'green'}>{notice.msg}</Pill> <span className="link" style={{ fontSize: 12 }} onClick={() => setNotice(null)}>{t('ausblenden')}</span></div>}

      <div className="tabrow">
        <span className={'tabpill' + (tab === 'komponenten' ? ' active' : '')} onClick={() => setTab('komponenten')}>{t('Komponenten')} ({compRows.length !== components.length ? compRows.length + ' / ' : ''}{components.length})</span>
        <span className={'tabpill' + (tab === 'sboms' ? ' active' : '')} onClick={() => setTab('sboms')}>{t('SBOMs')} ({sboms.length})</span>
        <span className={'tabpill' + (tab === 'funde' ? ' active' : '')} onClick={() => setTab('funde')}>{t('Funde')} ({findRows.length !== findings.length ? findRows.length + ' / ' : ''}{findings.length})</span>
        <span className={'tabpill' + (tab === 'aenderungen' ? ' active' : '')} onClick={() => setTab('aenderungen')}>{t('Änderungen')}</span>
        <span style={{ flex: 1 }} />
      </div>

      {/* ---------- Reiter 1: Komponenten (Inventar = Obermenge, Abschnitt 1.6) ---------- */}
      {tab === 'komponenten' && <>
        <div className="tblwrap sc">
          <table className="tbl">
            <thead><tr><th style={{ width: '28%' }}>{t('Komponente')}</th><th>{t('Typ')}</th><th>{t('Version')}</th><th>{t('Schwachstellen')}</th><th>{t('Sorgfalt')}</th></tr></thead>
            <tbody>
              {compRows.map(c => {
                const fs = findingsByComp[c.id] || []
                const grp = {}
                fs.forEach(f => { const k = f.severity in sevCounts ? f.severity : '—'; grp[k] = (grp[k] || 0) + 1 })
                const [, kindLabel, kindColor] = kindMeta(c.kind)
                return (
                  <tr key={c.id} className="row" onClick={() => setCompOpen(c)}>
                    <td>
                      <span style={{ display: 'block', fontWeight: 500, color: '#0B1928' }}>{c.name}</span>
                      <span style={{ display: 'block', fontSize: 11.5, color: '#8B95A3', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 320 }}>
                        {c.purl || c.cpe || (c.kind === 'hardware' ? 'Lieferantenweg — keine purl' : 'ohne purl — nicht OSV-abgleichbar')}
                      </span>
                    </td>
                    <td><Pill kind={kindColor}>{t(kindLabel)}</Pill>{!!c.is_direct && <span className="muted" style={{ marginLeft: 6 }}>{t('direkt')}</span>}{!!c.is_core_function && <span className="muted" style={{ marginLeft: 6 }}>{t('Kernfunktion')}</span>}</td>
                    <td>{c.version || '—'}</td>

                    <td>
                      {fs.length === 0
                        ? <span className="muted">{c.kind === 'hardware' ? 'über Advisories' : 'keine bekannt'}</span>
                        : <span style={{ display: 'inline-flex', gap: 5 }}>
                            {SEVS.map(([k, , col]) => grp[k] ? <span key={k} className="sevbadge" style={{ background: col }} title={k}>{grp[k]}</span> : null)}
                          </span>}
                    </td>
                    <td>
                      {!ddRelevant(c)
                        ? <span className="muted">{t('entfällt')}</span>
                        : c.dd_status === 'geprueft' ? <Pill kind="green">{t('Geprüft')}</Pill> : <Pill kind="amber">{t('Offen')}</Pill>}
                    </td>
                  </tr>
                )
              })}
              {!compRows.length && <tr><td colSpan={5} style={{ color: '#B6C1CD', textAlign: 'center', padding: 30 }}>
                {components.length ? 'Keine Komponenten für diesen Filter.' : 'Noch keine Komponenten — SBOM importieren oder Hardware/Software manuell anlegen.'}</td></tr>}
            </tbody>
          </table>
        </div>
      </>}

      {/* ---------- Reiter 2: SBOMs je Version ---------- */}
      {tab === 'sboms' && <>
        <div className="tblwrap sc" style={{ marginTop: 10 }}>
          <table className="tbl">
            <thead><tr><th style={{ width: '30%' }}>{t('Datei')}</th><th>{t('Format')}</th><th>{t('Tiefe')}</th><th>{t('Erstellt')}</th><th>{t('Importiert')}</th><th>{t('Komponenten')}</th></tr></thead>
            <tbody>
              {sboms.map(s => (
                <tr key={s.id} className="row" onClick={() => setSbomOpen(s)}>
                  <td><span style={{ fontWeight: 500, color: '#0B1928' }}>{s.file_name}</span></td>
                  <td><Pill kind="blue">{s.format}</Pill></td>
                  <td>{s.depth === 'top_level' ? 'oberste Abhängigkeiten' : 'vollständig'}</td>
                  <td>{s.generated_at ? fmtD(s.generated_at) : '—'}</td>
                  <td>{fmtD(s.imported_at)}</td>
                  <td>{s.component_count}</td>
                </tr>
              ))}
              {!sboms.length && <tr><td colSpan={6} style={{ color: '#B6C1CD', textAlign: 'center', padding: 30 }}>
                {t('Noch keine SBOM für')} {product?.name} {version?.version} {t('— oben „SBOM importieren" (CycloneDX- oder SPDX-JSON).')}</td></tr>}
            </tbody>
          </table>
        </div>
      </>}

      {/* ---------- Reiter 3: Funde (Schwachstellen auf dem Inventar) ---------- */}
      {tab === 'funde' && <>
        {selected.size > 0 && (
          <BulkBar count={selected.size} busy={bulkBusy} onClear={() => setSelected(new Set())}
            onApply={async (vex, just) => {
              setBulkBusy(true)
              try {
                await call('PATCH', '/api/versions/' + sel.vid + '/findings/bulk',
                  { ids: [...selected], vex_status: vex, vex_justification: just })
                setSelected(new Set())
              } finally { setBulkBusy(false) }
            }} />
        )}
        <div className="tblwrap sc">
          <table className="tbl">
            <thead><tr><th className="selcell"><input type="checkbox" className="selbox" checked={findRows.length > 0 && selected.size === findRows.length} onChange={e => setSelected(e.target.checked ? new Set(findRows.map(x => x.id)) : new Set())} /></th><th>{t('Schwere')}</th><th style={{ width: '28%' }}>{t('Schwachstelle')}</th><th>{t('Komponente')}</th><th>{t('Behebung')}</th><th>{t('Betroffenheit')}</th><th>{t('Entscheidung')}</th><th>{t('Verantwortlich')}</th></tr></thead>
            <tbody>
              {findRows.map(f => (
                <tr key={f.id} className="row" onClick={() => setFindOpen(f)}>
                  <td className="selcell" onClick={e => e.stopPropagation()}>
                    <input type="checkbox" className="selbox" checked={selected.has(f.id)}
                      onChange={e => setSelected(prev => { const n = new Set(prev); e.target.checked ? n.add(f.id) : n.delete(f.id); return n })} />
                  </td>
                  <td><SevPill f={f} />{!!f.actively_exploited && <div style={{ marginTop: 4 }}><Pill kind="red">{t('Aktiv ausgenutzt')}</Pill></div>}</td>
                  <td>
                    <span className="link">{(f.aliases || '').split(', ').find(a => a.startsWith('CVE-')) || f.vuln_id}</span>
                    {(f.aliases || '').includes('CVE-') && <span style={{ display: 'block', fontSize: 11, color: '#B6C1CD' }}>{f.vuln_id}</span>}
                    <span style={{ display: 'block', fontSize: 12, color: '#8B95A3' }}>{(f.summary || '').slice(0, 100)}</span>
                  </td>
                  <td>{f.component_name || '—'}</td>
                  <td>
                    {f.fix_version
                      ? <Pill kind="green">→ {f.fix_version}</Pill>
                      : f.fixed_versions
                        ? (f.fixed_versions.startsWith('kein Fix')
                            ? <Pill kind="red">{t('kein Fix')}</Pill>
                            : <span style={{ fontSize: 12.5, color: '#27AE60' }}>{f.fixed_versions.split(', ').slice(0, 2).join(', ')}</span>)
                        : <span className="muted">—</span>}
                  </td>
                  <td><VexPill v={f.vex_status} /></td>
                  <td>{f.decision ? t(DECISIONS.find(d => d[0] === f.decision)?.[1] || f.decision) : <span className="muted">{t('offen')}</span>}
                    {f.decision === 'accept' && f.accept_until && <span className="muted" style={{ display: 'block' }}>bis {fmtD(f.accept_until)}</span>}</td>
                  <td>{f.owner || <span className="muted">—</span>}</td>
                </tr>
              ))}
              {!findRows.length && <tr><td colSpan={8} style={{ color: '#B6C1CD', textAlign: 'center', padding: 30 }}>
                {findings.length ? 'Keine Funde für diesen Filter.' : 'Noch keine Funde — oben „CVE-Abgleich (OSV)" starten (Software mit purl nötig).'}</td></tr>}
            </tbody>
          </table>
        </div>
      </>}

      {/* ---------- Reiter 4: Änderungen zur Vorversion (automatisch, D-019) ---------- */}
      {tab === 'aenderungen' && <DiffTab versionLabel={version?.version} />}

      {modal === 'produkt' && <NewProductModal onClose={() => setModal(null)} />}
      {modal === 'version' && <NewVersionModal onClose={() => setModal(null)} />}
      {modal === 'filter' && <FilterDrawer tab={tab} f={filter} set={setFilter} counts={filterCounts} onClose={() => setModal(null)} />}
      {modal === 'scans' && <ScanHistoryModal scans={data?.scans || []} onClose={() => setModal(null)} />}
      {compOpen && <ComponentDrawer comp={compOpen === 'neu' ? null : compOpen} onClose={() => setCompOpen(null)} />}
      {findOpen && <FindingDrawer finding={findOpen} onClose={() => setFindOpen(null)} />}
      {sbomOpen && <SbomDrawer sbom={sboms.find(s => s.id === sbomOpen.id) || sbomOpen} onClose={() => setSbomOpen(null)} />}
    </main>
  )
}
