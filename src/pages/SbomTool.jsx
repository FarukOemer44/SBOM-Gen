import React, { useRef, useState } from 'react'
import { useStore } from '../store.jsx'
import { useT, useI18n } from '../i18n.jsx'
import { TitleBar, SearchBox, Pill, Toggle, Drawer, Modal, CloseX, HelpDot, fmtDT, fmtD, fmtM, pshow } from '../ui.jsx'

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
  ['mitigate', 'Risiko mindern'],
  ['accept', 'Risiko akzeptieren (befristet)'],
  ['defer', 'Zurückstellen'],
]

// Eingangskanäle (ENISA 4.13: Intake-Kanäle festhalten; D-020: Mail-Eingang beim Kunden)
const INTAKE = [
  ['osv_scan', 'Automatischer Abgleich'],
  ['cvd_mail', 'Meldung per Mail an die Sicherheitsadresse'],
  ['advisory', 'Lieferanten-Advisory'],
  ['test', 'Eigene Tests'],
  ['csirt', 'Hinweis von außen'],
  ['other', 'Sonstiges'],
]
const intakeLabel = v => (INTAKE.find(x => x[0] === v) || [v, v])[1]

// Art. 23 Abs. 2: Lieferantenangaben zehn Jahre nach dem Bezug vorlegbar halten.
function aufbewahrenBis(bezug) {
  if (!bezug) return null
  const d = new Date(bezug)
  if (isNaN(d)) return null
  d.setFullYear(d.getFullYear() + 10)
  return d
}
// Endet die Unterstuetzung einer Kernkomponente vor der des Produkts, ist das der
// Konflikt, den Art. 13 Abs. 8 im Blick hat.
const monatVor = (a, b) => !!a && !!b && a < b

// Aus der Liste der behobenen Versionen die passende Zielversion waehlen. Advisories
// nennen oft mehrere Wartungszweige (6.10.3, 6.9.7, 6.7.3 …). Fuer ein eingebautes
// 6.7.0 ist 6.7.3 die richtige Antwort — der kleinste Sprung im selben Zweig.
const verTeile = v => String(v || '').split('.').map(x => parseInt(x, 10) || 0)
const verGroesser = (a, b) => {
  const A = verTeile(a), B = verTeile(b)
  for (let k = 0; k < 3; k++) if ((A[k] || 0) !== (B[k] || 0)) return (A[k] || 0) > (B[k] || 0)
  return false
}
function empfohleneFixVersion(installiert, fixListe) {
  const liste = (fixListe || []).map(x => x.trim()).filter(Boolean)
  if (!installiert || !liste.length) return null
  const groesser = liste.filter(f => verGroesser(f, installiert))
  if (!groesser.length) return null
  const i = verTeile(installiert)
  const zweig = groesser.filter(f => verTeile(f)[0] === i[0] && verTeile(f)[1] === i[1])
  const kandidaten = zweig.length ? zweig : groesser
  return kandidaten.sort((a, b) => (verGroesser(a, b) ? 1 : verGroesser(b, a) ? -1 : 0))[0]
}

// SBOM-Datei lesen und in eine Version importieren — genutzt von Produkt- und Versionsdialog.
async function importSbomInto(versionId, file, call, t) {
  const text = await file.text()
  const jx = JSON.parse(text)
  // CycloneDX erlaubt verschachtelte components[]; ohne Aufloesung fehlen Komponenten
  // im Inventar und der Abhaengigkeitsgraph bekommt Luecken.
  const flatten = (lst) => (lst || []).flatMap(c => [c, ...flatten(c.components)])
  const raw = jx.components ? flatten(jx.components) : (jx.packages || [])
  if (!raw.length) throw new Error(t('Keine Komponenten gefunden — CycloneDX (components[]) oder SPDX (packages[]) erwartet.'))
  const rootRef = jx.metadata?.component?.['bom-ref'] || jx.metadata?.component?.purl
  const directRefs = new Set((jx.dependencies || []).filter(d => d.ref === rootRef).flatMap(d => d.dependsOn || []))

  // Schluessel je Komponente: purl, sonst Name — muss zur Server-Logik passen.
  const keyOf = c => c.purl || (c.externalRefs || []).find(r => r.referenceType === 'purl')?.referenceLocator || c.name
  const refToKey = new Map(raw.map(c => [c['bom-ref'] ?? c.SPDXID, keyOf(c)]))

  // Lieferkettenbeziehungen (Art. 3 Nr. 39): CycloneDX "dependencies",
  // SPDX "relationships" mit DEPENDS_ON. Die Wurzel wird als '' abgelegt.
  const edges = []
  for (const d of jx.dependencies || []) {
    const parent = d.ref === rootRef ? '' : refToKey.get(d.ref)
    if (parent === undefined) continue
    for (const ch of d.dependsOn || []) {
      const child = refToKey.get(ch)
      if (child && child !== parent) edges.push({ parent, child })
    }
  }
  for (const r of jx.relationships || []) {
    if (r.relationshipType !== 'DEPENDS_ON') continue
    const isRoot = r.spdxElementId === (jx.documentDescribes?.[0] || 'SPDXRef-DOCUMENT')
    const parent = isRoot ? '' : refToKey.get(r.spdxElementId)
    const child = refToKey.get(r.relatedSpdxElement)
    if (parent !== undefined && child && child !== parent) edges.push({ parent, child })
  }

  const list = raw.map(c => ({
    name: c.name || '?', version: c.version || c.versionInfo || '',
    purl: c.purl || (c.externalRefs || []).find(r => r.referenceType === 'purl')?.referenceLocator || '',
    supplier: c.supplier?.name || c.publisher || (typeof c.supplier === 'string' ? c.supplier.replace(/^Organization: /, '') : '') || '',
    license: (c.licenses && (c.licenses[0]?.license?.id || c.licenses[0]?.expression)) || c.licenseConcluded || '',
    is_direct: directRefs.has(c['bom-ref']) ? 1 : 0,
  }))
  const fmt = jx.bomFormat ? 'CycloneDX ' + (jx.specVersion || '') : jx.spdxVersion ? 'SPDX ' + jx.spdxVersion : 'SBOM'
  // Jede SBOM benennt im Kopf, was sie beschreibt — das ist der Artefaktname.
  const artifact = jx.metadata?.component?.name || jx.name || ''
  return call('POST', '/api/versions/' + versionId + '/sboms', {
    fileName: file.name, format: fmt, artifact,
    // Tiefe ableiten statt behaupten: gibt es Kanten unterhalb der Wurzel,
    // ist der Baum weiter aufgeloest als nur die obersten Abhaengigkeiten.
    depth: edges.some(e => e.parent !== '') ? 'full' : 'top_level',
    generatedAt: jx.metadata?.timestamp || jx.creationInfo?.created || '',
    components: list, edges, content: text,
  })
}

// Automatisches Speichern: Auswahl sofort, Freitext nach kurzer Pause.
// Kein Speichern-Knopf, kein Abbrechen — was man aendert, ist gespeichert.
function useAutoSave(url, initial, call) {
  const [f, setF] = useState(initial)
  const [saved, setSaved] = useState(false)
  const timer = useRef(null)
  const flash = () => { setSaved(true); setTimeout(() => setSaved(false), 1400) }
  const apply = (patch, { debounce = false } = {}) => {
    setF(prev => {
      const next = { ...prev, ...patch }
      clearTimeout(timer.current)
      const send = () => call('PATCH', url, next).then(flash).catch(() => {})
      if (debounce) timer.current = setTimeout(send, 700)
      else send()
      return next
    })
  }
  const set = (k, v, o) => apply({ [k]: v }, o)
  React.useEffect(() => () => clearTimeout(timer.current), [])
  return [f, set, saved, apply]
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
  return <Pill kind={kind} title={f.score != null ? t('CVSS — Schweregrad von 0 bis 10, aus der Meldungsquelle') : undefined}>{t(label)}{f.severity !== '—' ? sc : ''}</Pill>
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
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState(false); const [err, setErr] = useState(null)
  const fileRef = useRef(null)
  const save = async () => {
    setBusy(true); setErr(null)
    try {
      const res = await call('POST', '/api/products', { name, hersteller, version }, { reloadProducts: true })
      if (file) await importSbomInto(res.versionId, file, call, t)   // erste Version gleich belegen
      setSel({ pid: res.productId, vid: res.versionId })
      onClose()
    } catch (e) { setErr(String(e.message || e)) } finally { setBusy(false) }
  }
  return (
    <Modal onClose={onClose} width={480}>
      <div style={{ display: 'flex', alignItems: 'center' }}><span className="dtitle" style={{ flex: 1 }}>{t('Neues Produkt')}</span><CloseX onClick={onClose} /></div>
      <div className="dsub">{t('Die Zusammensetzung wird je Version geführt.')}</div>
      <div className="fieldlab">{t('Produktname')}</div>
      <input className="field" value={name} onChange={e => setName(e.target.value)} placeholder={t('z. B. SmartPanel 3000')} autoFocus />
      <div className="fieldlab">{t('Hersteller')}</div>
      <input className="field" value={hersteller} onChange={e => setHersteller(e.target.value)} placeholder={t('z. B. Muster GmbH')} />
      <div className="fieldlab">{t('Erste Version')}</div>
      <input className="field" value={version} onChange={e => setVersion(e.target.value)} />

      <div className="fieldlab">{t('SBOM')} <span className="fund">{t('(optional — später jederzeit im Reiter SBOMs)')}</span></div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <button className="hb sm" onClick={() => fileRef.current?.click()}>{t('Datei wählen')}</button>
        <input ref={fileRef} type="file" accept=".json" style={{ display: 'none' }}
          onChange={e => { setFile(e.target.files[0] || null); setErr(null) }} />
        <span className="muted">{file ? file.name : t('CycloneDX- oder SPDX-JSON')}</span>
      </div>

      {err && <div style={{ marginTop: 12 }}><Pill kind="red">{err}</Pill></div>}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 18 }}>
        <button className="hb" onClick={onClose}>{t('Abbrechen')}</button>
        <button className="ab" disabled={!name.trim() || busy} onClick={save}>{busy ? t('Bitte warten …') : t('Anlegen')}</button>
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
        await importSbomInto(res.versionId, file, call, t)   // eine Stelle, ein Parser
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
      <input className="field" value={ver} onChange={e => setVer(e.target.value)} placeholder={t('z. B. 1.1.0')} autoFocus />

      <div className="fieldlab">{t('Hat sich die Software geändert?')}</div>
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
        <button className="ab" disabled={!ready || busy} onClick={save}
          title={!ready && mode === 'new_sbom' && !file ? t('Erst möglich, wenn eine Datei gewählt ist') : undefined}>
          {busy ? t('Bitte warten …') : t('Anlegen')}
        </button>
      </div>
    </Modal>
  )
}

// ---------- Komponenten-Drawer (anlegen/bearbeiten) ----------
function ComponentDrawer({ comp, onClose, onOpenFinding }) {
  const t = useT()
  const { call, sel, product, data } = useStore()
  const blank = {
    kind: 'hardware', name: '', version: '', supplier: '', purl: '', cpe: '', license: '',
    is_core_function: 0, dd_status: 'offen', dd_note: '',
    artifact: '', supplier_address: '', acquired_at: '', supplier_support_until: '',
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
        <span className="dtitle" style={{ flex: 1 }}>{comp ? f.name || t('Komponente') : t('Komponente hinzufügen')}</span>
        {comp?.source === 'sbom_import' && <Pill kind="blue">{t('aus SBOM-Import')}</Pill>}
        {comp && <SavedHint on={saved} />}
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
      <div className="fieldlab">{t('Lieferant')} {isOwn && <span className="fund">{t('— entfällt bei Eigenentwicklung')}</span>}</div>
      <input className="field" value={f.supplier} onChange={e => set('supplier', e.target.value, { debounce: true })} disabled={isOwn} />
      {!isHw && <>
        <div className="fieldlab">{t('Paket-Kennung (purl)')}<HelpDot text={t('Eindeutige Kennung des Pakets. Über sie findet die Prüfung die Schwachstellen — ohne sie bleibt die Komponente ungeprüft.')} /></div>
        <input className="field" value={f.purl} onChange={e => set('purl', e.target.value, { debounce: true })} placeholder="pkg:npm/lodash@4.17.21" />
      </>}
      <div className="fieldlab">{t('Hardware-Kennung (cpe)')}<HelpDot text={t('Kennung für Hardware und Firmware aus dem staatlichen Schwachstellenkatalog (NVD). Freiwillig.')} /></div>
      <input className="field" value={f.cpe} onChange={e => set('cpe', e.target.value, { debounce: true })} placeholder="cpe:2.3:h:…" />
      <div className="fieldlab">{t('Artefakt')} <span className="fund">{t('— beim Import gesetzt, sonst selbst eintragen')}</span></div>
      <input className="field" value={f.artifact || ''} onChange={e => set('artifact', e.target.value, { debounce: true })}
        placeholder={f.kind === 'hardware' ? t('z. B. Gerät, Baugruppe') : t('z. B. Backend, Firmware')} />

      <div className="fieldlab">{t('Lizenz')} <span className="fund">{t('— wird nur festgehalten, nicht bewertet')}</span></div>
      <input className="field" value={f.license} onChange={e => set('license', e.target.value, { debounce: true })} />

      {!isOwn && f.kind !== 'software_oss' && <>
        <div className="fieldlab">{t('Anschrift des Lieferanten')} <span className="fund">{t('— 10 Jahre aufbewahren, für Behördenanfragen')}</span></div>
        <textarea className="field" rows={2} value={f.supplier_address || ''}
          onChange={e => set('supplier_address', e.target.value, { debounce: true })}
          placeholder={t('Straße, PLZ Ort, Land')} />

        <div className="fieldlab">{t('Bezogen am')}</div>
        <input type="date" className="field" style={{ maxWidth: 220 }} value={f.acquired_at || ''}
          onChange={e => set('acquired_at', e.target.value)} />
        {aufbewahrenBis(f.acquired_at) && (
          <div className="muted" style={{ marginTop: 6 }}>
            {t('Aufbewahren bis')} <b>{fmtD(aufbewahrenBis(f.acquired_at).toISOString())}</b>
          </div>
        )}
      </>}

      <div className="fieldlab">{t('Kernfunktion des Produkts')}<HelpDot text={t('Ohne diese Komponente tut das Produkt nicht mehr, wofür es gebaut ist. Dann zählt der Unterstützungszeitraum des Lieferanten für euren mit.')} /></div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Toggle on={!!f.is_core_function} onChange={v => set('is_core_function', v ? 1 : 0)} />
        <span className="muted">{f.is_core_function ? t('Ja — Unterstützungszeitraum des Lieferanten zählt mit') : t('Nein')}</span>
      </div>

      {/* Art. 13 Abs. 8 i. V. m. Abs. 5: auch eine quelloffene Kernkomponente
          braucht ein erfassbares Unterstützungsende. */}
      {!isOwn && (f.kind !== 'software_oss' || !!f.is_core_function) && <>
        <div className="fieldlab">{t('Lieferant unterstützt bis')}</div>
        <input type="month" className="field" style={{ maxWidth: 220 }} value={f.supplier_support_until || ''}
          onChange={e => set('supplier_support_until', e.target.value)} />
        {monatVor(f.supplier_support_until, product?.support_until) && (
          <div style={{ marginTop: 6 }}>
            <Pill kind="red">{t('endet vor dem Produkt')}</Pill>
          </div>
        )}
        {monatVor(f.supplier_support_until, product?.support_until) && !!f.is_core_function && (
          <div className="muted" style={{ marginTop: 8, lineHeight: 1.6 }}>
            {t('Kernkomponente: Der Lieferant hört vor eurem Produkt auf')} ({fmtM(f.supplier_support_until)} {t('gegen')} {fmtM(product.support_until)}).
            {' '}{t('Kürzt euren Unterstützungszeitraum oder plant einen Ersatz.')}
          </div>
        )}
      </>}

      {!isOwn && <>
        <div className="fieldlab">{t('Lieferant geprüft')}<HelpDot text={t('Was habt ihr geprüft, bevor ihr die Komponente eingebaut habt? Pflicht für alles, was ihr selbst ausgewählt habt.')} /></div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
          <Toggle on={f.dd_status === 'geprueft'} onChange={v => set('dd_status', v ? 'geprueft' : 'offen')} />
          {f.dd_status === 'geprueft' ? <Pill kind="green">{t('Geprüft')}</Pill> : <Pill kind="amber">{t('Offen')}</Pill>}
        </div>
        <textarea className="field" rows={3} value={f.dd_note} onChange={e => set('dd_note', e.target.value, { debounce: true })}
          placeholder={t('z. B. Sicherheitskontakt und Update-Zusagen des Lieferanten liegen vor')} />
      </>}

      {comp && !isHw && <DependencyPath componentId={comp.id} componentName={f.name} ziel={null} />}

      {comp && (data?.findings || []).some(x => x.component_id === comp.id) && <>
        <div className="fieldlab">{t('Funde an dieser Komponente')}</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {(data?.findings || []).filter(x => x.component_id === comp.id).map(x => (
            <div key={x.id} className="popitem" style={{ border: '1px solid #E3E8ED', borderRadius: 8 }}
              onClick={() => onOpenFinding && onOpenFinding(x)}>
              <SevPill f={x} />
              <span className="link">{(x.aliases || '').split(', ').find(a => a.startsWith('CVE-')) || x.vuln_id}</span>
              <span className="muted" style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{x.summary}</span>
            </div>
          ))}
        </div>
      </>}

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 20 }}>
        {comp && <button className="hb" style={{ color: '#DC2626' }} onClick={del}>{t('Löschen')}</button>}
        <span style={{ flex: 1 }} />
        {!comp && <button className="ab" disabled={!draft.name.trim()} onClick={create}>{t('Anlegen')}</button>}
      </div>
    </Drawer>
  )
}

// ---------- Funde: Triage-Drawer ----------
function FindingDrawer({ finding, onClose }) {
  const { t, lang } = useI18n()
  const T = (de, en) => (lang === 'en' ? en : de)
  const { call, product, version } = useStore()
  const [f, set, saved, apply] = useAutoSave('/api/findings/' + finding.id, { ...finding }, call)
  const advisory = () => {
    // Advisory-Entwurf (Anhang I Teil II Nr. 4) — Entwurf herunterladen; veröffentlichen muss der Hersteller.
    const md = [
      T('# Sicherheitshinweis (ENTWURF) — ', '# Security advisory (DRAFT) — ') + product.name + ' ' + version.version,
      '',
      T('> Entwurf nach Anhang I Teil II Nr. 4 CRA — erst veröffentlichen, wenn das Update verfügbar ist.',
        '> Draft under Annex I Part II No. 4 CRA — publish only once the security update is available.'),
      '',
      T('## Betroffenes Produkt', '## Affected product'),
      T('- Produkt: ', '- Product: ') + product.name + (product.hersteller ? ' (' + product.hersteller + ')' : ''),
      T('- Betroffene Version(en): ', '- Affected version(s): ') + version.version,
      T('- Betroffene Komponente: ', '- Affected component: ') + (f.component_name || '—') + (f.component_purl ? ' (`' + f.component_purl + '`)' : ''),
      '',
      T('## Schwachstelle', '## Vulnerability'),
      T('- Kennung: ', '- Identifier: ') + f.vuln_id + (f.aliases ? ' (' + f.aliases + ')' : ''),
      T('- Schwere: ', '- Severity: ') + t((SEVS.find(x => x[0] === f.severity) || [, '—'])[1]) + (f.score != null ? ' (CVSS ' + Number(f.score).toFixed(1) + ')' : ''),
      T('- Beschreibung: ', '- Description: ') + (f.summary && !f.summary.startsWith('osv.dev/') ? f.summary : T('Keine Beschreibung vorhanden — siehe Quellen.', 'No description available — see sources.')),
      '',
      T('## Auswirkungen und Behebung', '## Impact and remediation'),
      T('- Status: behoben', '- Status: fixed'),
      T('- Behebung: ', '- Remediation: ') + (f.fix_version ? f.component_name + ' ' + f.fix_version
          : f.fixed_versions ? T('Version ', 'Version ') + f.fixed_versions
            : T('[Sicherheitsaktualisierung eintragen]', '[enter the security update]')),
      T('- Maßnahmen für Nutzer: [eindeutige, verständliche Anleitung ergänzen]',
        '- Action for users: [add clear, understandable instructions]'),
      '',
      ...(f.refs_json ? ['', T('## Quellen', '## Sources'), ...(() => { try { return JSON.parse(f.refs_json).map(r => '- ' + r.label + ': ' + r.url) } catch { return [] } })()] : []),
      '',
      T('_Entwurf erzeugt am ', '_Draft generated on ') + new Date().toLocaleDateString(lang === 'en' ? 'en-GB' : 'de-DE')
        + T('. Vor dem Veröffentlichen prüfen und ergänzen._', '. Review and complete before publishing._'),
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
        <SavedHint on={saved} />
        <CloseX onClick={onClose} />
      </div>
      <div style={{ marginTop: 6, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <SevPill f={f} />
        {f.aliases && f.aliases.split(', ').filter(a => a.startsWith('CVE-')).map(a => <Pill key={a} kind="blue">{a}</Pill>)}
        {f.cwe_ids && f.cwe_ids.split(', ').slice(0, 4).map(c => <Pill key={c} kind="neutral" title={t('Art der Schwachstelle (CWE-Katalog)')}>{c}</Pill>)}
      </div>
      <div className="dsub">{f.component_purl ? pshow(f.component_purl) + ' · ' : ''}{f.summary}</div>
      <div className="dsub">
        {t('Gemeldet über:')} {t(intakeLabel(f.intake_channel))}
        {f.published ? ' · ' + t('Advisory veröffentlicht:') + ' ' + fmtD(f.published) : ''}
      </div>

      {/* Behebung und Quellen — automatisch beim Abgleich aus OSV übernommen */}
      <div className="fieldlab">{t('Behebung')}</div>
      {f.component_version && (
        <div className="muted" style={{ marginBottom: 8, lineHeight: 1.6 }}>
          {t('Eingebaut ist')} <b>{f.component_name} {f.component_version}</b>
          {empfohleneFixVersion(f.component_version, (f.fixed_versions || '').split(', ').filter(Boolean))
            && <> · {t('behoben ab')} <b style={{ color: '#27AE60' }}>{f.component_name} {empfohleneFixVersion(f.component_version, f.fixed_versions.split(', '))}</b></>}
        </div>
      )}
      {f.fix_status === 'none'
        ? <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Pill kind="red">{t('Keine Behebung verfügbar')}</Pill>
            {f.last_affected && <span className="muted">{t('betroffen bis')} {f.last_affected}</span>}</div>
        : f.fixed_versions
          ? <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <span className="muted">{t('Behoben in:')}</span>
              {f.fixed_versions.split(', ').map(v => (
                <button key={v} className={'hb sm' + (f.fix_version === v ? ' active' : '')
                  + (v === empfohleneFixVersion(f.component_version, f.fixed_versions.split(', ')) ? ' empfohlen' : '')}
                  title={t('Als Zielversion übernehmen — Entscheidung wird „Sofort beheben“')}
                  onClick={() => apply({ fix_version: v, decision: f.decision || 'fix_now' })}>
                  {f.component_name} {v}
                </button>
              ))}
              {f.fix_version && <Pill kind="blue">{t('Zielversion:')} {f.fix_version}</Pill>}
            </div>
          : <span className="muted">{t('Keine Versionsangabe im Advisory.')}</span>}

      <DependencyPath componentId={f.component_id} componentName={f.component_name}
        ziel={empfohleneFixVersion(f.component_version, (f.fixed_versions || '').split(', '))} />

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

      <div className="fieldlab">{t('Betroffenheit')}<HelpDot text={t('Ist euer Produkt durch diese Schwachstelle wirklich angreifbar? Nicht jede Schwachstelle in einer Komponente trifft euch.')} /></div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {VEX_STATI.map(([v, label]) => (
          <span key={v} className={'tabpill' + (f.vex_status === v ? ' active' : '')} onClick={() => set('vex_status', v)}>{t(label)}</span>
        ))}
      </div>
      <div className="fieldlab">{t('Begründung')}</div>
      <textarea className="field" rows={2} value={f.vex_justification}
        placeholder={f.vex_status === 'not_affected' ? t('z. B. die verwundbare Funktion wird bei uns nie aufgerufen') : t('Einschätzung, Analyse-Stand')}
        onChange={e => set('vex_justification', e.target.value, { debounce: true })} />

      <div className="fieldlab">{t('Entscheidung')}</div>
      <div style={{ display: 'flex', gap: 12 }}>
        <select className="field" style={{ flex: 1 }} value={f.decision} onChange={e => set('decision', e.target.value)}>
          {DECISIONS.map(([v, label]) => <option key={v} value={v}>{t(label)}</option>)}
        </select>
        {f.decision === 'accept' && (
          <input type="date" className="field" style={{ flex: 1 }} value={f.accept_until} onChange={e => set('accept_until', e.target.value)} title={t('Bis wann gilt das?')} />
        )}
      </div>
      {(f.decision === 'accept' || f.decision === 'defer') && (
        <textarea className="field" rows={2} style={{ marginTop: 8 }} value={f.decision_rationale}
          placeholder={t('Warum diese Entscheidung?')} onChange={e => set('decision_rationale', e.target.value, { debounce: true })} />
      )}

      <div style={{ display: 'flex', gap: 12 }}>
        <div style={{ flex: 1 }}>
          <div className="fieldlab">{t('Verantwortlich')}</div>
          <input className="field" value={f.owner} onChange={e => set('owner', e.target.value, { debounce: true })}
            placeholder={product?.owner || t('Name')} />
        </div>
        <div style={{ flex: 1 }}>
          <div className="fieldlab">{t('Bekannt seit')}</div>
          <input type="datetime-local" className="field" value={toLocal(f.became_known_at)} onChange={e => set('became_known_at', fromLocal(e.target.value))} />
        </div>
      </div>

      <div className="fieldlab">{t('Behebung verfügbar seit')} <span className="fund">{t('(sobald Update oder Abhilfe bereitsteht)')}</span></div>
      <input type="date" className="field" style={{ maxWidth: 220 }} value={f.mitigation_available_at || ''}
        onChange={e => set('mitigation_available_at', e.target.value)} />

      <div className="fieldlab">{t('Aktiv ausgenutzt')}<HelpDot text={t('Es gibt belastbare Hinweise, dass die Schwachstelle tatsächlich angegriffen wird. Nie aus dem CVSS-Wert ableiten.')} /></div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Toggle on={!!f.actively_exploited} onChange={v => set('actively_exploited', v ? 1 : 0)} />
        <span className="muted">{f.actively_exploited ? t('Ja — verlässliche Nachweise erforderlich') : t('Nein / keine Nachweise')}</span>
      </div>
      {!!f.actively_exploited && <>
        <textarea className="field" rows={2} style={{ marginTop: 8 }} value={f.exploit_evidence}
          placeholder={t('Nachweis: worauf stützt sich die Einstufung?')} onChange={e => set('exploit_evidence', e.target.value, { debounce: true })} />
      </>}

      <div className="fieldlab">{t('Meldung an den Komponenten-Hersteller')}</div>
      <div style={{ display: 'flex', gap: 12 }}>
        <input className="field" style={{ flex: 2 }} value={f.upstream_reported_to} placeholder={t('Gemeldet an — Projekt oder Lieferant')} onChange={e => set('upstream_reported_to', e.target.value, { debounce: true })} />
        <input type="date" className="field" style={{ flex: 1 }} value={f.upstream_reported_at} onChange={e => set('upstream_reported_at', e.target.value)} />
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 8 }}>
        <Toggle on={!!f.upstream_fix_shared} onChange={v => set('upstream_fix_shared', v ? 1 : 0)} />
        <span className="muted">{t('Fix-Code oder Unterlagen geteilt')}</span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 20 }}>
        {f.vex_status === 'fixed' && <button className="hb" onClick={advisory}>{t('Advisory-Entwurf')}</button>}
        <span style={{ flex: 1 }} />
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
        <span className={'tabpill' + (sbom.depth === 'top_level' ? ' active' : '')} onClick={() => patch({ depth: 'top_level' })}>{t('Nur direkte Abhängigkeiten')}</span>
        <span className={'tabpill' + (sbom.depth === 'full' ? ' active' : '')} onClick={() => patch({ depth: 'full' })}>{t('Alle Abhängigkeiten')}</span>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 20 }}>
        <button className="hb" style={{ color: '#DC2626', marginRight: 'auto' }} onClick={del}>{t('Löschen')}</button>
        <a className="ab" style={{ textDecoration: 'none' }} href={'/api/sboms/' + sbom.id + '/download'}>{t('Herunterladen')}</a>
      </div>
    </Drawer>
  )
}

// ---------- Manuelle Fund-Erfassung (D-020): Eingang kommt per Mail/Advisory, hier wird nur
// dokumentiert. Kein Fristentext (D-036) — die Meldekette gehoert ins Modul Meldungen. ----------
function NewFindingModal({ onClose }) {
  const t = useT()
  const { call, sel, data } = useStore()
  const comps = data?.components || []
  const [f, setFx] = useState({ vuln_id: '', component_id: '', intake_channel: 'cvd_mail',
    severity: '—', summary: '', became_known_at: toLocal(new Date().toISOString()) })
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(null)
  const upd = (k, v) => setFx(x => ({ ...x, [k]: v }))
  const save = async () => {
    setBusy(true); setErr(null)
    try {
      await call('POST', '/api/versions/' + sel.vid + '/findings',
        { ...f, component_id: f.component_id || null, became_known_at: fromLocal(f.became_known_at) })
      onClose()
    } catch (e) { setErr(String(e.message || e)) } finally { setBusy(false) }
  }
  return (
    <Modal onClose={onClose} width={520}>
      <div style={{ display: 'flex', alignItems: 'center' }}><span className="dtitle" style={{ flex: 1 }}>{t('Fund erfassen')}</span><CloseX onClick={onClose} /></div>
      <div className="dsub">{t('Der Abgleich findet Software automatisch. Was per Mail, Lieferanten-Advisory oder aus eigenen Tests hereinkommt, erfasst du hier.')}</div>

      <div className="fieldlab">{t('Kennung')}</div>
      <input className="field" value={f.vuln_id} onChange={e => upd('vuln_id', e.target.value)}
        placeholder={t('CVE-Nummer oder Advisory-Kennung')} autoFocus />

      <div className="fieldlab">{t('Komponente')}</div>
      <select className="field" value={f.component_id} onChange={e => upd('component_id', e.target.value)}>
        <option value="">{t('— keine Zuordnung —')}</option>
        {comps.map(c => <option key={c.id} value={c.id}>{c.name}{c.version ? ' ' + c.version : ''}</option>)}
      </select>

      <div style={{ display: 'flex', gap: 12 }}>
        <div style={{ flex: 1 }}>
          <div className="fieldlab">{t('Gemeldet über:')}</div>
          <select className="field" value={f.intake_channel} onChange={e => upd('intake_channel', e.target.value)}>
            {INTAKE.filter(([v]) => v !== 'osv_scan').map(([v, label]) => <option key={v} value={v}>{t(label)}</option>)}
          </select>
        </div>
        <div style={{ flex: 1 }}>
          <div className="fieldlab">{t('Schwere')}</div>
          <select className="field" value={f.severity} onChange={e => upd('severity', e.target.value)}>
            {SEVS.map(([k, label]) => <option key={k} value={k}>{t(label)}</option>)}
          </select>
        </div>
      </div>

      <div className="fieldlab">{t('Bekannt seit')}</div>
      <input type="datetime-local" className="field" value={f.became_known_at}
        onChange={e => upd('became_known_at', e.target.value)} />

      <div className="fieldlab">{t('Zusammenfassung')}</div>
      <textarea className="field" rows={2} value={f.summary} onChange={e => upd('summary', e.target.value)}
        placeholder={t('Was ist betroffen, was ist passiert?')} />

      {err && <div style={{ marginTop: 12 }}><Pill kind="red">{t(err)}</Pill></div>}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 18 }}>
        <button className="hb" onClick={onClose}>{t('Abbrechen')}</button>
        <button className="ab" disabled={!f.vuln_id.trim() || !f.became_known_at || busy} onClick={save}>
          {busy ? t('Bitte warten …') : t('Anlegen')}
        </button>
      </div>
    </Modal>
  )
}

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

  if (err) return <div className="hintbox" style={{ margin: 16 }}>{t(err)}</div>
  if (!diff) return <div className="hintbox" style={{ margin: 16 }}>{t('Vergleich wird berechnet …')}</div>
  if (!diff.base) return (
    <div className="hintbox" style={{ margin: 16 }}>
      <b style={{ color: '#0B1928' }}>{t('Erste Version')}</b> — {t('es gibt keine Vorversion zum Vergleichen. Sobald du eine zweite Version anlegst, steht hier, was sich geändert hat.')}
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
        <span className="muted">{diff.added.length} {t('neu ·')} {diff.removed.length} {t('entfernt ·')} {diff.changed.length} {t('Version geändert ·')} {diff.unchanged} {t('unverändert')}</span>
      </div>
      <div className="tblwrap sc">
        <table className="tbl">
          <thead><tr><th style={{ width: '34%' }}>{t('Komponente')}</th><th>{t('Typ')}</th><th>{t('Version')}</th><th>{t('Lieferant')}</th></tr></thead>
          <tbody>
            <Section title={t('Neu hinzugekommen')} kind="green" rows={diff.added}
              render={(c, i) => (
                <tr key={'a' + i}>
                  <td><span style={{ fontWeight: 500, color: '#0B1928' }}>{c.name}</span>
                    <span style={{ display: 'block', fontSize: 11.5, color: '#8B95A3' }}>{c.purl ? pshow(c.purl) : '—'}</span></td>
                  <td>{t(kindLabel(c.kind))}</td>
                  <td><Pill kind="green">{c.version || '—'}</Pill></td>
                  <td>{c.supplier || '—'}</td>
                </tr>
              )} />
            <Section title={t('Version geändert')} kind="amber" rows={diff.changed}
              render={(c, i) => (
                <tr key={'c' + i}>
                  <td><span style={{ fontWeight: 500, color: '#0B1928' }}>{c.name}</span>
                    <span style={{ display: 'block', fontSize: 11.5, color: '#8B95A3' }}>{c.purl ? pshow(c.purl) : '—'}</span></td>
                  <td>{t(kindLabel(c.kind))}</td>
                  <td><Pill kind="amber">{c.from} → {c.to}</Pill></td>
                  <td>{c.supplier || '—'}</td>
                </tr>
              )} />
            <Section title={t('Entfernt')} kind="red" rows={diff.removed}
              render={(c, i) => (
                <tr key={'r' + i}>
                  <td><span style={{ fontWeight: 500, color: '#0B1928' }}>{c.name}</span>
                    <span style={{ display: 'block', fontSize: 11.5, color: '#8B95A3' }}>{c.purl ? pshow(c.purl) : '—'}</span></td>
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

// ---------- Woher kommt eine transitive Komponente? ----------
function DependencyPath({ componentId, componentName, ziel }) {
  const t = useT()
  const { product } = useStore()
  const [pfad, setPfad] = useState(undefined)   // undefined = laedt, null = keiner
  React.useEffect(() => {
    if (!componentId) { setPfad(null); return }
    setPfad(undefined)
    fetch('/api/components/' + componentId + '/path')
      .then(r => r.json())
      .then(d => setPfad(d.paths?.[0] || null))
      .catch(() => setPfad(null))
  }, [componentId])

  if (pfad === undefined || pfad === null || pfad.length < 2) return null
  const direkt = pfad[0]
  return (
    <>
      <div className="fieldlab">{t('Wird hereingezogen über')}<HelpDot text={t('Über welche eurer direkten Abhängigkeiten dieses Paket hereinkommt.')} /></div>
      <div className="deppath">
        <span className="depnode root" title={t('Euer Produkt')}>{product?.name || t('Produkt')}</span>
        {pfad.map((c, i) => (
          <React.Fragment key={i}>
            <span className="deparrow">→</span>
            <span className={'depnode' + (i === 0 ? ' first' : '') + (i === pfad.length - 1 ? ' last' : '')}>
              {c.name}{c.version ? ' ' + c.version : ''}
            </span>
          </React.Fragment>
        ))}
      </div>
      <div className="muted" style={{ marginTop: 6, fontSize: 11.5 }}>
        {t('Produkt → direkt eingebunden → … → verwundbare Komponente')}
      </div>
      <div className="muted" style={{ marginTop: 8, lineHeight: 1.6 }}>
        <b>{componentName}</b> {t('habt ihr nicht direkt eingebunden — es lässt sich nicht einzeln austauschen.')}
        {ziel
          ? <> {t('Ihr braucht eine Version von')} <b>{direkt.name}</b>{t(', die')} <b>{componentName} {ziel}</b> {t('oder neuer enthält.')}</>
          : <> {t('Ansatzpunkt ist die direkte Abhängigkeit')} <b>{direkt.name}</b>.</>}
      </div>
    </>
  )
}

// ---------- Filter als eigener Bereich ----------
function FilterRow({ label, children }) {
  return (
    <div style={{ marginTop: 16 }}>
      <div className="fieldlab" style={{ margin: '0 0 8px' }}>{label}</div>
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
  const reset = () => set({ kind: null, compSev: null, compDd: false, compDirect: null, artifact: null, sev: null, vex: null, fix: null })
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
        <FilterRow label={t('Funde an der Komponente')}>
          <Chip active={!f.compSev} onClick={() => set({ compSev: null })}>{t('Alle')} </Chip>
          {SEVS.filter(([k]) => k !== '—').map(([k, label, col]) => (
            <Chip key={k} active={f.compSev === k} count={counts.compSev[k]} disabled={!counts.compSev[k]} dot={col}
              onClick={() => set({ compSev: f.compSev === k ? null : k })}>{t(label)} </Chip>
          ))}
          <Chip active={f.compSev === 'none'} count={counts.compSev.none}
            onClick={() => set({ compSev: f.compSev === 'none' ? null : 'none' })}>{t('Ohne Funde')} </Chip>
        </FilterRow>
        {Object.keys(counts.artifact).length > 0 && (
          <FilterRow label={t('Artefakt')}>
            <Chip active={!f.artifact} onClick={() => set({ artifact: null })}>{t('Alle')} </Chip>
            {Object.entries(counts.artifact).map(([a, n]) => (
              <Chip key={a} active={f.artifact === a} count={n}
                onClick={() => set({ artifact: f.artifact === a ? null : a })}>{a} </Chip>
            ))}
            {counts.ohneArtefakt > 0 && (
              <Chip active={f.artifact === '—'} count={counts.ohneArtefakt}
                onClick={() => set({ artifact: f.artifact === '—' ? null : '—' })}>{t('ohne Zuordnung')} </Chip>
            )}
          </FilterRow>
        )}

        <FilterRow label={t('Sorgfalt')}>
          <Chip active={!f.compDd} onClick={() => set({ compDd: false })}>{t('Alle')} </Chip>
          <Chip active={f.compDd} count={counts.ddOpen} disabled={!counts.ddOpen}
            onClick={() => set({ compDd: !f.compDd })}>{t('Sorgfalt offen')} </Chip>
        </FilterRow>
      </>}

      {tab === 'funde' && <>
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
            onClick={() => set({ fix: f.fix === 'has' ? null : 'has' })}>{t('Behebung verfügbar')} </Chip>
          <Chip active={f.fix === 'none'} count={counts.fixNone} disabled={!counts.fixNone}
            onClick={() => set({ fix: f.fix === 'none' ? null : 'none' })}>{t('Keine Behebung')} </Chip>
        </FilterRow>
      </>}
    </Drawer>
  )
}

// ---------- Scan-Historie ----------
function ScanHistoryModal({ scans, onClose }) {
  const t = useT()
  return (
    <Modal onClose={onClose} width={620}>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <span className="dtitle" style={{ flex: 1 }}>{t('Prüfverlauf')}</span><CloseX onClick={onClose} />
      </div>
      <div className="dsub">{t('Hier steht jede Prüfung: wann sie lief, wie viele Komponenten geprüft wurden und was sie gefunden hat.')}</div>
      {scans.length ? (
        <table className="tbl" style={{ marginTop: 12 }}>
          <thead><tr><th>{t('Zeitpunkt')}</th><th>{t('Quelle')}</th><th>{t('Komponenten')}</th><th>{t('Neu')}</th><th>{t('Aktualisiert')}</th></tr></thead>
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
      ) : <div className="muted" style={{ marginTop: 14 }}>{t('Noch keine Prüfung für diese Version')}</div>}
    </Modal>
  )
}

// ---------- Verantwortliche Person: einmal am Produkt statt an jedem Fund ----------
function OwnerPicker() {
  const t = useT()
  const { product, call, reloadProducts } = useStore()
  const [open, setOpen] = useState(false)
  const [val, setVal] = useState(product?.owner || '')
  const [bis, setBis] = useState(product?.support_until || '')
  const [pom, setPom] = useState(product?.placed_on_market || '')
  const ref = useRef(null)
  React.useEffect(() => { setVal(product?.owner || '') }, [product?.owner])
  React.useEffect(() => { setBis(product?.support_until || '') }, [product?.support_until])
  React.useEffect(() => { setPom(product?.placed_on_market || '') }, [product?.placed_on_market])
  React.useEffect(() => {
    if (!open) return
    const away = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', away)
    return () => document.removeEventListener('mousedown', away)
  }, [open])

  const save = async () => {
    await call('PATCH', '/api/products/' + product.id, { owner: val.trim(), support_until: bis, placed_on_market: pom })
    await reloadProducts()
    setOpen(false)
  }
  // Art. 13 Abs. 8: mindestens fuenf Jahre AB INVERKEHRBRINGEN — nicht ab heute,
  // sonst wandert die Warnung mit dem Kalender (Pruefbericht S12).
  const jahreBis = bis && pom ? (new Date(bis + '-01') - new Date(pom)) / (365.25 * 24 * 3600 * 1000) : null
  const initials = (product?.owner || '').split(/\s+/).filter(Boolean).map(w => w[0]).slice(0, 2).join('').toUpperCase()

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button className="hb" style={{ height: 36 }} onClick={() => setOpen(o => !o)} title={t('Verantwortlich für die Schwachstellenbehandlung')}>
        {product?.owner
          ? <><span className="ownerdot">{initials}</span><b style={{ fontWeight: 600 }}>{product.owner}</b></>
          : <><svg width="15" height="15" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="8" r="3.4" stroke="currentColor" strokeWidth="1.7" /><path d="M5 20c0-3.3 3.1-5.5 7-5.5s7 2.2 7 5.5" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" /></svg>{t('Verantwortlich')}</>}
        <span style={{ color: '#B6C1CD', fontSize: 11 }}>▾</span>
      </button>
      {open && (
        <div className="popmenu" style={{ padding: 12, minWidth: 260 }}>
          <div style={{ fontSize: 12, color: '#69778E', lineHeight: 1.5, marginBottom: 10 }}>
            {t('Gilt für alle Funde dieses Produkts. Einzelne Funde können abweichend zugewiesen werden.')}
          </div>
          <div className="fieldlab" style={{ marginTop: 0 }}>{t('Verantwortlich')}</div>
          <input className="field" value={val} autoFocus placeholder={t('Name')}
            onChange={e => setVal(e.target.value)} onKeyDown={e => e.key === 'Enter' && save()} />

          <div className="fieldlab">{t('Inverkehrbringen am')} <span className="fund">{t('(für die Fünfjahresprüfung)')}</span></div>
          <input type="date" className="field" value={pom} onChange={e => setPom(e.target.value)} />

          <div className="fieldlab">{t('Sicherheitsupdates bis')} <span className="fund">{t('(Monat und Jahr)')}</span></div>
          <input type="month" className="field" value={bis} onChange={e => setBis(e.target.value)} />
          {jahreBis !== null && jahreBis < 5 && (
            <div style={{ marginTop: 6 }}><Pill kind="amber">{t('kürzer als fünf Jahre — nur mit Begründung zulässig')}</Pill></div>
          )}
          {bis && !pom && (
            <div className="muted" style={{ marginTop: 6 }}>{t('Datum des Inverkehrbringens angeben, dann wird der Zeitraum geprüft')}</div>
          )}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 10 }}>
            {product?.owner && <button className="hb sm" style={{ marginRight: 'auto' }} onClick={() => { if (!confirm(t('Verantwortlichen entfernen? Gilt für alle Funde dieses Produkts.'))) return; setVal(''); call('PATCH', '/api/products/' + product.id, { owner: '' }).then(reloadProducts).then(() => setOpen(false)) }}>{t('Entfernen')}</button>}
            <button className="ab sm" onClick={save}>{t('Übernehmen')}</button>
          </div>
        </div>
      )}
    </div>
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
    if (!confirm(t('Version {v} löschen? Komponenten, SBOMs und Funde dieser Version gehen mit verloren.').replace('{v}', v.version))) return
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
  const EMPTY_FILTER = { kind: null, compSev: null, compDd: false, compDirect: null, artifact: null, sev: null, vex: null, fix: null }
  const [filter, setFilterRaw] = useState(EMPTY_FILTER)
  const setFilter = patchObj => setFilterRaw(f => ({ ...f, ...patchObj }))
  const activeFilters = Object.values(filter).filter(v => v !== null && v !== false).length
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
  const importSbom = async (file) => {
    try {
      const res = await importSbomInto(sel.vid, file, call, t)
      const noPurl = res.components.filter(c => !c.purl).length
      setNotice({ err: false, msg: res.sboms[0].format + ' · ' + res.imported.added + ' ' + t('neu,') + ' '
        + res.imported.updated + ' ' + t('aktualisiert — Original archiviert')
        + (res.imported.removed ? ' · ' + res.imported.removed + ' ' + t('entfernt') : '')
        + (noPurl ? ' · ' + noPurl + ' ' + t('ohne purl') : '') })
      setTab('komponenten')
    } catch (e) { setNotice({ err: true, msg: String(e.message || e) }) }
  }
  const runScan = async () => {
    setScanBanner(null)
    try {
      const res = await call('POST', '/api/versions/' + sel.vid + '/scan')
      setScanBanner(res.scan)
      setTab('funde')
    } catch { /* Fehlermeldung kommt über notice */ }
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
  const hasFix = f => !!f.fixed_versions
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
    artifact: components.reduce((acc, c) => {
      for (const a of (c.artifact || '').split(', ').map(x => x.trim()).filter(Boolean)) acc[a] = (acc[a] || 0) + 1
      return acc
    }, {}),
    ohneArtefakt: components.filter(c => !(c.artifact || '').trim()).length,
    sev: sevCounts,
    vex: Object.fromEntries(VEX_STATI.map(([v]) => [v, findings.filter(f => f.vex_status === v).length])),
    fixHas: findings.filter(f => !!f.fixed_versions).length,
    fixNone: findings.filter(f => !f.fixed_versions).length,
  }
  const compRows = components
    .filter(c => !filter.kind || c.kind === filter.kind)
    .filter(c => !filter.compDirect || (filter.compDirect === 'direct' ? !!c.is_direct : !c.is_direct))
    .filter(c => !filter.compSev || (filter.compSev === 'none' ? compFindings(c).length === 0
      : compFindings(c).some(f => (f.severity in sevCounts ? f.severity : '—') === filter.compSev)))
    .filter(c => !filter.compDd || ddOpen(c))
    .filter(c => !filter.artifact || (filter.artifact === '—'
      ? !(c.artifact || '').trim()
      : (c.artifact || '').split(', ').includes(filter.artifact)))
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
        <div className="muted" style={{ maxWidth: 500, textAlign: 'center', lineHeight: 1.7 }}>{t('Komponenten, SBOMs und Funde hängen an der Produktversion. Lege ein Produkt mit seiner ersten Version an — danach importierst du die SBOM, die dein Build erzeugt.')}
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
        <button className="hb" onClick={runScan} disabled={busy || !components.some(c => c.purl && c.kind !== 'hardware')}
          title={!components.some(c => c.purl && c.kind !== 'hardware') ? t('Erst möglich, wenn Software mit purl im Inventar steht') : undefined}>
          {busy ? t('Bitte warten …') : t('Auf Schwachstellen prüfen')}
        </button>
        <button className="hb" onClick={() => setModal('scans')} disabled={!version}>{t('Prüfverlauf')}</button>
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
        <OwnerPicker />
        <button className="hb sm" onClick={() => setModal('version')}>{t('+ Version')}</button>
        <span style={{ flex: 1 }} />
        {scanBanner && <Pill kind="green">{t('Prüfung fertig —')} {scanBanner.scanned} {t('Komponenten geprüft ·')} {scanBanner.added} {t('neue Funde ·')} {scanBanner.updated} {t('aktualisierte Funde')}</Pill>}
        {!scanBanner && lastScan && <span className="muted">{t('Letzte Prüfung:')} {fmtDT(lastScan.ran_at)} · {lastScan.source} · {lastScan.components_scanned} {t('Komponenten geprüft')}</span>}
        {!scanBanner && !lastScan && <span className="muted">{t('Noch keine Prüfung für diese Version')}</span>}
      </div>

      {/* Kennzahlen je Version */}
      <div style={{ display: 'flex', gap: 14, padding: '14px 16px 0', flexWrap: 'wrap' }}>
        <div className="kpi">
          <div className="l">{t('Komponenten')}</div>
          <div className="v">{components.length}</div>
          <div className="s">{hw} {t('Hardware ·')} {components.length - hw} {t('Software (SBOM)')}</div>
        </div>
        <div className="kpi">
          <div className="l">{t('Lieferanten geprüft')}</div>
          <div className="v">{geprueft}<span style={{ fontSize: 13, fontWeight: 500, color: '#8B95A3' }}> / {ddPool.length}</span></div>
          <div className="progress" style={{ marginTop: 7 }}><div style={{ width: (ddPool.length ? geprueft / ddPool.length * 100 : 0) + '%', background: '#27AE60' }} /></div>
          <div className="s">{t('von den Komponenten, die ihr selbst ausgewählt habt')}</div>
        </div>
        <div className="kpi">
          <div className="l">{t('Funde insgesamt')}</div>
          <div className="v">{findings.length}</div>
          <div className="sevbar">
            {SEVS.map(([k, lbl, c]) => sevCounts[k] > 0 && <div key={k} style={{ flex: sevCounts[k], background: c }} title={t(lbl) + ': ' + sevCounts[k]} />)}
            {!findings.length && <div style={{ flex: 1, background: '#EFF3F8' }} />}
          </div>
          <div className="s">{sevCounts.KRITISCH} {t('kritisch ·')} {sevCounts.HOCH} {t('hoch ·')} {sevCounts.MITTEL} {t('mittel ·')} {sevCounts.NIEDRIG} {t('niedrig')}</div>
        </div>
        <div className="kpi">
          <div className="l">{t('Betroffenheit bewertet')}</div>
          <div className="v">{triaged}<span style={{ fontSize: 13, fontWeight: 500, color: '#8B95A3' }}> / {findings.length}</span></div>
          <div className="progress" style={{ marginTop: 7 }}><div style={{ width: (findings.length ? triaged / findings.length * 100 : 0) + '%', background: '#1298ff' }} /></div>
          <div className="s">{findings.filter(f => f.actively_exploited).length} {t('aktiv ausgenutzt')}</div>
        </div>
      </div>

      {notice && <div style={{ padding: '10px 16px 0' }}><Pill kind={notice.err ? 'red' : 'green'}>{t(notice.msg)}</Pill> <span className="link" style={{ fontSize: 12 }} onClick={() => setNotice(null)}>{t('ausblenden')}</span></div>}

      <div className="tabrow">
        <span className={'tabpill' + (tab === 'komponenten' ? ' active' : '')} onClick={() => setTab('komponenten')}>{t('Komponenten')} ({compRows.length !== components.length ? compRows.length + ' / ' : ''}{components.length})</span>
        <span className={'tabpill' + (tab === 'sboms' ? ' active' : '')} onClick={() => setTab('sboms')}>{t('SBOMs')} ({sboms.length})</span>
        <span className={'tabpill' + (tab === 'funde' ? ' active' : '')} onClick={() => setTab('funde')}>{t('Funde')} ({findRows.length !== findings.length ? findRows.length + ' / ' : ''}{findings.length})</span>
        <span className={'tabpill' + (tab === 'aenderungen' ? ' active' : '')} onClick={() => setTab('aenderungen')}>{t('Änderungen')}</span>
        <span style={{ flex: 1 }} />
      </div>

      {/* ---------- Reiter 1: Komponenten (Inventar = Obermenge, Abschnitt 1.6) ---------- */}
      {tab === 'komponenten' && <>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px 0' }}>
          <span className="muted" style={{ flex: 1 }}>{t('Software kommt über den SBOM-Import; Hardware und Zukauf legst du hier an.')}</span>
          <button className="ab sm" onClick={() => setCompOpen('neu')} disabled={!version}>{t('+ Komponente')}</button>
        </div>
        <div className="tblwrap sc" style={{ marginTop: 10 }}>
          <table className="tbl">
            <thead><tr><th style={{ width: '28%' }}>{t('Komponente')}</th><th>{t('Typ')}</th><th>{t('Version')}</th><th>{t('Funde')}</th><th>{t('Sorgfalt')}</th></tr></thead>
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
                        {c.purl ? pshow(c.purl) : c.cpe || (c.kind === 'hardware' ? '' : t('ohne Paket-Kennung — wird bei der Prüfung übersprungen'))}
                      </span>
                    </td>
                    <td><Pill kind={kindColor}>{t(kindLabel)}</Pill></td>
                    <td>{c.version || '—'}</td>

                    <td>
                      {fs.length === 0
                        ? <span className="muted">{t('keine bekannt')}</span>
                        : <span style={{ display: 'inline-flex', gap: 5 }}>
                            {SEVS.map(([k, lbl, col]) => grp[k] ? <span key={k} className="sevbadge" style={{ background: col }} title={t(lbl)}>{grp[k]}</span> : null)}
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
                {components.length ? (q ? t('Keine Treffer für die Suche.') : t('Keine Komponenten für diesen Filter.')) : t('Noch keine Komponenten — im Reiter SBOMs eine SBOM importieren oder mit „+ Komponente“ Hardware anlegen.')}</td></tr>}
            </tbody>
          </table>
        </div>
      </>}

      {/* ---------- Reiter 2: SBOMs je Version ---------- */}
      {tab === 'sboms' && <>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px 0' }}>
          <span className="muted" style={{ flex: 1 }}>{t('Ein Produkt kann mehrere SBOMs haben — etwa je Artefakt (Backend, Firmware). Alle laufen in ein Komponenteninventar.')}</span>
          <button className="ab sm" onClick={() => fileRef.current?.click()} disabled={!version}>{t('SBOM importieren')}</button>
        </div>
        <div className="tblwrap sc" style={{ marginTop: 10 }}>
          <table className="tbl">
            <thead><tr><th style={{ width: '30%' }}>{t('Datei')}</th><th>{t('Format')}</th><th>{t('Tiefe')}</th><th>{t('Erstellt')}</th><th>{t('Importiert')}</th><th>{t('Komponenten')}</th></tr></thead>
            <tbody>
              {sboms.map(s => (
                <tr key={s.id} className="row" onClick={() => setSbomOpen(s)}>
                  <td><span style={{ fontWeight: 500, color: '#0B1928' }}>{s.file_name}</span></td>
                  <td><Pill kind="blue">{s.format}</Pill></td>
                  <td>{s.depth === 'top_level' ? t('Nur direkte Abhängigkeiten') : t('Alle Abhängigkeiten')}</td>
                  <td>{s.generated_at ? fmtD(s.generated_at) : '—'}</td>
                  <td>{fmtD(s.imported_at)}</td>
                  <td>{s.component_count}</td>
                </tr>
              ))}
              {!sboms.length && <tr><td colSpan={6} style={{ color: '#B6C1CD', textAlign: 'center', padding: 30 }}>
                {t('Noch keine SBOM für')} {product?.name} {version?.version}</td></tr>}
            </tbody>
          </table>
        </div>
      </>}

      {/* ---------- Reiter 3: Funde (Schwachstellen auf dem Inventar) ---------- */}
      {tab === 'funde' && <>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px 0' }}>
          <span className="muted" style={{ flex: 1 }}>{t('Der Abgleich findet Software automatisch. Was per Mail, Lieferanten-Advisory oder aus eigenen Tests hereinkommt, erfasst du hier.')}</span>
          <button className="ab sm" onClick={() => setModal('fund')} disabled={!version}>{t('+ Fund erfassen')}</button>
        </div>
        <div className="tblwrap sc" style={{ marginTop: 10 }}>
          <table className="tbl">
            <thead><tr><th>{t('Schwere')}</th><th style={{ width: '28%' }}>{t('Schwachstelle')}</th><th>{t('Komponente')}</th><th>{t('Behebung')}</th><th>{t('Betroffenheit')}</th><th>{t('Entscheidung')}</th><th>{t('Verantwortlich')}</th></tr></thead>
            <tbody>
              {findRows.map(f => (
                <tr key={f.id} className="row" onClick={() => setFindOpen(f)}>
                  <td><SevPill f={f} />{!!f.actively_exploited && <div style={{ marginTop: 4 }}><Pill kind="red">{t('Aktiv ausgenutzt')}</Pill></div>}</td>
                  <td>
                    <span className="link">{(f.aliases || '').split(', ').find(a => a.startsWith('CVE-')) || f.vuln_id}</span>
                    {(f.aliases || '').includes('CVE-') && <span style={{ display: 'block', fontSize: 11, color: '#B6C1CD' }}>{f.vuln_id}</span>}
                    <span style={{ display: 'block', fontSize: 12, color: '#8B95A3' }}>{(f.summary || '').slice(0, 100)}{(f.summary || '').length > 100 ? ' …' : ''}</span>
                  </td>
                  <td>{f.component_name || '—'}{f.component_version ? <span className="muted" style={{ marginLeft: 5 }}>{f.component_version}</span> : null}</td>
                  <td>
                    {f.fix_version
                      ? <Pill kind="blue" title={t('Gewählte Zielversion')}>{t('auf')} {f.fix_version}</Pill>
                      : f.fix_status === 'none'
                        ? <Pill kind="red">{t('keine Behebung')}</Pill>
                        : f.fixed_versions
                          ? <span style={{ fontSize: 12 }}>{f.fixed_versions.split(', ').slice(0, 2).join(', ')}{f.fixed_versions.split(', ').length > 2 ? ' …' : ''}</span>
                          : <span className="muted">—</span>}
                  </td>
                  <td><VexPill v={f.vex_status} /></td>
                  <td>{f.decision ? t(DECISIONS.find(d => d[0] === f.decision)?.[1] || f.decision) : <span className="muted">{t('offen')}</span>}
                    {f.decision === 'accept' && f.accept_until && <span className="muted" style={{ display: 'block' }}>{t('bis')} {fmtD(f.accept_until)}</span>}</td>
                  <td>{f.owner || (product?.owner ? <span className="muted" title={t('vom Produkt übernommen')}>{product.owner}</span> : <span className="muted">—</span>)}</td>
                </tr>
              ))}
              {!findRows.length && <tr><td colSpan={7} style={{ color: '#B6C1CD', textAlign: 'center', padding: 30 }}>
                {findings.length ? (q ? t('Keine Treffer für die Suche.') : t('Keine Funde für diesen Filter.')) : t('Noch keine Funde — oben „Auf Schwachstellen prüfen“ starten oder einen Fund erfassen.')}</td></tr>}
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
      {modal === 'fund' && <NewFindingModal onClose={() => setModal(null)} />}
      {compOpen && <ComponentDrawer comp={compOpen === 'neu' ? null : compOpen} onClose={() => setCompOpen(null)}
        onOpenFinding={x => { setCompOpen(null); setFindOpen(x) }} />}
      {findOpen && <FindingDrawer finding={findOpen} onClose={() => setFindOpen(null)} />}
      {sbomOpen && <SbomDrawer sbom={sboms.find(s => s.id === sbomOpen.id) || sbomOpen} onClose={() => setSbomOpen(null)} />}
    </main>
  )
}
