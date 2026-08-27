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
  ['test', 'Eigene Tests (Teil II Nr. 3)'],
  ['csirt', 'Hinweis über CSIRT (Art. 15 Abs. 4)'],
  ['other', 'Sonstiges'],
]
const intakeLabel = v => (INTAKE.find(x => x[0] === v) || [v, v])[1]

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
      <div className="dsub">{t('Produkt mit digitalen Elementen (Art. 3 Nr. 1). Die Konformität hängt an der Version (Anhang VII Nr. 1 Buchst. b).')}</div>
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
  const [ver, setVer] = useState(''); const [copy, setCopy] = useState(true)
  const save = async () => {
    const res = await call('POST', '/api/products/' + product.id + '/versions',
      { version: ver, copyFrom: copy ? sel.vid : null }, { reloadProducts: true })
    setSel({ pid: product.id, vid: res.versionId }); onClose()
  }
  return (
    <Modal onClose={onClose} width={480}>
      <div style={{ display: 'flex', alignItems: 'center' }}><span className="dtitle" style={{ flex: 1 }}>{t('Neue Version —')} {product.name}</span><CloseX onClick={onClose} /></div>
      <div className="dsub">{t('Jede Version führt Komponenten, SBOMs und Funde getrennt.')}</div>
      <div className="fieldlab">{t('Versionsbezeichnung')}</div>
      <input className="field" value={ver} onChange={e => setVer(e.target.value)} placeholder="z. B. 1.1.0" autoFocus />
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 16 }}>
        <Toggle on={copy} onChange={setCopy} />
        <span style={{ fontSize: 13 }}>{t('Komponenten aus')} <b>{version?.version}</b> {t('übernehmen (Funde und SBOMs bewusst nicht)')}</span>
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 18 }}>
        <button className="hb" onClick={onClose}>{t('Abbrechen')}</button>
        <button className="ab" disabled={!ver.trim()} onClick={save}>{t('Anlegen')}</button>
      </div>
    </Modal>
  )
}

// ---------- Komponenten-Drawer (anlegen/bearbeiten) ----------
function ComponentDrawer({ comp, onClose }) {
  const t = useT()
  const { call, sel } = useStore()
  const [f, setF] = useState(comp ? { ...comp } : {
    kind: 'software_oss', name: '', version: '', supplier: '', purl: '', cpe: '', license: '',
    is_core_function: 0, dd_status: 'offen', dd_note: '',
  })
  const set = (k, v) => setF(x => ({ ...x, [k]: v }))
  const isHw = f.kind === 'hardware'
  const isOwn = f.kind === 'software_eigen'
  const save = async () => {
    if (comp) await call('PATCH', '/api/components/' + comp.id, f)
    else await call('POST', '/api/versions/' + sel.vid + '/components', f)
    onClose()
  }
  const del = async () => { if (confirm(t('Komponente löschen? Zugehörige Funde werden mit entfernt.'))) { await call('DELETE', '/api/components/' + comp.id); onClose() } }
  return (
    <Drawer onClose={onClose}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span className="dtitle" style={{ flex: 1 }}>{comp ? f.name || 'Komponente' : 'Komponente hinzufügen'}</span>
        {comp?.source === 'sbom_import' && <Pill kind="blue">{t('aus SBOM-Import')}</Pill>}
        <CloseX onClick={onClose} />
      </div>
      <div className="dsub">{t('Komponente = Software oder Hardware (Art. 3 Nr. 6). Hardware steht im Inventar, nicht in der SBOM (Art. 3 Nr. 39).')}</div>

      <div className="fieldlab">{t('Typ')}</div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {KINDS.map(([k, label]) => (
          <span key={k} className={'tabpill' + (f.kind === k ? ' active' : '')} onClick={() => set('kind', k)}>{t(label)}</span>
        ))}
      </div>
      {isHw && <div className="hintbox" style={{ margin: '10px 0 0' }}>{t('Hardware: kein SBOM-Eintrag; Schwachstellen kommen über Lieferanten-Advisories (Sorgfalts-Baseline, Art. 13 Abs. 5 / ENISA 4.14) — Identifikation optional über cpe.')}</div>}

      <div style={{ display: 'flex', gap: 12 }}>
        <div style={{ flex: 2 }}><div className="fieldlab">{t('Name')}</div><input className="field" value={f.name} onChange={e => set('name', e.target.value)} /></div>
        <div style={{ flex: 1 }}><div className="fieldlab">{t('Version')}</div><input className="field" value={f.version} onChange={e => set('version', e.target.value)} /></div>
      </div>
      <div className="fieldlab">{t('Lieferant')} <span className="fund">{isOwn ? t('— entfällt bei Eigenentwicklung') : t('(Verknüpfung ins Lieferantenmanagement)')}</span></div>
      <input className="field" value={f.supplier} onChange={e => set('supplier', e.target.value)} disabled={isOwn} />
      {!isHw && <>
        <div className="fieldlab">purl <span className="fund">{t('(Package URL — Schlüssel für den OSV-Abgleich)')}</span></div>
        <input className="field" value={f.purl} onChange={e => set('purl', e.target.value)} placeholder="pkg:npm/lodash@4.17.21" />
      </>}
      <div className="fieldlab">cpe <span className="fund">{t('(für Hardware/Firmware — NVD-Identifikation, optional)')}</span></div>
      <input className="field" value={f.cpe} onChange={e => set('cpe', e.target.value)} placeholder="cpe:2.3:h:…" />
      <div className="fieldlab">{t('Lizenz')} <span className="fund">{t('(nur mitgespeichert — keine Lizenzanalyse, D-006)')}</span></div>
      <input className="field" value={f.license} onChange={e => set('license', e.target.value)} />

      <div className="fieldlab">{t('Kernfunktion des Produkts?')} <span className="fund">{t('(Abwägungsfaktor Unterstützungszeitraum, Art. 13 Abs. 8)')}</span></div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Toggle on={!!f.is_core_function} onChange={v => set('is_core_function', v ? 1 : 0)} />
        <span className="muted">{f.is_core_function ? 'Ja — Unterstützungszeitraum des Lieferanten berücksichtigen' : 'Nein'}</span>
      </div>

      {!isOwn && <>
        <div className="fieldlab">{t('Sorgfaltsnachweis')} <span className="fund">{t('(Art. 13 Abs. 5 — Baseline-Verweis genügt; Lieferanten-SBOM ist optional, D-016)')}</span></div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
          <Toggle on={f.dd_status === 'geprueft'} onChange={v => set('dd_status', v ? 'geprueft' : 'offen')} />
          {f.dd_status === 'geprueft' ? <Pill kind="green">{t('Geprüft')}</Pill> : <Pill kind="amber">{t('Offen')}</Pill>}
        </div>
        <textarea className="field" rows={3} value={f.dd_note} onChange={e => set('dd_note', e.target.value)}
          placeholder={t('z. B. Lieferanten-Baseline 2026 (Security-Kontakt, Patch-Zusagen) im Lieferantenmanagement abgelegt')} />
      </>}
      {isOwn && <div className="hintbox" style={{ margin: '14px 0 0' }}>{t('Eigenentwicklung: keine Sorgfaltspflicht nach Art. 13 Abs. 5 — stattdessen regelmäßige Tests (Anhang I Teil II Nr. 3).')}</div>}

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 20 }}>
        {comp && <button className="hb" style={{ color: '#DC2626', marginRight: 'auto' }} onClick={del}>{t('Löschen')}</button>}
        <button className="hb" onClick={onClose}>{t('Abbrechen')}</button>
        <button className="ab" disabled={!f.name.trim()} onClick={save}>{t('Speichern')}</button>
      </div>
    </Drawer>
  )
}

// ---------- Funde: Triage-Drawer ----------
function FindingDrawer({ finding, onClose }) {
  const { t, lang } = useI18n()
  const T = (de, en) => (lang === 'en' ? en : de)
  const { call, product, version } = useStore()
  const [f, setF] = useState({ ...finding })
  const set = (k, v) => setF(x => ({ ...x, [k]: v }))
  const save = async () => { await call('PATCH', '/api/findings/' + finding.id, f); onClose() }
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
        {!!f.actively_exploited && <Pill kind="red" title={t('Art. 3 Nr. 42 — startet die Art.-14-Meldekette')}>{t('Aktiv ausgenutzt')}</Pill>}
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

      <div className="fieldlab">{t('Betroffenheit (VEX-Status)')} <span className="fund">{t('— erster Triage-Schritt (PT2.2, Art. 13 Abs. 7)')}</span></div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {VEX_STATI.map(([v, label]) => (
          <span key={v} className={'tabpill' + (f.vex_status === v ? ' active' : '')} onClick={() => set('vex_status', v)}>{t(label)}</span>
        ))}
      </div>
      <div className="fieldlab">{t('Begründung')}</div>
      <textarea className="field" rows={2} value={f.vex_justification}
        placeholder={f.vex_status === 'not_affected' ? 'z. B. die verwundbare Funktion wird nicht aufgerufen (code_not_reachable)' : 'Einschätzung, Analyse-Stand'}
        onChange={e => set('vex_justification', e.target.value)} />

      <div className="fieldlab">{t('Entscheidung')} <span className="fund">{t('(ENISA 4.13: fix / mitigate / accept befristet / defer begründet)')}</span></div>
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
          placeholder={t('Begründung (Pflicht bei accept/defer)')} onChange={e => set('decision_rationale', e.target.value)} />
      )}

      <div style={{ display: 'flex', gap: 12 }}>
        <div style={{ flex: 1 }}>
          <div className="fieldlab">{t('Verantwortlich')} <span className="fund">{t('(ENISA 4.13: ein Owner je Fund)')}</span></div>
          <input className="field" value={f.owner} onChange={e => set('owner', e.target.value)} placeholder={t('Name')} />
        </div>
        <div style={{ flex: 1 }}>
          <div className="fieldlab">{t('Kenntnis am')} <span className="fund">{t('(startet Fristen, Art. 14)')}</span></div>
          <input type="datetime-local" className="field" value={toLocal(f.became_known_at)} onChange={e => set('became_known_at', fromLocal(e.target.value))} />
        </div>
      </div>

      <div className="fieldlab">{t('Aktiv ausgenutzt?')} <span className="fund">{t('(Art. 3 Nr. 42 — nie aus CVSS ableiten)')}</span></div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Toggle on={!!f.actively_exploited} onChange={v => set('actively_exploited', v ? 1 : 0)} />
        <span className="muted">{f.actively_exploited ? t('Ja — verlässliche Nachweise erforderlich, löst Art. 14 Abs. 1 aus') : t('Nein / keine Nachweise')}</span>
      </div>
      {!!f.actively_exploited && <>
        <textarea className="field" rows={2} style={{ marginTop: 8 }} value={f.exploit_evidence}
          placeholder={t('Nachweis (Pflichtfeld): worauf stützt sich die Einstufung?')} onChange={e => set('exploit_evidence', e.target.value)} />
        <div className="hintbox" style={{ margin: '10px 0 0' }}>
          <b style={{ color: '#0B1928' }}>{t('Meldepflicht (Art. 14 Abs. 2):')}</b>{t('Frühwarnung ≤ 24 h, Meldung ≤ 72 h ab Kenntnis, Abschlussbericht ≤ 14 Tage ab Verfügbarkeit der Korrekturmaßnahme. Die Meldekette nach Art. 14 gehört in das Modul')}<b>Meldungen</b>{t('und ist hier bewusst nicht enthalten.')}</div>
      </>}

      <div className="fieldlab">{t('Upstream-Meldung')} <span className="fund">{t('(Art. 13 Abs. 6 — an den Komponentenhersteller)')}</span></div>
      <div style={{ display: 'flex', gap: 12 }}>
        <input className="field" style={{ flex: 2 }} value={f.upstream_reported_to} placeholder={t('Gemeldet an (Hersteller/Wartende)')} onChange={e => set('upstream_reported_to', e.target.value)} />
        <input type="date" className="field" style={{ flex: 1 }} value={f.upstream_reported_at} onChange={e => set('upstream_reported_at', e.target.value)} />
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 8 }}>
        <Toggle on={!!f.upstream_fix_shared} onChange={v => set('upstream_fix_shared', v ? 1 : 0)} />
        <span className="muted">{t('Fix-Code oder Unterlagen geteilt')}</span>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 20 }}>
        {f.vex_status === 'fixed' && <button className="hb" style={{ marginRight: 'auto' }} onClick={advisory}>{t('Advisory-Entwurf (PT2.4) ↓')}</button>}
        <button className="hb" onClick={onClose}>{t('Abbrechen')}</button>
        <button className="ab" onClick={save}>{t('Speichern')}</button>
      </div>
    </Drawer>
  )
}

// ---------- SBOM-Drawer ----------
function SbomDrawer({ sbom, onClose }) {
  const t = useT()
  const { call } = useStore()
  const [loc, setLoc] = useState(sbom.access_location || '')
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

      <div className="fieldlab">{t('Tiefe')} <span className="fund">{t('(Anhang I Teil II Nr. 1: oberste Abhängigkeiten genügen)')}</span></div>
      <div style={{ display: 'flex', gap: 8 }}>
        <span className={'tabpill' + (sbom.depth === 'top_level' ? ' active' : '')} onClick={() => patch({ depth: 'top_level' })}>{t('Oberste Abhängigkeiten')}</span>
        <span className={'tabpill' + (sbom.depth === 'full' ? ' active' : '')} onClick={() => patch({ depth: 'full' })}>{t('Vollständig aufgelöst')}</span>
      </div>

      <div className="fieldlab">{t('An Nutzer bereitgestellt?')} <span className="fund">{t('(keine Pflicht — nur dann Angabe des Zugangs, Anhang II Nr. 9)')}</span></div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Toggle on={!!sbom.provided_to_users} onChange={v => patch({ provided_to_users: v })} />
        <span className="muted">{sbom.provided_to_users ? 'Ja — Zugangsort unten angeben (wandert in die Nutzerinformationen)' : 'Nein (Standard)'}</span>
      </div>
      {!!sbom.provided_to_users && (
        <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
          <input className="field" value={loc} onChange={e => setLoc(e.target.value)} placeholder={t('Zugangsort, z. B. https://…/sbom')} />
          <button className="hb" onClick={() => patch({ access_location: loc })}>{t('Übernehmen')}</button>
        </div>
      )}

      <div className="hintbox" style={{ margin: '16px 0 0' }}>{t('Auf begründetes Verlangen der Marktüberwachungsbehörde ist die SBOM Teil der technischen Dokumentation (Anhang VII Nr. 8) — Download unten. Format bleibt offen, bis der Durchführungsrechtsakt nach Art. 13 Abs. 24 vorliegt.')}</div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 20 }}>
        <button className="hb" style={{ color: '#DC2626', marginRight: 'auto' }} onClick={del}>{t('Löschen')}</button>
        <a className="ab" style={{ textDecoration: 'none' }} href={'/api/sboms/' + sbom.id + '/download'}>{t('Herunterladen (Anhang VII Nr. 8)')}</a>
      </div>
    </Drawer>
  )
}

// ---------- Manuelle Fund-Erfassung (D-020): Eingang kommt per Mail/Advisory, hier wird nur dokumentiert ----------
function NewFindingModal({ onClose }) {
  const t = useT()
  const { call, sel, data } = useStore()
  const [f, setF] = useState({
    vuln_id: '', component_id: '', severity: '—', summary: '',
    intake_channel: 'cvd_mail', became_known_at: new Date().toISOString(),
  })
  const set = (k, v) => setF(x => ({ ...x, [k]: v }))
  const save = async () => { await call('POST', '/api/versions/' + sel.vid + '/findings', f); onClose() }
  return (
    <Modal onClose={onClose} width={560}>
      <div style={{ display: 'flex', alignItems: 'center' }}><span className="dtitle" style={{ flex: 1 }}>{t('Fund erfassen')}</span><CloseX onClick={onClose} /></div>
      <div className="dsub">{t('Für Meldungen, die außerhalb des Scans hereinkommen — per Mail an die Kontaktadresse (Teil II Nr. 6), Lieferanten-Advisory oder CSIRT-Hinweis. Der Kenntniszeitpunkt startet die Fristen (Art. 14): im Zweifel zählt der Mail-Eingang.')}</div>
      <div style={{ display: 'flex', gap: 12 }}>
        <div style={{ flex: 1 }}><div className="fieldlab">{t('Kennung')}</div>
          <input className="field" value={f.vuln_id} onChange={e => set('vuln_id', e.target.value)} placeholder={t('CVE-2026-… oder intern')} autoFocus /></div>
        <div style={{ flex: 1 }}><div className="fieldlab">{t('Schwere (vorläufig)')}</div>
          <select className="field" value={f.severity} onChange={e => set('severity', e.target.value)}>
            {SEVS.map(([k, label]) => <option key={k} value={k}>{t(label)}</option>)}
          </select></div>
      </div>
      <div className="fieldlab">{t('Betroffene Komponente')}</div>
      <select className="field" value={f.component_id} onChange={e => set('component_id', e.target.value)}>
        <option value="">{t('— noch unklar —')}</option>
        {(data?.components || []).map(c => <option key={c.id} value={c.id}>{c.name} {c.version}</option>)}
      </select>
      <div className="fieldlab">{t('Beschreibung / Inhalt der Meldung')}</div>
      <textarea className="field" rows={3} value={f.summary} onChange={e => set('summary', e.target.value)} />
      <div style={{ display: 'flex', gap: 12 }}>
        <div style={{ flex: 1 }}><div className="fieldlab">{t('Eingangskanal')}</div>
          <select className="field" value={f.intake_channel} onChange={e => set('intake_channel', e.target.value)}>
            {INTAKE.filter(([v]) => v !== 'osv_scan').map(([v, label]) => <option key={v} value={v}>{t(label)}</option>)}
          </select></div>
        <div style={{ flex: 1 }}><div className="fieldlab">{t('Kenntnis am')}</div>
          <input type="datetime-local" className="field" value={toLocal(f.became_known_at)} onChange={e => set('became_known_at', fromLocal(e.target.value))} /></div>
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 18 }}>
        <button className="hb" onClick={onClose}>{t('Abbrechen')}</button>
        <button className="ab" disabled={!f.vuln_id.trim()} onClick={save}>{t('Erfassen')}</button>
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
            <Section title={t('Neu hinzugekommen — Kandidaten für die Sorgfaltsprüfung (Art. 13 Abs. 5, ENISA 4.14)')} kind="green" rows={diff.added}
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
      <div className="hintbox" style={{ margin: '0 16px 14px' }}>
        <b style={{ color: '#0B1928' }}>{t('Automatische Dokumentation:')}</b>{t('Dieser Vergleich wird live aus den je Version getrennt gespeicherten Inventaren berechnet — niemand pflegt ein Changelog. Zusätzlich protokolliert das Audit-Log jede einzelne Änderung mit Zeitstempel (Art. 13 Abs. 7). Ob eine Änderung „wesentlich" ist (Art. 3 Nr. 30), entscheidet der Mensch — der Vergleich liefert die Grundlage.')}</div>
    </>
  )
}

// ---------- Hauptseite ----------
export default function SbomTool() {
  const t = useT()
  const { products, product, version, sel, setSel, data, call, busy, notice, setNotice, reloadProducts } = useStore()
  const [q, setQ] = useState('')
  const [tab, setTab] = useState('komponenten')
  const [kindFilter, setKindFilter] = useState(null)
  const [sevFilter, setSevFilter] = useState(null)
  const [vexFilter, setVexFilter] = useState(null)
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
        const list = raw.map(c => ({
          name: c.name || '?', version: c.version || c.versionInfo || '',
          purl: c.purl || (c.externalRefs || []).find(r => r.referenceType === 'purl')?.referenceLocator || '',
          supplier: c.supplier?.name || c.publisher || (typeof c.supplier === 'string' ? c.supplier.replace(/^Organization: /, '') : '') || '',
          license: (c.licenses && (c.licenses[0]?.license?.id || c.licenses[0]?.expression)) || c.licenseConcluded || '',
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
  const geprueft = components.filter(c => c.kind === 'software_eigen' || c.dd_status === 'geprueft').length
  const triaged = findings.filter(f => f.vex_status !== 'under_investigation').length

  const compRows = components
    .filter(c => !kindFilter || c.kind === kindFilter)
    .filter(c => !q || (c.name + ' ' + c.purl + ' ' + c.supplier).toLowerCase().includes(q.toLowerCase()))
  const findRows = findings
    .filter(f => !sevFilter || (f.severity in sevCounts ? f.severity : '—') === sevFilter)
    .filter(f => !vexFilter || f.vex_status === vexFilter)
    .filter(f => !q || (f.vuln_id + ' ' + (f.component_name || '') + ' ' + f.summary).toLowerCase().includes(q.toLowerCase()))

  // ---------- Leerer Zustand ----------
  if (!products.length) return (
    <main className="main">
      <TitleBar title={t('SBOM & Komponenten')} />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 12 }}>
        <div style={{ fontSize: 17, fontWeight: 700, color: '#0B1928' }}>{t('Noch kein Produkt angelegt')}</div>
        <div className="muted" style={{ maxWidth: 500, textAlign: 'center', lineHeight: 1.7 }}>{t('Komponenten, SBOMs und Funde hängen an der Produktversion (Anhang I Teil II Nr. 1). Lege ein Produkt mit seiner ersten Version an und importiere anschließend die SBOM, die dein Build erzeugt hat — eine echte Beispiel-SBOM liegt im Ordner')}<code>sboms/</code>.
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
        <button className="hb" onClick={runScan} disabled={busy || !components.some(c => c.purl && c.kind !== 'hardware')}>
          {busy ? t('Bitte warten …') : t('CVE-Abgleich (OSV)')}
        </button>
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
        <select className="field" style={{ width: 'auto', height: 36, padding: '0 12px', borderRadius: 10 }}
          value={version?.id || ''} onChange={e => setSel({ pid: product.id, vid: e.target.value })}>
          {(product?.versions || []).map(v => <option key={v.id} value={v.id}>{t('Version:')} {v.version}</option>)}
        </select>
        <button className="hb sm" onClick={() => setModal('version')}>{t('+ Version')}</button>
        <button className="hb sm" onClick={() => setModal('produkt')}>{t('+ Produkt')}</button>
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
          <div className="l">{t('Sorgfalt (Art. 13 Abs. 5)')}</div>
          <div className="v">{geprueft}<span style={{ fontSize: 13, fontWeight: 500, color: '#8B95A3' }}> / {components.length}</span></div>
          <div className="progress" style={{ marginTop: 7 }}><div style={{ width: (components.length ? geprueft / components.length * 100 : 0) + '%', background: '#27AE60' }} /></div>
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
          <div className="s">{findings.filter(f => f.actively_exploited).length} {t('aktiv ausgenutzt (Art. 14!)')}</div>
        </div>
      </div>

      {notice && <div style={{ padding: '10px 16px 0' }}><Pill kind={notice.err ? 'red' : 'green'}>{notice.msg}</Pill> <span className="link" style={{ fontSize: 12 }} onClick={() => setNotice(null)}>{t('ausblenden')}</span></div>}

      <div className="tabrow">
        <span className={'tabpill' + (tab === 'komponenten' ? ' active' : '')} onClick={() => setTab('komponenten')}>{t('Komponenten')} ({components.length})</span>
        <span className={'tabpill' + (tab === 'sboms' ? ' active' : '')} onClick={() => setTab('sboms')}>{t('SBOMs')} ({sboms.length})</span>
        <span className={'tabpill' + (tab === 'funde' ? ' active' : '')} onClick={() => setTab('funde')}>{t('Funde')} ({findings.length})</span>
        <span className={'tabpill' + (tab === 'aenderungen' ? ' active' : '')} onClick={() => setTab('aenderungen')}>{t('Änderungen')}</span>
        <span style={{ flex: 1 }} />
        {tab === 'komponenten' && <button className="hb sm" onClick={() => setCompOpen('neu')}>{t('+ Komponente')}</button>}
        {tab === 'funde' && <button className="hb sm" onClick={() => setModal('fund')}>{t('+ Fund erfassen')}</button>}
      </div>

      {/* ---------- Reiter 1: Komponenten (Inventar = Obermenge, Abschnitt 1.6) ---------- */}
      {tab === 'komponenten' && <>
        <div style={{ display: 'flex', gap: 6, padding: '10px 16px 0', flexWrap: 'wrap' }}>
          <span className={'sevchip' + (kindFilter === null ? ' active' : '')} onClick={() => setKindFilter(null)}>{t('Alle')}</span>
          {KINDS.map(([k, label]) => (
            <span key={k} className={'sevchip' + (kindFilter === k ? ' active' : '')} onClick={() => setKindFilter(kindFilter === k ? null : k)}>
              {t(label)} <b>{components.filter(c => c.kind === k).length}</b>
            </span>
          ))}
        </div>
        <div className="tblwrap sc">
          <table className="tbl">
            <thead><tr><th style={{ width: '28%' }}>{t('Komponente')}</th><th>{t('Typ')}</th><th>{t('Version')}</th><th>{t('Lieferant')}</th><th>{t('SBOM')}</th><th>{t('Schwachstellen')}</th><th>{t('Sorgfalt')}</th></tr></thead>
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
                    <td><Pill kind={kindColor}>{t(kindLabel)}</Pill>{!!c.is_core_function && <span className="muted" style={{ marginLeft: 6 }}>{t('Kernfunktion')}</span>}</td>
                    <td>{c.version || '—'}</td>
                    <td>{c.supplier || '—'}</td>
                    <td>{c.kind === 'hardware' ? <Pill kind="neutral">{t('Inventar')}</Pill> : <Pill kind="blue">{t('SBOM')}</Pill>}</td>
                    <td>
                      {fs.length === 0
                        ? <span className="muted">{c.kind === 'hardware' ? 'über Advisories' : 'keine bekannt'}</span>
                        : <span style={{ display: 'inline-flex', gap: 5 }}>
                            {SEVS.map(([k, , col]) => grp[k] ? <span key={k} className="sevbadge" style={{ background: col }} title={k}>{grp[k]}</span> : null)}
                          </span>}
                    </td>
                    <td>
                      {c.kind === 'software_eigen'
                        ? <span className="muted">{t('entfällt')}</span>
                        : c.dd_status === 'geprueft' ? <Pill kind="green">{t('Geprüft')}</Pill> : <Pill kind="amber">{t('Offen')}</Pill>}
                    </td>
                  </tr>
                )
              })}
              {!compRows.length && <tr><td colSpan={7} style={{ color: '#B6C1CD', textAlign: 'center', padding: 30 }}>
                {components.length ? 'Keine Komponenten für diesen Filter.' : 'Noch keine Komponenten — SBOM importieren oder Hardware/Software manuell anlegen.'}</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="hintbox" style={{ margin: '0 16px 14px' }}>
          <b style={{ color: '#0B1928' }}>{t('Pflicht (Anhang I Teil II Nr. 1):')}</b>{t('Komponenten ermitteln und dokumentieren — Hardware und Software. In die SBOM gehört nur die Software (Art. 3 Nr. 39); Hardware läuft über das Lieferantenmanagement (Art. 13 Abs. 5).')}</div>
      </>}

      {/* ---------- Reiter 2: SBOMs je Version ---------- */}
      {tab === 'sboms' && <>
        <div className="tblwrap sc" style={{ marginTop: 10 }}>
          <table className="tbl">
            <thead><tr><th style={{ width: '30%' }}>{t('Datei')}</th><th>{t('Format')}</th><th>{t('Tiefe')}</th><th>{t('Erstellt')}</th><th>{t('Importiert')}</th><th>{t('Komponenten')}</th><th>{t('Nutzer-Bereitstellung')}</th></tr></thead>
            <tbody>
              {sboms.map(s => (
                <tr key={s.id} className="row" onClick={() => setSbomOpen(s)}>
                  <td><span style={{ fontWeight: 500, color: '#0B1928' }}>{s.file_name}</span></td>
                  <td><Pill kind="blue">{s.format}</Pill></td>
                  <td>{s.depth === 'top_level' ? 'oberste Abhängigkeiten' : 'vollständig'}</td>
                  <td>{s.generated_at ? fmtD(s.generated_at) : '—'}</td>
                  <td>{fmtD(s.imported_at)}</td>
                  <td>{s.component_count}</td>
                  <td>{s.provided_to_users ? <Pill kind="green">{t('Ja — Anhang II Nr. 9')}</Pill> : <Pill kind="neutral">{t('Nein (keine Pflicht)')}</Pill>}</td>
                </tr>
              ))}
              {!sboms.length && <tr><td colSpan={7} style={{ color: '#B6C1CD', textAlign: 'center', padding: 30 }}>
                {t('Noch keine SBOM für')} {product?.name} {version?.version} {t('— oben „SBOM importieren" (CycloneDX- oder SPDX-JSON).')}</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="hintbox" style={{ margin: '0 16px 14px' }}>
          <b style={{ color: '#0B1928' }}>{t('Historie je Version (Art. 13 Abs. 7):')}</b>{t('jeder importierte Stand bleibt archiviert und ist für die Marktüberwachung exportierbar (Anhang VII Nr. 8). Eine Herausgabe an Nutzer ist keine Pflicht (Anhang II Nr. 9).')}</div>
      </>}

      {/* ---------- Reiter 3: Funde (Schwachstellen auf dem Inventar) ---------- */}
      {tab === 'funde' && <>
        <div style={{ display: 'flex', gap: 6, padding: '10px 16px 0', flexWrap: 'wrap', alignItems: 'center' }}>
          <span className={'sevchip' + (sevFilter === null ? ' active' : '')} onClick={() => setSevFilter(null)}>{t('Alle')}</span>
          {SEVS.map(([k, label, c]) => (
            <span key={k} className={'sevchip' + (sevFilter === k ? ' active' : '')} onClick={() => setSevFilter(sevFilter === k ? null : k)}>
              <span className="dot" style={{ background: c }} />{t(label)} <b>{sevCounts[k]}</b>
            </span>
          ))}
          <span style={{ width: 14 }} />
          {VEX_STATI.map(([v, label]) => (
            <span key={v} className={'sevchip' + (vexFilter === v ? ' active' : '')} onClick={() => setVexFilter(vexFilter === v ? null : v)}>
              {t(label)} <b>{findings.filter(f => f.vex_status === v).length}</b>
            </span>
          ))}
        </div>
        <div className="tblwrap sc">
          <table className="tbl">
            <thead><tr><th>{t('Schwere')}</th><th style={{ width: '28%' }}>{t('Schwachstelle')}</th><th>{t('Komponente')}</th><th>{t('Behebung')}</th><th>{t('Betroffenheit')}</th><th>{t('Entscheidung')}</th><th>{t('Verantwortlich')}</th></tr></thead>
            <tbody>
              {findRows.map(f => (
                <tr key={f.id} className="row" onClick={() => setFindOpen(f)}>
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
              {!findRows.length && <tr><td colSpan={7} style={{ color: '#B6C1CD', textAlign: 'center', padding: 30 }}>
                {findings.length ? 'Keine Funde für diesen Filter.' : 'Noch keine Funde — oben „CVE-Abgleich (OSV)" starten (Software mit purl nötig).'}</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="hintbox" style={{ margin: '0 16px 14px' }}>
          <b style={{ color: '#0B1928' }}>{t('Triage (PT2.2, ENISA 4.13):')}</b>{t('je Fund Betroffenheit (VEX) → Entscheidung (fix/mitigate/accept befristet/defer begründet) → Verantwortlicher. „Aktiv ausgenutzt" (Art. 3 Nr. 42) nie aus CVSS ableiten — Nachweis erfassen; die Art.-14-Meldekette gehört ins Modul Meldungen.')}</div>
      </>}

      {/* ---------- Reiter 4: Änderungen zur Vorversion (automatisch, D-019) ---------- */}
      {tab === 'aenderungen' && <DiffTab versionLabel={version?.version} />}

      {/* Fußzeile: Verwaltung */}
      <div style={{ display: 'flex', gap: 14, padding: '0 16px 12px', alignItems: 'center' }}>
        <span className="muted">{t('Produktverwaltung:')}</span>
        <span className="link" style={{ fontSize: 12 }} onClick={delVersion}>{t('Version löschen')}</span>
        <span className="link" style={{ fontSize: 12 }} onClick={delProduct}>{t('Produkt löschen')}</span>
      </div>

      {modal === 'produkt' && <NewProductModal onClose={() => setModal(null)} />}
      {modal === 'version' && <NewVersionModal onClose={() => setModal(null)} />}
      {modal === 'fund' && <NewFindingModal onClose={() => setModal(null)} />}
      {compOpen && <ComponentDrawer comp={compOpen === 'neu' ? null : compOpen} onClose={() => setCompOpen(null)} />}
      {findOpen && <FindingDrawer finding={findOpen} onClose={() => setFindOpen(null)} />}
      {sbomOpen && <SbomDrawer sbom={sboms.find(s => s.id === sbomOpen.id) || sbomOpen} onClose={() => setSbomOpen(null)} />}
    </main>
  )
}
