// SBOM-Gen — SBOM-Import, Komponenteninventar und CVE-Abgleich fuer das CRA-Modul
// "SBOM & Komponenten". Keine Beispieldaten: jeder Datensatz entsteht durch Import,
// manuelle Eingabe oder den Abgleich gegen OSV.dev.
// Relationale Ablage: Produkte → Versionen → Komponenten / SBOMs / Funde (je Version getrennt).
// Audit-Log: systematische Dokumentation i. S. v. Art. 13 Abs. 7.
import express from 'express'
import Database from 'better-sqlite3'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import crypto from 'node:crypto'

const dir = path.dirname(fileURLToPath(import.meta.url))
const db = new Database(path.join(dir, 'sbom.db'))
db.pragma('journal_mode = WAL')
db.exec(`
  CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, hersteller TEXT DEFAULT '',
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS versions (
    id TEXT PRIMARY KEY, product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    version TEXT NOT NULL, status TEXT DEFAULT 'aktiv', copied_from TEXT, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS components (
    id TEXT PRIMARY KEY, version_id TEXT NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    kind TEXT NOT NULL DEFAULT 'software_oss',      -- hardware | software_eigen | software_oss | software_zukauf
    name TEXT NOT NULL, version TEXT DEFAULT '', supplier TEXT DEFAULT '',
    purl TEXT DEFAULT '', cpe TEXT DEFAULT '', license TEXT DEFAULT '',
    is_direct INTEGER DEFAULT 0,                    -- direkte Abhaengigkeit laut SBOM-Graph
    is_core_function INTEGER DEFAULT 0,             -- Art. 13 Abs. 8 (Unterstützungszeitraum-Begründung)
    dd_status TEXT DEFAULT 'offen',                 -- Sorgfaltspflicht Art. 13 Abs. 5: offen | geprueft
    dd_note TEXT DEFAULT '',                        -- due_diligence_record (Baseline-Verweis genügt)
    source TEXT DEFAULT 'manuell',                  -- manuell | sbom_import
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sboms (
    id TEXT PRIMARY KEY, version_id TEXT NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    file_name TEXT NOT NULL, format TEXT DEFAULT '',           -- Art. 13 Abs. 24: Format offen
    depth TEXT DEFAULT 'top_level',                            -- Anhang I Teil II Nr. 1: top_level genügt
    generated_at TEXT DEFAULT '', imported_at TEXT NOT NULL,
    provided_to_users INTEGER DEFAULT 0,                       -- Anhang II Nr. 9
    access_location TEXT DEFAULT '',
    component_count INTEGER DEFAULT 0, content TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, version_id TEXT NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    component_id TEXT REFERENCES components(id) ON DELETE CASCADE,
    vuln_id TEXT NOT NULL, severity TEXT DEFAULT '—', score REAL, summary TEXT DEFAULT '',
    intake_channel TEXT DEFAULT 'osv_scan',                    -- ENISA 4.13: Eingangskanal festhalten
    became_known_at TEXT NOT NULL,                             -- startet Fristen (Art. 14)
    vex_status TEXT DEFAULT 'under_investigation',             -- Betroffenheitsprüfung (erster Triage-Schritt)
    vex_justification TEXT DEFAULT '',
    decision TEXT DEFAULT '',                                  -- fix_now | mitigate | accept | defer (ENISA 4.13)
    decision_rationale TEXT DEFAULT '', accept_until TEXT DEFAULT '', owner TEXT DEFAULT '',
    actively_exploited INTEGER DEFAULT 0,                      -- Art. 3 Nr. 42 — nie aus CVSS
    exploit_evidence TEXT DEFAULT '',
    upstream_reported_to TEXT DEFAULT '',                      -- Art. 13 Abs. 6
    upstream_reported_at TEXT DEFAULT '', upstream_fix_shared INTEGER DEFAULT 0,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY, version_id TEXT NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    ran_at TEXT NOT NULL, source TEXT DEFAULT '',
    components_scanned INTEGER DEFAULT 0, findings_new INTEGER DEFAULT 0, findings_updated INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, action TEXT NOT NULL, detail TEXT DEFAULT ''
  );
`)

// Abgleich-Parameter (bewusst grosszuegig: echte SBOMs haben hunderte Komponenten)
const QUERY_CHUNK = 400      // purls je querybatch-Request
const DETAIL_PARALLEL = 10   // parallele Detail-Abfragen an /v1/vulns

// Spalten, die erst spaeter dazukamen — bestehende Datenbanken nachziehen
// Komponenten: direkte Abhaengigkeit? Nur fuer diese (und Hardware/Zukauf) ist die
// Sorgfaltspflicht praktikabel — transitive Pakete waehlt niemand aus.
{
  const has = db.prepare('PRAGMA table_info(components)').all().some(c => c.name === 'is_direct')
  if (!has) db.exec('ALTER TABLE components ADD COLUMN is_direct INTEGER DEFAULT 0')
}

for (const [col, ddl] of [
  ['aliases', "TEXT DEFAULT ''"],          // CVE-Nummern zur OSV-/GHSA-ID
  ['cwe_ids', "TEXT DEFAULT ''"],          // Schwachstellenklassen
  ['published', "TEXT DEFAULT ''"],        // Veroeffentlichung des Advisories
  ['fixed_versions', "TEXT DEFAULT ''"],   // Behebung: Versionen aus affected[].ranges
  ['refs_json', "TEXT DEFAULT ''"],        // Advisory-Links (GitHub, NVD, OSV, Hersteller)
  ['fix_version', "TEXT DEFAULT ''"],      // vom Bearbeiter gewaehlte Zielversion
]) {
  const has = db.prepare('PRAGMA table_info(findings)').all().some(c => c.name === col)
  if (!has) db.exec(`ALTER TABLE findings ADD COLUMN ${col} ${ddl}`)
}

const uid = () => crypto.randomBytes(8).toString('hex')
const now = () => new Date().toISOString()
const audit = (action, detail = '') =>
  db.prepare('INSERT INTO audit_log (ts, action, detail) VALUES (?, ?, ?)').run(now(), action, String(detail).slice(0, 400))

const app = express()
app.use(express.json({ limit: '25mb' }))

// ---------- Stammdaten ----------
app.get('/api/bootstrap', (_req, res) => {
  const products = db.prepare('SELECT * FROM products ORDER BY created_at').all()
  const versions = db.prepare('SELECT * FROM versions ORDER BY created_at').all()
  res.json({ products: products.map(p => ({ ...p, versions: versions.filter(v => v.product_id === p.id) })) })
})

app.post('/api/products', (req, res) => {
  const { name, hersteller = '', version = '1.0.0' } = req.body
  if (!name?.trim()) return res.status(400).json({ error: 'Name fehlt' })
  const pid = uid(), vid = uid()
  db.prepare('INSERT INTO products (id, name, hersteller, created_at) VALUES (?, ?, ?, ?)').run(pid, name.trim(), hersteller, now())
  db.prepare('INSERT INTO versions (id, product_id, version, created_at) VALUES (?, ?, ?, ?)').run(vid, pid, version.trim() || '1.0.0', now())
  audit('product.create', name)
  res.json({ productId: pid, versionId: vid })
})

app.delete('/api/products/:id', (req, res) => {
  db.prepare('DELETE FROM products WHERE id = ?').run(req.params.id)
  audit('product.delete', req.params.id)
  res.json({ ok: true })
})

app.post('/api/products/:id/versions', (req, res) => {
  // mode steuert, was aus der Vorversion uebernommen wird:
  //   'unchanged' — Zusammensetzung unveraendert: alle Komponenten UND der SBOM-Stand
  //                 werden uebernommen; die neue Version ist damit sofort belegt
  //                 (Anhang I Teil II Nr. 1 verlangt die SBOM je Produktversion).
  //   'new_sbom'  — Software hat sich geaendert: nur Hardware wird uebernommen,
  //                 weil sie nicht in der SBOM steht (Art. 3 Nr. 39); die Software
  //                 kommt aus der neuen SBOM, die der Aufrufer anschliessend importiert.
  const { version, copyFrom, mode = 'unchanged' } = req.body
  if (!version?.trim()) return res.status(400).json({ error: 'Version fehlt' })
  const vid = uid()
  db.prepare('INSERT INTO versions (id, product_id, version, copied_from, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(vid, req.params.id, version.trim(), copyFrom || null, now())

  let copied = 0, sbomsCopied = 0
  if (copyFrom) {
    const all = db.prepare('SELECT * FROM components WHERE version_id = ?').all(copyFrom)
    const comps = mode === 'new_sbom' ? all.filter(c => c.kind === 'hardware') : all
    const ins = db.prepare(`INSERT INTO components (id, version_id, kind, name, version, supplier, purl, cpe, license,
      is_direct, is_core_function, dd_status, dd_note, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    for (const c of comps) {
      ins.run(uid(), vid, c.kind, c.name, c.version, c.supplier, c.purl, c.cpe, c.license,
        c.is_direct, c.is_core_function, c.dd_status, c.dd_note, c.source, now())
      copied++
    }
    if (mode === 'unchanged') {
      // Denselben SBOM-Stand auch fuer die neue Version dokumentieren.
      const sb = db.prepare('SELECT * FROM sboms WHERE version_id = ? ORDER BY imported_at DESC LIMIT 1').get(copyFrom)
      if (sb) {
        db.prepare(`INSERT INTO sboms (id, version_id, file_name, format, depth, generated_at, imported_at,
          provided_to_users, access_location, component_count, content)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
          .run(uid(), vid, sb.file_name, sb.format, sb.depth, sb.generated_at, now(),
            sb.provided_to_users, sb.access_location, sb.component_count, sb.content)
        sbomsCopied = 1
      }
    }
  }
  audit('version.create', version.trim() + ' · ' + mode + ' · Komponenten: ' + copied + ' · SBOM: ' + sbomsCopied)
  res.json({ versionId: vid, copied, sbomsCopied })
})

app.delete('/api/versions/:id', (req, res) => {
  db.prepare('DELETE FROM versions WHERE id = ?').run(req.params.id)
  audit('version.delete', req.params.id)
  res.json({ ok: true })
})

// ---------- Versionsdaten (Komponenten, SBOMs, Funde, Scans) ----------
const versionData = (vid) => ({
  components: db.prepare('SELECT * FROM components WHERE version_id = ? ORDER BY kind, name').all(vid),
  sboms: db.prepare(`SELECT id, version_id, file_name, format, depth, generated_at, imported_at,
    provided_to_users, access_location, component_count, length(content) AS bytes
    FROM sboms WHERE version_id = ? ORDER BY imported_at DESC`).all(vid),
  findings: db.prepare(`SELECT f.*, c.name AS component_name, c.purl AS component_purl
    FROM findings f LEFT JOIN components c ON c.id = f.component_id
    WHERE f.version_id = ? ORDER BY
      CASE f.severity WHEN 'KRITISCH' THEN 0 WHEN 'HOCH' THEN 1 WHEN 'MITTEL' THEN 2 WHEN 'NIEDRIG' THEN 3 ELSE 4 END,
      f.score DESC`).all(vid),
  scans: db.prepare('SELECT * FROM scans WHERE version_id = ? ORDER BY ran_at DESC LIMIT 5').all(vid),
})
app.get('/api/versions/:id', (req, res) => {
  // Wichtig: unbekannte Version als 404 melden. Leere Listen zurueckzugeben wuerde
  // wie "Version ohne Daten" aussehen — der Client kann das nicht unterscheiden.
  const v = db.prepare('SELECT id FROM versions WHERE id = ?').get(req.params.id)
  if (!v) return res.status(404).json({ error: 'Version nicht gefunden' })
  res.json(versionData(req.params.id))
})

app.post('/api/versions/:id/components', (req, res) => {
  const c = req.body
  if (!c.name?.trim()) return res.status(400).json({ error: 'Name fehlt' })
  db.prepare(`INSERT INTO components (id, version_id, kind, name, version, supplier, purl, cpe, license,
    is_direct, is_core_function, dd_status, dd_note, source, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, 'manuell', ?)`)
    .run(uid(), req.params.id, c.kind || 'software_oss', c.name.trim(), c.version || '', c.supplier || '',
      c.purl || '', c.cpe || '', c.license || '', c.is_core_function ? 1 : 0,
      c.dd_status || 'offen', c.dd_note || '', now())
  audit('component.create', c.name)
  res.json(versionData(req.params.id))
})

app.patch('/api/components/:id', (req, res) => {
  const cur = db.prepare('SELECT * FROM components WHERE id = ?').get(req.params.id)
  if (!cur) return res.status(404).json({ error: 'nicht gefunden' })
  const c = { ...cur, ...req.body }
  db.prepare(`UPDATE components SET kind=?, name=?, version=?, supplier=?, purl=?, cpe=?, license=?,
    is_core_function=?, dd_status=?, dd_note=? WHERE id=?`)
    .run(c.kind, c.name, c.version, c.supplier, c.purl, c.cpe, c.license,
      c.is_core_function ? 1 : 0, c.dd_status, c.dd_note, req.params.id)
  audit('component.update', c.name)
  res.json(versionData(cur.version_id))
})

app.delete('/api/components/:id', (req, res) => {
  const cur = db.prepare('SELECT * FROM components WHERE id = ?').get(req.params.id)
  if (!cur) return res.status(404).json({ error: 'nicht gefunden' })
  db.prepare('DELETE FROM components WHERE id = ?').run(req.params.id)
  audit('component.delete', cur.name)
  res.json(versionData(cur.version_id))
})

// ---------- SBOM-Import (Anhang I Teil II Nr. 1) ----------
app.post('/api/versions/:id/sboms', (req, res) => {
  const { fileName, format, depth = 'top_level', generatedAt = '', components = [], content } = req.body
  const vid = req.params.id
  if (!content) return res.status(400).json({ error: 'Inhalt fehlt' })
  db.prepare(`INSERT INTO sboms (id, version_id, file_name, format, depth, generated_at, imported_at, component_count, content)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(uid(), vid, fileName || 'sbom.json', format || 'SBOM', depth, generatedAt, now(), components.length, content)
  // Software-Einträge ins Komponenteninventar übernehmen (Obermenge, Abschnitt 1.6):
  // Abgleich über purl, sonst Name+Version. Typ/Sorgfalt bestehender Einträge bleiben erhalten.
  const existing = db.prepare('SELECT * FROM components WHERE version_id = ?').all(vid)
  const ins = db.prepare(`INSERT INTO components (id, version_id, kind, name, version, supplier, purl, cpe, license,
    is_direct, is_core_function, dd_status, dd_note, source, created_at)
    VALUES (?, ?, 'software_oss', ?, ?, ?, ?, '', ?, ?, 0, 'offen', '', 'sbom_import', ?)`)
  const upd = db.prepare('UPDATE components SET version=?, supplier=?, license=?, is_direct=?, source=? WHERE id=?')
  let added = 0, updated = 0
  for (const c of components) {
    const direct = c.is_direct ? 1 : 0
    const match = existing.find(e => (c.purl && e.purl === c.purl) || (!c.purl && e.name === c.name))
    if (match) { upd.run(c.version || match.version, c.supplier || match.supplier, c.license || match.license,
                         direct || match.is_direct, 'sbom_import', match.id); updated++ }
    else { ins.run(uid(), vid, c.name, c.version || '', c.supplier || '', c.purl || '', c.license || '', direct, now()); added++ }
  }
  audit('sbom.import', (fileName || '') + ' · +' + added + ' / ~' + updated)
  res.json({ ...versionData(vid), imported: { added, updated } })
})

app.patch('/api/sboms/:id', (req, res) => {
  const cur = db.prepare('SELECT id, version_id FROM sboms WHERE id = ?').get(req.params.id)
  if (!cur) return res.status(404).json({ error: 'nicht gefunden' })
  const { provided_to_users, access_location, depth } = req.body
  if (provided_to_users !== undefined) db.prepare('UPDATE sboms SET provided_to_users=? WHERE id=?').run(provided_to_users ? 1 : 0, cur.id)
  if (access_location !== undefined) db.prepare('UPDATE sboms SET access_location=? WHERE id=?').run(access_location, cur.id)
  if (depth !== undefined) db.prepare('UPDATE sboms SET depth=? WHERE id=?').run(depth, cur.id)
  audit('sbom.update', cur.id)
  res.json(versionData(cur.version_id))
})

app.get('/api/sboms/:id/download', (req, res) => {
  const row = db.prepare('SELECT file_name, content FROM sboms WHERE id = ?').get(req.params.id)
  if (!row) return res.status(404).json({ error: 'nicht gefunden' })
  res.setHeader('Content-Type', 'application/json')
  res.setHeader('Content-Disposition', 'attachment; filename="' + encodeURIComponent(row.file_name) + '"')
  res.send(row.content)
})

app.delete('/api/sboms/:id', (req, res) => {
  const cur = db.prepare('SELECT version_id, file_name FROM sboms WHERE id = ?').get(req.params.id)
  if (!cur) return res.status(404).json({ error: 'nicht gefunden' })
  db.prepare('DELETE FROM sboms WHERE id = ?').run(req.params.id)
  audit('sbom.delete', cur.file_name)
  res.json(versionData(cur.version_id))
})

// ---------- OSV-Scan (PT2.1 „Schwachstellen ermitteln" als Dauerlauf; A-005) ----------
// CVSS-3.x-Basescore aus dem Vektorstring (First.org-Formel)
function cvss3Score(vec) {
  try {
    const m = Object.fromEntries(vec.split('/').slice(1).map(p => p.split(':')))
    const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV]
    const AC = { L: 0.77, H: 0.44 }[m.AC]
    const UI = { N: 0.85, R: 0.62 }[m.UI]
    const scope = m.S === 'C'
    const PR = { N: 0.85, L: scope ? 0.68 : 0.62, H: scope ? 0.5 : 0.27 }[m.PR]
    const cia = k => ({ H: 0.56, L: 0.22, N: 0 }[m[k]])
    const iss = 1 - (1 - cia('C')) * (1 - cia('I')) * (1 - cia('A'))
    const impact = scope ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss
    const expl = 8.22 * AV * AC * PR * UI
    if (impact <= 0) return 0
    return Math.ceil(Math.min(scope ? 1.08 * (impact + expl) : impact + expl, 10) * 10) / 10
  } catch { return null }
}
function sevOf(rec) {
  const MAP = { CRITICAL: 'KRITISCH', HIGH: 'HOCH', MODERATE: 'MITTEL', MEDIUM: 'MITTEL', LOW: 'NIEDRIG' }
  let score = null
  for (const sv of rec.severity || []) {
    if (sv.type === 'CVSS_V3' && sv.score) { const x = cvss3Score(sv.score); if (x != null) score = Math.max(score ?? 0, x) }
  }
  let label = MAP[(rec.database_specific?.severity || '').toUpperCase()] || null
  if (!label && score != null) label = score >= 9 ? 'KRITISCH' : score >= 7 ? 'HOCH' : score >= 4 ? 'MITTEL' : 'NIEDRIG'
  return { label: label || '—', score }
}

// purl ohne Versionsanteil — Schluessel fuer Paketvergleiche
const purlBase = (p) => {
  const i = p.lastIndexOf('@')
  return i > 0 ? p.slice(0, i) : p
}

// Behebung und Quellen aus dem OSV-Datensatz ziehen — beides liefert OSV mit,
// wird aber nur nutzbar, wenn man es speichert und anzeigt.
function remediationOf(rec, componentPurl) {
  const base = purlBase(componentPurl)
  const fixed = new Set(), lastAffected = new Set()
  for (const a of rec.affected || []) {
    const apurl = a.package?.purl
    if (apurl && purlBase(apurl) !== base) continue     // anderes Paket im selben Advisory
    for (const r of a.ranges || []) for (const e of r.events || []) {
      if (e.fixed) fixed.add(e.fixed)
      else if (e.last_affected) lastAffected.add(e.last_affected)
    }
  }
  return { fixed: [...fixed], lastAffected: [...lastAffected] }
}

function sourcesOf(rec) {
  const out = [], seen = new Set()
  const add = (label, url) => { if (url && !seen.has(url)) { seen.add(url); out.push({ label, url }) } }
  add('OSV', 'https://osv.dev/vulnerability/' + rec.id)
  if (rec.id.startsWith('GHSA-')) add('GitHub Advisory', 'https://github.com/advisories/' + rec.id)
  for (const a of rec.aliases || []) {
    if (a.startsWith('CVE-')) add('NVD ' + a, 'https://nvd.nist.gov/vuln/detail/' + a)
    if (a.startsWith('GHSA-')) add('GitHub Advisory', 'https://github.com/advisories/' + a)
  }
  const rank = { ADVISORY: 0, FIX: 1, REPORT: 2, PACKAGE: 3 }
  for (const r of (rec.references || []).filter(r => r.type in rank).sort((x, y) => rank[x.type] - rank[y.type])) {
    if (out.length >= 12) break
    const label = r.type === 'FIX' ? 'Fix' : r.type === 'PACKAGE' ? 'Projekt'
      : r.type === 'REPORT' ? 'Meldung' : 'Advisory'
    add(label, r.url)
  }
  return out
}

app.post('/api/versions/:id/scan', async (req, res) => {
  const vid = req.params.id
  // Nur Software mit purl ist OSV-abgleichbar; Hardware läuft über Lieferanten-Advisories (Abschnitt 8.6).
  const comps = db.prepare("SELECT * FROM components WHERE version_id = ? AND purl != '' AND kind != 'hardware'").all(vid)
  if (!comps.length) return res.status(400).json({ error: 'Keine Software-Komponenten mit purl — erst SBOM importieren oder purl pflegen.' })
  try {
    // querybatch in Bloecken: OSV begrenzt die Anzahl Queries je Request.
    const hits = []   // { component, vulnId }
    for (let i = 0; i < comps.length; i += QUERY_CHUNK) {
      const chunk = comps.slice(i, i + QUERY_CHUNK)
      const ctrl = new AbortController()
      const t = setTimeout(() => ctrl.abort(), 30000)
      const r = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST', signal: ctrl.signal, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries: chunk.map(c => ({ package: { purl: c.purl } })) }),
      })
      clearTimeout(t)
      if (!r.ok) throw new Error('HTTP ' + r.status)
      const j = await r.json()
      // Alle gemeldeten Schwachstellen uebernehmen — keine Begrenzung je Komponente.
      j.results.forEach((row, k) => (row.vulns || []).forEach(v => hits.push({ comp: chunk[k], vulnId: v.id })))
    }
    // Details je Schwachstelle (Schweregrad, CVSS, Kurzbeschreibung), gebündelt zu je 8
    const ids = [...new Set(hits.map(h => h.vulnId))]
    const details = {}
    for (let i = 0; i < ids.length; i += DETAIL_PARALLEL) {
      await Promise.all(ids.slice(i, i + DETAIL_PARALLEL).map(id =>
        fetch('https://api.osv.dev/v1/vulns/' + id).then(r2 => r2.ok ? r2.json() : null)
          .then(rec => { if (rec) details[id] = rec }).catch(() => {})))
    }
    // Upsert: Bewertung immer frisch, Bearbeitungsstand (VEX/Entscheidung/Nachweise) bleibt erhalten
    const existing = db.prepare('SELECT id, vuln_id, component_id FROM findings WHERE version_id = ?').all(vid)
    const ins = db.prepare(`INSERT INTO findings (id, version_id, component_id, vuln_id, severity, score, summary,
      aliases, cwe_ids, published, fixed_versions, refs_json,
      intake_channel, became_known_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'osv_scan', ?, ?, ?)`)
    const upd = db.prepare(`UPDATE findings SET severity=?, score=?, summary=?,
      aliases=?, cwe_ids=?, published=?, fixed_versions=?, refs_json=?, updated_at=? WHERE id=?`)
    let added = 0, updated = 0
    for (const h of hits) {
      const rec = details[h.vulnId]
      const { label, score } = rec ? sevOf(rec) : { label: '—', score: null }
      const summary = rec?.summary || 'osv.dev/vulnerability/' + h.vulnId
      const aliases = (rec?.aliases || []).join(', ')
      const cwe = (rec?.database_specific?.cwe_ids || []).join(', ')
      const published = rec?.published || ''
      const rem = rec ? remediationOf(rec, h.comp.purl) : { fixed: [], lastAffected: [] }
      const fixedVersions = rem.fixed.length ? rem.fixed.join(', ')
        : rem.lastAffected.length ? 'kein Fix — betroffen bis ' + rem.lastAffected.join(', ') : ''
      const refs = rec ? JSON.stringify(sourcesOf(rec)) : ''
      const match = existing.find(e => e.vuln_id === h.vulnId && e.component_id === h.comp.id)
      if (match) { upd.run(label, score, summary, aliases, cwe, published, fixedVersions, refs, now(), match.id); updated++ }
      else { ins.run(uid(), vid, h.comp.id, h.vulnId, label, score, summary, aliases, cwe, published,
                     fixedVersions, refs, now(), now(), now()); added++ }
    }
    db.prepare('INSERT INTO scans (id, version_id, ran_at, source, components_scanned, findings_new, findings_updated) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(uid(), vid, now(), 'OSV.dev', comps.length, added, updated)
    audit('scan.run', comps.length + ' Komponenten · +' + added + ' / ~' + updated)
    res.json({ ...versionData(vid), scan: { scanned: comps.length, added, updated } })
  } catch (e) {
    res.status(502).json({ error: 'OSV.dev nicht erreichbar (' + (e.message || e) + ') — kein Abgleich durchgeführt.' })
  }
})

// ---------- Triage / Funde ----------
// Manuelle Fund-Erfassung (D-020): Eingang läuft beim Kunden per Mail/Advisory —
// die Software dokumentiert den Fund mit Eingangskanal und Kenntniszeitpunkt (startet Fristen).
app.post('/api/versions/:id/findings', (req, res) => {
  const f = req.body
  if (!f.vuln_id?.trim()) return res.status(400).json({ error: 'Kennung fehlt' })
  if (!f.became_known_at) return res.status(400).json({ error: 'Kenntniszeitpunkt fehlt (startet die Fristen, Art. 14)' })
  db.prepare(`INSERT INTO findings (id, version_id, component_id, vuln_id, severity, score, summary,
    intake_channel, became_known_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)`)
    .run(uid(), req.params.id, f.component_id || null, f.vuln_id.trim(), f.severity || '—',
      f.summary || '', f.intake_channel || 'cvd_mail', f.became_known_at, now(), now())
  audit('finding.create', f.vuln_id + ' (' + (f.intake_channel || 'cvd_mail') + ')')
  res.json(versionData(req.params.id))
})

const FINDING_FIELDS = ['vex_status', 'vex_justification', 'decision', 'decision_rationale', 'accept_until',
  'owner', 'became_known_at', 'actively_exploited', 'exploit_evidence',
  'upstream_reported_to', 'upstream_reported_at', 'upstream_fix_shared', 'fix_version']
app.patch('/api/findings/:id', (req, res) => {
  const cur = db.prepare('SELECT * FROM findings WHERE id = ?').get(req.params.id)
  if (!cur) return res.status(404).json({ error: 'nicht gefunden' })
  const f = { ...cur }
  for (const k of FINDING_FIELDS) if (req.body[k] !== undefined) f[k] = req.body[k]
  db.prepare(`UPDATE findings SET vex_status=?, vex_justification=?, decision=?, decision_rationale=?, accept_until=?,
    owner=?, became_known_at=?, actively_exploited=?, exploit_evidence=?,
    upstream_reported_to=?, upstream_reported_at=?, upstream_fix_shared=?, fix_version=?, updated_at=? WHERE id=?`)
    .run(f.vex_status, f.vex_justification, f.decision, f.decision_rationale, f.accept_until,
      f.owner, f.became_known_at, f.actively_exploited ? 1 : 0, f.exploit_evidence,
      f.upstream_reported_to, f.upstream_reported_at, f.upstream_fix_shared ? 1 : 0, f.fix_version || '',
      now(), req.params.id)
  audit('finding.update', cur.vuln_id)
  res.json(versionData(cur.version_id))
})

// Massen-Bewertung: nur die Betroffenheit (VEX). Entscheidung, Verantwortlicher und
// Fristen bleiben bewusst Einzelfall — betroffen ist erst der Anfang der Arbeit.
app.patch('/api/versions/:id/findings/bulk', (req, res) => {
  const { ids, vex_status, vex_justification } = req.body
  if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'Keine Funde ausgewaehlt' })
  if (!['under_investigation', 'affected', 'not_affected', 'fixed'].includes(vex_status))
    return res.status(400).json({ error: 'Unbekannter VEX-Status' })
  const upd = db.prepare('UPDATE findings SET vex_status=?, vex_justification=?, updated_at=? WHERE id=? AND version_id=?')
  const run = db.transaction(list => { for (const id of list) upd.run(vex_status, vex_justification || '', now(), id, req.params.id) })
  run(ids)
  audit('finding.bulk', ids.length + ' Funde -> ' + vex_status)
  res.json(versionData(req.params.id))
})

app.get('/api/audit', (_req, res) =>
  res.json(db.prepare('SELECT ts, action, detail FROM audit_log ORDER BY id DESC LIMIT 200').all()))

// ---------- Versionsvergleich (D-019): automatisch berechnet, nie gepflegt ----------
// Vergleicht das Komponenteninventar einer Version mit ihrer Vorversion (copied_from,
// sonst die zeitlich vorangehende Version desselben Produkts). Match über purl ohne
// Versionsanteil, sonst Typ+Name — so wird "gleiche Komponente, neue Version" erkannt.
app.get('/api/versions/:id/diff', (req, res) => {
  const v = db.prepare('SELECT * FROM versions WHERE id = ?').get(req.params.id)
  if (!v) return res.status(404).json({ error: 'Version nicht gefunden' })
  let base = v.copied_from ? db.prepare('SELECT * FROM versions WHERE id = ?').get(v.copied_from) : null
  if (!base) base = db.prepare(
    'SELECT * FROM versions WHERE product_id = ? AND created_at < ? ORDER BY created_at DESC LIMIT 1'
  ).get(v.product_id, v.created_at)
  if (!base) return res.json({ base: null, added: [], removed: [], changed: [], unchanged: 0 })

  const key = c => (c.purl ? 'p:' + purlBase(c.purl) : 'n:' + c.kind + '|' + c.name.toLowerCase())
  const cur = db.prepare('SELECT * FROM components WHERE version_id = ?').all(v.id)
  const prev = db.prepare('SELECT * FROM components WHERE version_id = ?').all(base.id)
  const prevMap = new Map(prev.map(c => [key(c), c]))
  const curKeys = new Set(cur.map(key))

  const pick = c => ({ name: c.name, version: c.version, kind: c.kind, supplier: c.supplier, purl: c.purl })
  const added = [], changed = []
  let unchanged = 0
  for (const c of cur) {
    const old = prevMap.get(key(c))
    if (!old) { added.push(pick(c)) }
    else if ((old.version || '') !== (c.version || '')) changed.push({ ...pick(c), from: old.version || '—', to: c.version || '—' })
    else unchanged++
  }
  const removed = prev.filter(c => !curKeys.has(key(c))).map(pick)
  res.json({ base: { id: base.id, version: base.version }, added, removed, changed, unchanged })
})

const PORT = 5178
app.listen(PORT, () => console.log('SBOM-Tool-API auf http://localhost:' + PORT + ' · DB: server/sbom.db'))
