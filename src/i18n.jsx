import React, { createContext, useContext, useState } from 'react'

// Sprachumschaltung: Deutsch ist die Ausgangssprache, der deutsche Text ist
// zugleich der Schluessel. Fehlt eine Uebersetzung, bleibt der deutsche Text
// stehen — sichtbar, aber nie kaputt.
const EN = {
  // --- Navigation, Kopf, Aktionen ---
  'SBOM & Komponenten': 'SBOM & Components',
  'CRA-Modul · SBOM-Gen': 'CRA module · SBOM-Gen',
  'Datenbank:': 'Database:',
  'Suchen …': 'Search …',
  'CVE-Abgleich (OSV)': 'Scan for CVEs (OSV)',
  'SBOM importieren': 'Import SBOM',
  'Bitte warten …': 'Please wait …',
  'Abbrechen': 'Cancel',
  'Speichern': 'Save',
  'Anlegen': 'Create',
  'Erfassen': 'Add',
  'Löschen': 'Delete',
  'Übernehmen': 'Apply',
  'ausblenden': 'dismiss',
  'Produkt:': 'Product:',
  'Version:': 'Version:',
  '+ Version': '+ Version',
  '+ Produkt': '+ Product',
  '+ Komponente': '+ Component',
  '+ Fund erfassen': '+ Add finding',

  // --- Kennzahlen ---
  'Komponenteninventar (HW + SW)': 'Component inventory (HW + SW)',
  'Hardware ·': 'hardware ·',
  'Software (SBOM)': 'software (SBOM)',
  'Sorgfalt (Art. 13 Abs. 5)': 'Due diligence (Art. 13(5))',
  'Drittkomponenten geprüft bzw. Eigenentwicklung': 'Third-party components reviewed, or in-house',
  'Schwachstellen (offene Funde)': 'Vulnerabilities (open findings)',
  'kritisch ·': 'critical ·',
  'hoch ·': 'high ·',
  'mittel ·': 'medium ·',
  'niedrig': 'low',
  'Triage (Betroffenheit bewertet)': 'Triage (affectedness assessed)',
  'aktiv ausgenutzt (Art. 14!)': 'actively exploited (Art. 14!)',
  'Letzter Abgleich:': 'Last scan:',
  'Noch kein Abgleich für diese Version': 'No scan yet for this version',
  'Komponenten geprüft': 'components checked',
  'Abgleich abgeschlossen — SBOM-Komponenten:': 'Scan complete — SBOM components:',
  'neu:': 'new:',
  'aktualisiert:': 'updated:',

  // --- Reiter, Filter ---
  'Komponenten': 'Components',
  'SBOMs': 'SBOMs',
  'Funde': 'Findings',
  'Änderungen': 'Changes',
  'Alle': 'All',
  'Kritisch': 'Critical',
  'Hoch': 'High',
  'Mittel': 'Medium',
  'Niedrig': 'Low',
  'Unbewertet': 'Unrated',
  'In Prüfung': 'Under investigation',
  'Betroffen': 'Affected',
  'Nicht betroffen': 'Not affected',
  'Behoben': 'Fixed',

  // --- Komponententypen ---
  'Hardware': 'Hardware',
  'Software (eigen)': 'Software (in-house)',
  'Open Source': 'Open source',
  'Software (Zukauf)': 'Software (purchased)',

  // --- Tabellen ---
  'Komponente': 'Component',
  'Typ': 'Type',
  'Version': 'Version',
  'Lieferant': 'Supplier',
  'Lizenz': 'License',
  'SBOM': 'SBOM',
  'Schwachstellen': 'Vulnerabilities',
  'Sorgfalt': 'Due diligence',
  'Inventar': 'Inventory',
  'über Advisories': 'via advisories',
  'keine bekannt': 'none known',
  'Geprüft': 'Reviewed',
  'Offen': 'Open',
  'entfällt': 'n/a',
  'Kernfunktion': 'core function',
  'Lieferantenweg — keine purl': 'supplier channel — no purl',
  'ohne purl — nicht OSV-abgleichbar': 'no purl — cannot be matched against OSV',
  'Datei': 'File',
  'Format': 'Format',
  'Tiefe': 'Depth',
  'Erstellt': 'Generated',
  'Importiert': 'Imported',
  'Nutzer-Bereitstellung': 'Provided to users',
  'oberste Abhängigkeiten': 'top-level dependencies',
  'vollständig': 'fully resolved',
  'Ja — Anhang II Nr. 9': 'Yes — Annex II No. 9',
  'Nein (keine Pflicht)': 'No (not required)',
  'Schwere': 'Severity',
  'Schwachstelle': 'Vulnerability',
  'Behebung': 'Remediation',
  'Betroffenheit': 'Affectedness',
  'Entscheidung': 'Decision',
  'Verantwortlich': 'Owner',
  'Kenntnis': 'Known since',
  'kein Fix': 'no fix',
  'offen': 'open',
  'keine': 'none',
  'aus SBOM-Import': 'from SBOM import',

  // --- Entscheidungen, Eingangskanäle ---
  '— offen —': '— none —',
  'Sofort beheben': 'Fix now',
  'Mitigieren': 'Mitigate',
  'Risiko akzeptieren (befristet)': 'Accept risk (time bound)',
  'Zurückstellen': 'Defer',
  'OSV-Abgleich': 'OSV scan',
  'Meldung per Mail (CVD-Kontaktadresse)': 'Report by email (CVD contact address)',
  'Lieferanten-Advisory': 'Supplier advisory',
  'Eigene Tests (Teil II Nr. 3)': 'Own testing (Part II No. 3)',
  'Hinweis über CSIRT (Art. 15 Abs. 4)': 'Notification via CSIRT (Art. 15(4))',
  'Sonstiges': 'Other',

  // --- Produkt/Version anlegen ---
  'Neues Produkt': 'New product',
  'Neues Produkt anlegen': 'Create a product',
  'Produktname': 'Product name',
  'Hersteller': 'Manufacturer',
  'Erste Version': 'First version',
  'Versionsbezeichnung': 'Version label',
  'Neue Version —': 'New version —',
  'Produkt mit digitalen Elementen (Art. 3 Nr. 1). Die Konformität hängt an der Version (Anhang VII Nr. 1 Buchst. b).':
    'Product with digital elements (Art. 3(1)). Conformity attaches to the version (Annex VII No. 1(b)).',
  'Jede Version führt Komponenten, SBOMs und Funde getrennt.':
    'Every version keeps its own components, SBOMs and findings.',
  'Komponenten aus': 'Copy components from',
  'übernehmen (Funde und SBOMs bewusst nicht)': '(findings and SBOMs deliberately not copied)',
  'Noch kein Produkt angelegt': 'No product yet',
  'Komponenten, SBOMs und Funde hängen an der Produktversion (Anhang I Teil II Nr. 1). Lege ein Produkt mit seiner ersten Version an und importiere anschließend die SBOM, die dein Build erzeugt hat — eine echte Beispiel-SBOM liegt im Ordner':
    'Components, SBOMs and findings attach to the product version (Annex I Part II No. 1). Create a product with its first version, then import the SBOM your build produced — a real example SBOM sits in',
  'Produktverwaltung:': 'Manage:',
  'Version löschen': 'Delete version',
  'Produkt löschen': 'Delete product',

  // --- Komponenten-Drawer ---
  'Komponente hinzufügen': 'Add component',
  'Komponente = Software oder Hardware (Art. 3 Nr. 6). Hardware steht im Inventar, nicht in der SBOM (Art. 3 Nr. 39).':
    'A component is software or hardware (Art. 3(6)). Hardware belongs in the inventory, not in the SBOM (Art. 3(39)).',
  'Hardware: kein SBOM-Eintrag; Schwachstellen kommen über Lieferanten-Advisories (Sorgfalts-Baseline, Art. 13 Abs. 5 / ENISA 4.14) — Identifikation optional über cpe.':
    'Hardware: no SBOM entry. Vulnerabilities arrive through supplier advisories (due diligence baseline, Art. 13(5) / ENISA 4.14) — identification via cpe is optional.',
  'Name': 'Name',
  '— entfällt bei Eigenentwicklung': '— not applicable for in-house development',
  '— entfällt bei Eigenentwicklung': '— not applicable for in-house development',
  '(Verknüpfung ins Lieferantenmanagement)': '(links to supplier management)',
  '(Package URL — Schlüssel für den OSV-Abgleich)': '(Package URL — the key for OSV matching)',
  '(für Hardware/Firmware — NVD-Identifikation, optional)': '(for hardware/firmware — NVD identification, optional)',
  '(nur mitgespeichert — keine Lizenzanalyse, D-006)': '(stored only — no license analysis)',
  'Kernfunktion des Produkts?': 'Core function of the product?',
  '(Abwägungsfaktor Unterstützungszeitraum, Art. 13 Abs. 8)': '(a factor when justifying the support period, Art. 13(8))',
  'Ja — Unterstützungszeitraum des Lieferanten berücksichtigen': 'Yes — take the supplier’s support period into account',
  'Nein': 'No',
  'Sorgfaltsnachweis': 'Due diligence record',
  '(Art. 13 Abs. 5 — Baseline-Verweis genügt; Lieferanten-SBOM ist optional, D-016)':
    '(Art. 13(5) — a pointer to the supplier baseline is enough; a supplier SBOM is optional)',
  'z. B. Lieferanten-Baseline 2026 (Security-Kontakt, Patch-Zusagen) im Lieferantenmanagement abgelegt':
    'e.g. supplier baseline 2026 (security contact, patch commitments) filed in supplier management',
  'Eigenentwicklung: keine Sorgfaltspflicht nach Art. 13 Abs. 5 — stattdessen regelmäßige Tests (Anhang I Teil II Nr. 3).':
    'In-house development: no due diligence duty under Art. 13(5) — regular testing applies instead (Annex I Part II No. 3).',
  'Komponente löschen? Zugehörige Funde werden mit entfernt.': 'Delete this component? Its findings are removed with it.',

  // --- Fund-Drawer ---
  'Art. 3 Nr. 42 — startet die Art.-14-Meldekette': 'Art. 3(42) — starts the Art. 14 reporting chain',
  'Aktiv ausgenutzt': 'Actively exploited',
  'Eingang:': 'Intake:',
  'Advisory veröffentlicht:': 'Advisory published:',
  'Schwachstellenklasse': 'Weakness class',
  '(aus dem Advisory, affected[].ranges)': '(from the advisory, affected[].ranges)',
  'Behoben in:': 'Fixed in:',
  'Keine feste Version': 'No fixed version',
  'Keine Versionsangabe im Advisory.': 'The advisory names no version.',
  'Zielversion:': 'Target version:',
  'Als Zielversion uebernehmen und Entscheidung auf Sofort beheben setzen':
    'Adopt as remediation target and set the decision to Fix now',
  'Quellen': 'Sources',
  '(Advisory, Fix-Commit, Projektseite)': '(advisory, fix commit, project page)',
  'Betroffenheit (VEX-Status)': 'Affectedness (VEX status)',
  '— erster Triage-Schritt (PT2.2, Art. 13 Abs. 7)': '— the first triage step (Part II No. 2, Art. 13(7))',
  'Begründung': 'Justification',
  'z. B. die verwundbare Funktion wird nicht aufgerufen (code_not_reachable)':
    'e.g. the vulnerable function is never called (code_not_reachable)',
  'Einschätzung, Analyse-Stand': 'Assessment, state of analysis',
  '(ENISA 4.13: fix / mitigate / accept befristet / defer begründet)':
    '(ENISA 4.13: fix / mitigate / accept time-bound / defer with rationale)',
  'Befristung (Pflicht bei accept)': 'Expiry (required for accept)',
  'Begründung (Pflicht bei accept/defer)': 'Rationale (required for accept/defer)',
  '(ENISA 4.13: ein Owner je Fund)': '(ENISA 4.13: one owner per finding)',
  'Kenntnis am': 'Known since',
  '(startet Fristen, Art. 14)': '(starts the deadlines, Art. 14)',
  'Aktiv ausgenutzt?': 'Actively exploited?',
  '(Art. 3 Nr. 42 — nie aus CVSS ableiten)': '(Art. 3(42) — never inferred from CVSS)',
  'Ja — verlässliche Nachweise erforderlich, löst Art. 14 Abs. 1 aus':
    'Yes — requires reliable evidence, triggers Art. 14(1)',
  'Nein / keine Nachweise': 'No / no evidence',
  'Nachweis (Pflichtfeld): worauf stützt sich die Einstufung?':
    'Evidence (required): what is this assessment based on?',
  'Meldepflicht (Art. 14 Abs. 2):': 'Reporting duty (Art. 14(2)):',
  'Frühwarnung ≤ 24 h, Meldung ≤ 72 h ab Kenntnis, Abschlussbericht ≤ 14 Tage ab Verfügbarkeit der Korrekturmaßnahme. Die Meldekette nach Art. 14 gehört in das Modul':
    'Early warning ≤ 24 h, notification ≤ 72 h from awareness, final report ≤ 14 days from the availability of the remedy. The Art. 14 reporting chain belongs to the module',
  'und ist hier bewusst nicht enthalten.': 'and is deliberately not part of this tool.',
  'Upstream-Meldung': 'Upstream report',
  '(Art. 13 Abs. 6 — an den Komponentenhersteller)': '(Art. 13(6) — to the component’s manufacturer)',
  'Gemeldet an (Hersteller/Wartende)': 'Reported to (manufacturer/maintainer)',
  'Fix-Code oder Unterlagen geteilt': 'Fix code or documentation shared',
  'Advisory-Entwurf (PT2.4) ↓': 'Advisory draft (Part II No. 4) ↓',

  // --- Fund erfassen ---
  'Fund erfassen': 'Add finding',
  'Für Meldungen, die außerhalb des Scans hereinkommen — per Mail an die Kontaktadresse (Teil II Nr. 6), Lieferanten-Advisory oder CSIRT-Hinweis. Der Kenntniszeitpunkt startet die Fristen (Art. 14): im Zweifel zählt der Mail-Eingang.':
    'For reports arriving outside the scan — by email to the contact address (Part II No. 6), a supplier advisory or a CSIRT notification. The point of awareness starts the deadlines (Art. 14); when in doubt, the email’s arrival counts.',
  'Kennung': 'Identifier',
  'CVE-2026-… oder intern': 'CVE-2026-… or internal',
  'Schwere (vorläufig)': 'Severity (preliminary)',
  'Betroffene Komponente': 'Affected component',
  '— noch unklar —': '— not yet known —',
  'Beschreibung / Inhalt der Meldung': 'Description / content of the report',
  'Eingangskanal': 'Intake channel',

  // --- SBOM-Drawer ---
  '(Anhang I Teil II Nr. 1: oberste Abhängigkeiten genügen)': '(Annex I Part II No. 1: top-level dependencies suffice)',
  'Oberste Abhängigkeiten': 'Top-level dependencies',
  'Vollständig aufgelöst': 'Fully resolved',
  'An Nutzer bereitgestellt?': 'Provided to users?',
  '(keine Pflicht — nur dann Angabe des Zugangs, Anhang II Nr. 9)':
    '(not required — only then must the access point be stated, Annex II No. 9)',
  'Ja — Zugangsort unten angeben (wandert in die Nutzerinformationen)':
    'Yes — state the access point below (it goes into the user information)',
  'Nein (Standard)': 'No (default)',
  'Zugangsort, z. B. https://…/sbom': 'Access point, e.g. https://…/sbom',
  'Auf begründetes Verlangen der Marktüberwachungsbehörde ist die SBOM Teil der technischen Dokumentation (Anhang VII Nr. 8) — Download unten. Format bleibt offen, bis der Durchführungsrechtsakt nach Art. 13 Abs. 24 vorliegt.':
    'On a reasoned request from a market surveillance authority the SBOM forms part of the technical documentation (Annex VII No. 8) — download below. The format stays open until the implementing act under Art. 13(24) exists.',
  'Herunterladen (Anhang VII Nr. 8)': 'Download (Annex VII No. 8)',
  'SBOM-Stand löschen? (Komponenten bleiben im Inventar)': 'Delete this SBOM snapshot? (components stay in the inventory)',
  'Komponenten · erstellt': 'components · generated',
  '· importiert': '· imported',

  // --- Hinweisboxen und Leerzustände ---
  'Pflicht (Anhang I Teil II Nr. 1):': 'Required (Annex I Part II No. 1):',
  'Komponenten ermitteln und dokumentieren — Hardware und Software. In die SBOM gehört nur die Software (Art. 3 Nr. 39); Hardware läuft über das Lieferantenmanagement (Art. 13 Abs. 5).':
    'Identify and document components — hardware and software alike. Only software belongs in the SBOM (Art. 3(39)); hardware runs through supplier management (Art. 13(5)).',
  'Historie je Version (Art. 13 Abs. 7):': 'History per version (Art. 13(7)):',
  'jeder importierte Stand bleibt archiviert und ist für die Marktüberwachung exportierbar (Anhang VII Nr. 8). Eine Herausgabe an Nutzer ist keine Pflicht (Anhang II Nr. 9).':
    'every imported snapshot stays archived and can be exported for market surveillance (Annex VII No. 8). Handing it to users is not mandatory (Annex II No. 9).',
  'Triage (PT2.2, ENISA 4.13):': 'Triage (Part II No. 2, ENISA 4.13):',
  'je Fund Betroffenheit (VEX) → Entscheidung (fix/mitigate/accept befristet/defer begründet) → Verantwortlicher. „Aktiv ausgenutzt" (Art. 3 Nr. 42) nie aus CVSS ableiten — Nachweis erfassen; die Art.-14-Meldekette gehört ins Modul Meldungen.':
    'per finding: affectedness (VEX) → decision (fix / mitigate / accept time-bound / defer with rationale) → owner. Never infer “actively exploited” (Art. 3(42)) from CVSS — record the evidence. The Art. 14 reporting chain belongs to the Reports module.',
  'Keine Komponenten für diesen Filter.': 'No components match this filter.',
  'Noch keine Komponenten — SBOM importieren oder Hardware/Software manuell anlegen.':
    'No components yet — import an SBOM or add hardware/software by hand.',
  'Keine Funde für diesen Filter.': 'No findings match this filter.',
  'Noch keine Funde — oben „CVE-Abgleich (OSV)" starten (Software mit purl nötig).':
    'No findings yet — run “Scan for CVEs (OSV)” above (needs software with a purl).',
  'Noch keine SBOM für': 'No SBOM yet for',
  '— oben „SBOM importieren" (CycloneDX- oder SPDX-JSON).': '— use “Import SBOM” above (CycloneDX or SPDX JSON).',
  'Keine Komponenten gefunden — CycloneDX (components[]) oder SPDX (packages[]) erwartet.':
    'No components found — expected CycloneDX (components[]) or SPDX (packages[]).',
  'Datei konnte nicht gelesen werden:': 'Could not read the file:',
  'Komponenten importiert': 'components imported',
  'neu,': 'new,',
  'aktualisiert), Original archiviert': 'updated), original archived',
  'ohne purl': 'without a purl',

  // --- Versionsvergleich ---
  'Vergleich wird berechnet …': 'Computing the comparison …',
  'Erste Version': 'First version',
  'es gibt keine Vorversion zum Vergleichen. Sobald eine weitere Version existiert, erscheint hier automatisch der Unterschied der Komponenteninventare.':
    'there is no previous version to compare against. As soon as a second version exists, the difference between the component inventories appears here automatically.',
  'Vergleich:': 'Comparison:',
  'neu ·': 'new ·',
  'entfernt ·': 'removed ·',
  'Version geändert ·': 'version changed ·',
  'unverändert — automatisch aus den Inventaren berechnet': 'unchanged — computed from the inventories automatically',
  'Neu hinzugekommen — Kandidaten für die Sorgfaltsprüfung (Art. 13 Abs. 5, ENISA 4.14)':
    'Newly added — candidates for due diligence (Art. 13(5), ENISA 4.14)',
  'Version geändert': 'Version changed',
  'Entfernt': 'Removed',
  'Automatische Dokumentation:': 'Automatic documentation:',
  'Dieser Vergleich wird live aus den je Version getrennt gespeicherten Inventaren berechnet — niemand pflegt ein Changelog. Zusätzlich protokolliert das Audit-Log jede einzelne Änderung mit Zeitstempel (Art. 13 Abs. 7). Ob eine Änderung „wesentlich" ist (Art. 3 Nr. 30), entscheidet der Mensch — der Vergleich liefert die Grundlage.':
    'This comparison is computed live from the inventories stored per version — nobody maintains a changelog. The audit log additionally records every single change with a timestamp (Art. 13(7)). Whether a change is “substantial” (Art. 3(30)) is a human decision; the comparison provides the basis for it.',

  // --- Datenbank / Fehler ---
  'Datenbank nicht erreichbar': 'Database unavailable',
  'API-Server starten:': 'Start the API server:',
  'Erneut verbinden': 'Reconnect',
  'lädt': 'loading',
  'fehler': 'error',
}

const Ctx = createContext({ lang: 'de', t: s => s, setLang: () => {} })

export function I18nProvider({ children }) {
  const [lang, setLangState] = useState(() => {
    try { return localStorage.getItem('sbomgen-lang') || 'de' } catch { return 'de' }
  })
  const setLang = (l) => {
    setLangState(l)
    try { localStorage.setItem('sbomgen-lang', l) } catch { /* private mode */ }
  }
  const t = (s) => (lang === 'en' ? (EN[s] ?? s) : s)
  return <Ctx.Provider value={{ lang, t, setLang }}>{children}</Ctx.Provider>
}

export const useI18n = () => useContext(Ctx)
export const useT = () => useContext(Ctx).t
