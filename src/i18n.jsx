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
  'Anlegen': 'Create',
  'Löschen': 'Delete',
  'Übernehmen': 'Apply',
  'ausblenden': 'dismiss',
  'Produkt:': 'Product:',
  'Version:': 'Version:',
  '+ Version': '+ Version',

  // --- Kennzahlen ---
  'Komponenteninventar (HW + SW)': 'Component inventory (HW + SW)',
  'Hardware ·': 'hardware ·',
  'Software (SBOM)': 'software (SBOM)',
  'Drittkomponenten geprüft bzw. Eigenentwicklung': 'Third-party components reviewed, or in-house',
  'Schwachstellen (offene Funde)': 'Vulnerabilities (open findings)',
  'kritisch ·': 'critical ·',
  'hoch ·': 'high ·',
  'mittel ·': 'medium ·',
  'niedrig': 'low',
  'Triage (Betroffenheit bewertet)': 'Triage (affectedness assessed)',
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
  'Schwachstellen': 'Vulnerabilities',
  'Sorgfalt': 'Due diligence',
  'Geprüft': 'Reviewed',
  'Offen': 'Open',
  'entfällt': 'n/a',
  'Kernfunktion': 'core function',
  'Datei': 'File',
  'Format': 'Format',
  'Tiefe': 'Depth',
  'Erstellt': 'Generated',
  'Importiert': 'Imported',
  'Schwere': 'Severity',
  'Schwachstelle': 'Vulnerability',
  'Behebung': 'Remediation',
  'Betroffenheit': 'Affectedness',
  'Entscheidung': 'Decision',
  'Verantwortlich': 'Owner',
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
  'Sonstiges': 'Other',

  // --- Produkt/Version anlegen ---
  'Neues Produkt': 'New product',
  'Neues Produkt anlegen': 'Create a product',
  'Produktname': 'Product name',
  'Hersteller': 'Manufacturer',
  'Erste Version': 'First version',
  'Versionsbezeichnung': 'Version label',
  'Neue Version —': 'New version —',
  'Hat sich die Softwarezusammensetzung geändert?': 'Has the software composition changed?',
  'Nein — SBOM unverändert': 'No — SBOM unchanged',
  'Komponenten und der SBOM-Stand aus': 'Components and the SBOM snapshot from',
  'werden übernommen.': 'are carried over.',
  'Ja — neue SBOM hochladen': 'Yes — upload a new SBOM',
  'Hardware wird übernommen (steht nicht in der SBOM), die Software kommt aus der neuen Datei.':
    'Hardware is carried over (it is not part of an SBOM); the software comes from the new file.',
  'Datei wählen': 'Choose file',
  'CycloneDX- oder SPDX-JSON': 'CycloneDX or SPDX JSON',

  'Jede Version führt Komponenten, SBOMs und Funde getrennt.':
    'Every version keeps its own components, SBOMs and findings.',
  'Noch kein Produkt angelegt': 'No product yet',
  'Version löschen': 'Delete version',
  'Produkt löschen': 'Delete product',

  // --- Komponenten-Drawer ---
  'Die Zusammensetzung wird je Version geführt.': 'Composition is tracked per version.',
  'Hardware und Software stehen im Inventar; in die SBOM gehört nur Software.':
    'Hardware and software live in the inventory; only software belongs in the SBOM.',
  'Advisory-Entwurf ↓': 'Advisory draft ↓',
  'Herunterladen': 'Download',
  'Neu hinzugekommen': 'Newly added',
  'Komponenten, SBOMs und Funde hängen an der Produktversion. Lege ein Produkt mit seiner ersten Version an und importiere anschließend die SBOM, die dein Build erzeugt hat — eine Beispiel-SBOM liegt im Ordner':
    'Components, SBOMs and findings attach to the product version. Create a product with its first version, then import the SBOM your build produced — an example SBOM sits in',
  'Sorgfalt': 'Due diligence',
  'aktiv ausgenutzt': 'actively exploited',
  'Ja — verlässliche Nachweise erforderlich': 'Yes — reliable evidence required',
  'Eigene Tests': 'Own testing',
  'Hinweis von außen': 'External notification',
  'Nachweis: worauf stützt sich die Einstufung?': 'Evidence: what is this assessment based on?',
  'Version löschen?': 'Delete version?',
  'Gespeichert': 'Saved',
  'Scan-Historie': 'Scan history',
  'Jeder Abgleich wird protokolliert — wann er lief, wie viele Komponenten geprüft wurden und was dabei herauskam.':
    'Every scan is logged — when it ran, how many components were checked and what came out of it.',
  'Zeitpunkt': 'When',
  'Quelle': 'Source',
  'Geprüft': 'Checked',
  'Neu': 'New',
  'Aktualisiert': 'Updated',
  'Ohne Funde': 'No findings',
  'Sorgfalt offen': 'Due diligence open',
  'Filter': 'Filter',
  'Zurücksetzen': 'Reset',
  'Herkunft': 'Origin',
  'Direkt eingebunden': 'Direct dependency',
  'Transitiv': 'Transitive',
  'direkt': 'direct',
  'Schwachstellen an der Komponente': 'Vulnerabilities on the component',
  'Behebung': 'Remediation',
  'Fix verfügbar': 'Fix available',
  'Kein Fix': 'No fix',
  'Verantwortlich für die Schwachstellenbehandlung': 'Responsible for vulnerability handling',
  'Gilt für alle Funde dieses Produkts. Einzelne Funde können abweichend zugewiesen werden.':
    'Applies to every finding of this product. Individual findings can be assigned to someone else.',
  'vom Produkt übernommen': 'inherited from the product',
  'Entfernen': 'Remove',
  'Ein Produkt kann mehrere SBOMs haben — etwa je Artefakt (Backend, Firmware). Alle laufen in ein Komponenteninventar.':
    'A product can have several SBOMs — one per artifact, say backend and firmware. They all feed one component inventory.',
  'Noch keine Komponenten — im Reiter SBOMs eine SBOM importieren.':
    'No components yet — import an SBOM from the SBOMs tab.',
  '(optional — später jederzeit im Reiter SBOMs)': '(optional — you can add it any time from the SBOMs tab)',
  'Wird hereingezogen über': 'Pulled in via',
  'Nicht behebbar an': 'Cannot be fixed on',
  'selbst — aktualisiert werden muss die direkte Abhängigkeit': 'itself — the direct dependency to update is',
  'Euer Produkt': 'Your product',
  'Produkt': 'Product',
  'Produkt → direkt eingebunden → … → verwundbare Komponente':
    'product → direct dependency → … → vulnerable component',
  'Eingebaut ist': 'Installed is',
  'behoben ab': 'fixed from',
  'steht nicht in der package.json und lässt sich nicht einzeln austauschen.':
    'is not listed in package.json and cannot be replaced on its own.',
  'Nötig ist eine Fassung von': 'What you need is a release of',
  'die': 'that ships',
  'oder neuer mitbringt.': 'or newer.',
  'Ansatzpunkt ist die direkte Abhängigkeit': 'The place to start is the direct dependency',
  'Anschrift des Lieferanten': 'Supplier address',
  '(auf Anfrage der Marktüberwachung, 10 Jahre)': '(on request from market surveillance, 10 years)',
  'Straße, PLZ Ort, Land': 'Street, postcode city, country',
  'Bezogen am': 'Acquired on',
  'Angaben vorzuhalten bis': 'Records to be kept until',
  'Unterstützt bis': 'Supported until',
  'endet vor dem Produkt': 'ends before the product',
  'Kernkomponente: Die Unterstützung endet vor der des Produkts':
    'Core component: support ends before the product’s does',
  'Das ist bei der Festlegung des Unterstützungszeitraums zu berücksichtigen.':
    'That has to be taken into account when setting the support period.',
  'Unterstützungszeitraum bis': 'Support period until',
  '(Monat und Jahr)': '(month and year)',
  'unter fünf Jahren — Begründung nötig': 'under five years — needs justification',
  'Name': 'Name',
  '— entfällt bei Eigenentwicklung': '— not applicable for in-house development',
  '— entfällt bei Eigenentwicklung': '— not applicable for in-house development',
  '(Verknüpfung ins Lieferantenmanagement)': '(links to supplier management)',
  '(Package URL — Schlüssel für den OSV-Abgleich)': '(Package URL — the key for OSV matching)',
  '(für Hardware/Firmware — NVD-Identifikation, optional)': '(for hardware/firmware — NVD identification, optional)',
  '(nur mitgespeichert — keine Lizenzanalyse, D-006)': '(stored only — no license analysis)',
  'Kernfunktion des Produkts?': 'Core function of the product?',
  'Sorgfaltsnachweis': 'Due diligence record',
  'z. B. Lieferanten-Baseline 2026 (Security-Kontakt, Patch-Zusagen) im Lieferantenmanagement abgelegt':
    'e.g. supplier baseline 2026 (security contact, patch commitments) filed in supplier management',
  'Komponente löschen? Zugehörige Funde werden mit entfernt.': 'Delete this component? Its findings are removed with it.',

  // --- Fund-Drawer ---
  'Aktiv ausgenutzt': 'Actively exploited',
  'Eingang:': 'Intake:',
  'Advisory veröffentlicht:': 'Advisory published:',
  'Schwachstellenklasse': 'Weakness class',
  'Behoben in:': 'Fixed in:',
  'Keine feste Version': 'No fixed version',
  'Keine Versionsangabe im Advisory.': 'The advisory names no version.',
  'Als Zielversion uebernehmen und Entscheidung auf Sofort beheben setzen':
    'Adopt as remediation target and set the decision to Fix now',
  'Quellen': 'Sources',
  '(Advisory, Fix-Commit, Projektseite)': '(advisory, fix commit, project page)',
  'Betroffenheit (VEX-Status)': 'Affectedness (VEX status)',
  'Begründung': 'Justification',
  'Befristung (Pflicht bei accept)': 'Expiry (required for accept)',
  'Begründung (Pflicht bei accept/defer)': 'Rationale (required for accept/defer)',
  'Kenntnis am': 'Known since',
  'Aktiv ausgenutzt?': 'Actively exploited?',
  'Nein / keine Nachweise': 'No / no evidence',
  'Upstream-Meldung': 'Upstream report',
  'Gemeldet an (Hersteller/Wartende)': 'Reported to (manufacturer/maintainer)',
  'Fix-Code oder Unterlagen geteilt': 'Fix code or documentation shared',

  // --- Fund erfassen ---

  // --- SBOM-Drawer ---
  'Oberste Abhängigkeiten': 'Top-level dependencies',
  'Vollständig aufgelöst': 'Fully resolved',
  'SBOM-Stand löschen? (Komponenten bleiben im Inventar)': 'Delete this SBOM snapshot? (components stay in the inventory)',
  'Komponenten · erstellt': 'components · generated',
  '· importiert': '· imported',

  // --- Hinweisboxen und Leerzustände ---
  'Noch keine SBOM für': 'No SBOM yet for',
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
  'Vergleich:': 'Comparison:',
  'neu ·': 'new ·',
  'entfernt ·': 'removed ·',
  'Version geändert ·': 'version changed ·',
  'unverändert — automatisch aus den Inventaren berechnet': 'unchanged — computed from the inventories automatically',
  'Version geändert': 'Version changed',
  'Entfernt': 'Removed',

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
