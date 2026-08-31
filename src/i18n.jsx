import React, { createContext, useContext, useState } from 'react'

// Sprachumschaltung: Deutsch ist die Ausgangssprache, der deutsche Text ist
// zugleich der Schluessel. Fehlt eine Uebersetzung, bleibt der deutsche Text
// stehen — sichtbar, aber nie kaputt.
const EN = {
  // --- Navigation, Kopf, Aktionen ---
  'SBOM & Komponenten': 'SBOM & Components',
  'CRA-Modul': 'CRA module',
  'Suchen …': 'Search …',
  'Auf Schwachstellen prüfen': 'Check for vulnerabilities',
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
  'Hardware ·': 'hardware ·',
  'Software (SBOM)': 'software (SBOM)',
  'Lieferanten geprüft': 'Suppliers reviewed',
  'von den selbst ausgewählten Komponenten': 'of the components selected in-house',
  'Funde insgesamt': 'Findings total',
  'kritisch ·': 'critical ·',
  'hoch ·': 'high ·',
  'mittel ·': 'medium ·',
  'niedrig': 'low',
  'Betroffenheit bewertet': 'Affected status assessed',
  'Letzte Prüfung:': 'Last check:',
  'Noch keine Prüfung für diese Version': 'No check yet for this version',
  'Komponenten geprüft': 'components checked',
  'Prüfung fertig —': 'Check complete —',
  'Komponenten geprüft ·': 'components checked ·',
  'neue Funde ·': 'new findings ·',
  'aktualisierte Funde': 'updated findings',

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
  'entfällt': 'not applicable',
  'Kernfunktion': 'core function',
  'Datei': 'File',
  'Format': 'Format',
  'Tiefe': 'Depth',
  'Erstellt': 'Generated',
  'Importiert': 'Imported',
  'Schwere': 'Severity',
  'Schwachstelle': 'Vulnerability',
  'Behebung': 'Remediation',
  'Betroffenheit': 'Affected status',
  'Entscheidung': 'Decision',
  'Verantwortlich': 'Owner',
  'keine Behebung': 'no fix available',
  'offen': 'open',
  'keine': 'none',
  'aus SBOM-Import': 'from SBOM import',

  // --- Entscheidungen, Eingangskanäle ---
  '— offen —': '— open —',
  'Sofort beheben': 'Fix now',
  'Risiko mindern': 'Mitigate',
  'Risiko akzeptieren (befristet)': 'Accept risk (time bound)',
  'Zurückstellen': 'Defer',
  'Automatischer Abgleich': 'Automatic check',
  'Meldung per Mail': 'Report by email',
  'Meldung des Lieferanten': 'Supplier report',
  'Sonstiges': 'Other',

  // --- Produkt/Version anlegen ---
  'Neues Produkt': 'New product',
  'Neues Produkt anlegen': 'Create a product',
  'Produktname': 'Product name',
  'Hersteller': 'Manufacturer',
  'Erste Version': 'First version',
  'Versionsbezeichnung': 'Version label',
  'Neue Version —': 'New version —',
  'Hat sich die Software geändert?': 'Has the software changed?',
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

  // --- Komponenten-Drawer ---
  'Die Zusammensetzung wird je Version geführt.': 'Composition is tracked per version.',
  'Hardware und Software stehen im Inventar; in die SBOM gehört nur Software.':
    'Hardware and software live in the inventory; only software belongs in the SBOM.',
  'Sicherheitshinweis (Entwurf)': 'Security advisory (draft)',
  'Herunterladen': 'Download',
  'Neu hinzugekommen': 'Newly added',
  'Komponenten, SBOMs und Funde hängen an der Produktversion. Zuerst ein Produkt mit seiner ersten Version anlegen, danach die SBOM des Builds importieren.':
    'Components, SBOMs and findings attach to the product version. First create a product with its first version, then import the SBOM from the build.',
  'aktiv ausgenutzt': 'actively exploited',
  'Ja — verlässliche Nachweise erforderlich': 'Yes — reliable evidence required',
  'Eigene Tests': 'Own testing',
  'Hinweis von außen': 'External notification',
  'Nachweis: worauf stützt sich die Einstufung?': 'Evidence: what is this assessment based on?',
  'Version löschen?': 'Delete version?',
  'Gespeichert': 'Saved',
  'Prüfverlauf': 'Check history',
  'Hier steht jede Prüfung: wann sie lief, wie viele Komponenten geprüft wurden und was sie gefunden hat.':
    'Every check is listed here: when it ran, how many components were checked and what it found.',
  'Zeitpunkt': 'When',
  'Quelle': 'Source',
  'Neu': 'New',
  'Aktualisiert': 'Updated',
  'Ohne Funde': 'No findings',
  'Sorgfalt offen': 'Due diligence outstanding',
  'Filter': 'Filter',
  'Zurücksetzen': 'Reset',
  'Herkunft': 'Origin',
  'Direkt eingebunden': 'Direct dependency',
  'Transitiv': 'Transitive',
  'direkt': 'direct',
  'Funde an der Komponente': 'Findings on the component',
  'Behebung verfügbar': 'Fix available',
  'Keine Behebung': 'No fix',
  'Verantwortlich für die Schwachstellenbehandlung': 'Responsible for vulnerability handling',
  'Gilt für alle Funde dieses Produkts. Einzelne Funde können abweichend zugewiesen werden.':
    'Applies to every finding of this product. Individual findings can be assigned to someone else.',
  'vom Produkt übernommen': 'inherited from the product',
  'Entfernen': 'Remove',
  'Ein Produkt kann mehrere SBOMs haben — etwa je Artefakt (Backend, Firmware). Alle laufen in ein Komponenteninventar.':
    'A product can have several SBOMs — one per artifact, say backend and firmware. They all feed one component inventory.',
  '(optional — später jederzeit im Reiter SBOMs)': '(optional — you can add it any time from the SBOMs tab)',
  'Wird hereingezogen über': 'Pulled in via',
  'Produkt': 'Product',
  'Produkt → direkt eingebunden → … → verwundbare Komponente':
    'product → direct dependency → … → vulnerable component',
  'Eingebaut ist': 'Currently installed:',
  'empfohlen': 'recommended',
  'Empfohlen — kleinster Sprung im gleichen Versionszweig': 'Recommended — the smallest step within the same version branch',
  'ist keine direkte Abhängigkeit und kann nicht einzeln ausgetauscht werden.':
    'is not a direct dependency and cannot be replaced on its own.',
  'Erforderlich ist eine Version von': 'What is required is a release of',
  ', die': ' that ships',
  'oder neuer enthält.': 'or newer.',
  'Ansatzpunkt ist die direkte Abhängigkeit': 'The place to start is the direct dependency',
  'Anschrift des Lieferanten': 'Supplier address',
  '— 10 Jahre aufbewahren, für Behördenanfragen': '— keep for 10 years, for authority requests',
  'Straße, PLZ Ort, Land': 'Street, postcode, city, country',
  'Bezogen am': 'Acquired on',
  'Aufbewahren bis': 'Keep until',
  'Lieferant unterstützt bis': 'Supplier support until',
  'endet vor dem Produkt': 'ends before the product',
  'Kernkomponente: Der Lieferant hört vor eurem Produkt auf':
    'Core component: the supplier stops before your product does',
  'gegen': 'vs',
  'Der eigene Unterstützungszeitraum ist zu kürzen oder ein Ersatz einzuplanen.':
    'The product support period has to be shortened, or a replacement planned.',
  'Sicherheitsupdates bis': 'Security updates until',
  '(Monat und Jahr)': '(month and year)',
  'kürzer als fünf Jahre — nur mit Begründung zulässig': 'shorter than five years — allowed only with justification',
  'Artefakt': 'Artifact',
  'Der Teil des Produkts, in dem diese Komponente steckt — etwa Backend, Firmware oder App. Beim Import wird er aus dem Kopf der SBOM übernommen; steht dort nichts, selbst eintragen.': 'The part of the product this component sits in — backend, firmware or app, for example. On import it is taken from the SBOM header; if nothing is stated there, enter it yourself.',
  'z. B. Gerät, Baugruppe': 'e.g. device, assembly',
  'z. B. Backend, Firmware': 'e.g. backend, firmware',
  'ohne Zuordnung': 'unassigned',
  'Name': 'Name',
  '— entfällt bei Eigenentwicklung': '— not applicable for in-house development',
  'Paket-Kennung (purl)': 'Package ID (purl)',
  'Die Lizenz der Komponente, so wie sie in der SBOM steht. Sie wird nur festgehalten und nicht geprüft — Lizenzfragen sind kein Gegenstand der Verordnung.': 'The licence of the component exactly as stated in the SBOM. It is recorded only and not assessed — licensing is not a matter the Regulation covers.',
  'z. B. Sicherheitskontakt und Update-Zusagen des Lieferanten liegen vor':
    'e.g. the supplier’s security contact and update commitments are on file',
  'Komponente löschen? Zugehörige Funde werden mit entfernt.': 'Delete this component? Its findings are removed with it.',

  // --- Fund-Drawer ---
  'Aktiv ausgenutzt': 'Actively exploited',
  'Gemeldet über:': 'Reported via:',
  'Meldung veröffentlicht:': 'Report published:',
  'Art der Schwachstelle (CWE-Katalog)': 'Type of weakness (CWE catalogue)',
  'Behoben in:': 'Fixed in:',
  'Keine Behebung verfügbar': 'No fix available',
  'Die Meldung nennt keine behebende Version.': 'The report does not name a fixed version.',
  'Als Zielversion übernehmen — Entscheidung wird „Sofort beheben“':
    'Use as the target version — the decision becomes “Fix now”',
  'Quellen': 'Sources',
  '(Meldung, Korrektur, Projektseite)': '(report, fix, project page)',
  'Begründung': 'Justification',
  'Bis wann gilt das?': 'Until when does this apply?',
  'Warum diese Entscheidung?': 'Why this decision?',
  'Bekannt seit': 'Known since',
  'Nein / keine Nachweise': 'No / no evidence',
  'Meldung an den Komponenten-Hersteller': 'Report to the component manufacturer',
  'Wird eine Schwachstelle in einer fremden Komponente gefunden, ist sie an deren Hersteller oder das zuständige Projekt zu melden — auch bei quelloffener Software. Wurde bereits eine Korrektur erstellt, ist sie mitzuteilen.':
    'If a vulnerability is found in a third-party component, it has to be reported to its manufacturer or the project that maintains it — open-source components included. If a fix has already been produced, it has to be shared.',
  'Gemeldet an — Projekt oder Lieferant': 'Reported to — project or supplier',
  'Korrektur oder Unterlagen weitergegeben': 'Fix or documentation shared',

  // --- Fund erfassen ---

  // --- SBOM-Drawer ---
  'Nur direkte Abhängigkeiten': 'Direct dependencies only',
  'Alle Abhängigkeiten': 'All dependencies',
  'SBOM-Stand löschen? (Komponenten bleiben im Inventar)': 'Delete this SBOM snapshot? (components stay in the inventory)',
  'Komponenten · erstellt': 'components · generated',
  '· importiert': '· imported',

  // --- Hinweisboxen und Leerzustände ---
  'Noch keine SBOM für': 'No SBOM yet for',
  'Keine Komponenten gefunden — CycloneDX (components[]) oder SPDX (packages[]) erwartet.':
    'No components found — expected CycloneDX (components[]) or SPDX (packages[]).',
  'neu,': 'new,',
  'aktualisiert — Original archiviert': 'updated — original archived',
  'ohne purl': 'without a purl',

  // --- Versionsvergleich ---
  'Vergleich wird berechnet …': 'Computing the comparison …',
  'Vergleich:': 'Comparison:',
  'neu ·': 'new ·',
  'entfernt ·': 'removed ·',
  'Version geändert ·': 'version changed ·',
  'unverändert': 'unchanged',
  'Version geändert': 'Version changed',
  'Entfernt': 'Removed',

  // --- Datenbank / Fehler ---
  'Datenbank nicht erreichbar': 'Database unavailable',
  'API-Server starten:': 'Start the API server:',
  'Erneut verbinden': 'Reconnect',
  // --- Fußzeile ---
  'Daten gespeichert': 'Data saved',
  'verbinde …': 'connecting …',
  'keine Verbindung': 'no connection',

  // --- Nachgezogen (Prüfbericht 2026-08-31): Beschriftungen, Hilfetexte, Servermeldungen ---
  'Zielversion:': 'Target version:',
  'betroffen bis': 'affected up to',
  'bis': 'until',
  'keine bekannt': 'none known',
  'ohne Paket-Kennung — wird bei der Prüfung übersprungen': 'no package ID — skipped by the check',
  'auf': 'to',
  'Gewählte Zielversion': 'Chosen target version',
  'Zielversion entfernen': 'Remove target version',
  'Meldung': 'Report',
  'Korrektur': 'Fix',
  'Bericht': 'Report page',
  'Projekt': 'Project',
  'Kernfunktion des Produkts': 'Core function of the product',
  'Lieferant geprüft': 'Supplier reviewed',
  'Keine Komponenten für diesen Filter.': 'No components match this filter.',
  'Keine Funde für diesen Filter.': 'No findings match this filter.',
  'Keine Treffer für die Suche.': 'No matches for this search.',
  'Noch keine Komponenten — im Reiter SBOMs eine SBOM importieren oder mit „+ Komponente“ Hardware anlegen.':
    'No components yet — import an SBOM from the SBOMs tab, or add hardware with “+ Component”.',
  'Noch keine Funde — oben „Auf Schwachstellen prüfen“ starten oder einen Fund erfassen.':
    'No findings yet — run “Check for vulnerabilities” above, or record one.',
  'Erst möglich, wenn Software mit purl im Inventar steht': 'Available once the inventory has software with a package ID (purl)',
  'Erst möglich, wenn eine Datei gewählt ist': 'Available once a file is chosen',
  '+ Komponente': '+ Component',
  '+ Fund erfassen': '+ Record finding',
  'Fund erfassen': 'Record a finding',
  'Software kommt über den SBOM-Import. Hardware und zugekaufte Software werden hier angelegt.':
    'Software arrives via the SBOM import. Hardware and purchased software are added here.',
  'Der Abgleich findet Software automatisch. Meldungen per Mail, Meldungen des Lieferanten und Ergebnisse eigener Tests werden hier erfasst.':
    'The check finds software issues automatically. Reports by email, supplier reports and results from in-house testing are recorded here.',
  'Kennung': 'Identifier',
  'CVE-Nummer oder Kennung der Meldung': 'CVE number or report identifier',
  '— keine Zuordnung —': '— no component —',
  'Zusammenfassung': 'Summary',
  'Was ist betroffen, was ist passiert?': 'What is affected, what happened?',
  'Komponente hinzufügen': 'Add component',
  'Funde an dieser Komponente': 'Findings on this component',
  'es gibt keine Vorversion zum Vergleichen. Sobald eine zweite Version angelegt ist, steht hier, was sich geändert hat.':
    'there is no previous version to compare against. Once a second version exists, what changed shows up here.',
  'Behebung verfügbar seit': 'Fix available since',
  '(sobald Update oder Abhilfe bereitsteht)': '(as soon as an update or workaround is available)',
  'Ja — Unterstützungszeitraum des Lieferanten zählt mit': 'Yes — the supplier’s support period counts toward yours',
  'Nein': 'No',
  'Inverkehrbringen am': 'Placed on the market on',
  '(für die Fünfjahresprüfung)': '(for the five-year check)',
  'Datum des Inverkehrbringens angeben, dann wird der Zeitraum geprüft':
    'Enter the market-placement date and the period gets checked',
  'Verantwortlichen entfernen? Gilt für alle Funde dieses Produkts.': 'Remove the owner? This applies to every finding of this product.',
  'Version {v} löschen? Komponenten, SBOMs und Funde dieser Version gehen mit verloren.':
    'Delete version {v}? Its components, SBOMs and findings are lost with it.',
  'entfernt': 'removed',
  'CVSS — Schweregrad von 0 bis 10, aus der Meldungsquelle': 'CVSS — severity from 0 to 10, from the advisory source',
  'z. B. SmartPanel 3000': 'e.g. SmartPanel 3000',
  'z. B. Muster GmbH': 'e.g. Muster GmbH',
  'z. B. 1.1.0': 'e.g. 1.1.0',
  'z. B. die verwundbare Funktion wird bei uns nie aufgerufen': 'e.g. the vulnerable function is never called in our product',
  'Einschätzung, Analyse-Stand': 'Assessment, state of analysis',

  // Fragezeichen-Erklärungen (D-037)
  'Eindeutige Kennung des Pakets. Über sie findet die Prüfung die Schwachstellen — ohne sie bleibt die Komponente ungeprüft.':
    'The unique ID of the package. The check uses it to find vulnerabilities — without it the component stays unchecked.',
  'Ist das Produkt durch diese Schwachstelle angreifbar? Nicht jede Schwachstelle in einer Komponente wirkt sich auf das Produkt aus.':
    'Is the product exposed to this vulnerability? Not every vulnerability in a component affects the product.',
  'Welche Prüfung erfolgte vor dem Einbau der Komponente? Pflicht für alle selbst ausgewählten Komponenten.':
    'What was checked before the component was built in? Required for every component selected in-house.',
  'Es gibt belastbare Hinweise, dass die Schwachstelle tatsächlich angegriffen wird. Der CVSS-Wert ist dafür kein Nachweis.':
    'There is solid evidence that the vulnerability is actually being attacked. The CVSS score is not evidence of this.',
  'Ohne diese Komponente erfüllt das Produkt seinen Zweck nicht mehr. Dann ist der Unterstützungszeitraum des Lieferanten beim eigenen zu berücksichtigen.':
    'Without this component the product no longer serves its purpose. The supplier’s support period then has to be taken into account when setting the product’s own.',
  'Über welche direkte Abhängigkeit das Paket in das Produkt gelangt.':
    'Which direct dependency pulls this package into the product.',

  // Servermeldungen — der Server spricht deutsch, das Wörterbuch übersetzt (stabile Sätze als Schlüssel)
  'Name fehlt': 'Name is missing',
  'Produkt nicht gefunden': 'Product not found',
  'Version fehlt': 'Version is missing',
  'Version nicht gefunden': 'Version not found',
  'Inhalt fehlt': 'Content is missing',
  'nicht gefunden': 'not found',
  'Komponente nicht gefunden': 'Component not found',
  'Kennung fehlt': 'Identifier is missing',
  'Kenntniszeitpunkt fehlt (startet die Fristen, Art. 14)': 'Time of knowledge is missing (it starts the deadlines, Art. 14)',
  'Keine Software-Komponenten mit purl — erst SBOM importieren oder purl pflegen.':
    'No software with a package ID (purl) — import an SBOM first or fill in the purl.',
}

const Ctx = createContext({ lang: 'de', t: s => s, setLang: () => {} })

// Modulweiter Zugriff fuer Formatierer ausserhalb von React (ui.jsx: fmtD/fmtDT).
let _lang = 'de'
export const getLang = () => _lang

export function I18nProvider({ children }) {
  const [lang, setLangState] = useState(() => {
    try { return localStorage.getItem('sbomgen-lang') || 'de' } catch { return 'de' }
  })
  const setLang = (l) => {
    setLangState(l)
    try { localStorage.setItem('sbomgen-lang', l) } catch { /* private mode */ }
  }
  _lang = lang
  const t = (s) => (lang === 'en' ? (EN[s] ?? s) : s)
  return <Ctx.Provider value={{ lang, t, setLang }}>{children}</Ctx.Provider>
}

export const useI18n = () => useContext(Ctx)
export const useT = () => useContext(Ctx).t
