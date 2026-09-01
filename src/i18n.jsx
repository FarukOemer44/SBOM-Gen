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
  'von den selbst ausgewählten Komponenten': 'of the components selected in-house',
  'Funde insgesamt': 'Findings total',
  'kritisch ·': 'critical ·',
  'hoch ·': 'high ·',
  'mittel ·': 'medium ·',
  'niedrig': 'low',
  'Betroffenheit bewertet': 'Affected status assessed',
  'Letzte Prüfung:': 'Last check:',
  'heute': 'today',
  'gestern': 'yesterday',
  'vor {n} Tagen': '{n} days ago',
  'vor {n} Monaten': '{n} months ago',
  'Inventar seither geändert': 'inventory changed since',
  'Die Entscheidung braucht eine Begründung': 'The decision needs a rationale',
  'Ein akzeptiertes Risiko braucht eine Befristung': 'An accepted risk needs a time limit',
  'Die Meldung nennt diese Version nicht mehr': 'The report no longer names this version',
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
  'Beschreibung': 'Description',
  'z. B. Steuerungslogik für die Ventilansteuerung': 'e.g. control logic for the valve actuation',
  'z. B. Touch-Display der Bedieneinheit, 7 Zoll': 'e.g. touch display of the control unit, 7 inch',
  'z. B. Bibliothek für die Verschlüsselung der Gerätekommunikation': 'e.g. library encrypting device communication',
  'Schwachstellen': 'Vulnerabilities',
  'Sorgfalt': 'Due diligence',
  'Vor dem Einbau einer fremden Komponente ist zu prüfen, dass sie die Sicherheit des Produkts nicht gefährdet — quelloffene Software eingeschlossen. Die Pflicht gilt für Hardware, Zukauf und direkt eingebundene Pakete; transitive Pakete wählt niemand aus.':
    'Before a third-party component is built in, it has to be checked that it does not compromise the security of the product — open-source software included. The duty covers hardware, purchased software and direct dependencies; nobody selects transitive packages.',
  'z. B. Projekt wird aktiv gepflegt, veröffentlicht Sicherheitsmeldungen, beim Einbau keine offenen Funde':
    'e.g. project is actively maintained, publishes security advisories, no open findings at integration time',
  'Geprüft': 'Reviewed',
  'Offen': 'Open',
  'Kernfunktion': 'core function',
  'Datei': 'File',
  'Format': 'Format',
  'Erstellt': 'Generated',
  'Importiert': 'Imported',
  'Schwere': 'Severity',
  'Schwachstelle': 'Vulnerability',
  'Behebung': 'Remediation',
  'Betroffenheit': 'Affected status',
  'Ob das Produkt angreifbar ist, wurde noch nicht bewertet. Entscheidung und Behebung folgen danach.':
    'Whether the product is exposed has not been assessed yet. Decision and remediation follow after that.',
  'Das Produkt ist angreifbar. Es braucht eine Entscheidung und eine Begründung dafür.':
    'The product is exposed. It needs a decision and a rationale for it.',
  'Das Produkt ist nicht angreifbar. Die Begründung dafür ist verpflichtend.':
    'The product is not exposed. A rationale for that is mandatory.',
  'Die Schwachstelle ist behoben. Der Sicherheitshinweis lässt sich jetzt als Entwurf erzeugen.':
    'The vulnerability is fixed. The security advisory can now be produced as a draft.',
  'Ohne Begründung ist „Nicht betroffen“ nicht belegt': '“Not affected” is not substantiated without a rationale',
  'Erst möglich, wenn die Betroffenheit bewertet ist': 'Possible once the affected status has been assessed',
  'Eine Entscheidung ist erst möglich, wenn die Betroffenheit oben auf „Betroffen“ steht.':
    'A decision is only possible once the affected status above is set to “Affected”.',
  'Entscheidung': 'Decision',
  'Wie wurde die Schwachstelle behoben?': 'How was the vulnerability fixed?',
  'z. B. auf die behebende Version angehoben, Komponente ausgebaut, Korrektur zurückportiert':
    'e.g. raised to the fixed version, component removed, fix backported',
  'Ohne Angabe ist „Behoben“ nicht belegt': '“Fixed” is not substantiated without an entry',
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
  'Komponenten, SBOMs und Funde werden je Produktversion geführt. Der SBOM-Import ist nach dem Anlegen der ersten Version möglich.':
    'Components, SBOMs and findings are tracked per product version. The SBOM import becomes available once the first version exists.',
  'aktiv ausgenutzt': 'actively exploited',
  'Ja — verlässliche Nachweise erforderlich': 'Yes — reliable evidence required',
  'Eigene Tests': 'Own testing',
  'Hinweis von außen': 'External notification',
  'Nachweis der Einstufung': 'Evidence for this assessment',
  'Version löschen?': 'Delete version?',
  'Gespeichert': 'Saved',
  'Prüfverlauf': 'Check history',
  'Protokoll aller Prüfungen mit Zeitpunkt, Umfang und Ergebnis.':
    'Log of every check with time, scope and result.',
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
  '(optional, auch später möglich)': '(optional, can be added later)',
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
  'Auszutauschen ist die direkte Abhängigkeit': 'The direct dependency to replace is',
  'Anschrift des Lieferanten': 'Supplier address',
  '— 10 Jahre aufbewahren, für Behördenanfragen': '— keep for 10 years, for authority requests',
  'Straße, PLZ Ort, Land': 'Street, postcode, city, country',
  'Bezogen am': 'Acquired on',
  'Aufbewahren bis': 'Keep until',
  'Lieferant unterstützt bis': 'Supplier support until',
  'endet vor dem Produkt': 'ends before the product',
  'Kernkomponente: Die Unterstützung des Lieferanten endet vor der des Produkts':
    'Core component: the supplier’s support ends before the product’s',
  'gegen': 'vs',
  'Der eigene Unterstützungszeitraum ist zu kürzen oder ein Ersatz einzuplanen.':
    'The product support period has to be shortened, or a replacement planned.',
  'Name': 'Name',
  'Paket-Kennung (purl)': 'Package ID (purl)',
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
  'Begründung der Betroffenheit': 'Rationale for the affected status',
  'Befristung': 'Time limit',
  'Begründung der Entscheidung': 'Rationale for the decision',
  'Bekannt seit': 'Known since',
  'Nein / keine Nachweise': 'No / no evidence',
  'Meldung an den Komponenten-Hersteller': 'Report to the component manufacturer',
  'Wird eine Schwachstelle in einer fremden Komponente gefunden, ist sie an deren Hersteller oder das zuständige Projekt zu melden — auch bei quelloffener Software. Wurde bereits eine Korrektur erstellt, ist sie mitzuteilen.':
    'If a vulnerability is found in a third-party component, it has to be reported to its manufacturer or the project that maintains it — open-source components included. If a fix has already been produced, it has to be shared.',
  'Gemeldet an — Projekt oder Lieferant': 'Reported to — project or supplier',
  'Korrektur oder Unterlagen weitergegeben': 'Fix or documentation shared',

  // --- Fund erfassen ---

  // --- SBOM-Drawer ---
  'SBOM-Stand löschen? (Komponenten bleiben im Inventar)': 'Delete this SBOM snapshot? (components stay in the inventory)',
  'Komponenten · erstellt': 'components · generated',
  '· importiert': '· imported',

  // --- Hinweisboxen und Leerzustände ---
  'Noch keine SBOM für': 'No SBOM yet for',
  'Die Datei enthält keine Komponenten. Erwartet wird eine SBOM im Format CycloneDX oder SPDX.':
    'The file contains no components. A SBOM in CycloneDX or SPDX format is expected.',
  'neu,': 'new,',
  'aktualisiert — Original archiviert': 'updated — original archived',
  'ohne Paket-Kennung': 'without a package ID',

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
  'Keine Komponenten für diesen Filter.': 'No components match this filter.',
  'Keine Funde für diesen Filter.': 'No findings match this filter.',
  'Keine Treffer für die Suche.': 'No matches for this search.',
  'Noch keine Komponenten. Software kommt über den SBOM-Import, Hardware und Zukauf über „+ Komponente“.':
    'No components yet. Software arrives via the SBOM import, hardware and purchased software via “+ Component”.',
  'Noch keine Funde. Der Abgleich erfasst Software mit Paket-Kennung, alles Übrige über „+ Fund erfassen“.':
    'No findings yet. The check covers software with a package ID; everything else via “+ Record finding”.',
  'Erfordert Software mit Paket-Kennung im Inventar':
    'Requires software with a package ID in the inventory',
  'Erfordert eine ausgewählte Datei': 'Requires a selected file',
  '+ Komponente': '+ Component',
  '+ Fund erfassen': '+ Record finding',
  'Fund erfassen': 'Record a finding',
  'Kennung': 'Identifier',
  'CVE-Nummer oder Kennung der Meldung': 'CVE number or report identifier',
  '— keine Zuordnung —': '— no component —',
  'Zusammenfassung': 'Summary',
  'Kurzbeschreibung der Schwachstelle': 'Brief description of the vulnerability',
  'Komponente hinzufügen': 'Add component',
  'Funde an dieser Komponente': 'Findings on this component',
  'Es gibt keine Vorversion zum Vergleich. Der Unterschied der Komponenteninventare erscheint ab der zweiten Version.':
    'There is no previous version to compare against. The difference between component inventories appears from the second version on.',
  'Behebung verfügbar seit': 'Fix available since',
  '(sobald eine Korrektur bereitsteht)': '(once a fix is available)',
  'Ja — der Unterstützungszeitraum des Lieferanten ist zu berücksichtigen':
    'Yes — the supplier’s support period has to be taken into account',
  'Nein': 'No',
  'Verantwortlichen entfernen? Gilt für alle Funde dieses Produkts.': 'Remove the owner? This applies to every finding of this product.',
  'Version {v} löschen? Komponenten, SBOMs und Funde dieser Version werden mit gelöscht.':
    'Delete version {v}? Its components, SBOMs and findings are deleted with it.',
  'entfernt': 'removed',
  'CVSS — Schweregrad von 0 bis 10, aus der Meldungsquelle': 'CVSS — severity from 0 to 10, from the advisory source',
  'z. B. SmartPanel 3000': 'e.g. SmartPanel 3000',
  'z. B. Muster GmbH': 'e.g. Muster GmbH',
  'z. B. 1.1.0': 'e.g. 1.1.0',
  'z. B. die verwundbare Funktion wird bei uns nie aufgerufen': 'e.g. the vulnerable function is never called in our product',
  'Einschätzung und Stand der Analyse': 'Assessment and state of the analysis',

  // Fragezeichen-Erklärungen (D-037)
  'Eindeutige Kennung des Pakets. Über sie findet die Prüfung die Schwachstellen — ohne sie bleibt die Komponente ungeprüft.':
    'The unique ID of the package. The check uses it to find vulnerabilities — without it the component stays unchecked.',
  'Nicht jede Schwachstelle in einer Komponente wirkt sich auf das Produkt aus. Hier wird festgehalten, ob es tatsächlich angreifbar ist.':
    'Not every vulnerability in a component affects the product. This records whether it is actually exposed.',
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
  'Kenntniszeitpunkt fehlt — Pflichtangabe.': 'Time of knowledge is missing — a required entry.',
  'Keine Software mit Paket-Kennung im Inventar.': 'No software with a package ID in the inventory.',
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
