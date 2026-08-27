# SBOM-Gen — SBOM ingestion, component inventory and CVE matching

Working implementation of the **"SBOM & Components"** module for a CRA compliance product
(Regulation (EU) 2024/2847). It takes the SBOM a customer's build produces, maintains a component
inventory per product version, and matches that inventory against a live vulnerability database.

**There is no demo mode and no seeded data.** Every product, component and finding in the database
got there through an import, a manual entry, or a real HTTP call to OSV.dev. If the network is
down, the scan fails with an error instead of inventing results.

---

## Quick start

```bash
npm install
npm start            # API on :5178 and UI on :5200 in parallel
```

Open <http://localhost:5200>. The database starts empty — that is intentional.

### First run, end to end (5 minutes)

1. **Create a product.** Click *Neues Produkt anlegen*, e.g. `ACME IoT Gateway`, version `2.4.0`.
2. **Import the SBOM.** Click *SBOM importieren* and pick
   [`sboms/acme-iot-gateway.cdx.json`](sboms/acme-iot-gateway.cdx.json) from this repository.
   → 732 components land in the inventory, the original file is archived.
3. **Run the scan.** Click *CVE-Abgleich (OSV)*. Takes about 15–20 seconds.
   → 337 findings, roughly 59 critical / 130 high / 123 medium / 25 low. 319 of them arrive with
   a CVE number and a concrete fixed version, all 337 with links to the advisory, the NVD entry
   and the project.
4. **Triage a finding.** Open any row in the *Funde* tab. The drawer already shows the CVE
   number, the weakness class, which versions fix it and where the advisory lives — click a
   version to adopt it as the remediation target. Then set affectedness (VEX), a decision and an
   owner. Re-run the scan: your triage survives, only advisory data is refreshed.
5. **Create a second version** with *+ Version* (copying the components), change a component
   version, and look at the *Änderungen* tab: added / removed / version-changed, computed live.

Separate processes if you prefer: `npm run server` and `npm run dev`.

### Requirements

Node.js 18 or newer (the server uses the built-in `fetch`) and outbound HTTPS to `api.osv.dev`.
No API key, no account, no local vulnerability database.

---

## The bundled SBOM is real

`sboms/acme-iot-gateway.cdx.json` — 1.1 MB, CycloneDX 1.6, **732 components, all with a purl**.

It was not hand-written. It was generated with the official CycloneDX generator from a real,
installed dependency tree:

```bash
npx @cyclonedx/cyclonedx-npm --omit dev --output-format JSON --output-file acme-iot-gateway.cdx.json
```

The dependency list that produced it is included as
[`sboms/acme-iot-gateway.package.json`](sboms/acme-iot-gateway.package.json) — around 90 direct
dependencies pinned to versions from roughly 2020/21, the sort of stack a shipped device backend
still runs. Everything in the file is genuine: real packages, real versions, real transitive
resolution, real purls. Only the product name on top is fictitious.

That is what makes it useful as a fixture: the vulnerabilities it surfaces are real CVEs in real
libraries, fetched live at scan time. Concentrations sit where you would expect them —
`vm2@3.9.5` (43), `axios@0.21.1` (24), `dompurify@2.0.11` (20), `tar@6.1.0` (18),
`node-forge@0.9.2` (15).

Regenerating it with a newer generator or a different dependency set is fine — nothing in the code
depends on this particular file.

---

## How the data is organised

Everything domain-related hangs off the **product version**, never the product.

```
products (id, name, hersteller)
   └── versions (id, product_id, version, copied_from)
         ├── components (inventory: hardware + software)
         ├── sboms      (imported snapshots, original JSON kept verbatim)
         ├── findings   (vulnerabilities + triage state)
         └── scans      (scan log)
audit_log (ts, action, detail)   ← every mutation
```

SQLite via `better-sqlite3`, file `server/sbom.db`, created on first start and gitignored.

### `components` — the inventory is a superset of the SBOM

| Field | Notes |
|---|---|
| `kind` | `hardware` · `software_eigen` · `software_oss` · `software_zukauf` |
| `name`, `version`, `supplier` | base data |
| `purl` | Package URL — the key the OSV matching runs on |
| `cpe` | for hardware/firmware; stored for documentation, no automated lookup |
| `license` | stored, never analysed |
| `is_core_function` | flag used when justifying the support period |
| `dd_status`, `dd_note` | due diligence record for third-party components |
| `source` | `manuell` or `sbom_import` |

Hardware belongs in the inventory but never in an SBOM — an SBOM covers the *software elements*
of a product by definition. So the inventory is the superset and the SBOM is the software subset.
Hardware vulnerabilities arrive through supplier advisories and are entered by hand.

---

## Import: SBOM → database

`POST /api/versions/:versionId/sboms`

The browser reads the file and normalizes both supported formats onto one shape, so nothing
downstream cares which format it was:

| Field | CycloneDX (`components[]`) | SPDX (`packages[]`) |
|---|---|---|
| Name | `name` | `name` |
| Version | `version` | `versionInfo` |
| purl | `purl` | `externalRefs[]` where `referenceType === "purl"` |
| Supplier | `supplier.name` / `publisher` | `supplier` (leading `Organization: ` stripped) |
| License | `licenses[0].license.id` | `licenseConcluded` |

The server then performs **two writes**:

1. **Archive.** The untouched original JSON goes into `sboms.content`. A market surveillance
   authority can request the SBOM as part of the technical documentation, and what you hand over
   should be the build artifact, not a re-serialization of it. Retrieve it with
   `GET /api/sboms/:id/download`.
2. **Upsert the inventory.** Matched by purl, falling back to the name. Hits get version, supplier
   and license refreshed; misses are inserted as `software_oss` / `sbom_import`.

**Re-importing never overwrites `kind`, `is_core_function`, `dd_status` or `dd_note`.** Those are
human judgments — a component someone classified as purchased firmware with a completed supplier
baseline must not be reset by the next build.

The detected format is stored as a **label and never validated**, because the Commission may still
prescribe SBOM format and elements by implementing act. Accept what arrives, record what it was,
enforce nothing. Likewise `depth`: top-level dependencies are the legal minimum, so `top_level`
is the default and a shallow SBOM never produces a warning.

---

## Scan: database → OSV.dev → findings

`POST /api/versions/:versionId/scan`. Runs server-side; the browser never talks to OSV.

**Source:** [OSV.dev](https://github.com/google/osv.dev) — purl-native, no API key.
Record schema: [OSV Schema](https://github.com/ossf/osv-schema).

1. **Select candidates.** `purl != '' AND kind != 'hardware'`. No purl, no matching. An empty
   selection returns `400` and writes no scan record.
2. **Batch query.** `POST https://api.osv.dev/v1/querybatch`, chunked at `QUERY_CHUNK = 400`
   purls per request, 30 s timeout each. Returns vulnerability IDs per component — **all of them,
   with no per-component cap**.
3. **Fetch details.** `GET https://api.osv.dev/v1/vulns/{id}` over the distinct IDs,
   `DETAIL_PARALLEL = 10` at a time. A failed detail request is tolerated; the finding is then
   stored with severity `—`.
4. **Enrich.** Everything the advisory carries and a reviewer needs is extracted and stored, so
   it shows up on the finding automatically — no extra lookup:
   - `aliases` → the **CVE number**, shown as the primary identifier in the table (the GHSA id
     stays underneath, because nobody recognises `GHSA-9m93-w8w6-76hh` but everybody knows
     `CVE-2023-3696`)
   - `affected[].ranges[].events[].fixed` → the **fixed versions** for *this* package, matched by
     purl so other packages in the same advisory do not leak in. Where a range only carries
     `last_affected`, the finding says so instead of pretending a fix exists.
   - `references` plus derived links → **sources**: OSV, the GitHub advisory, the NVD entry for
     each CVE alias, the fix commit and the project page
   - `database_specific.cwe_ids` → weakness classes, and `published` → advisory date
5. **Score locally.** The CVSS 3.x base score is computed from the vector string
   ([FIRST.org formula](https://www.first.org/cvss/v3.1/specification-document)) — OSV ships the
   vector but not the score. The GitHub severity label wins when present, otherwise thresholds on
   the computed score decide (`≥9` critical, `≥7` high, `≥4` medium).
6. **Upsert findings**, keyed on `(vuln_id, component_id)`:
   - **known finding** → only the advisory-derived data changes: severity, score, summary,
     aliases, CWEs, fixed versions, sources, `updated_at`. VEX status,
     decision, owner, exploitation evidence and the upstream fields are left alone. That is what
     makes a daily rescan safe.
   - **new finding** → `became_known_at = now`. This timestamp is the deadline anchor for
     regulatory reporting and is never derived from anything else.
   - Findings OSV no longer returns are **not** deleted. A disappearing match is not evidence that
     the product is unaffected.
7. **Log it.** A row in `scans` plus an `audit_log` entry.

If OSV is unreachable the endpoint answers `502` and changes nothing. There is deliberately no
fallback to cached data: a scan that did not happen must not look like one that did.

Both constants live at the top of `server/index.mjs` and can be raised.

### Check it yourself

```bash
# what our API stored
curl -s -X POST http://localhost:5178/api/versions/<vid>/scan | jq '.scan'

# what OSV returns for one package, independently of this tool
curl -s -X POST https://api.osv.dev/v1/querybatch \
  -H 'Content-Type: application/json' \
  -d '{"queries":[{"package":{"purl":"pkg:npm/vm2@3.9.5"}}]}' | jq
```

The ID sets match. That comparison is the acceptance test for "the scanner is real".

---

## Triage

`PATCH /api/findings/:id` (whitelisted fields only)

The drawer follows the order the work actually happens in:

1. **Affectedness (VEX)** — `under_investigation` → `affected` / `not_affected` / `fixed`.
   First, because "not affected" with a justification closes a finding without remediation, which
   is how the false positives inherent to SBOM matching get cleared.
2. **Decision** — `fix_now` / `mitigate` / `accept` / `defer`. `accept` requires an expiry date;
   `accept` and `defer` require a rationale. The fixed versions from the advisory are offered as
   buttons: picking one writes it to `fix_version` and sets the decision to *fix now*, so the
   remediation target is recorded rather than retyped.
3. **Actively exploited** — a separate boolean with a mandatory evidence field. **Never derived
   from the CVSS score**: the legal definition requires reliable evidence of real-world
   exploitation, which a severity number is not. Setting it surfaces the reporting deadlines as a
   hint; the reporting chain itself belongs to a different module.
4. **Upstream report** — who the vulnerability in a third-party component was reported to, when,
   and whether fix code was shared.
5. **Advisory draft** — available once a finding is `fixed`; downloads a Markdown skeleton
   pre-filled with the affected product and version, the remediation target and the source links.
   Publishing stays with the manufacturer.

Findings that arrive outside the scanner — an email to the security contact, a supplier advisory,
a CSIRT notification, your own testing — are entered with `POST /api/versions/:id/findings`.
`vuln_id` and `became_known_at` are mandatory there; a finding without a time anchor is useless
as evidence.

---

## Versions and the automatic comparison

`POST /api/products/:id/versions` with `{ version, copyFrom }` copies the **components** of the
previous version and records `copied_from`. Findings and SBOMs are deliberately not copied —
each version carries its own assessment.

`GET /api/versions/:id/diff` computes the comparison; nothing is maintained by hand. The matching
key strips the version off the purl:

```js
const key = c => c.purl ? 'p:' + purlBase(c.purl)          // purl WITHOUT @version
                        : 'n:' + c.kind + '|' + c.name.toLowerCase()
```

Without that, upgrading `lodash@4.17.20` to `4.17.21` would read as "removed + added" instead of
**changed**. Output: `added` / `removed` / `changed` (with `from`/`to`) / `unchanged`.

---

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/bootstrap` | products and versions |
| `POST` | `/api/products` | product plus first version |
| `POST` | `/api/products/:id/versions` | new version, optionally copying components |
| `DELETE` | `/api/products/:id` · `/api/versions/:id` | delete (cascades) |
| `GET` | `/api/versions/:id` | components, sboms, findings, scans |
| `GET` | `/api/versions/:id/diff` | comparison against the previous version |
| `POST` | `/api/versions/:id/components` | add a component (mainly hardware) |
| `PATCH` `DELETE` | `/api/components/:id` | update / delete |
| `POST` | `/api/versions/:id/sboms` | import an SBOM |
| `PATCH` | `/api/sboms/:id` | depth, user-provision flag, access location |
| `GET` | `/api/sboms/:id/download` | original JSON |
| `POST` | `/api/versions/:id/scan` | OSV matching |
| `POST` | `/api/versions/:id/findings` | enter a finding manually |
| `PATCH` | `/api/findings/:id` | triage |
| `GET` | `/api/audit` | audit log, last 200 entries |

---

## Regulatory anchors

Every non-obvious rule in the code traces to a provision of Regulation (EU) 2024/2847:

| Behaviour | Provision |
|---|---|
| Identify and document components and vulnerabilities, SBOM in a machine-readable format covering at least the top-level dependencies | Annex I Part II No. 1 |
| An SBOM covers software elements — hardware stays in the inventory | Art. 3(39), Art. 3(6) |
| Due diligence for integrated third-party components, open source included | Art. 13(5) |
| Report vulnerabilities in third-party components upstream, share fix code | Art. 13(6) |
| Systematic documentation of security-relevant activity (the audit log) | Art. 13(7) |
| Support-period reasoning uses core-function components | Art. 13(8) |
| "Actively exploited" needs reliable evidence — never inferred from CVSS | Art. 3(42) |
| The point of awareness starts the 24 h / 72 h reporting clocks | Art. 14 |
| Handle and remediate vulnerabilities without delay | Annex I Part II No. 2 |
| Publish information about fixed vulnerabilities once an update is available | Annex I Part II No. 4 |
| SBOM belongs to the technical documentation on a reasoned request | Annex VII No. 8 |
| Where the SBOM is available is stated only if it is published to users | Annex II No. 9 |
| Format and elements of the SBOM may be prescribed later — so the format is not enforced | Art. 13(24) |

---

## Deliberately out of scope

- **Generating SBOMs.** The customer's build does that (Syft, Trivy, cdxgen, a build plugin).
  This tool consumes them.
- **The Article 14 reporting chain** with its calculated deadlines — a separate module. Marking a
  finding as actively exploited shows the deadlines as a hint and nothing more.
- **Publishing advisories and shipping updates.** The tool produces a draft and keeps the record;
  acting is the manufacturer's job.
- **Supplier master data.** Components link to supplier management, they do not replace it.
- **License analysis.** The license field is carried along, never evaluated.
- **Internal SLA timers.** Deliberately absent: the statutory deadlines are what matter, and
  proof of acting "without delay" comes from documented triage, not from a traffic light.
- **NVD / CISA KEV integration.** OSV covers the same ground for package dependencies and is
  purl-native. A KEV badge would invite the false inference "no badge means not exploited"; the
  catalogue is far from complete. Assessing exploitation stays a human decision with written
  evidence.

---

## Stack

Vite + React 19 on the front end, Express 5 + better-sqlite3 on the back end. Runtime
dependencies: `express`, `better-sqlite3`, `react`, `react-dom`. No UI framework, no state
library, no ORM. Hash-free single view; the styling mirrors the target product's design tokens.
