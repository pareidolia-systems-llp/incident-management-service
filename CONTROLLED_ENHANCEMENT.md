# Controlled enhancement — 15 October 2026

## Implemented: clearer ticket actions and optional report times

The existing Incident Details actions are presented as **Record Investigation**, **Log Work on This Incident**, and **Resolve Incident**, with a short explanation below each main button. Buttons, modal headings and supporting Help wording use the new labels. The three existing API operations remain separate and unchanged. Investigation still updates the incident's diagnostic fields, records INVESTIGATION_UPDATED and may advance OPEN/ASSIGNED to IN_PROGRESS. Ticket work is still WORK_NOTE in IncidentHistory. Resolution still moves the incident to RESOLVED for original-reporter validation. No operational controls were granted to reporters.

Reports were found inside the Incident List as a month-picker card, not on a separate Reports page. The card now offers Month (unchanged default) or Date / time range. This change does not introduce a new route/sidebar item.

The existing endpoint remains `GET /api/reports/incidents/monthly`:

- Existing `year=2026&month=10` remains backward-compatible, including the filename.
- Alternatively supply `fromDate=2026-10-01&toDate=2026-10-15`, with independently optional `fromTime` and `toTime`.
- Do not mix month/year parameters with range parameters; supply both dates for a range.
- Missing From Time means 00:00 on From Date. Missing To Time includes all of To Date by querying `< next day 00:00`, avoiding fractional precision truncation.
- Explicit times are exact inclusive boundaries: `toTime=17:30` includes 17:30:00 but excludes 17:30:00.000001. Equal explicit endpoints are valid.
- From > To returns HTTP 400 with a clear message, and the UI rejects it before requesting. Values are never swapped. Date limits remain 1900–9998. Invalid calendar/time values are rejected.
- Selection remains based on `Incident.reportedAt`, and the workbook still includes the complete lifecycle history of matching incidents, even when individual history events fall outside the selected range. Current incident data/history are not modified by exports.
- Both incident and history queries apply identical bounds and retain deterministic ordering. Exports still use explicit string Excel cells, preserve long text, avoid attachment BLOB reads, and set no-store.
- Authorization remains IT_HANDLER/ADMIN at the service boundary. OAuth, CSRF, attachment permissions, work-note storage, lifecycle rules, polling and Faro filtering were not changed. No report contents or work text are logged; export logs contain actor and range metadata only.

### Time convention and deployment check

Existing entities use timezone-less LocalDateTime and LocalDateTime.now(); repository configuration specifies no explicit application/JDBC timezone. Existing report date semantics are local wall-clock values. The new UI sends literal dates/times without UTC conversion; the backend preserves those semantics. Before deployment, verify that the VM/JVM and existing stored incident timestamps use the intended business timezone. No timezone migration, production inspection, or production change was performed.

### Files changed in this pass

Backend under `src/main/java/com/pareidolia/incidentmanagement/`:

- `controller/IncidentReportController.java`
- `service/IncidentReportService.java`
- `service/impl/IncidentReportServiceImpl.java`
- `repository/IncidentRepository.java`
- `repository/IncidentHistoryRepository.java`

Backend tests: `src/test/java/com/pareidolia/incidentmanagement/IncidentFeatureTests.java`.

Frontend under `incident-management-ui/src/`:

- `pages/IncidentDetails.jsx`
- `utils/incidentGuidance.js`
- `utils/portalHelp.js`
- `App.css`
- `components/MonthlyReport.jsx`
- `api/reports.js`
- `utils/reportRange.js` (new)
- `utils/reportRange.test.js` (new)
- `ReportRange.test.jsx` (new)
- Existing action-label assertions updated in `Activity.test.jsx`, `IncidentWorkspace.test.jsx`, and `ReporterLifecycle.test.jsx`. These assertions still test the same behavior.

### Validation

- All Maven tests attempted against explicitly isolated H2 with dummy OAuth configuration: **105 passed; 1 application-context startup error** (106 total, zero assertion failures). AuthenticationFlowTests: 6 passed; IncidentFeatureTests: 30 passed; IncidentLocationTests: 69 passed. The existing contextLoads test still fails because Windows Java cannot create a loopback connection during OAuth HTTP-client initialization (`SocketException: Invalid argument: connect`). No tests were removed, weakened or disabled. Local ignored log: `report-range-maven.log`.
- Node tests: **23 passed**.
- Vitest: **132 passed in 10 files**. After the final Help copy-only update, its 15 tests were rerun and passed.
- ESLint: passed. Frontend production build: passed, with the existing non-fatal large-bundle/ineffective react-router dynamic-import warnings.
- `git diff --check`: passed in both repositories.
- No schema changes, commits, pushes, merges, deployments or production VM operations in this pass.
- Manual checks remaining: responsive report controls and explanatory action text, date/time selection and Excel download in a real browser, and verification of the deployed VM/JVM/stored timestamp convention before release. No combined work-log reporting was implemented.

## Proposed / waiting for schema approval: My Work Log

**No entity, table, migration, endpoint, or navigation entry has been created for this feature.** Existing entities are Incident, IncidentHistory, IncidentAttachment and AppUser. No migration framework or checked-in schema SQL was found; the application defaults to Hibernate ddl-auto=update. Therefore even adding a mapped entity could implicitly create a table at startup and must wait for explicit approval. Production must use an explicitly reviewed migration rather than relying silently on Hibernate update.

Proposed smallest model: one separate `work_log_entries` table, with no incident_id and no IncidentHistory reuse.

| Field | Proposed type | Required / behavior |
|---|---|---|
| id | BIGINT primary key, generated | Required |
| owner_id | BIGINT foreign key to app_users.id | Required; assigned from authenticated user, never trusted from request |
| worked_at | LocalDateTime / DATETIME(6) | Required; user-selected work date/time, initially current local time |
| category | VARCHAR(32) | Required with application default OTHER; fixed application allowlist, not native DB ENUM |
| summary | VARCHAR(255) | Required, trimmed, nonblank |
| details | TEXT | Optional, maximum 8,000 characters at API boundary |
| duration_minutes | INT | Optional positive integer; not billing/timekeeping |
| created_at | LocalDateTime / DATETIME(6) | Required; generated by server, immutable |

Proposed index: `(owner_id, worked_at, id)` for own-entry chronological listing; primary-key index as usual. No updated_at because this MVP has no editing. Keep the owner foreign key restrictive on deletion so identity is not silently lost. Validate actual MySQL schema/version before preparing the eventual reviewed migration.

Fixed categories: User Support, Maintenance, Network, Server, Security, Administration, Other. Category values can be application enum/string constants stored as VARCHAR so extending the allowlist does not require a database enum alteration. No category administration.

Proposed permissions: active authenticated IT_HANDLER/ADMIN may create and read **only their own entries**, enforced by owner predicate in backend reads and session-derived owner on creation. REPORTER/REVIEWER receive no access. ADMIN initially has the same own-entry scope; cross-user access/reporting should be separately approved. No edit/delete, work-log attachments, calendar, approvals, recurring entries, or payroll functionality.

After approval, proposed UI: a My Work Log navigation item visible to operational roles, a compact own-entry list and an Add Work Entry modal using existing form/card/validation patterns. The intended sidebar can later place Reports and My Work Log before How to Use; Reports is currently embedded in Incidents, so a dedicated Reports navigation route would need a small separately agreed extraction. No empty/broken links were added now.

### Later reporting feasibility

Standalone entries can be reported cleanly later by filtering worked_at and adding a dedicated export or worksheet using the existing Apache POI formatting conventions. The present writer is incident-specific (including ticket references and long-text handling); extract common cell/style helpers only when that export is implemented. Add explicit own-entry authorization (or separately approved admin-wide scope), query/controller/service coverage, and export tests. Do not join unrelated work into IncidentHistory or pretend it is an incident. Combined reporting is not implemented in this pass.

### Approval needed

Approve the single-table design and own-entry-only IT_HANDLER/ADMIN permissions before any entity or migration is created. This stop is required by the user's explicit schema-approval instruction, not a technical inability to implement the feature.
