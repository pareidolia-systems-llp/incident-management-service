# Activity / Work Log MVP — 15 October 2026

## Database and deployment verification (not executed)

Repository evidence inspected: `IncidentHistory` mapping, `HistoryActionType`, both application property files, Maven dependencies, repository SQL/migration file inventory, H2/JPA tests, and `IMPLEMENTATION_REPORT.md`. No checked-in schema SQL or migration framework was found. `remarks` is already TEXT. `action_type` is `@Enumerated(EnumType.STRING)`, and the installed Hibernate 7.4.5 MySQL dialect registers native ENUM handling. The configured default is `spring.jpa.hibernate.ddl-auto=${JPA_DDL_AUTO:update}`; the deployment guide also permits `validate`.

**Do not rely on Hibernate update to change production.** No production connection, schema inspection, migration, simulation, or deployment was performed. No table, column, index or mapping was added for work notes or attention state. The only persistent type change potentially needed is adding `WORK_NOTE` to the existing action enum.

Before deployment, the VM/database operator must verify the effective database/schema, MySQL version, effective JPA_DDL_AUTO, and actual column definition using read-only inspection:

```sql
SELECT DATABASE(), VERSION();
SHOW CREATE TABLE incident_history;
SHOW FULL COLUMNS FROM incident_history LIKE 'action_type';
```

If `action_type` is native ENUM and lacks `WORK_NOTE`, an explicitly reviewed SQL alteration is required before the new application accepts notes. Construct this from the actual `SHOW CREATE TABLE` output: copy the entire existing column definition, append `'WORK_NOTE'` at the end of its existing enum literal list, and preserve every existing value in its original order, nullability, default, character set/collation, comment and other attributes. The conceptual template below is intentionally **not executable**; placeholders must be replaced from verified production metadata:

```text
ALTER TABLE <verified_schema>.incident_history
  MODIFY COLUMN action_type
  ENUM(<all existing literals in their existing order>, 'WORK_NOTE')
  <all existing column attributes unchanged>;
```

Do not reconstruct the deployed list from the Java enum: production may contain additional values. If the value already exists, no alteration is needed. If the column is unconstrained VARCHAR/TEXT, adding the Java constant needs no column change; inspect any CHECK constraint and stop for review if it prevents the new value. Verify the prepared SQL against the actual MySQL version and ordinary release/change process. No executable migration was supplied because the complete deployed definition is unknown. No other schema change is authorized or implemented. Explicitly set production JPA_DDL_AUTO to `validate` through the release configuration after the verified change; this repository's existing configuration is not silently changed.

## Behavior

- `POST /api/incidents/{id}/work-notes` accepts required `remarks` (maximum 8,000 characters), trims it, and records WORK_NOTE with the authenticated actor and existing history timestamp. Only IT_HANDLER/ADMIN may write, with the existing non-closed operational restriction. No edit/delete route, notification, or work-note body logging was added.
- Incident DTOs expose `issueStillPersists`, `issueStillPersistsAt`, and `issueStillPersistsReportedBy`. A batch history query finds the newest relevant rejection/resolution event by timestamp and ID. Only IN_PROGRESS incidents whose latest relevant event is RESOLUTION_NOT_ACCEPTED receive attention. Intervening investigation/notes do not clear it; re-resolution does. Normal IN_PROGRESS incidents remain unflagged. Existing visibility checks precede enrichment.
- List shows an additional attention badge; Details shows a warning with actor/time; Dashboard counts flagged authorized incidents using its existing list API. Dashboard's existing cards are non-clickable; this MVP adds no attention filter or extra list.
- A single Activity & Work Log renders existing history oldest first, ordered in the backend by changedAt then ID, including persistent reporter rejection events and notes. Actor/time remain visible. Initial values say e.g. `Priority set to HIGH`; clearing says `Value cleared`. Free text is rendered as React text with line breaks preserved, without fabricated historical values.
- Investigation uses the existing ImagePicker and attachment API after the investigation request succeeds. Attachment failure cannot roll back the investigation. A visible partial-success warning directs retry to Attachments. PNG/JPEG, 5 files, 5 MB each, and 20 million pixels remain enforced by the unchanged attachment service.
- Dashboard, List and Details poll every 30 seconds. Reads are serialized; manual refresh waits for older reads and fetches again. Hidden tabs and open/saving action modals pause polling. Stale/unmounted responses are ignored, timers are cleared, background errors retain displayed data, and background refresh does not set page loading state or reset filters/form fields. Successful actions immediately refresh the incident/history. No full-page reload.
- Google OAuth, CSRF, reporter-only validation/closure, review roles, attachment authorization, reports, and Faro payload filtering remain unchanged. Work-note/feedback contents are not instrumented.

## Manual checks remaining

Real-browser two-session reporter/handler flow, OAuth/CSRF with real sessions, responsive layout, actual PNG/JPEG upload/download, partial upload failure against a running backend, tab visibility and modal typing during polling. H2 tests do not establish compatibility of an ALTER against the deployed MySQL enum; VM metadata verification remains required before deployment.

## Changed files

Backend production files, relative to `src/main/java/com/pareidolia/incidentmanagement/`:

- `controller/IncidentController.java`
- `dto/AddWorkNoteRequestDto.java` (new)
- `dto/IncidentResponseDto.java`
- `enums/HistoryActionType.java`
- `repository/IncidentHistoryRepository.java`
- `service/IncidentService.java`
- `service/impl/IncidentServiceImpl.java`

Backend test: `src/test/java/com/pareidolia/incidentmanagement/IncidentFeatureTests.java`. Deployment/implementation report: this file (`ACTIVITY_MVP.md`). No entity mapping, security configuration, attachment storage or application configuration was changed.

Frontend files, relative to sibling repository `incident-management-ui/src/`:

- `api/incidents.js`
- `components/IncidentBadges.jsx`
- `pages/Dashboard.jsx`
- `pages/IncidentList.jsx`
- `pages/IncidentDetails.jsx`
- `hooks/usePolling.js` (new)
- `utils/incidentHistory.js` (new)
- `utils/incidentHistory.test.js` (new)
- `Activity.test.jsx` (new)
- `EvidenceAttachments.test.jsx` (the obsolete no-investigation-picker assertion now checks Resolve Incident, preserving the unrelated-action test)

## Validation results

- Maven: all 98 tests attempted with an explicitly isolated in-memory H2 datasource, create-drop only for that test database, and dummy OAuth client values. AuthenticationFlowTests: 6 passed; IncidentFeatureTests: 22 passed; IncidentLocationTests: 69 passed. Total 97 passed, 0 assertion failures, 1 context startup error.
- IncidentManagementServiceApplicationTests.contextLoads cannot initialize Spring OAuth's Java HTTP client in this Windows environment: `java.io.IOException: Unable to establish loopback connection`, caused by `java.net.SocketException: Invalid argument: connect`. An isolated IPv4-loopback retry also failed. The full Maven run therefore does **not** pass. No test was disabled, removed, or weakened. Logs: `activity-maven.log`, `activity-context.log` (ignored local artifacts).
- An earlier Maven run could not write pre-existing hidden report files; its zero-test summary is not counted. The definitive run used a fresh `surefire.reportNameSuffix=activity-mvp` and produced individual reports for all 98 tests.
- Frontend `npm test`: 16 Node tests passed; 97 Vitest tests passed in seven files. Includes permission/persistence, attention lifecycle/history ordering, screenshots, failure handling, polling overlap/hidden-tab/unmount protection, late response during editing, preservation of filters/forms, dashboard counts, and semantic wording across the backend/frontend suites.
- `npm run lint`: passed.
- `npm run build`: passed. Vite reports a >500 kB bundle warning and an ineffective dynamic import of react-router-dom already statically imported elsewhere; these are non-fatal and were not addressed by a scope-expanding bundle redesign.
- `git diff --check`: passed in both repositories.
- No commit, push, merge, deployment, or production VM action was performed. All requested core MVP items are implemented; remaining items are the environment-blocked context test and manual/browser/deployment verification above.
