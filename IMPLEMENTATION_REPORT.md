# Sidebar, monthly reports, and screenshot attachments

Implemented locally across `incident-management-service` and sibling `incident-management-ui`. No commits, pushes, deployments, production-data operations, or hosting/server changes were made.

## Existing behavior preserved

- Google Workspace/OIDC authentication, session identity, domain restriction, Axios credentials, and existing CSRF configuration are unchanged.
- New incidents still use the existing JSON API, authenticated reporter, configured default IT owner, and ASSIGNED status.
- Reporter incident visibility is still enforced by `IncidentService.getIncident` / `IncidentServiceImpl.ensureCanViewIncident`. Every attachment operation calls that service before accessing attachment data.
- Existing lifecycle rules are unchanged. **The repository differs from the initial task description:** validation and closure require the original reporter, regardless of role; post-closure review requires REVIEWER/ADMIN. Those existing rules were preserved.

## Backend file inventory

Modified:

- `pom.xml`: Apache POI dependency.
- `src/main/resources/application.properties`: application multipart limits only (5 MB/file, 26 MB/request).
- `src/main/java/com/pareidolia/incidentmanagement/enums/HistoryActionType.java`: ATTACHMENT_ADDED.
- `src/main/java/com/pareidolia/incidentmanagement/exception/GlobalExceptionHandler.java`: safe invalid-request and multipart errors (400).
- `src/main/java/com/pareidolia/incidentmanagement/repository/IncidentRepository.java`: half-open reportedAt range query.
- `src/main/java/com/pareidolia/incidentmanagement/repository/IncidentHistoryRepository.java`: one range query for report history, fetching its incident reference.
- `src/main/java/com/pareidolia/incidentmanagement/repository/AppUserRepository.java`: bulk reporter-name lookup.
- `src/test/java/com/pareidolia/incidentmanagement/AuthenticationFlowTests.java`: protected new routes and multipart CSRF checks.

Added under `src/main/java/com/pareidolia/incidentmanagement/`:

- `controller/IncidentAttachmentController.java`
- `controller/IncidentReportController.java`
- `dto/AttachmentContentDto.java`
- `dto/IncidentAttachmentResponseDto.java`
- `entity/IncidentAttachment.java`
- `exception/InvalidRequestException.java`
- `repository/IncidentAttachmentRepository.java`
- `service/IncidentAttachmentService.java`
- `service/IncidentReportService.java`
- `service/impl/IncidentAttachmentServiceImpl.java`
- `service/impl/IncidentReportServiceImpl.java`

Also added `src/test/java/com/pareidolia/incidentmanagement/IncidentFeatureTests.java` and this report. Controllers delegate to service interfaces; services own business logic and transactions.

## Frontend file inventory

Modified:

- `src/components/AppLayout.jsx`: compact navigation, preference, toggle, route highlighting.
- `src/App.css`: sidebar widths and contained responsive-table layout.
- `src/pages/IncidentList.jsx`: role-gated monthly report controls.
- `src/pages/CreateIncident.jsx`: optional image selection and second-stage upload.
- `src/pages/IncidentDetails.jsx`: attachments panel and partial-upload warning.

Added:

- `src/api/attachments.js`
- `src/api/reports.js`
- `src/utils/download.js`
- `src/components/ImagePicker.jsx`
- `src/components/IncidentAttachments.jsx`
- `src/components/MonthlyReport.jsx`
- `src/Features.test.jsx`

## Schema changes

Hibernate currently defaults to `ddl-auto=update`. On a normal application startup with that setting, the new mapping is expected to create `incident_attachments`:

| Column | Mapping | Nullability |
| --- | --- | --- |
| id | BIGINT identity, primary key | Not null |
| incident_id | BIGINT FK to incidents.id, lazy many-to-one | Not null |
| original_filename | VARCHAR(180), sanitized name | Not null |
| content_type | VARCHAR(50), detected PNG/JPEG type | Not null |
| file_size | BIGINT, bytes | Not null |
| file_data | LONGBLOB | Not null |
| uploaded_by | VARCHAR(255), authenticated email | Not null |
| uploaded_at | LocalDateTime timestamp | Not null |

Index: `idx_attachment_incident_uploaded(incident_id, uploaded_at)`.

`incident_history.action_type` gains ATTACHMENT_ADDED. If the deployed MySQL column uses a native ENUM, its allowed values must also expand; Hibernate update is expected to handle the mapping change. Verify this on a disposable MySQL database with the same version/schema before rollout. If Hibernate schema updates are disabled, an additive migration must be prepared through the existing change process. No destructive migration, table drop, or manual production change was performed.

Existing incident rows need no backfill and have no new required columns or attachment collection. Their normal queries/DTOs cannot accidentally fetch an attachment BLOB. Metadata queries explicitly select DTO columns, independent of Hibernate basic-field lazy-loading behavior.

## API and authorization

| Endpoint | Behavior | Authorization |
| --- | --- | --- |
| GET /api/reports/incidents/monthly?year=2026&month=10 | XLSX download | IT_HANDLER / ADMIN only |
| GET /api/incidents/{incidentId}/attachments | Metadata list | Existing incident visibility |
| POST /api/incidents/{incidentId}/attachments | Multipart `files`, 1–5 images | Existing visibility plus REPORTER / IT_HANDLER / ADMIN |
| GET /api/incidents/{incidentId}/attachments/{attachmentId} | Image download | Existing visibility plus matching incident/attachment pair |

REVIEWER can read/download visible attachments but cannot upload or export reports. Reporter ownership applies to every attachment operation, including guessed URLs. Backend checks are authoritative and follow the existing service-level AppUser role-checking style; no new method-security mechanism was introduced.

Unauthenticated protected GETs return 401; forbidden access returns 403; invalid input returns 400; missing incidents/attachments return 404. Multipart POSTs retain the existing Spring Security CSRF behavior (a missing/invalid CSRF token is rejected before the controller). No browser-controlled actor field is consumed. Binary downloads use explicit content types, safe Content-Disposition filenames, and no-store; attachment downloads also specify nosniff.

## Sidebar and table behavior

- Expanded desktop width is 236px; collapsed width is 72px.
- A 28px chevron toggle sits near the upper right sidebar edge, with an accessible Expand/Collapse name, title, controlled navigation ID, expanded state, and visible keyboard focus.
- The collapsed rail shows only lightweight SVG navigation icons and the PS company mark. Full labels remain in expanded mode; icon links retain accessible names, hover titles, active-route styling, and role-specific visibility. No icon dependency was added.
- Initial state is compact below 1200px unless the user saved a preference. Only the boolean `incidentSidebarCollapsed` is stored in localStorage; blocked storage is tolerated.
- On phones, compact icon navigation is horizontal. The existing branding remains in expanded mode, with the PS mark retained when collapsed.
- Header identity, role, Sign Out, navigation and page structure remain intact. Incidents remains highlighted on detail routes; Create has its own active route.
- The existing table-responsive wrapper is retained. Sidebar shrinking restores space; a bounded table, wrapping cells/badges, and a reserved View column keep overflow inside the table.

## Monthly report behavior

- Filters the actual `Incident.reportedAt` using `[first day 00:00, next month first day 00:00)`. LocalDateTime semantics match the existing application; no timezone conversion was introduced.
- Valid years: 1900–9998, months: 1–12. Invalid or missing request parameters return 400.
- Empty months produce a valid workbook with headers and no data rows.
- File: `incident-report-YYYY-MM.xlsx`, using the XLSX MIME type and attachment Content-Disposition.
- `Incidents` sheet: 38 columns, starting with Incident / Ticket Number. Includes all current business fields, desk number, current directory reporter name, reporter email, and creation/update timestamps.
- `Lifecycle History` sheet: ticket number, timestamp, action, actor, old/new values, remarks. It supplies assignment timing, reassignment history, closure remarks, reporter feedback, and other audit-only details without inventing entity fields. History is for selected incidents, including their later lifecycle events.
- Reporter names use one bulk AppUser query. Names are explicitly labeled as current directory values, not historical snapshots; missing directory names stay blank.
- Bold wrapped headers, frozen first row and ticket column, sensible fixed widths, wrapped text, consistently formatted Excel date cells, and header filters.
- Text is written as string cells, never formulas. Text exceeding Excel's cell limit is preserved in ordered parts in a `Long Text` sheet, with a reference in the main cell.
- No raw image data is exported. Optional attachment counts/current filename columns were omitted; safe ATTACHMENT_ADDED history metadata appears in the history sheet.
- Unavailable separate fields: assigned team, dedicated remediation field, standalone closure-confirmation text/boolean, historical reporter-name snapshot. Assignment time and closure remarks are represented through actual history records. No database fields were invented for reporting.
- Operational log: `MONTHLY_INCIDENT_REPORT_EXPORTED actor=<authenticated-email> period=YYYY-MM`, after successful workbook generation. No IncidentHistory export event or report/image content is logged.

## Attachment behavior

- Stores PNG/JPEG originals in MySQL; no SVG, WEBP, or arbitrary format support.
- ImageIO detects format from bytes, checks dimensions (maximum 20 million pixels) before decoding, and decodes to detect damaged contents. Filename extension and supplied MIME do not determine acceptance.
- Maximum 5 MB per image and 5 images per upload; no per-incident lifetime limit.
- Sanitizes filenames, strips path components/control characters, bounds length, and uses an extension matching detected content. No user filename becomes a filesystem path.
- Validates the complete batch before writes. Attachment and history writes share one transaction; each successful attachment gets exactly one ATTACHMENT_ADDED event with its ID, safe filename, and session-derived actor. Lifecycle status is unchanged.
- Metadata and binary retrieval are separate; tests inspect generated SQL to ensure list/read/report queries do not select file_data.
- Creation stays JSON, then uploads selected images only after receiving the incident ID. Failed image upload leaves the incident intact and displays a clear warning on its details page.
- The picker shows names/sizes, supports removal and optional selection, and supplies friendly type/size/count feedback.
- Details show filename, uploader, upload time, size, and Download. Authorized users can upload more images; metadata and audit history refresh afterward.
- All requests reuse the existing Axios client and CSRF interceptor. Browser/Axios generates multipart boundaries. Downloads use short-lived object URLs.

## Dependencies

- Maven: `org.apache.poi:poi-ooxml:5.5.1` plus its resolved transitive dependencies. Version verified against the [official Apache POI release page](https://poi.apache.org/download.cgi).
- npm: no application or development dependency/lockfile changes.
- A temporary Playwright installation under ignored backend `target/browser-check` was used solely for headless Edge verification. The temporary frontend fixture was removed and Vite stopped after testing.

## Automated verification

Commands executed:

```powershell
# Backend repository (isolated H2, no production datasource)
.\mvnw.cmd '-Dtest=IncidentFeatureTests,IncidentLocationTests,AuthenticationFlowTests' test
.\mvnw.cmd -B '-Dtest=IncidentFeatureTests,IncidentLocationTests,AuthenticationFlowTests' package
git diff --check

# Frontend repository
npm.cmd test
npm.cmd run lint
npm.cmd run build
git diff --check

# Temporary local browser runner, synthetic data only
node check.cjs # working directory: backend target/browser-check
```

Results:

- Backend package: **PASS**, 90 tests, zero failures/errors/skips (15 feature tests, 69 existing incident regressions, 6 authentication/security tests).
- Feature tests cover month boundaries, report role matrix, empty/invalid month/year, XLSX structure/formatting, string safety and long text, valid PNG/JPEG persistence, session actor spoof prevention, exact audit count, all-role attachment behavior, reporter ownership, mismatched attachment IDs, unsupported/corrupt/empty/oversized/excess-file batches, and no-BLOB metadata/report queries.
- Security tests exercise the real security filter chain: OAuth initiation/session behavior, logout, anonymous GET protection, and multipart CSRF rejection/acceptance. No Google network login is performed.
- Frontend: **38 tests pass** (15 existing Node utility tests + 23 Vitest tests, including 17 new feature cases). Includes sidebar preference/navigation/sign-out, role-gated reports, month parameters/download, file validation/removal, creation with/without images, partial upload failure, attachment role UI/download, and upload/history refresh.
- Frontend lint and production build: **PASS**.
- Browser: headless Edge using actual React components and synthetic incidents at 1440, 1280, 1024, 768, and 375px. No document-level horizontal overflow at any tested width. View buttons remain reachable through contained table scrolling. 1280px collapsed table fits completely. Expanded layout and preference after reload verified; desktop/phone screenshots inspected and badge overlap corrected.
- The existing unrestricted `IncidentManagementServiceApplicationTests.contextLoads` test was not run, because it uses externally configured application datasource/OAuth settings. The explicit suite above tests real persistence with H2 and packages the application without accessing production resources.

## Remaining manual checks and follow-up

1. Test real Google Workspace sign-in, allowed-domain restriction, logout, and expired sessions in a test environment.
2. Verify Hibernate's additive table/index/FK and history-enum changes against disposable MySQL with the actual deployed version/configuration; verify binary round-trip and persistence after restart. H2 validates behavior but is not a MySQL migration rehearsal.
3. Verify actual HTTP multipart size enforcement and credentialed cross-origin upload/download using the deployed test origins. MockMvc validates service file limits/CSRF but does not exercise a real servlet container's multipart parser.
4. Open a representative exported workbook in the organization's Excel version and review report usability; test multi-image selection from actual browsers and devices.
5. Run the listed existing lifecycle/dashboard/category flows with real role accounts in a test environment. Existing regression suites passed; live end-to-end Google/MySQL testing remains outstanding.
6. Monitor monthly export volume and attachment growth. The first implementation builds a selected month's workbook in memory; consider streaming/paging exports and storage quotas if usage grows. No infrastructure or backup changes were made.

No ISO-compliance claim is made. Security controls are implemented and tested within the limits above.

## Additional requirement: evidence-action images and compact navigation rail

Implemented on October 12, 2026, reusing the existing attachment model/API/service and ImagePicker. No additional backend code, schema, audit-event mechanism, dependency, routing, or authorization changes were needed.

Files changed for this follow-up:

- Frontend `src/pages/IncidentDetails.jsx`: optional evidence-modal picker; action-local file selection; evidence-first/upload-second sequence; partial-success warning; explicit attachment-panel refresh key plus existing details/history reload. Selection resets on cancel, opening another action, and successful evidence completion.
- Frontend `src/components/AppLayout.jsx` and `src/App.css`: 236px expanded sidebar, 72px icon-only rail, PS mark, lightweight inline SVG icons, 28px edge chevron, hover titles, accessible names/focus, existing localStorage preference retained.
- Frontend `src/Features.test.jsx`: sidebar assertions updated for icons and chevron while retaining preference, routing and logout coverage.
- Added frontend `src/EvidenceAttachments.test.jsx`: 15 cases covering no/one/multiple images, removal, unsupported/oversized/excess-file rejection, required evidence validation despite selected images, evidence failure preventing upload, partial-success warning and later upload through the existing panel, warning persistence when details refresh fails, refresh of all three datasets, cancellation/reset, other modals not getting the picker, and existing role restrictions.
- This report.

The existing evidence API remains the first and required request. Only after it succeeds does the UI call the existing `uploadAttachments` helper once with all selected files. No actor fields are added. The backend continues to create the existing evidence history event independently from each successful attachment's ATTACHMENT_ADDED event. Upload errors do not retry or undo evidence updates, and no attachment upload is attempted when evidence validation or saving fails.

Follow-up verification results:

- `npm.cmd test`: **PASS**, 53 tests (15 Node utility tests + 38 Vitest tests).
- `npm.cmd run lint`: **PASS**.
- `npm.cmd run build`: **PASS**.
- `.\mvnw.cmd -B '-Dtest=IncidentFeatureTests,IncidentLocationTests,AuthenticationFlowTests' test`: **PASS**, all 90 existing relevant backend tests. No backend test duplication was introduced.
- Headless Edge checks and inspected screenshots at **1440, 1280, and 1024px** confirm 236px expanded / 72px collapsed, hidden collapsed labels, SVG icons, PS mark, small toggle, active route, saved preference after reload, and no document horizontal overflow. Collapse adds **164px** to available table width; the synthetic full table and View buttons fit even at 1024px (854px table area).
- The actual evidence modal was rendered in the browser with a selected PNG, and its required Evidence Reference, Remarks, actor identity, optional picker, Remove, and Update Evidence controls were visually inspected.
- Browser fixtures used synthetic data, were removed afterward, and the temporary Vite server was stopped. Existing live Google/MySQL test limitations above still apply.

No commit, push, or deployment was performed.
