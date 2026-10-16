# Controlled final polish — 16 October 2026

Changes remain uncommitted. No push, merge, deployment, infrastructure or schema changes were performed. Existing uncommitted MVP work was preserved.

## Backend files changed in this pass

- `src/main/java/com/pareidolia/incidentmanagement/dto/CreateIncidentRequestDto.java`: supported-category validation at the existing creation API boundary. Existing optional null/empty category compatibility remains. Supported categories are independent of Issue Type so reclassification does not invalidate existing incidents.
- `src/test/java/com/pareidolia/incidentmanagement/IncidentLocationTests.java`: accepted categories persist as strings without changing Issue Type; unknown categories return 400 before persistence.
- `src/test/java/com/pareidolia/incidentmanagement/IncidentFeatureTests.java`: original reporter feedback followed by a real PNG upload retains In Progress and produces the existing feedback, status and attachment history events.

## Frontend files changed in this pass

- `src/pages/IncidentDetails.jsx`
- `src/components/ImagePicker.jsx`
- `src/pages/Help.jsx`
- `src/utils/incidentOptions.js`
- `src/utils/incidentGuidance.js`
- `src/utils/portalHelp.js`
- `src/App.css`
- Tests: `src/ResolutionScreenshots.test.jsx` (new), `src/IncidentWorkspace.test.jsx`, `src/EvidenceAttachments.test.jsx`, `src/Features.test.jsx`, `src/Help.test.jsx`.

Paths above are relative to the sibling `incident-management-ui` repository. Other dirty files in either repository predate this pass.

## Behavior and presentation

Issue Still Persists now offers Supporting Screenshots through the existing ImagePicker. Feedback saves first through the unchanged resolution-feedback endpoint. Only after success does the existing attachment API upload selected files. The incident/history and attachment list refresh afterward. Upload failure preserves the saved feedback and In Progress state and shows an explicit warning directing the reporter to retry through Attachments. A feedback failure keeps the dialog/files and makes no attachment request. Existing PNG/JPEG, five-file, 5 MB and 20-million-pixel rules and backend authorization remain unchanged. Attachment history remains separate; raw attachment IDs and duplicate feedback remain suppressed.

Incident.category is a String mapped to a length-100 column, not an enum. No schema change is required by the checked-in model, and no database was modified or inspected remotely. Server / Infrastructure, Database and Security / Endpoint were added to the IT Issue category dropdown, preserving all existing category options and Other. Backend validation accepts all supported category values across the existing Issue Types; help distinguishes technical area from incident/request type.

Work on Incident presents the three operational actions in consistently spaced, wrapping groups with the requested short explanations. More Actions remains a native disclosure containing the existing administrative actions and descriptions. It has a bounded width/height, stays in document flow, and closes on selection, Escape or focus leaving the disclosure. Backend action behavior and permissions are unchanged.

Activity keeps one chronological timeline and all four filters. Headings/timestamps wrap cleanly; actor text and filenames wrap; semantic summaries and remarks have distinct presentation. Existing actor labels and history formatting logic remain unchanged.

How to Use now starts with a seven-step React-state Quick Tour with Previous/Next, boundary-disabled buttons, live progress and no autoplay/dependency/video. Detailed documentation remains below in native disclosures, including new focused work-log and reporter-feedback guidance. Deep links open both the targeted disclosure and its enclosing sections before focusing. Security warnings and existing field guidance remain.

Responsive CSS retains the existing design language, makes action controls wrap, keeps tables within their scroll containers, and allows long text and modal buttons to wrap. Existing modal-body scrolling, local work-time default/adjustment, report date/time semantics, polling, authentication, authorization and Faro filtering are preserved.

## Validation

- Maven, isolated H2 and dummy OAuth credentials: 125 tests run; 124 passed, zero assertion failures, one application-context error. AuthenticationFlowTests 7, IncidentFeatureTests 31, IncidentLocationTests 77 and WorkLogTests 9 all pass. The contextLoads error is the previously documented Windows `java.net.SocketException: Invalid argument: connect` while initializing the OAuth HTTP client. No tests were disabled or weakened. Initial execution encountered hidden old Surefire report files; rerunning with `-Dsurefire.reportNameSuffix=final-polish` produced reliable reports. See ignored `polish-maven.log` and `target/surefire-reports/*final-polish*`.
- Node: 27 passed.
- Vitest: all 150 tests pass across the full run and targeted rerun. The initial full run passed 147 and failed three new payload assertions; assertions were corrected to include the existing empty optional evidenceReference, then all four screenshot tests passed. No application behavior was changed to satisfy those assertions.
- ESLint: passed.
- Production build: passed. Existing non-fatal large-chunk and ineffective React Router dynamic-import warnings remain.
- `git diff --check`: passed for both repositories.
- Headless Edge production-build checks with synthetic API responses: passed at 1440, 1024, 768 and 390 px, including expanded sidebar at desktop/laptop widths. Covered Incident List/status badges, report range controls, Incident Details/primary action wrapping, More Actions dismissal, all Activity filters, My Work Log, Add Work Entry, Quick Tour navigation, reporter restrictions and Issue Still Persists with a long screenshot filename. Assertions verified no page/control horizontal overflow, no primary-action/badge overlap and scrollable modal bodies. Screenshots and the check script are local ignored artifacts under `target/polish-browser/` and `target/polish-browser.cjs`.

## Remaining manual DEV browser checks

1. With real OAuth sessions, submit reporter feedback with a valid screenshot; confirm In Progress, attachment download and separate feedback/attachment history after reload.
2. Simulate attachment-request failure after feedback succeeds; verify warning, persisted feedback/state and retry through Attachments without resubmitting feedback.
3. Smoke-check the five existing More Actions updates with real DEV persistence and their previous/new values.
4. Verify a real report download with optional times and a standalone work entry with an adjusted earlier time. These semantics are covered by existing automated tests but the browser layout checks use synthetic responses.
5. Confirm the final visuals in the team's target browser/zoom settings. Resolve the local JVM/OAuth socket initialization issue before declaring the entire Maven suite green.
