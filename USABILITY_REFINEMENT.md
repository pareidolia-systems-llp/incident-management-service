# Final usability refinement — 16 October 2026

All changes are uncommitted. No commit, push, merge or deployment was performed. Existing uncommitted work from earlier passes was preserved.

## Exact files changed in this pass

Backend repository:

- `src/main/java/com/pareidolia/incidentmanagement/dto/ChangeSeverityRequestDto.java`
- `src/main/java/com/pareidolia/incidentmanagement/dto/ChangePriorityRequestDto.java`
- `src/test/java/com/pareidolia/incidentmanagement/IncidentFeatureTests.java`
- `USABILITY_REFINEMENT.md` (this report)

Sibling frontend repository `incident-management-ui`:

- `src/pages/IncidentDetails.jsx`
- `src/pages/Help.jsx`
- `src/utils/incidentHistory.js`
- `src/utils/incidentGuidance.js`
- `src/utils/portalHelp.js`
- `src/App.css`
- `src/Activity.test.jsx`
- `src/IncidentWorkspace.test.jsx`
- `src/ReporterLifecycle.test.jsx`
- `src/Help.test.jsx`
- `src/Features.test.jsx`

Other dirty files predate this pass. Local verification scripts, screenshots and logs remain ignored under `target/` or as `.log` files.

## Scope and reassessment

This pass is mostly frontend, with two small backend validation changes. The existing severity/priority endpoints already accept remarks and persist them to history with old/new values, actor and timestamp. Both DTOs now require nonblank remarks using Bean Validation. The existing maximum length, endpoint names, field names, service behavior, authorization, history actions and storage remain unchanged. No schema change is required or performed.

Create Incident retains Severity and Priority labels and fields, with guidance identifying them as the reporter's initial impact/urgency assessment. It explains that IT may reassess after investigation and every change is recorded in Activity. More Actions now labels these operations Reassess Severity and Reassess Priority. Each dialog shows the current value, the new-value selector and a required Reason for reassessment. Activity retains Severity Changed/Priority Changed and the value transition, with remarks labeled Reason. No reason is copied into telemetry or new logs.

## Activity and warning

Activity defaults to the latest five entries matching the current filter, displayed in the backend's existing chronological order. View full activity expands all matching entries; Show recent activity collapses them. A count explains how many are displayed. Changing the filter returns to the latest-five view. Short timelines need no expansion control. No records are removed, fetched differently or reordered; source history remains unchanged.

The warning title is now “Issue reported as still unresolved.” Supporting text states that the reporter confirmed the previous resolution did not fix the issue and that the incident returned to IT for further investigation. Reported by/at, the backend flag and RESOLUTION_NOT_ACCEPTED behavior remain unchanged.

## Help hierarchy

1. What do you want to do? Four compact task cards link to existing detailed help anchors, opening and focusing the corresponding disclosure.
2. Quick Tour: all seven steps retained, with Previous/Next, direct numbered step controls and a current-step indicator. Optional compact disclosures explain the reporter journey, IT journey and independent IT work.
3. Which action should I use? A responsive comparison distinguishes discoveries, actions performed, resolution and standalone IT work with concrete examples.
4. Detailed Guide: existing collapsible content, security warnings and field guidance preserved. More Actions guidance explains all five actions and limits them to IT Handler/Admin.
5. FAQ: seven requested questions, individually collapsible, followed by a More questions disclosure preserving all previous FAQ content.

Help cards and journey text grant no operational access. No routes, dependencies, authentication, schema or infrastructure were added. There is no autoplay or video.

## Validation

- Maven: 127 tests, 126 passed, zero assertion failures, one pre-existing application-context startup error. AuthenticationFlowTests 7, IncidentFeatureTests 33, IncidentLocationTests 77 and WorkLogTests 9 pass. The unchanged contextLoads failure is `java.net.SocketException: Invalid argument: connect` during OAuth HTTP-client initialization on Windows. Tests use isolated H2 and dummy OAuth credentials; no DEV database was touched. Reports use suffix `usability-refinement`; log: `refine-maven.log`.
- Node: all 27 tests pass.
- Vitest: all 156 tests across 12 files pass in the final full run. Coverage includes collapse/expand and filters, reason validation and Activity rendering, reporter restrictions, task cards, tour navigation/current state, comparisons, FAQ toggling, initial-assessment guidance, and existing workflow/privacy regressions. The pre-existing full-history assertion now explicitly expands the timeline before checking all records; it still verifies order, no refetch and no source mutation.
- ESLint: passed.
- Production build: passed, retaining existing non-fatal large-chunk and React Router dynamic-import warnings.
- Headless Edge, production build with synthetic API responses: passed at 1440, 1024, 768 and 390px. Checked page/control overflow, primary action wrapping, status badges, More Actions, activity filters and five/full toggling, report controls, work log/modal, tour navigation and reporter screenshot modal. Sidebar expanded at desktop/laptop widths. Local script: `target/polish-browser.cjs`; screenshots: `target/polish-browser/`.
- `git diff --check`: passed in both repositories.

## Remaining manual browser checks

- With real IT Handler/Admin DEV sessions, reassess Severity/Priority, verify a blank reason is rejected and reload to confirm the stored value, reason, actor and timestamp. Confirm Reporter still lacks these controls.
- On an incident with a long real history, verify latest-five/full views across all four filters, including refresh/polling.
- Check Help cards, journeys, step selection and FAQ disclosures in the team's target browser and zoom settings.
- Smoke-check the existing reporter feedback/screenshot success and partial-success paths, report download, and earlier work-time entry against real DEV persistence. Automated browser checks use synthetic responses.
- Resolve the local JVM OAuth socket issue before declaring the complete Maven suite green; no test was disabled or weakened to hide it.
