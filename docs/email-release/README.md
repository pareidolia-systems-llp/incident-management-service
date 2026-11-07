# Email-only V2 portal-link release

The release instructions below describe the historical portal-link release. The detailed-email branch has a separate opt-in routine policy. See [Routine IT and HR routing](#routine-it-and-hr-routing) for its rollout prerequisites.

Branch codex/email-v2-portal-link starts at verified GitHub backend main 2e61571cb7fdd182f1f57ccfe36d31c83c14ea2d. No commits or pushes were made during preparation. The source email-notifications-v2 worktree is retained intact.

## Integration and deliberate differences

The base commit lacks V2. Imported from the email-notifications-v2 worktree are the complete four notification classes, mail starter dependency, incident creation event publication, all five email test files and the constructor adjustment in IncidentLocationTests. No Employee Management, stable assignment, incident-access policy, activation guard, Phase 2 classes, tables or flags were imported.

The change relative to the reviewed local V2 is a new optional INCIDENT_EMAIL_PORTAL_ORIGIN and the corresponding validator/link rendering. V2 still uses render(event,false), the same generic subject, number, sender restrictions, generic body, HTML/plain alternatives, recipients/deduplication, asynchronous after-commit sending, error behavior and default-off flags. V1 remains plain-text with its existing text. A missing origin preserves the previous V2 output. A nonblank invalid origin fails startup with a generic message. Set the approved origin before deployment to obtain the new link.

The origin must be HTTPS with a host, optional valid port, and no userinfo, path other than /, query, fragment or whitespace. The server constructs a normalized root URL, never a request-derived destination. Templates HTML-escape the href. No incident identifier or bearer token is added to the URL. The React / route enters its authenticated application gate, redirects unauthenticated users to login, and the success handler returns them to the configured frontend. API routes continue requiring sessions and CSRF, with the original role/reporter checks. This release preserves the baseline authorization model. It adds no confidential-case enforcement. Detailed content remains disabled.

The actual production hostname, running JAR SHA, VM configuration, systemd unit and deploy-incident.sh content have not been inspected. Source equivalence of local V2 notification classes was established before this enhancement. Equivalence to the deployed artifact, baseline and VM configuration must be independently checked before deployment. New builds may differ due to build metadata/dependency versions. The base frontend and currently deployed frontend source must also be confirmed at approval.

## Files and proposed commits

First proposed commit, after approval: integrate reviewed V2 email notifications.
- pom.xml
- src/main/java/com/pareidolia/incidentmanagement/service/impl/IncidentServiceImpl.java (event publication and constructor only)
- src/main/resources/application.properties (existing V2 properties)
- notification/IncidentCreated.java
- notification/IncidentEmailConfiguration.java
- notification/IncidentEmailNotifications.java
- notification/IncidentEmailTemplate.java
- src/test/java/com/pareidolia/incidentmanagement/IncidentLocationTests.java
- src/test/java/com/pareidolia/incidentmanagement/IncidentEmailTests.java
- src/test/java/com/pareidolia/incidentmanagement/IncidentEmailSmtpTests.java
- src/test/java/com/pareidolia/incidentmanagement/IncidentEmailPostfixTests.java
- src/test/java/com/pareidolia/incidentmanagement/IncidentEmailV2SmtpTests.java
- src/test/java/com/pareidolia/incidentmanagement/notification/IncidentEmailV2Tests.java

Second proposed commit, after approval: add trusted HTTPS portal link and email release checks.
- notification/IncidentEmailPortalLink.java
- changes to IncidentEmailTemplate, IncidentEmailNotifications, IncidentEmailConfiguration, application.properties and IncidentEmailV2SmtpTests
- src/test/java/com/pareidolia/incidentmanagement/notification/IncidentEmailPortalLinkTests.java
- src/test/java/com/pareidolia/incidentmanagement/IncidentManagementServiceApplicationTests.java (test-only OAuth client doubles for the environment loopback problem, and absence checks for unfinished beans)
- docs/email-release/README.md

Notification paths above are under src/main/java/com/pareidolia/incidentmanagement. The final diff is currently uncommitted and unstaged. Separate commits require splitting the overlapping files against the retained V2 source, with review of each diff. A single reviewed email-only commit is also valid. Neither option has been executed.

## Build and test

Java 17 and Maven wrapper dependencies are required. From this branch, use a clean CI runner or an isolated local shell:

    $env:DB_URL='jdbc:h2:mem:email_release;DB_CLOSE_DELAY=-1'
    $env:DB_USER='sa'
    $env:DB_PASS=''
    $env:GOOGLE_CLIENT_ID='test'
    $env:GOOGLE_CLIENT_SECRET='test'
    $env:JPA_DDL_AUTO='create-drop'
    $env:INCIDENT_EMAIL_ENABLED='false'
    .\mvnw.cmd -o package

Tests use in-memory H2, test doubles and synthetic loopback SMTP capture. Ordinary application mail is disabled. The production transport is never exercised against a live mail server by these tests. Run with an empty incident-email environment in CI. The frontend App.test.jsx suite checks the existing root/auth routing. No frontend code is changed by this release.

Before creating the GitHub PR after approval, inspect all new files plus git diff, verify the base SHA, run whitespace checks, and ensure no secrets/test output or unfinished code enter the commit. CI must rerun the full backend package from the exact committed SHA. No migrations or frontend rebuild are required by the backend email link itself.

## Production preflight for the human operator

This document contains future commands, not authorization to execute them now. Use a reviewed build from the exact approved commit. Inspect /opt/pareidolia/scripts/deploy-incident.sh first if choosing to use it. Its behavior is unknown here, and no command below invokes it.

Record the actual systemd service, active JAR path, Java version, approved frontend HTTPS origin and candidate SHA256. Confirm systemd uses the fixed active JAR path before replacing it. Verify frontend / loads and requires Google login, then verify an authorized user reaches their permitted incidents. Test the emailed origin from the real client network.

Preserve existing default Spring profile and all existing V2 environment values. Required existing keys are INCIDENT_EMAIL_ENABLED=true, INCIDENT_EMAIL_V2_ENABLED=true, INCIDENT_EMAIL_LOCAL_POSTFIX_ENABLED=true, INCIDENT_EMAIL_FROM=alerts@pareidolia.in, the approved IT/HR/department mappings, and the existing localhost SMTP configuration. Add only INCIDENT_EMAIL_PORTAL_ORIGIN=<approved HTTPS frontend origin>. Confirm JPA_DDL_AUTO=validate so startup performs no automatic DDL. Review this choice against existing production configuration before approval.

The approved mapping is global IT itadmin@pareidolia.in; global HR schakravorty@pareidolia.in; Operations (Annotation) and Operations (Perioperative Flow Analysis) each annotator@pareidolia.in,annotator02@pareidolia.in; R&D debolina@pareidolia.in; HR schakravorty@pareidolia.in. Exact labels matter. Preserve the actual approved running configuration rather than rewriting it from this document. Do not enable detailed content or new security/assignment flags.

Back up the existing active JAR (dereferenced if symlink), checksum, unit/drop-ins, protected environment file and Nginx configuration with restrictive permissions. Verify normal scheduled database backups and restore evidence. This release has no SQL changes, and rollback does not restore or discard current incident/audit data.

## Manual Ubuntu deployment after explicit approval

Supply these reviewed variables in a maintenance shell. Do not guess SERVICE or ACTIVE_JAR. RELEASE_SHA is the approved commit, APPROVED_SHA256 is from the approved candidate, and CANDIDATE is the already transferred artifact. Commands deliberately avoid rebuilding on the VM or pulling an arbitrary main HEAD.

    set -euo pipefail
    SERVICE='<verified systemd unit>'
    ACTIVE_JAR='<verified fixed ExecStart JAR path>'
    CANDIDATE='<absolute staged candidate JAR path>'
    RELEASE_SHA='<approved full commit SHA>'
    APPROVED_SHA256='<approved candidate sha256>'
    test -f "$CANDIDATE"
    printf '%s  %s\n' "$APPROVED_SHA256" "$CANDIDATE" | sha256sum --check -
    java -version
    sudo systemctl is-active "$SERVICE"
    sudo systemctl cat "$SERVICE"     # inspect privately, protect any embedded secrets

Preflight must confirm these paths and expected unit arguments. Use the actual approved release directory:

    RELEASE_DIR="$(dirname "$ACTIVE_JAR")/releases"
    STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
    sudo install -d -m 0750 "$RELEASE_DIR"
    ROLLBACK_JAR="$RELEASE_DIR/pre-email-link-$STAMP.jar"
    sudo cp --dereference --preserve=mode,timestamps -- "$ACTIVE_JAR" "$ROLLBACK_JAR"
    sudo sha256sum "$ROLLBACK_JAR"
    NEW_JAR="$RELEASE_DIR/email-link-$RELEASE_SHA.jar"
    sudo install -m 0644 -- "$CANDIDATE" "$NEW_JAR"
    printf '%s  %s\n' "$APPROVED_SHA256" "$NEW_JAR" | sudo sha256sum --check -

Human config step: back up the protected systemd environment/drop-in privately, add the approved portal origin, and confirm validate-only schema mode. A new drop-in may be used through sudo systemctl edit "$SERVICE" with only reviewed Environment entries. Record the previous config for rollback. Do not print SMTP/OAuth/database secrets.

After approval of unit/path/config/artifact checks:

    sudo ln -s -- "$NEW_JAR" "$ACTIVE_JAR.next"
    sudo mv -Tf -- "$ACTIVE_JAR.next" "$ACTIVE_JAR"
    sudo systemctl daemon-reload
    sudo systemctl restart "$SERVICE"
    sudo systemctl is-active "$SERVICE"
    sudo journalctl -u "$SERVICE" --since '5 minutes ago' --no-pager

Require ACTIVE_JAR.next to be absent before creating the link. Halt on any failed command. Inspect logs privately for startup errors without copying sensitive content. The service account must be able to read NEW_JAR and traverse RELEASE_DIR. Use the actual approved local port and health endpoint if one exists; no health endpoint is assumed. Authenticated API/login and incident list checks are required.

## Smoke test and rollback

Prefer candidate smoke verification against isolated DEV plus local capture before production approval. A production email smoke incident/mailbox must be separately approved. Once approved, create one generic synthetic smoke incident, confirm it commits once, check global/department dedup and the generic HTML/plain link, open the link signed out and signed in, and confirm the normal role-filtered destination. Never include real HR/restricted content in a smoke incident. Preserve real incident history created during deployment.

Rollback immediately for startup, auth, lifecycle, routing, confidential content or delivery regression:

    sudo ln -s -- "$ROLLBACK_JAR" "$ACTIVE_JAR.rollback"
    sudo mv -Tf -- "$ACTIVE_JAR.rollback" "$ACTIVE_JAR"
    # Restore the privately backed-up environment/drop-in if configuration was changed.
    sudo systemctl daemon-reload
    sudo systemctl restart "$SERVICE"
    sudo systemctl is-active "$SERVICE"

Require ACTIVE_JAR.rollback to be absent first, and verify ROLLBACK_JAR checksum against the saved value before switching. Recheck login, incident creation/history, and the existing V2 generic notification behavior. Do not run migrations, delete incidents, or restore a stale database backup for this application-only rollback.

## Release blockers

Approval of exact source diff/commit and actual HTTPS portal origin; confirmation of active production artifact/config/baseline and systemd paths; clean CI build from the approved committed SHA; human review of the live deployment script if using it; backup/rollback and approved smoke-mailbox readiness. These are release prerequisites, not source-test failures.

## Verification evidence

[INFO] Tests run: 164, Failures: 0, Errors: 0, Skipped: 0

Offline Maven package passed. The isolated frontend App.test.jsx routing suite passed all 6 tests. MIME and routing tests used synthetic mailboxes and a test double or loopback capture. Packaged JAR inspection found no unfinished incident access, employee directory or assignment classes. Application authentication source files have no changes against the base.

## Exact final changed-file list

- docs/email-release/README.md
- docs/email-release/previews/detailed-review-only.html
- docs/email-release/previews/detailed-review-only.txt
- docs/email-release/previews/generic-portal.html
- docs/email-release/previews/generic-portal.txt
- pom.xml
- src/main/java/com/pareidolia/incidentmanagement/notification/IncidentCreated.java
- src/main/java/com/pareidolia/incidentmanagement/notification/IncidentEmailConfiguration.java
- src/main/java/com/pareidolia/incidentmanagement/notification/IncidentEmailNotifications.java
- src/main/java/com/pareidolia/incidentmanagement/notification/IncidentEmailPortalLink.java
- src/main/java/com/pareidolia/incidentmanagement/notification/IncidentEmailTemplate.java
- src/main/java/com/pareidolia/incidentmanagement/service/impl/IncidentServiceImpl.java
- src/main/resources/application.properties
- src/test/java/com/pareidolia/incidentmanagement/IncidentEmailPostfixTests.java
- src/test/java/com/pareidolia/incidentmanagement/IncidentEmailSmtpTests.java
- src/test/java/com/pareidolia/incidentmanagement/IncidentEmailTests.java
- src/test/java/com/pareidolia/incidentmanagement/IncidentEmailV2SmtpTests.java
- src/test/java/com/pareidolia/incidentmanagement/IncidentLocationTests.java
- src/test/java/com/pareidolia/incidentmanagement/IncidentManagementServiceApplicationTests.java
- src/test/java/com/pareidolia/incidentmanagement/notification/IncidentEmailPortalLinkTests.java
- src/test/java/com/pareidolia/incidentmanagement/notification/IncidentEmailV2Tests.java

Synthetic preview files are review artifacts only. Their portal.example.test destination must be replaced by the approved production origin through configuration, never by editing template literals.

## Trusted case routing on the detailed-email branch

The production-compatible incident model has IT issues, service requests and security issue types. It has no trusted HR case marker. The reporter department, title, description and issue type cannot establish an HR or ordinary IT route. An explicitly reported security type only suppresses email.

Outside the opt-in routine mode, the listener requires exactly one trusted `IncidentEmailDetailAuthority` for all incident emails, including the legacy transport path. The authority must return a consistent case-specific decision using the incident number, based on independent case data and exact approved mailbox addresses. Missing, unknown, ambiguous or failed decisions withhold mail. This is an intentional change from the current production branch, which sends generic V2 mail without an authority.

- Trusted ordinary IT cases classified STANDARD use configured global IT and HR recipients and, in V2, configured reporter-department recipients. Addresses are deduplicated. Approved addresses receive detail only with the explicit V2 details opt-in and a trusted portal origin. Other configured recipients receive the existing generic notice.
- Trusted HR cases have one possible recipient, `schakravorty@pareidolia.in`. The global and departmental settings cannot add recipients to that route. Full details require trusted STANDARD classification and exact mailbox approval. Otherwise an explicit minimal-disclosure decision is required, and the notice contains no incident number or case details.
- Security, unknown routing, and non-STANDARD ordinary IT cases withhold email. There is no security recipient policy.

The branch registers no production authority. Keep the running generic V2 release until the replacement is independently verified. Before rollout, approve the authoritative classification and routing workflow, exact-recipient and HR minimal-disclosure rules, and handling for cases approved after creation. The after-commit listener sends only on creation and does not replay withheld messages. Detailed delivery remains disabled by default.

### Authority integration prerequisite

The legacy Reclassify Incident action updates the issue type and records its history. It cannot certify an HR route, a confidentiality classification, or permission to disclose information by email. The authenticated reporter's identity, default IT owner and configured recipient mappings cannot certify those facts either. A department-only or issue-type-only fallback can expose a confidential HR incident to the global lists even in generic mode.

The smallest independent authority would read one approved decision per persisted incident number from a server-controlled case intake or review process. The decision must identify the route and confidentiality classification, list exact mailboxes approved for full disclosure, and explicitly approve any HR-only minimal notice. The organization must designate the source, its approvers, and when their decision becomes available. This branch contains no such data source. The separate guarded incident-access work models confidentiality and portal grants, but those grants do not approve email disclosure or establish an HR route.

Incident numbers are generated during creation and the email listener runs after commit. A static per-case list cannot reliably authorize newly created incidents at that point. If the trusted review happens later, a separately authorized and tested post-review send path is required. In authority mode a missing decision withholds email, including when the reporter labels a confidential case as an ordinary IT issue.

## Routine IT and HR routing

Routine routing is off by default. Enable `INCIDENT_EMAIL_V2_ROUTINE_ROUTING_ENABLED=true` with V2 only after approving the use of this intake form for routine requests. With no case authority installed, ordinary IT issues and service requests use configured global IT, global HR and reporter-department destinations, deduplicated. Set `INCIDENT_EMAIL_V2_DETAILS_ENABLED=true` and a valid portal origin to include the full detailed template for those destinations. An installed case authority takes precedence, including when its decision is absent, ambiguous, or fails.

An explicit `HR_ISSUE` or detected HR hint uses only the designated HR mailbox. Routine mode sends a minimal notice with no case identifier or content. Detailed HR email requires an approved case-specific authority decision for the HR route, STANDARD confidentiality, and the exact designated mailbox, plus the V2 detail opt-in and trusted HTTPS portal origin. It includes the resolved responsible department when available and keeps the 4,000-character description cap. Security issue types, detected security hints, and a missing issue type suppress email. HR hints include department, category, affected system, impact, and a limited keyword scan of the title and description. Security hints take precedence over HR hints. These checks narrow delivery and do not establish confidentiality. The service cannot independently verify that arbitrary free text is safe, and it can miss confidential content that contains no recognized hint. Enable detailed routine mail only if the organization accepts that residual risk. Keep confidential cases out of this form and use the designated direct contact.

The frontend HR choice is off by default. Enable `VITE_ROUTINE_HR_ISSUES_ENABLED=true` only with a matching backend that recognizes `HR_ISSUE` and enforces HR-only routing. In the combined backend, Phase A resolves the active responsible department name from the locked catalog row during incident creation. A recognized HR name can only narrow email routing. It confers no assignment, case access or disclosure permission. Ordinary departmental recipient lookup still uses the reporter department. The frontend warns users about confidential HR content, but it does not change portal visibility, default incident ownership, or case access.

Before rollout, inspect the actual MySQL `incidents.issue_type` definition. The Java mapping stores enum names. An unconstrained VARCHAR that accepts `HR_ISSUE` needs no column change. A native ENUM or CHECK constraint listing the old values needs a reviewed schema update before any HR issue is saved. Verify schema validation and rollback compatibility on disposable MySQL. An old backend cannot read an incident stored with an enum value it does not recognize.
