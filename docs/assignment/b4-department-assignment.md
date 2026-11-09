# B4 department-aware assignment and global incident viewing

B4 activation remains blocked by IncidentAccessActivationGuard. Tests exercise guarded services in isolated slices. The full application cannot turn on B4 through configuration alone.

## Assignment and access rules

- Incident creation validates the selected responsible department against the active server-side catalog. HR, security and department-directed incidents start OPEN with no assigned owner. Ordinary legacy IT creation without a responsible department retains its configured default owner. Existing owners and status values are not backfilled.
- Department membership is an explicit association. An effective handler needs active membership, current eligibility, and independent case VIEW and HANDLE grants. The assigning actor needs the assignment capability, case visibility and an approved actor-handler pair. Restricted assignment also requires the actor's case ASSIGN grant. Assignment and classification versions, reason, and assignment history are written together. A missing or inactive department denies assignment.
- Legacy mode restricts known confidential cases to the original reporter for ordinary reads. A legacy IT owner does not confer confidential access. The guarded path applies case permissions. Original-reporter lifecycle checks remain mandatory. In guarded mode, a restricted reporter requires an independent case VIEW grant before validation or closure. A department or issue-type label can narrow access; it cannot grant it.
- GLOBAL_INCIDENT_VIEW allows audited incident list, number lookup, detail, history, attachment reads, assignment state/history, and report output. It is independent of case VIEW used for changes. Assignment, investigation, resolution, validation, closure, uploads, case administration and email disclosure retain their existing permission requirements. No role gets this capability by default.
- Global view grants and revocations use the existing versioned capability API. Its actor must be a verified active account on both the ordinary capability-admin allowlist and the separate INCIDENT_GLOBAL_VIEW_APPROVER_EMAILS allowlist. Self-grants and self-revocations through this endpoint are denied. The grant or revocation reason belongs in the capability audit. Use an approval reference rather than confidential case content.
- Every successful privileged read records actor ID, incident ID, operation and timestamp in the guarded snapshot transaction. A failed audit write fails the read. Give the runtime INSERT access and restrict audit review separately. Access checks are current at snapshot time. Data already delivered cannot be recalled after revocation.

## Before activation

1. Obtain designated ISMS and HR approval for named global viewers, named approvers, membership ownership, access reviews, and audit retention. Use separate controlled processes for case classification and email disclosure.
2. Rehearse the review-only schema on disposable MySQL 8.4, using the existing B2, B3 and Phase A schema as prerequisites. Add department membership, consolidated incident security administration (including the global read audit table), security lock, and assignment state. Inspect the actual schema first. Install a reviewed delta if a draft table already exists. Verify app-user and incident key types, least-privilege grants, and audit immutability. Do not seed or infer HR mappings from departments, roles or legacy owner strings.
3. Establish a controlled, audited writer for membership changes using the same security gate, and approve the scope pairs and case grants. Prove revocation, concurrent writers, audit rollback, report performance, and lock timeouts on MySQL. Include the real OAuth/CSRF browser flow, legacy restricted incident samples, and all endpoint variants. Review whether an unknown legacy case can safely be exposed under legacy mode; the protective hints cannot recognize every sensitive description.
4. Separately review an activation strategy and guard change after evidence and approvals. Keep B4 disabled until then. A rollback plan must keep the confidential legacy restrictions and retain all audit records.

## Exact B4 worktree file list

Relative to the B4 base commit cbba90b. This includes B4 files already present as local changes at the start of this task.

- Modified `src/main/java/com/pareidolia/incidentmanagement/controller/IncidentController.java`
- Modified `src/main/java/com/pareidolia/incidentmanagement/dto/CreateIncidentRequestDto.java`
- Modified `src/main/java/com/pareidolia/incidentmanagement/repository/IncidentHistoryRepository.java`
- Modified `src/main/java/com/pareidolia/incidentmanagement/repository/IncidentRepository.java`
- Modified `src/main/java/com/pareidolia/incidentmanagement/service/IncidentService.java`
- Modified `src/main/java/com/pareidolia/incidentmanagement/service/impl/IncidentAttachmentServiceImpl.java`
- Modified `src/main/java/com/pareidolia/incidentmanagement/service/impl/IncidentReportServiceImpl.java`
- Modified `src/main/java/com/pareidolia/incidentmanagement/service/impl/IncidentServiceImpl.java`
- Modified `src/main/resources/application.properties`
- Modified `src/test/java/com/pareidolia/incidentmanagement/IncidentEmailV2SmtpTests.java`
- Modified `src/test/java/com/pareidolia/incidentmanagement/IncidentLocationTests.java`
- Modified `src/test/java/com/pareidolia/incidentmanagement/IncidentManagementServiceApplicationTests.java`
- Added `docs/assignment/assignment-schema.REVIEW-ONLY.sql`
- Added `docs/assignment/b4-department-assignment.md`
- Added `docs/assignment/department-membership.REVIEW-ONLY.sql`
- Added `docs/assignment/incident-security-administration.REVIEW-ONLY.sql`
- Added `docs/assignment/incident-security-lock.REVIEW-ONLY.sql`
- Added `src/main/java/com/pareidolia/incidentmanagement/assignment/AssignmentAuthorizationPolicy.java`
- Added `src/main/java/com/pareidolia/incidentmanagement/controller/IncidentAssignmentController.java`
- Added `src/main/java/com/pareidolia/incidentmanagement/controller/IncidentCapabilityAdministrationController.java`
- Added `src/main/java/com/pareidolia/incidentmanagement/controller/IncidentSecurityAdministrationController.java`
- Added `src/main/java/com/pareidolia/incidentmanagement/security/IncidentAccessPolicy.java`
- Added `src/main/java/com/pareidolia/incidentmanagement/security/IncidentConfidentiality.java`
- Added `src/main/java/com/pareidolia/incidentmanagement/service/EligibleHandlerDirectory.java`
- Added `src/main/java/com/pareidolia/incidentmanagement/service/IncidentAssignmentService.java`
- Added `src/main/java/com/pareidolia/incidentmanagement/service/IncidentCapabilityAdministrationService.java`
- Added `src/main/java/com/pareidolia/incidentmanagement/service/IncidentSecurityAdministrationService.java`
- Added `src/test/java/com/pareidolia/incidentmanagement/DisposableAssignmentDatabase.java`
- Added `src/test/java/com/pareidolia/incidentmanagement/IncidentAccessPolicyTests.java`
- Added `src/test/java/com/pareidolia/incidentmanagement/IncidentAccessWiringTests.java`
- Added `src/test/java/com/pareidolia/incidentmanagement/IncidentAssignmentWorkflowTests.java`
- Added `src/test/java/com/pareidolia/incidentmanagement/IncidentCapabilityAdministrationServiceTests.java`
- Added `src/test/java/com/pareidolia/incidentmanagement/IncidentSecurityAdministrationControllerTests.java`
- Added `src/test/java/com/pareidolia/incidentmanagement/IncidentSecurityAdministrationServiceTests.java`
- Added `src/test/java/com/pareidolia/incidentmanagement/IncidentSecurityLockCoordinationTests.java`
- Added `src/test/java/com/pareidolia/incidentmanagement/assignment/AssignmentAuthorizationPolicyTests.java`
