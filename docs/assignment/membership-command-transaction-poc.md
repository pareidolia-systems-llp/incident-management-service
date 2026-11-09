# Dedicated membership command transaction proof of concept

The membership PUT keeps its existing contract. If both membership flags are enabled, the service checks the verified OIDC email and configured allowlist before calling a private JDBC transaction owner. The command rejects an ambient transaction, checks the server UUID, schema, and authenticated MySQL account, then locks the same singleton row used by assignment. It resolves the active actor by verified email and checks the employee and department with current shared locking reads. It exclusively locks membership state and writes the versioned change and audit on the same connection. Failure propagates to the transaction manager and rolls back both writes.

Both flags default to false. List and history still use the ordinary JPA snapshot. The default write path for an already-enabled membership workflow uses the existing JPA transaction manager and gate. The dedicated data source and manager are private implementation details, so Boot still configures a single JPA persistence unit. No routing decision depends on controller name, a claimed role, or a mutable connection selector.

## Disposable configuration

Set DEPARTMENT_MEMBERSHIP_ADMIN_ENABLED and DEPARTMENT_MEMBERSHIP_COMMAND_ENABLED to true only for the isolated rehearsal. Set DEPARTMENT_MEMBERSHIP_ADMIN_ALLOWED_EMAILS to the approved synthetic actor. Supply DEPARTMENT_MEMBERSHIP_COMMAND_DB_URL, DEPARTMENT_MEMBERSHIP_COMMAND_DB_USER, and DEPARTMENT_MEMBERSHIP_COMMAND_DB_PASS through local secret configuration. Keep INCIDENT_ACCESS_ENABLED set to false, JPA_DDL_AUTO set to validate, and all incident email delivery disabled.

The ordinary and command accounts must authenticate as different MySQL users on the same server UUID and schema. The ordinary account needs membership and audit SELECT if list and history are used. It has no membership or audit writes. The isolated command tests can use an ordinary credential without audit SELECT. Verify the committed audit rows independently with the existing disposable fixture administrator before cleanup. The command account needs the following table grants in the target schema.

| Table | Dedicated command privileges |
| --- | --- |
| app_users and employee_departments | SELECT |
| incident_security_lock | SELECT and UPDATE(id) for the exclusive lock. Preserve CHECK (id=1). |
| employee_department_memberships | SELECT, INSERT, UPDATE(active, version) |
| employee_department_membership_audit | INSERT |

No new schema migration is required. Verify the existing security-lock, department-membership, and department-membership-administration review-only migrations, including the singleton row and unique audit version.

MembershipCommandMysqlTests runs only with INCIDENT_MEMBERSHIP_POC_MYSQL=true and the confirmed disposable loopback URL. Use fresh synthetic accounts with the four membership-poc emails in the test, an active department, and memberships at version 1 for the race and audit failure targets. Seed a version 2 audit for the failure target so the command hits the existing unique constraint. Run the named test with the ordinary and command credentials configured separately. Remove only those synthetic fixtures and lock the disposable command credential after the run.

## Scope limits

The dedicated identity is still available to the same JVM. This proves a transaction boundary and a SQL privilege boundary for the ordinary credential. It does not isolate the privileged credential from a compromised process. An independently authorized command process and separate credential custody are required before production adoption.

A second entity manager would create a separate persistence context and would require explicit transaction and repository ownership. A nested JPA call from this JDBC command could enlist another connection and would lose the atomicity guarantee. Keep the JDBC command limited to its own transaction and avoid cross-data-source callbacks. The proof uses a direct connection per command. Evaluate pooling, connection and lock timeouts, observability, credential rotation, and load before extending it.

The MySQL race pairs the real membership command with an assignment-side lock and eligibility read. Existing isolated application tests cover the actual assignment service race. Exercise both real commands together on MySQL as part of a future guarded rehearsal.
