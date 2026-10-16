# My Work Log MVP

Implemented as an independent entity and page. No incident relationship, history records,
incident report changes, editing, deletion, attachments, or administrator-wide listing.
Existing incident features and earlier uncommitted work are preserved.

## Database and release requirements

The repository uses Hibernate schema management (`JPA_DDL_AUTO`, default `update`),
not Flyway/Liquibase. Do not rely on production `ddl-auto=update` for this feature.
The exact additive development and future production SQL is in
[`schema/work_log_entries.sql`](schema/work_log_entries.sql). It creates only:

```sql
CREATE TABLE work_log_entries (
    id BIGINT NOT NULL AUTO_INCREMENT,
    owner_id BIGINT NOT NULL,
    worked_at DATETIME(6) NOT NULL,
    category VARCHAR(32) NOT NULL,
    summary VARCHAR(255) NOT NULL,
    details TEXT NULL,
    duration_minutes INT NULL,
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    INDEX idx_work_log_owner_worked_id (owner_id, worked_at, id),
    CONSTRAINT fk_work_log_owner FOREIGN KEY (owner_id)
        REFERENCES app_users (id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

Category is a bounded string, never a native MySQL ENUM. `created_at` is set by
the server's entity persistence callback; it deliberately has no client or SQL default.
No existing table or enum alteration is needed for this enhancement.

Before applying this file in development, verify the target database and existing
`app_users` definition, then execute the SQL explicitly. The same SQL is required
for a future, separately authorized production release. This task did not execute
it against development MySQL or production. Tests created only disposable H2 tables.

Required production verification (not executed here):

```sql
SELECT DATABASE(), VERSION();
SHOW CREATE TABLE app_users;
SHOW TABLES LIKE 'work_log_entries';
```

Confirm the intended schema, InnoDB support, existing `app_users.id` is signed BIGINT
and indexed as the primary key, and the new table does not already exist. If it does
exist, inspect `SHOW CREATE TABLE work_log_entries` and reconcile drift rather than
blindly running CREATE or hiding it with IF NOT EXISTS. The deployed definition cannot
be established from the Windows repository. If these prerequisites differ, adjust the
release SQL only after verifying the actual schema. After the explicitly approved DDL,
use `JPA_DDL_AUTO=validate` for production startup and verify the mappings. No production
configuration or VM was changed here.

## API and authorization

- `GET /api/work-logs`: authenticated, active IT_HANDLER or ADMIN; only that user's
  entries, ordered by `worked_at DESC, id DESC`. No query parameters/owner filters.
- `POST /api/work-logs`: same roles; returns 201. Only `workedAt`, `category`, `summary`,
  `details`, and `durationMinutes` are accepted. Unknown fields, including ownership
  or creation timestamps, are rejected with 400.
- Owner is resolved by the existing AppUserService from the authenticated OIDC
  security context and existing user record. No duplicate user is created.
- REPORTER and REVIEWER cannot list/create. ADMIN has no access to others' entries.
- Existing OAuth/session and CSRF handling apply. Responses specify `Cache-Control:
  no-store`. No work content is logged by the new application code or sent to Faro.

## Validation and UI

- Work date/time required; LocalDateTime, same local timestamp convention as incidents,
  with supported work years 1900 through 9998. No UTC conversion.
- Category required: USER_SUPPORT, MAINTENANCE, NETWORK, SERVER, SECURITY,
  ADMINISTRATION, OTHER. UI displays readable labels.
- Summary required/nonblank, maximum 255 characters; trimmed before storage.
- Details optional, maximum 8000 characters; blank maps to null.
- Duration optional, positive integer minutes (Java Integer range).
- Created timestamp is server-generated independently of the selected work time.
- Authorized navigation opens `/work-logs`. The page shows the backend's ordered list,
  empty state, optional details disclosure, and Add Work Entry modal using existing
  Bootstrap styling. Save refreshes the list on the same route and shows success.
- Save failure preserves the draft. A list-refresh failure after successful creation
  does not retry the POST. Existing incident polling is unchanged.

## Files changed in this enhancement

Backend source (under `src/main/java/com/pareidolia/incidentmanagement/`):

- `controller/WorkLogController.java`
- `dto/CreateWorkLogRequestDto.java`
- `dto/WorkLogResponseDto.java`
- `entity/WorkLogEntry.java`
- `repository/WorkLogRepository.java`
- `service/WorkLogService.java`
- `service/impl/WorkLogServiceImpl.java`

Backend tests (under `src/test/java/com/pareidolia/incidentmanagement/`):

- `WorkLogTests.java`
- `AuthenticationFlowTests.java`

Database/documentation: `schema/work_log_entries.sql`, `MY_WORK_LOG_MVP.md`.

Frontend (in sibling `incident-management-ui`):

- `src/App.jsx`
- `src/components/AppLayout.jsx`
- `src/api/workLogs.js`
- `src/pages/MyWorkLog.jsx`
- `src/utils/workLog.js`
- `src/utils/workLog.test.js`
- `src/MyWorkLog.test.jsx`
- `src/observability/faro.js`
- `src/observability/faro.test.jsx`

## Validation

- Full Maven tests with isolated H2 and dummy OAuth configuration: 116 run,
  115 passed, 0 assertion failures, 1 application context error. All 9 WorkLogTests
  cases and authentication/CSRF tests pass. The existing contextLoads test fails
  during OAuth client initialization because Java cannot establish a Windows
  loopback connection (`SocketException: Invalid argument: connect`). This environment
  issue also occurred before this feature; tests/security configuration were not weakened.
- Node: 27 passed.
- Vitest: 143 passed.
- ESLint and production build: passed. Build retains nonfatal chunk-size and mixed
  static/dynamic import warnings.
- `git diff --check`: passed in both repositories.

Remaining manual checks: apply the explicit SQL in an approved development database,
verify MySQL mapping/startup, sign in with separate IT_HANDLER/ADMIN accounts and confirm
own-entry isolation, confirm REPORTER/REVIEWER denial, create entries with/without optional
fields, inspect mobile/laptop modal and table layout, verify local displayed times, and
check deployed OAuth/CSRF and Faro network payloads. Production was not accessed.
