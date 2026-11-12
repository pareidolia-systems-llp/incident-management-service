package com.pareidolia.incidentmanagement.security;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class IncidentCriticalSchemaChecksTests {
    JdbcTemplate jdbc; List<String> columns, indexes, fks, checks;
    @BeforeEach void setup() {
        jdbc=mock(JdbcTemplate.class);
        columns=new ArrayList<>(IncidentCriticalSchemaChecks.REQUIRED_COLUMNS);
        indexes=new ArrayList<>(IncidentCriticalSchemaChecks.REQUIRED_INDEXES);
        indexes.add("app_users|synthetic_email_unique|0|1|email|FULL");
        fks=new ArrayList<>(IncidentCriticalSchemaChecks.REQUIRED_FKS);
        checks=new ArrayList<>(IncidentCriticalSchemaChecks.REQUIRED_CHECKS);
        when(jdbc.queryForList(IncidentCriticalSchemaChecks.COLUMNS,String.class)).thenReturn(columns);
        when(jdbc.queryForList(IncidentCriticalSchemaChecks.INDEXES,String.class)).thenReturn(indexes);
        when(jdbc.queryForList(IncidentCriticalSchemaChecks.FOREIGN_KEYS,String.class)).thenReturn(fks);
        when(jdbc.queryForList(IncidentCriticalSchemaChecks.CHECKS,String.class)).thenReturn(checks);
    }
    @Test void completeMetadataOnlyPassesForFurtherChecks() {
        assertThat(IncidentCriticalSchemaChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.VERIFIED_FOR_FURTHER_CHECKS);
    }
    @Test void missingColumnOrIncorrectTypeIsRejected() {
        columns.remove("incident_security_grants|version|bigint|NO");
        columns.add("incident_security_grants|version|int|NO");
        assertThat(IncidentCriticalSchemaChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.INVALID_SCHEMA);
    }
    @Test void missingMembershipAndReceiptSecurityConstraintsFailClosed() {
        columns.remove("employee_department_memberships|version|bigint|NO");
        assertThat(IncidentCriticalSchemaChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.INVALID_SCHEMA);
        columns.add("employee_department_memberships|version|bigint|NO");
        checks.remove("incident_department_detail_email_receipt|ck_detail_email_status|yes|statusin('CLAIMED','SENT','UNCERTAIN')");
        assertThat(IncidentCriticalSchemaChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.INVALID_SCHEMA);
        assertThat(IncidentCriticalSchemaChecks.FOREIGN_KEYS).contains("k.referenced_table_schema=database()");
    }
    @Test void emailIdentityMustHaveSingleColumnFullUniqueIndex() {
        indexes.add("app_users|synthetic_email_unique|0|2|id|FULL");
        assertThat(IncidentCriticalSchemaChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.INVALID_SCHEMA);
        indexes.remove("app_users|synthetic_email_unique|0|2|id|FULL");
        indexes.remove("app_users|synthetic_email_unique|0|1|email|FULL");
        indexes.add("app_users|synthetic_email_unique|0|1|email|8");
        assertThat(IncidentCriticalSchemaChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.INVALID_SCHEMA);
    }
    @Test void missingClassificationAndCapabilityAuditConstraintsFailClosed() {
        indexes.remove("incident_classification_audit|uk_ica_version|0|2|version|FULL");
        assertThat(IncidentCriticalSchemaChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.INVALID_SCHEMA);
        indexes.add("incident_classification_audit|uk_ica_version|0|2|version|FULL");
        fks.remove("assignment_admin_capability_audit|fk_aaca_capability|2|capability|assignment_admin_capabilities|capability|RESTRICT|RESTRICT");
        assertThat(IncidentCriticalSchemaChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.INVALID_SCHEMA);
    }
    @Test void missingClassificationAuditForeignKeyFailsClosed() {
        fks.remove("incident_classification_audit|fk_ica_classification|1|incident_id|incident_security_classification|incident_id|RESTRICT|RESTRICT");
        assertThat(IncidentCriticalSchemaChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.INVALID_SCHEMA);
    }
    @Test void missingCapabilityAuditUniquenessFailsClosed() {
        indexes.remove("assignment_admin_capability_audit|uk_aaca_version|0|3|version|FULL");
        assertThat(IncidentCriticalSchemaChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.INVALID_SCHEMA);
    }
    @Test void missingUniqueOrAlteredForeignKeyIsRejected() {
        indexes.remove("incident_assignment_audit|uk_assignment_audit_version|0|2|assignment_version|FULL");
        assertThat(IncidentCriticalSchemaChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.INVALID_SCHEMA);
        indexes.add("incident_assignment_audit|uk_assignment_audit_version|0|2|assignment_version|FULL"); fks.clear();
        assertThat(IncidentCriticalSchemaChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.INVALID_SCHEMA);
    }
    @Test void weakenedUniqueIndexesAndExtraForeignKeyColumnsAreRejected() {
        indexes.add("incident_security_grants|PRIMARY|0|4|version|FULL");
        assertThat(IncidentCriticalSchemaChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.INVALID_SCHEMA);
        indexes.remove("incident_security_grants|PRIMARY|0|4|version|FULL");
        indexes.remove("incident_security_grants|PRIMARY|0|3|permission|FULL");
        indexes.add("incident_security_grants|PRIMARY|0|3|permission|5");
        assertThat(IncidentCriticalSchemaChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.INVALID_SCHEMA);
        indexes.remove("incident_security_grants|PRIMARY|0|3|permission|5");
        indexes.add("incident_security_grants|PRIMARY|0|3|permission|FULL");
        fks.add("incident_security_grant_audit|fk_isga_grant|4|version|incident_security_grants|version|RESTRICT|RESTRICT");
        assertThat(IncidentCriticalSchemaChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.INVALID_SCHEMA);
    }
    @Test void unenforcedOrAlteredCheckIsRejected() {
        checks.remove("incident_security_lock|ck_incident_security_lock_singleton|yes|id=1");
        checks.add("incident_security_lock|ck_incident_security_lock_singleton|no|id=1");
        assertThat(IncidentCriticalSchemaChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.INVALID_SCHEMA);
    }
    @Test void canonicalizationPreservesStringAndExpressionMeaning() {
        assertThat(IncidentCriticalSchemaChecks.canonical("incident_security_grants|ck_isg_permission|YES|(`permission` in (_latin1\\'VIEW\\',_latin1\\'HANDLE\\',_latin1\\'MODIFY\\',_latin1\\'REPORT\\',_latin1\\'ASSIGN\\'))"))
                .isEqualTo("incident_security_grants|ck_isg_permission|yes|permissionin('VIEW','HANDLE','MODIFY','REPORT','ASSIGN')");
        assertThat(IncidentCriticalSchemaChecks.canonical("incident_assignment_audit|ck_assignment_reason|YES|(char_length(trim(`reason`) > 0))"))
                .isNotEqualTo("incident_assignment_audit|ck_assignment_reason|yes|char_length(trim(reason))>0");
        assertThat(IncidentCriticalSchemaChecks.canonical("incident_assignment_audit|ck_assignment_action|YES|(`action_type` in (_latin1\\'INI TIAL\\',_latin1\\'REASSIGN\\'))"))
                .isNotEqualTo("incident_assignment_audit|ck_assignment_action|yes|action_typein('INITIAL','REASSIGN')");
    }
    @Test void noQueryTimeoutFailsClosed() {
        when(jdbc.getQueryTimeout()).thenReturn(0);
        assertThat(IncidentCriticalSchemaChecks.inspect(jdbc)).isEqualTo(IncidentCriticalSchemaChecks.Result.UNAVAILABLE);
    }
    @Test
    @org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable(named="V2_SCHEMA_MYSQL_PROOF",matches="true")
    void readOnlyIsolatedMysqlMetadataMatchesCriticalMigrations() throws Exception {
        String password=System.getenv("V2_SCHEMA_MYSQL_PASSWORD");
        if(password==null || !password.matches("[0-9a-f]{64}")) throw new IllegalStateException("Missing isolated proof credential.");
        var source=new org.springframework.jdbc.datasource.DriverManagerDataSource("jdbc:mysql://127.0.0.1:59455/incident_v2_runtime_proof_20261112?connectTimeout=5000&socketTimeout=10000&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC","v2_runtime_test",password);
        var real=new JdbcTemplate(source); real.setQueryTimeout(5);
        var identity=real.queryForMap("select database() as db,@@server_uuid as uuid,version() as version,current_user() as account,current_role() as active_role");
        assertThat(identity.get("db")).isEqualTo("incident_v2_runtime_proof_20261112");
        assertThat(identity.get("uuid")).isEqualTo("a6563759-ddb5-11f1-9b7c-6e0023da6ea2");
        assertThat(identity.get("version")).isEqualTo("8.4.11");
        assertThat(identity.get("account")).isEqualTo("v2_runtime_test@172.22.0.1");
        assertThat(identity.get("active_role")).isEqualTo("NONE");
        assertThat(real.queryForList(IncidentCriticalSchemaChecks.COLUMNS,String.class)).containsAll(IncidentCriticalSchemaChecks.REQUIRED_COLUMNS);
        assertThat(real.queryForList(IncidentCriticalSchemaChecks.INDEXES,String.class)).containsAll(IncidentCriticalSchemaChecks.REQUIRED_INDEXES);
        assertThat(real.queryForList(IncidentCriticalSchemaChecks.FOREIGN_KEYS,String.class)).containsAll(IncidentCriticalSchemaChecks.REQUIRED_FKS);
        assertThat(real.queryForList(IncidentCriticalSchemaChecks.CHECKS,String.class).stream().map(IncidentCriticalSchemaChecks::canonical).toList()).containsAll(IncidentCriticalSchemaChecks.REQUIRED_CHECKS);
        assertThat(IncidentCriticalSchemaChecks.inspect(real)).isEqualTo(IncidentCriticalSchemaChecks.Result.VERIFIED_FOR_FURTHER_CHECKS);
        assertThat(IncidentRuntimePrivilegeChecks.inspect(real,true)).isEqualTo(IncidentRuntimePrivilegeChecks.Result.VERIFIED_FOR_FURTHER_CHECKS);
        assertThat(IncidentAccessReadinessChecks.inspectCoordinated(real,java.util.Set.of(1106L),"example.test"))
                .isEqualTo(IncidentAccessReadinessChecks.Result.READY_FOR_FURTHER_CHECKS);
        try (var blocker=source.getConnection();var statement=blocker.createStatement()) {
            blocker.setAutoCommit(false);
            try (var rows=statement.executeQuery("select id from incident_security_lock where id=1 for update")) { assertThat(rows.next()).isTrue(); }
            String connectionCount="select count(*) from information_schema.processlist where user=substring_index(current_user(),'@',1) and db=database()";
            Long baselineConnections=real.queryForObject(connectionCount,Long.class);
            real.setQueryTimeout(1);
            long start=System.nanoTime();
            assertThat(IncidentAccessReadinessChecks.inspectCoordinated(real,java.util.Set.of(1106L),"example.test"))
                    .isEqualTo(IncidentAccessReadinessChecks.Result.UNAVAILABLE);
            long elapsed=java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start);
            assertThat(elapsed).isLessThan(8000L);
            assertThat(real.queryForObject(connectionCount,Long.class)).isEqualTo(baselineConnections);
            blocker.rollback();
            real.setQueryTimeout(5);
            assertThat(IncidentAccessReadinessChecks.inspectCoordinated(real,java.util.Set.of(1106L),"example.test"))
                    .isEqualTo(IncidentAccessReadinessChecks.Result.READY_FOR_FURTHER_CHECKS);
            System.out.println("SCHEMA_PROBE LOCK_TIMEOUT_MS="+elapsed+" RECOVERED=true");
        }
        var configuration=new IncidentReadinessCoordinatorTests();configuration.setup();
        configuration.env.setProperty("app.incident-access.hr-account-ids","1106");
        String approvedRecipients=System.getenv("V2_READINESS_APPROVED_RECIPIENTS");
        if(approvedRecipients==null || approvedRecipients.isBlank()) throw new IllegalStateException("Missing synthetic recipient policy.");
        configuration.env.setProperty("app.notifications.email.readiness.approved-recipients",approvedRecipients);
        String hrEmail=java.util.Arrays.stream(approvedRecipients.split(";")).filter(value -> value.startsWith("HR=")).findFirst().orElseThrow().substring(3);
        configuration.env.setProperty("app.notifications.email.verified-department-routing.restricted-recipients","2="+hrEmail);
        try (var pool=new com.zaxxer.hikari.HikariDataSource()) {
            pool.setJdbcUrl("jdbc:mysql://127.0.0.1:59455/incident_v2_runtime_proof_20261112?connectTimeout=5000&socketTimeout=10000&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC");
            pool.setUsername("v2_runtime_test");pool.setPassword(password);pool.setConnectionTimeout(5000);pool.setValidationTimeout(1000);pool.setMaximumPoolSize(2);
            var coordinatorJdbc=new JdbcTemplate(pool);coordinatorJdbc.setQueryTimeout(2);
            assertThat(IncidentReadinessCoordinator.inspect(configuration.env,pool,coordinatorJdbc,configuration.google,configuration.sender,10000))
                    .isEqualTo(IncidentReadinessCoordinator.Result.READY);
            var missingPrivileges=spy(new JdbcTemplate(pool));missingPrivileges.setQueryTimeout(2);
            doReturn(java.util.List.of()).when(missingPrivileges).queryForList(IncidentRuntimePrivilegeChecks.TABLE_SQL,String.class);
            doReturn(java.util.List.of()).when(missingPrivileges).queryForList(IncidentRuntimePrivilegeChecks.COLUMN_SQL,String.class);
            assertThat(IncidentReadinessCoordinator.inspect(configuration.env,pool,missingPrivileges,configuration.google,configuration.sender,10000))
                    .isEqualTo(IncidentReadinessCoordinator.Result.SCHEMA_OR_PRIVILEGES_INVALID);
            assertThat(pool.getHikariPoolMXBean().getActiveConnections()).isZero();
            var invalidSchema=spy(new JdbcTemplate(pool));invalidSchema.setQueryTimeout(2);
            doReturn(java.util.List.of()).when(invalidSchema).queryForList(IncidentCriticalSchemaChecks.COLUMNS,String.class);
            assertThat(IncidentReadinessCoordinator.inspect(configuration.env,pool,invalidSchema,configuration.google,configuration.sender,10000))
                    .isEqualTo(IncidentReadinessCoordinator.Result.SCHEMA_OR_PRIVILEGES_INVALID);
            assertThat(pool.getHikariPoolMXBean().getActiveConnections()).isZero();
            var unavailableSchema=spy(new JdbcTemplate(pool));unavailableSchema.setQueryTimeout(2);
            doThrow(new org.springframework.dao.DataAccessResourceFailureException("synthetic detail")).when(unavailableSchema).queryForList(IncidentCriticalSchemaChecks.COLUMNS,String.class);
            assertThat(IncidentReadinessCoordinator.inspect(configuration.env,pool,unavailableSchema,configuration.google,configuration.sender,10000))
                    .isEqualTo(IncidentReadinessCoordinator.Result.DATABASE_UNAVAILABLE);
            assertThat(pool.getHikariPoolMXBean().getActiveConnections()).isZero();
            configuration.env.setProperty("app.incident-access.hr-account-ids","1105");
            assertThat(IncidentReadinessCoordinator.inspect(configuration.env,pool,coordinatorJdbc,configuration.google,configuration.sender,10000))
                    .isEqualTo(IncidentReadinessCoordinator.Result.CASE_OR_HR_INVALID);
            configuration.env.setProperty("app.incident-access.hr-account-ids","1106");
            assertThat(pool.getHikariPoolMXBean().getActiveConnections()).isZero();
            try(var blocker=source.getConnection();var statement=blocker.createStatement()) {
                blocker.setAutoCommit(false);
                try(var rows=statement.executeQuery("select id from incident_security_lock where id=1 for update")){assertThat(rows.next()).isTrue();}
                assertThat(IncidentReadinessCoordinator.inspect(configuration.env,pool,coordinatorJdbc,configuration.google,configuration.sender,10000))
                        .isEqualTo(IncidentReadinessCoordinator.Result.DATABASE_UNAVAILABLE);
                assertThat(pool.getHikariPoolMXBean().getActiveConnections()).isZero();
                blocker.rollback();
            }
            assertThat(IncidentReadinessCoordinator.inspect(configuration.env,pool,coordinatorJdbc,configuration.google,configuration.sender,10000))
                    .isEqualTo(IncidentReadinessCoordinator.Result.READY);
            assertThat(pool.getHikariPoolMXBean().getActiveConnections()).isZero();
            System.out.println("SCHEMA_PROBE COORDINATOR_LOCK_TIMEOUT_RECOVERED=true ACTIVE_CONNECTIONS=0");
        }
    }
}
