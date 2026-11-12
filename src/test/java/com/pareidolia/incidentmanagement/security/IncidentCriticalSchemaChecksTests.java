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
    void readOnlyIsolatedMysqlMetadataMatchesCriticalMigrations() {
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
        assertThat(IncidentRuntimePrivilegeChecks.inspect(real,true)).isEqualTo(IncidentRuntimePrivilegeChecks.Result.MISSING_PRIVILEGE);
    }
}
