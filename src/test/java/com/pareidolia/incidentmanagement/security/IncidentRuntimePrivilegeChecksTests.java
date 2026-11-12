package com.pareidolia.incidentmanagement.security;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class IncidentRuntimePrivilegeChecksTests {
    private JdbcTemplate jdbc;
    private List<String> grants;
    @BeforeEach void setUp() {
        jdbc=mock(JdbcTemplate.class);
        grants=new ArrayList<>(IncidentRuntimePrivilegeChecks.REQUIRED);
        when(jdbc.getQueryTimeout()).thenReturn(5);
        when(jdbc.queryForObject(IncidentRuntimePrivilegeChecks.ROLE_SQL,String.class)).thenReturn("NONE");
        when(jdbc.queryForList(IncidentRuntimePrivilegeChecks.TABLE_SQL,String.class)).thenReturn(grants);
        when(jdbc.queryForList(IncidentRuntimePrivilegeChecks.COLUMN_SQL,String.class)).thenReturn(List.of());
    }
    @Test void reviewedManifestIsOnlyPreliminary() {
        assertThat(IncidentRuntimePrivilegeChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentRuntimePrivilegeChecks.Result.VERIFIED_FOR_FURTHER_CHECKS);
    }
    @Test void missingIncidentHistoryInsertFailsClosed() {
        grants.remove("incident_history|INSERT|*");
        assertThat(IncidentRuntimePrivilegeChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentRuntimePrivilegeChecks.Result.MISSING_PRIVILEGE);
    }
    @Test void tableUpdateIncludesRequiredColumnUpdates() {
        grants.removeIf(value -> value.startsWith("incidents|UPDATE|"));
        grants.add("incidents|UPDATE|*");
        assertThat(IncidentRuntimePrivilegeChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentRuntimePrivilegeChecks.Result.VERIFIED_FOR_FURTHER_CHECKS);
    }
    @Test void activeRolesAndMissingTimeoutAreRejected() {
        when(jdbc.queryForObject(IncidentRuntimePrivilegeChecks.ROLE_SQL,String.class)).thenReturn("`synthetic_role`@`%`");
        assertThat(IncidentRuntimePrivilegeChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentRuntimePrivilegeChecks.Result.UNSUPPORTED_ROLE);
        when(jdbc.getQueryTimeout()).thenReturn(0);
        assertThat(IncidentRuntimePrivilegeChecks.inspect(jdbc)).isEqualTo(IncidentRuntimePrivilegeChecks.Result.UNAVAILABLE);
    }
    @Test void metadataFailureIsUnavailable() {
        when(jdbc.queryForList(IncidentRuntimePrivilegeChecks.TABLE_SQL,String.class)).thenThrow(new DataAccessResourceFailureException("synthetic"));
        assertThat(IncidentRuntimePrivilegeChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentRuntimePrivilegeChecks.Result.UNAVAILABLE);
    }
    @Test void incompleteMetadataAndMissingAuditInsertFailClosed() {
        grants.remove("incident_security_grant_audit|INSERT|*");
        assertThat(IncidentRuntimePrivilegeChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentRuntimePrivilegeChecks.Result.MISSING_PRIVILEGE);
        grants.clear();
        assertThat(IncidentRuntimePrivilegeChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentRuntimePrivilegeChecks.Result.MISSING_PRIVILEGE);
    }
    @Test void missingRequiredUpdateColumnFailsClosed() {
        grants.remove("incidents|UPDATE|status");
        assertThat(IncidentRuntimePrivilegeChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentRuntimePrivilegeChecks.Result.MISSING_PRIVILEGE);
    }
    @Test void missingRequiredSelectFailsClosed() {
        grants.remove("incidents|SELECT|*");
        assertThat(IncidentRuntimePrivilegeChecks.inspectOnConnection(jdbc)).isEqualTo(IncidentRuntimePrivilegeChecks.Result.MISSING_PRIVILEGE);
    }
    @Test
    @org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable(named="V2_PRIVILEGE_MYSQL_PROOF",matches="true")
    void isolatedMysqlDirectPrivilegesMatchExpectedAccount() {
        String user=System.getenv("V2_PRIVILEGE_MYSQL_USER");
        String password=System.getenv("V2_PRIVILEGE_MYSQL_PASSWORD");
        if (!List.of("v2_runtime_test","v2_denied_test").contains(user) || password==null || !password.matches("[0-9a-f]{64}"))
            throw new IllegalStateException("Missing isolated proof configuration.");
        var source=new org.springframework.jdbc.datasource.DriverManagerDataSource(
                "jdbc:mysql://127.0.0.1:59455/incident_v2_runtime_proof_20261112?connectTimeout=5000&socketTimeout=10000&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC",user,password);
        var real=new JdbcTemplate(source); real.setQueryTimeout(5);
        var identity=real.queryForMap("select database() as db,@@server_uuid as uuid,version() as version,current_user() as account,current_role() as active_role");
        assertThat(identity.get("db")).isEqualTo("incident_v2_runtime_proof_20261112");
        assertThat(identity.get("uuid")).isEqualTo("a6563759-ddb5-11f1-9b7c-6e0023da6ea2");
        assertThat(identity.get("version")).isEqualTo("8.4.11");
        assertThat(identity.get("account")).isEqualTo(user+"@172.22.0.1");
        assertThat(identity.get("active_role")).isEqualTo("NONE");
        var expected="v2_runtime_test".equals(user) ? IncidentRuntimePrivilegeChecks.Result.VERIFIED_FOR_FURTHER_CHECKS : IncidentRuntimePrivilegeChecks.Result.MISSING_PRIVILEGE;
        assertThat(IncidentRuntimePrivilegeChecks.inspect(real)).isEqualTo(expected);
        if ("v2_denied_test".equals(user)) {
            assertThat(real.queryForList(IncidentRuntimePrivilegeChecks.TABLE_SQL,String.class)).doesNotContain("incident_history|INSERT|*");
            assertThat(real.queryForList(IncidentRuntimePrivilegeChecks.COLUMN_SQL,String.class)).noneMatch(s -> s.startsWith("incident_history|INSERT|"));
        }
    }
}
