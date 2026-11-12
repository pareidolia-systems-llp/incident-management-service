package com.pareidolia.incidentmanagement.security;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Set;
import java.util.concurrent.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import static org.assertj.core.api.Assertions.*;

@EnabledIfEnvironmentVariable(named="INCIDENT_READINESS_MYSQL_PROOF", matches="true")
class IncidentAccessReadinessMysqlTests {
    private DriverManagerDataSource source;
    private JdbcTemplate jdbc;
    @BeforeEach void verifyIdentity() {
        String password=System.getenv("INCIDENT_READINESS_MYSQL_PASSWORD");
        if (password==null || !password.matches("[0-9a-f]{64}")) throw new IllegalStateException("Missing isolated test credential.");
        source=new DriverManagerDataSource("jdbc:mysql://127.0.0.1:59455/incident_readiness_proof_20261112?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC", "readiness_test_20261112", password);
        jdbc=new JdbcTemplate(source); jdbc.setQueryTimeout(5);
        var row=jdbc.queryForMap("select database() as db,@@server_uuid as uuid,version() as version,current_user() as account,current_role() as active_role");
        assertThat(row.get("db")).isEqualTo("incident_readiness_proof_20261112");
        assertThat(row.get("uuid")).isEqualTo("a6563759-ddb5-11f1-9b7c-6e0023da6ea2");
        assertThat(row.get("version")).isEqualTo("8.4.11");
        assertThat(row.get("account")).isEqualTo("readiness_test_20261112@172.22.0.1");
        assertThat(row.get("active_role")).isEqualTo("NONE");
    }
    @Test void acceptsOnlyFurtherChecksForConfiguredActiveEligibleHrHandler() {
        assertThat(IncidentAccessReadinessChecks.inspectCoordinated(jdbc,Set.of(1L),"example.test"))
                .isEqualTo(IncidentAccessReadinessChecks.Result.READY_FOR_FURTHER_CHECKS);
    }
    @Test void rejectsInactiveAccountAndMissingHrMembership() {
        assertThat(IncidentAccessReadinessChecks.inspect(jdbc,Set.of(2L),"example.test"))
                .isEqualTo(IncidentAccessReadinessChecks.Result.HR_HANDLER_UNAVAILABLE);
        assertThat(IncidentAccessReadinessChecks.inspect(jdbc,Set.of(3L),"example.test"))
                .isEqualTo(IncidentAccessReadinessChecks.Result.HR_HANDLER_UNAVAILABLE);
        assertThat(IncidentAccessReadinessChecks.inspect(jdbc,Set.of(),"example.test"))
                .isEqualTo(IncidentAccessReadinessChecks.Result.HR_HANDLER_UNAVAILABLE);
    }
    @Test void rejectsDomainMismatchAndMissingTimeout() {
        assertThat(IncidentAccessReadinessChecks.inspect(jdbc,Set.of(1L),"other.test"))
                .isEqualTo(IncidentAccessReadinessChecks.Result.HR_HANDLER_UNAVAILABLE);
        jdbc.setQueryTimeout(0);
        assertThat(IncidentAccessReadinessChecks.inspect(jdbc,Set.of(1L),"example.test"))
                .isEqualTo(IncidentAccessReadinessChecks.Result.INVALID_TIMEOUT);
    }
    @Test void permittedLockTimesOutUnderContentionAndRecoversAfterRollback() throws Exception {
        try (Connection first=source.getConnection(); Connection second=source.getConnection()) {
            first.setAutoCommit(false); second.setAutoCommit(false);
            try (var a=first.createStatement(); var b=second.createStatement()) {
                a.setQueryTimeout(5); b.setQueryTimeout(5);
                b.execute("set session innodb_lock_wait_timeout=1");
                try(var rows=a.executeQuery("select id from incident_security_lock where id=1 for update")) {
                    assertThat(rows.next()).isTrue(); assertThat(rows.getLong(1)).isEqualTo(1L);
                }
                assertThatThrownBy(()->b.executeQuery("select id from incident_security_lock where id=1 for update"))
                        .isInstanceOfSatisfying(SQLException.class, ex->assertThat(ex.getErrorCode()).isEqualTo(1205));
                first.rollback();
                try(var rows=b.executeQuery("select id from incident_security_lock where id=1 for update")) {
                    assertThat(rows.next()).isTrue(); assertThat(rows.getLong(1)).isEqualTo(1L);
                }
                second.rollback();
            }
        }
    }
    @Test void coordinatedInspectionWaitsForSecurityWriterBeforeReading() throws Exception {
        var pool=Executors.newSingleThreadExecutor();
        try (Connection first=source.getConnection()) {
            first.setAutoCommit(false);
            try (var statement=first.createStatement()) {
                statement.executeQuery("select id from incident_security_lock where id=1 for update").close();
                var future=pool.submit(()->IncidentAccessReadinessChecks.inspectCoordinated(jdbc,Set.of(1L),"example.test"));
                assertThatThrownBy(()->future.get(250,TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class);
                first.rollback();
                assertThat(future.get(10,TimeUnit.SECONDS)).isEqualTo(IncidentAccessReadinessChecks.Result.READY_FOR_FURTHER_CHECKS);
            }
        } finally { pool.shutdownNow(); }
    }
    @Test void coordinatedInspectionFailsClosedWhenLockRemainsContended() throws Exception {
        jdbc.setQueryTimeout(1);
        try (Connection first=source.getConnection()) {
            first.setAutoCommit(false);
            try (var statement=first.createStatement()) {
                statement.executeQuery("select id from incident_security_lock where id=1 for update").close();
                assertThat(IncidentAccessReadinessChecks.inspectCoordinated(jdbc,Set.of(1L),"example.test"))
                        .isEqualTo(IncidentAccessReadinessChecks.Result.UNAVAILABLE);
                first.rollback();
            }
        }
    }
}
