package com.pareidolia.incidentmanagement.security;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class IncidentAccessReadinessChecksTests {
    @Test void v2DependenciesRejectMissingAndIncompatibleSettings() {
        var env=new MockEnvironment().withProperty("app.incident-access.enabled","true")
                .withProperty("app.incident-assignment.enabled","true").withProperty("app.employee-management.enabled","true")
                .withProperty("spring.jpa.hibernate.ddl-auto","validate").withProperty("spring.sql.init.mode","never")
                .withProperty("app.employee-management.production-enabled","true").withProperty("app.incident-security-admin.enabled","true")
                .withProperty("app.department-membership-admin.enabled","true").withProperty("app.department-head-designations.enabled","true")
                .withProperty("app.handler-eligibility-admin.enabled","true").withProperty("app.employee-management.allowed-emails","synthetic@example.test")
                .withProperty("app.department-membership-admin.allowed-emails","synthetic@example.test").withProperty("app.handler-eligibility-admin.allowed-emails","synthetic@example.test")
                .withProperty("app.incident-access.hr-account-ids","1").withProperty("app.incident-access.hr-department-ids","2")
                .withProperty("app.incident-assignment.allowed-actor-handler-pairs","1:2");
        assertThat(IncidentAccessReadinessChecks.inspectV2Dependencies(env)).isEqualTo(IncidentAccessReadinessChecks.Result.READY_FOR_FURTHER_CHECKS);
        env.setProperty("app.department-head-designations.enabled","false");
        assertThat(IncidentAccessReadinessChecks.inspectV2Dependencies(env)).isEqualTo(IncidentAccessReadinessChecks.Result.UNSAFE_CONFIGURATION);
        env.setProperty("app.department-head-designations.enabled","true");
        env.setProperty("app.department-membership-admin.dedicated-command.enabled","true");
        assertThat(IncidentAccessReadinessChecks.inspectV2Dependencies(env)).isEqualTo(IncidentAccessReadinessChecks.Result.UNSAFE_CONFIGURATION);
        env.setProperty("app.department-membership-admin.dedicated-command.enabled","false");
        env.setProperty("app.incident-assignment.allowed-actor-handler-pairs","bad");
        assertThat(IncidentAccessReadinessChecks.inspectV2Dependencies(env)).isEqualTo(IncidentAccessReadinessChecks.Result.UNSAFE_CONFIGURATION);
    }
    @Test void googleRegistrationRequiresApprovedProviderAndOidcEmailScope() {
        var google = org.springframework.security.config.oauth2.client.CommonOAuth2Provider.GOOGLE.getBuilder("google")
                .clientId("synthetic").clientSecret("synthetic").build();
        assertThat(IncidentAccessReadinessChecks.inspectGoogleRegistration(google, "example.test"))
                .isEqualTo(IncidentAccessReadinessChecks.Result.READY_FOR_FURTHER_CHECKS);
        assertThat(IncidentAccessReadinessChecks.inspectGoogleRegistration(null, "example.test"))
                .isEqualTo(IncidentAccessReadinessChecks.Result.INVALID_OAUTH);
        assertThat(IncidentAccessReadinessChecks.inspectGoogleRegistration(google, "not a domain"))
                .isEqualTo(IncidentAccessReadinessChecks.Result.INVALID_OAUTH);
        var altered = org.springframework.security.oauth2.client.registration.ClientRegistration.withClientRegistration(google)
                .authorizationUri("https://untrusted.example.test/auth").build();
        assertThat(IncidentAccessReadinessChecks.inspectGoogleRegistration(altered, "example.test"))
                .isEqualTo(IncidentAccessReadinessChecks.Result.INVALID_OAUTH);
        var noOidc = org.springframework.security.oauth2.client.registration.ClientRegistration.withClientRegistration(google)
                .scope("email").build();
        assertThat(IncidentAccessReadinessChecks.inspectGoogleRegistration(noOidc, "example.test"))
                .isEqualTo(IncidentAccessReadinessChecks.Result.INVALID_OAUTH);
    }
    private JdbcTemplate jdbc;
    @BeforeEach void setup() {
        jdbc = mock(JdbcTemplate.class);
        when(jdbc.getQueryTimeout()).thenReturn(5);
        when(jdbc.execute(any(ConnectionCallback.class))).thenReturn("MySQL");
        when(jdbc.queryForList(IncidentAccessReadinessChecks.TABLES_SQL, String.class))
                .thenReturn(List.copyOf(IncidentAccessReadinessChecks.REQUIRED_TABLES));
        when(jdbc.queryForObject(IncidentAccessReadinessChecks.LOCK_SQL, Long.class)).thenReturn(1L);
        when(jdbc.queryForObject(IncidentAccessReadinessChecks.LOCK_TOTAL_SQL, Long.class)).thenReturn(1L);
        when(jdbc.queryForObject(IncidentAccessReadinessChecks.CLASSIFICATION_SQL, Long.class)).thenReturn(0L);
        when(jdbc.queryForList(IncidentAccessReadinessChecks.DEPARTMENTS_SQL, String.class)).thenReturn(
                List.of("IT", "Human Resources", "Operations (Annotation)", "Operations (Perioperative Flow Analysis)", "R&D"));
        when(jdbc.queryForObject(IncidentAccessReadinessChecks.HR_HANDLER_SQL, Long.class, 7L, "example.test")).thenReturn(1L);
    }
    private IncidentAccessReadinessChecks.Result check() { return IncidentAccessReadinessChecks.inspect(jdbc, Set.of(7L), "example.test"); }
    @Test void validStateIsOnlyReadyForFurtherChecks() {
        assertThat(check()).isEqualTo(IncidentAccessReadinessChecks.Result.READY_FOR_FURTHER_CHECKS);
    }
    @Test void configuredHrDepartmentMustBeTheActiveHrDepartment() {
        String sql="select count(*) from employee_departments where id=? and active=1 and binary display_name in ('HR','Human Resources')";
        when(jdbc.queryForObject(sql,Long.class,2L)).thenReturn(1L);
        when(jdbc.queryForObject(sql,Long.class,3L)).thenReturn(0L);
        assertThat(IncidentAccessReadinessChecks.inspectHrDepartments(jdbc,Set.of(2L))).isEqualTo(IncidentAccessReadinessChecks.Result.READY_FOR_FURTHER_CHECKS);
        assertThat(IncidentAccessReadinessChecks.inspectHrDepartments(jdbc,Set.of(3L))).isEqualTo(IncidentAccessReadinessChecks.Result.INVALID_DEPARTMENTS);
    }
    @Test void nonMysqlIsRejected() {
        when(jdbc.execute(any(ConnectionCallback.class))).thenReturn("H2");
        assertThat(check()).isEqualTo(IncidentAccessReadinessChecks.Result.UNSUPPORTED_DATABASE);
    }
    @Test void absentTablesAreRejected() {
        when(jdbc.queryForList(IncidentAccessReadinessChecks.TABLES_SQL, String.class)).thenReturn(List.of("app_users"));
        assertThat(check()).isEqualTo(IncidentAccessReadinessChecks.Result.MISSING_TABLES);
    }
    @Test void missingOrExtraLockRowsAreRejected() {
        when(jdbc.queryForObject(IncidentAccessReadinessChecks.LOCK_TOTAL_SQL, Long.class)).thenReturn(2L);
        assertThat(check()).isEqualTo(IncidentAccessReadinessChecks.Result.INVALID_SECURITY_LOCK);
    }
    @Test void inactiveOrAmbiguousDepartmentsAreRejected() {
        when(jdbc.queryForList(IncidentAccessReadinessChecks.DEPARTMENTS_SQL, String.class)).thenReturn(List.of("IT", "HR"));
        assertThat(check()).isEqualTo(IncidentAccessReadinessChecks.Result.INVALID_DEPARTMENTS);
        when(jdbc.queryForList(IncidentAccessReadinessChecks.DEPARTMENTS_SQL, String.class)).thenReturn(
                List.of("IT", "HR", "Human Resources", "Operations (Annotation)", "Operations (Perioperative Flow Analysis)", "R&D"));
        assertThat(check()).isEqualTo(IncidentAccessReadinessChecks.Result.INVALID_DEPARTMENTS);
    }
    @Test void invalidOrMissingClassificationsAreRejected() {
        when(jdbc.queryForObject(IncidentAccessReadinessChecks.CLASSIFICATION_SQL, Long.class)).thenReturn(1L);
        assertThat(check()).isEqualTo(IncidentAccessReadinessChecks.Result.INVALID_CLASSIFICATIONS);
    }
    @Test void unavailableDatabaseFailsClosed() {
        when(jdbc.queryForList(IncidentAccessReadinessChecks.TABLES_SQL, String.class))
                .thenThrow(new DataAccessResourceFailureException("synthetic"));
        assertThat(check()).isEqualTo(IncidentAccessReadinessChecks.Result.UNAVAILABLE);
    }
    @Test void missingApprovedHrHandlerFailsClosed() {
        when(jdbc.queryForObject(IncidentAccessReadinessChecks.HR_HANDLER_SQL, Long.class, 7L, "example.test")).thenReturn(0L);
        assertThat(check()).isEqualTo(IncidentAccessReadinessChecks.Result.HR_HANDLER_UNAVAILABLE);
        assertThat(IncidentAccessReadinessChecks.inspect(jdbc, Set.of(), "example.test"))
                .isEqualTo(IncidentAccessReadinessChecks.Result.HR_HANDLER_UNAVAILABLE);
    }
    @Test void missingOrExcessiveQueryTimeoutFailsClosed() {
        when(jdbc.getQueryTimeout()).thenReturn(-1);
        assertThat(check()).isEqualTo(IncidentAccessReadinessChecks.Result.INVALID_TIMEOUT);
        when(jdbc.getQueryTimeout()).thenReturn(6);
        assertThat(check()).isEqualTo(IncidentAccessReadinessChecks.Result.INVALID_TIMEOUT);
    }
    @Test void guardedCreationRequiresAssignmentEmployeeManagementAndNoAutomaticDdl() {
        var env=new MockEnvironment()
                .withProperty("app.incident-access.enabled","true")
                .withProperty("app.incident-assignment.enabled","true")
                .withProperty("app.employee-management.enabled","true")
                .withProperty("spring.jpa.hibernate.ddl-auto","validate")
                .withProperty("spring.sql.init.mode","never");
        assertThat(IncidentAccessReadinessChecks.inspectConfiguration(env))
                .isEqualTo(IncidentAccessReadinessChecks.Result.READY_FOR_FURTHER_CHECKS);
        for(String key : List.of("app.incident-access.enabled","app.incident-assignment.enabled","app.employee-management.enabled")) {
            env.setProperty(key,"false");
            assertThat(IncidentAccessReadinessChecks.inspectConfiguration(env)).isEqualTo(IncidentAccessReadinessChecks.Result.UNSAFE_CONFIGURATION);
            env.setProperty(key,"true");
        }
        env.setProperty("spring.jpa.hibernate.ddl-auto","update");
        assertThat(IncidentAccessReadinessChecks.inspectConfiguration(env)).isEqualTo(IncidentAccessReadinessChecks.Result.UNSAFE_CONFIGURATION);
        env.setProperty("spring.jpa.hibernate.ddl-auto","validate");
        env.setProperty("spring.sql.init.mode","always");
        assertThat(IncidentAccessReadinessChecks.inspectConfiguration(env)).isEqualTo(IncidentAccessReadinessChecks.Result.UNSAFE_CONFIGURATION);
    }
}
