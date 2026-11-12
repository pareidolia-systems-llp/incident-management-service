package com.pareidolia.incidentmanagement.security;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class IncidentRecipientReadinessChecksTests {
    JdbcTemplate jdbc; MockEnvironment env; List<String> active,eligible;
    @BeforeEach void setup() {
        env=new MockEnvironment().withProperty("app.auth.allowed-domain","example.test")
            .withProperty("app.notifications.email.readiness.approved-recipients","IT=it@example.test;HR=hr@example.test;Operations (Annotation)=a@example.test;Operations (Perioperative Flow Analysis)=b@example.test;R&D=rd@example.test");
        env.setProperty("app.notifications.email.verified-department-routing.hr-department-id","2");
        env.setProperty("app.notifications.email.verified-department-routing.restricted-recipients","2=hr@example.test");
        active=new ArrayList<>(List.of("IT|it@example.test","HR|hr@example.test","Operations (Annotation)|a@example.test","Operations (Perioperative Flow Analysis)|b@example.test","R&D|rd@example.test"));
        eligible=new ArrayList<>(active);jdbc=mock(JdbcTemplate.class);when(jdbc.getQueryTimeout()).thenReturn(5);
        when(jdbc.queryForList(IncidentRecipientReadinessChecks.DEPARTMENT_IDS_SQL,String.class)).thenReturn(List.of("1|IT","2|HR","3|Operations (Annotation)","4|Operations (Perioperative Flow Analysis)","5|R&D"));
        when(jdbc.queryForList(IncidentRecipientReadinessChecks.ACTIVE_SQL,String.class)).thenReturn(active);
        when(jdbc.queryForList(IncidentRecipientReadinessChecks.ELIGIBLE_SQL,String.class)).thenReturn(eligible);
    }
    @Test void fiveApprovedEligibleDepartmentsPassOnlyForFurtherChecks() {
        assertThat(IncidentRecipientReadinessChecks.inspectOnConnection(jdbc,env)).isEqualTo(IncidentRecipientReadinessChecks.Result.READY_FOR_FURTHER_CHECKS);
    }
    @Test void unapprovedActiveRecipientAndMissingEligibleRecipientFail() {
        active.add("IT|unapproved@example.test");
        assertThat(IncidentRecipientReadinessChecks.inspectOnConnection(jdbc,env)).isEqualTo(IncidentRecipientReadinessChecks.Result.INVALID_RECIPIENTS);
        active.remove("IT|unapproved@example.test");eligible.remove("HR|hr@example.test");
        assertThat(IncidentRecipientReadinessChecks.inspectOnConnection(jdbc,env)).isEqualTo(IncidentRecipientReadinessChecks.Result.INVALID_RECIPIENTS);
    }
    @Test void missingDepartmentAndWrongDomainFailClosed() {
        env.setProperty("app.notifications.email.readiness.approved-recipients","IT=it@example.test;HR=hr@example.test");
        assertThat(IncidentRecipientReadinessChecks.inspectOnConnection(jdbc,env)).isEqualTo(IncidentRecipientReadinessChecks.Result.INVALID_CONFIGURATION);
        env.setProperty("app.notifications.email.readiness.approved-recipients","IT=it@other.test;HR=hr@example.test;Operations (Annotation)=a@example.test;Operations (Perioperative Flow Analysis)=b@example.test;R&D=rd@example.test");
        assertThat(IncidentRecipientReadinessChecks.inspectOnConnection(jdbc,env)).isEqualTo(IncidentRecipientReadinessChecks.Result.INVALID_CONFIGURATION);
    }
    @Test void invalidRestrictedRecipientMatrixFailsClosed() {
        env.setProperty("app.notifications.email.verified-department-routing.restricted-recipients","2=unapproved@example.test");
        assertThat(IncidentRecipientReadinessChecks.inspectOnConnection(jdbc,env)).isEqualTo(IncidentRecipientReadinessChecks.Result.INVALID_CONFIGURATION);
        env.setProperty("app.notifications.email.verified-department-routing.restricted-recipients","");
        assertThat(IncidentRecipientReadinessChecks.inspectOnConnection(jdbc,env)).isEqualTo(IncidentRecipientReadinessChecks.Result.INVALID_CONFIGURATION);
    }
    @Test void startupEligibilityDoesNotRequirePriorLogin() {
        assertThat(IncidentRecipientReadinessChecks.ELIGIBLE_SQL).doesNotContain("last_login_at");
        assertThat(IncidentRecipientReadinessChecks.inspectOnConnection(jdbc,env)).isEqualTo(IncidentRecipientReadinessChecks.Result.READY_FOR_FURTHER_CHECKS);
    }
    @Test void unavailableMetadataFailsClosed() {
        when(jdbc.queryForList(IncidentRecipientReadinessChecks.ACTIVE_SQL,String.class)).thenThrow(new DataAccessResourceFailureException("synthetic"));
        assertThat(IncidentRecipientReadinessChecks.inspectOnConnection(jdbc,env)).isEqualTo(IncidentRecipientReadinessChecks.Result.UNAVAILABLE);
    }
    @Test void hrAliasUsesSameRoutingPolicy() {
        active.set(1,"Human Resources|hr@example.test");eligible.set(1,"Human Resources|hr@example.test");
        assertThat(IncidentRecipientReadinessChecks.inspectOnConnection(jdbc,env)).isEqualTo(IncidentRecipientReadinessChecks.Result.READY_FOR_FURTHER_CHECKS);
    }
}
