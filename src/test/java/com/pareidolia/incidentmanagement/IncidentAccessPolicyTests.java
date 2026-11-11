package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.entity.Incident;
import com.pareidolia.incidentmanagement.repository.AppUserRepository;
import com.pareidolia.incidentmanagement.security.IncidentAccessPolicy;
import com.pareidolia.incidentmanagement.security.IncidentAccessActivationGuard;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@DataJpaTest
class IncidentAccessPolicyTests {
    @Autowired EntityManager em; @Autowired JdbcTemplate db; @Autowired AppUserRepository users;
    AppUser user; Incident incident; IncidentAccessPolicy enabled;
    @BeforeEach void setup(){
        db.execute("create table if not exists incident_security_lock(id bigint primary key)");
        if(db.queryForObject("select count(*) from incident_security_lock",Long.class)==0)db.update("insert into incident_security_lock values(1)");
        db.execute("create table if not exists incident_security_classification(incident_id bigint primary key, classification varchar(20), version bigint)");
        db.execute("create table if not exists incident_security_grants(incident_id bigint,user_id bigint,permission varchar(20),active tinyint,primary key(incident_id,user_id,permission))");
        db.execute("create table if not exists assignment_admin_capabilities(user_id bigint, capability varchar(40), active tinyint)");
        db.execute("create table if not exists incident_global_view_audit(actor_user_id bigint, incident_id bigint, operation varchar(40))");
        db.update("delete from incident_security_grants");db.update("delete from incident_security_classification");
        user=new AppUser();user.setEmail("reporter@example.test");user.setDisplayName("Reporter");user=users.saveAndFlush(user);
        incident=new Incident();incident.setId(123L);incident.setReportedBy(user.getEmail());
        var oidc=mock(OidcUser.class);when(oidc.getEmail()).thenReturn(user.getEmail());when(oidc.getEmailVerified()).thenReturn(true);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(oidc,"",java.util.List.of()));
        enabled=new IncidentAccessPolicy(em,true);
    }
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    @Test void absentClassificationDeniesEvenReporterAndExplicitCaseGrant(){
        db.update("insert into incident_security_grants values(123,?,'VIEW',1)",user.getId());
        assertThat(enabled.can(user,incident,IncidentAccessPolicy.Permission.VIEW)).isFalse();
        assertThat(enabled.filter(user,java.util.List.of(incident),IncidentAccessPolicy.Permission.VIEW)).isEmpty();
    }
    @Test void auditedGlobalViewSkipsCasesWithMissingClassification(){
        db.update("insert into assignment_admin_capabilities values(?,'GLOBAL_INCIDENT_VIEW',1)",user.getId());
        var classified = new Incident();
        classified.setId(124L);
        classified.setIssueType(com.pareidolia.incidentmanagement.enums.IssueType.IT_ISSUE);
        db.update("insert into incident_security_classification values(124,'STANDARD',1)");
        enabled.can(user,incident,IncidentAccessPolicy.Permission.VIEW);
        assertThat(enabled.useGlobalView(user,java.util.List.of(incident),IncidentAccessPolicy.ReadOperation.DETAIL)).isFalse();
        assertThat(enabled.filterRead(user,java.util.List.of(incident,classified),
                IncidentAccessPolicy.Permission.VIEW,IncidentAccessPolicy.ReadOperation.LIST)).containsExactly(classified);
        assertThat(db.queryForList("select incident_id from incident_global_view_audit where actor_user_id=?",Long.class,user.getId()))
                .containsExactly(124L);
    }
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
        "STANDARD, 0", "STANDARD, -1", "STANDARD, NULL", "RESTRICTED, 0", "RESTRICTED, -1",
        "UNCLASSIFIED, -1", "UNCLASSIFIED, 1", "UNKNOWN, 1"
    })
    void invalidStateDeniesReporterGrantAndGlobalView(String classification, String version) {
        incident.setIssueType(com.pareidolia.incidentmanagement.enums.IssueType.IT_ISSUE);
        db.update("insert into incident_security_classification values(123,?,?)",
                classification, "NULL".equals(version) ? null : Long.valueOf(version));
        db.update("insert into incident_security_grants values(123,?,'VIEW',1)",user.getId());
        db.update("insert into assignment_admin_capabilities values(?,'GLOBAL_INCIDENT_VIEW',1)",user.getId());

        var candidates = java.util.List.of(incident);
        var permission = IncidentAccessPolicy.Permission.VIEW;
        assertThat(enabled.can(user, incident, permission)).isFalse();
        assertThat(enabled.filter(user, candidates, permission)).isEmpty();
        assertThat(enabled.useGlobalView(user, candidates, IncidentAccessPolicy.ReadOperation.DETAIL)).isFalse();
        assertThat(enabled.filterRead(user, candidates, permission, IncidentAccessPolicy.ReadOperation.LIST)).isEmpty();
        assertThat(db.queryForList("select incident_id from incident_global_view_audit where actor_user_id=?",
                Long.class, user.getId())).isEmpty();
    }

    @Test void globalViewAndCaseGrantDoNotGiveNonHrActorAccessToConfidentialCase() {
        incident.setIssueType(com.pareidolia.incidentmanagement.enums.IssueType.HR_ISSUE);
        incident.setReportedBy("other@example.test");
        db.update("insert into incident_security_classification values(123,'STANDARD',1)");
        db.update("insert into incident_security_grants values(123,?,'VIEW',1)",user.getId());
        db.update("insert into assignment_admin_capabilities values(?,'GLOBAL_INCIDENT_VIEW',1)",user.getId());
        var candidates = java.util.List.of(incident);
        assertThat(enabled.can(user, incident, IncidentAccessPolicy.Permission.VIEW)).isFalse();
        assertThat(enabled.useGlobalView(user, candidates, IncidentAccessPolicy.ReadOperation.DETAIL)).isFalse();
        assertThat(enabled.filterRead(user, candidates, IncidentAccessPolicy.Permission.VIEW,
                IncidentAccessPolicy.ReadOperation.LIST)).isEmpty();
    }

    @Test void unclassifiedReporterCanViewButNotModifyAndMissingGrantsDeny(){
        db.update("insert into incident_security_classification values(123,'UNCLASSIFIED',0)");
        assertThat(enabled.can(user,incident,IncidentAccessPolicy.Permission.VIEW)).isTrue();
        assertThat(enabled.can(user,incident,IncidentAccessPolicy.Permission.MODIFY)).isFalse();
        incident.setReportedBy("someone@example.test");assertThat(enabled.can(user,incident,IncidentAccessPolicy.Permission.VIEW)).isFalse();
    }
    @Test void restrictedRequiresIndependentViewAndActionGrants(){
        db.update("insert into incident_security_classification values(123,'RESTRICTED',1)");
        assertThat(enabled.can(user,incident,IncidentAccessPolicy.Permission.VIEW)).isFalse();
        db.update("insert into incident_security_grants values(123,?,'VIEW',1)",user.getId());
        assertThat(enabled.can(user,incident,IncidentAccessPolicy.Permission.VIEW)).isTrue();
        assertThat(enabled.can(user,incident,IncidentAccessPolicy.Permission.REPORT)).isFalse();
        db.update("insert into incident_security_grants values(123,?,'REPORT',1)",user.getId());
        assertThat(enabled.can(user,incident,IncidentAccessPolicy.Permission.REPORT)).isTrue();
        assertThat(enabled.can(user,incident,IncidentAccessPolicy.Permission.ASSIGN)).isFalse();
        db.update("update incident_security_grants set active=0 where incident_id=123 and permission='VIEW'");
        assertThat(enabled.can(user,incident,IncidentAccessPolicy.Permission.REPORT)).isFalse();
    }
    @Test void unverifiedIdentityAndDisabledAccountAreDenied(){
        var oidc=mock(OidcUser.class);when(oidc.getEmail()).thenReturn(user.getEmail());when(oidc.getEmailVerified()).thenReturn(false);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(oidc,"",java.util.List.of()));
        assertThat(enabled.can(user,incident,IncidentAccessPolicy.Permission.VIEW)).isFalse();
    }
    @Test void defaultOffPreservesLegacyAndActivationIsBlocked(){
        assertThat(new IncidentAccessPolicy(em,false).can(null,null,IncidentAccessPolicy.Permission.VIEW)).isTrue();
        assertThatCode(() -> new IncidentAccessActivationGuard(false)).doesNotThrowAnyException();
        assertThatThrownBy(() -> new IncidentAccessActivationGuard(true)).isInstanceOf(IllegalStateException.class);
    }
}
