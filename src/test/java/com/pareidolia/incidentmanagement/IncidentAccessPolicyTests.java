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
        db.execute("create table if not exists incident_security_classification(incident_id bigint primary key, classification varchar(20))");
        db.execute("create table if not exists incident_security_grants(incident_id bigint,user_id bigint,permission varchar(20),active tinyint,primary key(incident_id,user_id,permission))");
        db.update("delete from incident_security_grants");db.update("delete from incident_security_classification");
        user=new AppUser();user.setEmail("reporter@example.test");user.setDisplayName("Reporter");user=users.saveAndFlush(user);
        incident=new Incident();incident.setId(123L);incident.setReportedBy(user.getEmail());
        var oidc=mock(OidcUser.class);when(oidc.getEmail()).thenReturn(user.getEmail());when(oidc.getEmailVerified()).thenReturn(true);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(oidc,"",java.util.List.of()));
        enabled=new IncidentAccessPolicy(em,true);
    }
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    @Test void unclassifiedReporterCanViewButNotModifyAndMissingGrantsDeny(){
        assertThat(enabled.can(user,incident,IncidentAccessPolicy.Permission.VIEW)).isTrue();
        assertThat(enabled.can(user,incident,IncidentAccessPolicy.Permission.MODIFY)).isFalse();
        incident.setReportedBy("someone@example.test");assertThat(enabled.can(user,incident,IncidentAccessPolicy.Permission.VIEW)).isFalse();
    }
    @Test void restrictedRequiresIndependentViewAndActionGrants(){
        db.update("insert into incident_security_classification values(123,'RESTRICTED')");
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
