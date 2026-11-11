package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.entity.Incident;
import com.pareidolia.incidentmanagement.security.IncidentSecurityGate;
import com.pareidolia.incidentmanagement.security.IncidentReadSnapshot;
import com.pareidolia.incidentmanagement.security.IncidentAccessPolicy;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import static org.assertj.core.api.Assertions.assertThat;

/** Read-only authorization proof using existing synthetic accounts on isolated MySQL. */
@EnabledIfEnvironmentVariable(named="INCIDENT_ACCESS_READONLY_MYSQL_PROOF",matches="true")
@DataJpaTest(properties={"spring.jpa.hibernate.ddl-auto=none","spring.sql.init.mode=never",
        "app.incident-access.enabled=true","app.incident-access.hr-account-ids=3"})
@AutoConfigureTestDatabase(replace=AutoConfigureTestDatabase.Replace.NONE)
@Import({IncidentSecurityGate.class,IncidentReadSnapshot.class,IncidentAccessPolicy.class})
@Transactional(propagation=Propagation.NOT_SUPPORTED)
class IncidentAccessReadonlyMysqlProofTests {
    @DynamicPropertySource static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url",()->"jdbc:mysql://127.0.0.1:59455/incident_notification_proof?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC");
        registry.add("spring.datasource.username",()->"notification_test");
        registry.add("spring.datasource.password",()->System.getenv("INCIDENT_NOTIFICATION_MYSQL_PASSWORD"));
    }
    @Autowired JdbcTemplate jdbc;
    @Autowired EntityManager em;
    @Autowired IncidentReadSnapshot snapshot;
    @Autowired IncidentAccessPolicy policy;

    @Test void realMysqlCasePermissionsDenyCrossUserHrAndDoNotInferHandlerAuthority() {
        assertThat(jdbc.queryForObject("select @@server_uuid",String.class)).isEqualTo("a6563759-ddb5-11f1-9b7c-6e0023da6ea2");
        assertThat(jdbc.queryForObject("select database()",String.class)).isEqualTo("incident_notification_proof");
        assertThat(jdbc.queryForObject("select current_user()",String.class)).isEqualTo("notification_test@172.22.0.1");
        assertThat(jdbc.queryForObject("select count(*) from incidents where id=2 and issue_type='HR_ISSUE'",Integer.class)).isEqualTo(1);
        try {
            authenticate("reporter@example.test");
            assertThat(allowed(1,1,IncidentAccessPolicy.Permission.VIEW)).isTrue();
            assertThat(allowed(1,2,IncidentAccessPolicy.Permission.VIEW)).isFalse();
            authenticate("it@example.test");
            assertThat(allowed(2,1,IncidentAccessPolicy.Permission.VIEW)).isTrue();
            assertThat(allowed(2,1,IncidentAccessPolicy.Permission.HANDLE)).isFalse();
            assertThat(allowed(2,2,IncidentAccessPolicy.Permission.VIEW)).isFalse();
            authenticate("hr@example.test");
            assertThat(allowed(3,2,IncidentAccessPolicy.Permission.VIEW)).isTrue();
            assertThat(allowed(3,2,IncidentAccessPolicy.Permission.HANDLE)).isFalse();
        } finally { SecurityContextHolder.clearContext(); }
    }
    private boolean allowed(long user,long incident,IncidentAccessPolicy.Permission permission) {
        return snapshot.read(()->policy.can(em.find(AppUser.class,user),em.find(Incident.class,incident),permission));
    }
    private static void authenticate(String email) {
        var now=Instant.now();
        var idToken=new OidcIdToken("synthetic",now,now.plusSeconds(300),Map.of("sub","synthetic","email",email,"email_verified",true));
        var user=new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_REPORTER")),idToken);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user,"",user.getAuthorities()));
    }
}
