package com.pareidolia.incidentmanagement.notification;

import com.pareidolia.incidentmanagement.security.*;
import com.pareidolia.incidentmanagement.service.*;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.Executor;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Uses real authorization services and MySQL; the only mock is the mail transport. */
@EnabledIfEnvironmentVariable(named="INCIDENT_AUTHORIZATION_MYSQL_PROOF", matches="true")
@DataJpaTest(properties={"spring.jpa.hibernate.ddl-auto=none", "spring.sql.init.mode=never",
 "app.incident-access.enabled=true", "app.incident-security-admin.enabled=true",
 "app.employee-management.enabled=true", "app.employee-management.allowed-emails=auth-proof-admin@example.test",
 "app.department-membership-admin.enabled=true", "app.department-membership-admin.allowed-emails=auth-proof-admin@example.test",
 "app.auth.allowed-domain=example.test", "app.auth.bootstrap-admin-emails=", "app.auth.bootstrap-it-handler-emails=",
 "app.notifications.email.enabled=true", "app.notifications.email.verified-department-routing.enabled=true",
 "app.notifications.email.managed-recipients.enabled=true", "app.notifications.email.detailed-department.enabled=true",
 "app.notifications.email.portal-origin=https://portal.example.test"})
@AutoConfigureTestDatabase(replace=AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("dev")
@Import({IncidentSecurityGate.class,IncidentReadSnapshot.class,IncidentAccessPolicy.class,EmployeeManagementAccess.class,
 AppUserService.class,IncidentSecurityAdministrationService.class,DepartmentMembershipAdminService.class,EmployeeDirectoryService.class,
 VerifiedIncidentMailRouting.class,DepartmentHeadMailReceipt.class,DepartmentDetailMailReceipt.class,
 NotificationAuthorizationMysqlProofTests.Config.class})
@Transactional(propagation=Propagation.NOT_SUPPORTED)
class NotificationAuthorizationMysqlProofTests {
 @DynamicPropertySource static void datasource(DynamicPropertyRegistry r) {
  r.add("spring.datasource.url",()->"jdbc:mysql://127.0.0.1:59455/incident_notification_proof?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC");
  r.add("spring.datasource.username",()->"notification_command_test");
  r.add("spring.datasource.password",()->System.getenv("INCIDENT_AUTHORIZATION_MYSQL_PASSWORD"));
 }
 @TestConfiguration static class Config {
  @Bean BlockingQueue<Runnable> pending(){return new LinkedBlockingQueue<>();}
  @Bean JavaMailSender sender(){var sender=mock(JavaMailSender.class);when(sender.createMimeMessage()).thenAnswer(call->new MimeMessage(Session.getInstance(new Properties())));return sender;}
  @Bean IncidentEmailNotifications notifications(ConfigurableEnvironment env,ObjectProvider<JavaMailSender> sender,
    VerifiedIncidentMailRouting routing,BlockingQueue<Runnable> pending){
   return new IncidentEmailNotifications(new IncidentEmailNotifications.Settings(true,"sender@example.test","","","auth-proof-recipient@example.test"),
    env,sender,(Executor) pending::add,new IncidentEmailDetailPolicy(env,Stream::empty),routing);
  }
 }
 @Autowired JdbcTemplate jdbc; @Autowired PlatformTransactionManager manager; @Autowired ApplicationEventPublisher events;
 @Autowired IncidentSecurityAdministrationService security; @Autowired DepartmentMembershipAdminService memberships;
 @Autowired EmployeeDirectoryService employees; @Autowired BlockingQueue<Runnable> pending; @Autowired JavaMailSender sender;
 @Test void realGrantRollbackRevocationMembershipAndAccountChangesRecheckDelivery() {
  assertThat(jdbc.queryForObject("select @@server_uuid",String.class)).isEqualTo("a6563759-ddb5-11f1-9b7c-6e0023da6ea2");
  assertThat(jdbc.queryForObject("select database()",String.class)).isEqualTo("incident_notification_proof");
  assertThat(jdbc.queryForObject("select current_user()",String.class)).isEqualTo("notification_command_test@172.22.0.1");
  assertThat(jdbc.queryForObject("select count(*) from incidents where id in (920001,920002,920003)",Integer.class)).isEqualTo(3);
  assertThat(jdbc.queryForObject("select count(*) from incident_security_grants where incident_id in (920001,920002,920003) and user_id=920002",Integer.class)).isZero();
  assertThat(jdbc.queryForObject("select count(*) from incident_department_detail_email_receipt where incident_id in (920001,920002,920003) and recipient_user_id=920002",Integer.class)).isZero();
  var now=Instant.now(); var token=new OidcIdToken("synthetic",now,now.plusSeconds(300),Map.of("sub","synthetic-admin","email","auth-proof-admin@example.test","email_verified",true));
  var oidc=new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_REPORTER")),token);
  SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(oidc,"",oidc.getAuthorities()));
  try {
   var tx=new TransactionTemplate(manager);
   tx.executeWithoutResult(status->{security.setGrant(920002L,920002L,"VIEW",true,0L,"Synthetic rollback");status.setRollbackOnly();});
   assertThat(jdbc.queryForObject("select count(*) from incident_security_grants where incident_id=920002 and user_id=920002",Integer.class)).isZero();
   assertThat(jdbc.queryForObject("select count(*) from incident_security_grant_audit where incident_id=920002 and target_user_id=920002",Integer.class)).isZero();
   assertThat(pending).isEmpty();
   security.setGrant(920001L,920002L,"VIEW",true,0L,"Synthetic grant");
   assertThat(pending).hasSize(1); pending.remove().run(); verify(sender,times(1)).send(any(MimeMessage.class));
   assertThat(jdbc.queryForObject("select status from incident_department_detail_email_receipt where incident_id=920001 and recipient_user_id=920002",String.class)).isEqualTo("SENT");
   assertThat(jdbc.queryForObject("select count(*) from incident_security_grant_audit where incident_id=920001 and target_user_id=920002",Integer.class)).isEqualTo(1);
   tx.executeWithoutResult(status->events.publishEvent(new DepartmentHeadViewGranted("INC-20261111-210001-ABCDEF01",920002)));
   pending.remove().run(); verify(sender,times(1)).send(any(MimeMessage.class));
   security.setGrant(920003L,920002L,"VIEW",true,0L,"Synthetic grant before revoke");
   security.setGrant(920003L,920002L,"VIEW",false,1L,"Synthetic revoke");
   pending.remove().run(); verify(sender,times(1)).send(any(MimeMessage.class));
   assertThat(jdbc.queryForObject("select count(*) from incident_department_detail_email_receipt where incident_id=920003 and recipient_user_id=920002",Integer.class)).isZero();
   security.setGrant(920003L,920002L,"VIEW",true,2L,"Synthetic grant before membership deactivation");
   memberships.change(1L,920002L,false,1L,"Synthetic membership deactivation");
   pending.remove().run(); verify(sender,times(1)).send(any(MimeMessage.class));
   assertThat(jdbc.queryForObject("select count(*) from employee_department_membership_audit where department_id=1 and user_id=920002",Integer.class)).isEqualTo(1);
   memberships.change(1L,920002L,true,2L,"Synthetic membership restoration");
   tx.executeWithoutResult(status->events.publishEvent(new DepartmentHeadViewGranted("INC-20261111-210003-ABCDEF03",920002)));
   employees.status(920002L,false,0L,"Synthetic account deactivation");
   pending.remove().run(); verify(sender,times(1)).send(any(MimeMessage.class));
   assertThat(jdbc.queryForObject("select count(*) from employee_management_audit where target_id=920002",Integer.class)).isEqualTo(1);
   assertThat(jdbc.queryForObject("select count(*) from incident_department_detail_email_receipt where incident_id=920003 and recipient_user_id=920002",Integer.class)).isZero();
  } finally {SecurityContextHolder.clearContext();}
 }
}
