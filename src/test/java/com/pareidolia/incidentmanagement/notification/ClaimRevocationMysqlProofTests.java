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
 VerifiedIncidentMailRouting.class,DepartmentHeadMailReceipt.class,
 ClaimRevocationMysqlProofTests.Config.class})
@Transactional(propagation=Propagation.NOT_SUPPORTED)
class ClaimRevocationMysqlProofTests {
 @DynamicPropertySource static void datasource(DynamicPropertyRegistry r) {
  r.add("spring.datasource.url",()->"jdbc:mysql://127.0.0.1:59455/incident_notification_proof?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC");
  r.add("spring.datasource.username",()->"notification_command_test");
  r.add("spring.datasource.password",()->System.getenv("INCIDENT_AUTHORIZATION_MYSQL_PASSWORD"));
 }
 @TestConfiguration static class Config {
  @Bean BlockingQueue<Runnable> pending(){return new LinkedBlockingQueue<>();}
  @Bean ClaimSync claimSync(){return new ClaimSync();}
  @Bean DepartmentDetailMailReceipt detailReceipt(JdbcTemplate jdbc,ClaimSync sync){return new CoordinatedReceipt(jdbc,sync);}
  @Bean JavaMailSender sender(){var sender=mock(JavaMailSender.class);when(sender.createMimeMessage()).thenAnswer(call->new MimeMessage(Session.getInstance(new Properties())));return sender;}
  @Bean IncidentEmailNotifications notifications(ConfigurableEnvironment env,ObjectProvider<JavaMailSender> sender,
    VerifiedIncidentMailRouting routing,BlockingQueue<Runnable> pending){
   return new IncidentEmailNotifications(new IncidentEmailNotifications.Settings(true,"sender@example.test","","","auth-proof-claim@example.test"),
    env,sender,(Executor) pending::add,new IncidentEmailDetailPolicy(env,Stream::empty),routing);
  }
 }
 @Autowired JdbcTemplate jdbc; @Autowired PlatformTransactionManager manager; @Autowired ApplicationEventPublisher events;
 @Autowired IncidentSecurityAdministrationService security; @Autowired DepartmentMembershipAdminService memberships;
 @Autowired EmployeeDirectoryService employees; @Autowired BlockingQueue<Runnable> pending; @Autowired JavaMailSender sender;
 static class ClaimSync {
  final java.util.concurrent.CountDownLatch claimed=new java.util.concurrent.CountDownLatch(1);
  final java.util.concurrent.CountDownLatch release=new java.util.concurrent.CountDownLatch(1);
 }
 static class CoordinatedReceipt extends DepartmentDetailMailReceipt {
  private final ClaimSync sync;
  CoordinatedReceipt(JdbcTemplate jdbc,ClaimSync sync){super(jdbc);this.sync=sync;}
  @Override @org.springframework.transaction.annotation.Transactional(propagation=Propagation.REQUIRES_NEW)
  public void claim(long incident,long recipient) {
   super.claim(incident,recipient);
   org.springframework.transaction.support.TransactionSynchronizationManager.registerSynchronization(new org.springframework.transaction.support.TransactionSynchronization(){
    @Override public void afterCommit(){
     sync.claimed.countDown();
     try {if(!sync.release.await(15,java.util.concurrent.TimeUnit.SECONDS))throw new IllegalStateException("Synthetic claim coordination timed out");}
     catch(InterruptedException ex){Thread.currentThread().interrupt();throw new IllegalStateException(ex);}
    }
   });
  }
 }
 @Autowired ClaimSync sync;
 @Test void revokedAfterClaimIsRecheckedAndNotDelivered() throws Exception {
  assertThat(jdbc.queryForObject("select @@server_uuid",String.class)).isEqualTo("a6563759-ddb5-11f1-9b7c-6e0023da6ea2");
  assertThat(jdbc.queryForObject("select database()",String.class)).isEqualTo("incident_notification_proof");
  assertThat(jdbc.queryForObject("select current_user()",String.class)).isEqualTo("notification_command_test@172.22.0.1");
  assertThat(jdbc.queryForObject("select count(*) from incident_security_grants where incident_id=920004 and user_id=920003",Integer.class)).isZero();
  assertThat(jdbc.queryForObject("select count(*) from incident_department_detail_email_receipt where incident_id=920004 and recipient_user_id=920003",Integer.class)).isZero();
  var now=Instant.now(); var token=new OidcIdToken("synthetic",now,now.plusSeconds(300),Map.of("sub","synthetic-admin","email","auth-proof-admin@example.test","email_verified",true));
  var oidc=new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_REPORTER")),token);
  SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(oidc,"",oidc.getAuthorities()));
  var pool=java.util.concurrent.Executors.newSingleThreadExecutor();
  try {
   security.setGrant(920004L,920003L,"VIEW",true,0L,"Synthetic claim race grant");
   var dispatch=pool.submit(()->pending.remove().run());
   assertThat(sync.claimed.await(15,java.util.concurrent.TimeUnit.SECONDS)).isTrue();
   assertThat(jdbc.queryForObject("select status from incident_department_detail_email_receipt where incident_id=920004 and recipient_user_id=920003",String.class)).isEqualTo("CLAIMED");
   security.setGrant(920004L,920003L,"VIEW",false,1L,"Synthetic post-claim revocation");
   sync.release.countDown(); dispatch.get(15,java.util.concurrent.TimeUnit.SECONDS);
   verify(sender,never()).send(any(MimeMessage.class));
   assertThat(jdbc.queryForObject("select status from incident_department_detail_email_receipt where incident_id=920004 and recipient_user_id=920003",String.class)).isEqualTo("CLAIMED");
   assertThat(jdbc.queryForObject("select count(*) from incident_security_grant_audit where incident_id=920004 and target_user_id=920003",Integer.class)).isEqualTo(2);
  } finally {sync.release.countDown();pool.shutdownNow();SecurityContextHolder.clearContext();}
 }
}