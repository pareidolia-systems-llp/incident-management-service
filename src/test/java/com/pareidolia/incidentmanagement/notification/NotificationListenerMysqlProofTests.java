package com.pareidolia.incidentmanagement.notification;

import com.pareidolia.incidentmanagement.security.IncidentAccessPolicy;
import com.pareidolia.incidentmanagement.security.IncidentReadSnapshot;
import com.pareidolia.incidentmanagement.security.IncidentSecurityGate;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import java.io.ByteArrayOutputStream;
import java.util.Map;
import java.util.Properties;
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
import org.springframework.core.env.MapPropertySource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Real listener, security routing, receipts and MySQL transactions; SMTP is a mock. */
@EnabledIfEnvironmentVariable(named="INCIDENT_NOTIFICATION_MYSQL_PROOF", matches="true")
@DataJpaTest(properties={"spring.jpa.hibernate.ddl-auto=none", "spring.sql.init.mode=never",
 "app.incident-access.enabled=true", "app.notifications.email.enabled=true",
 "app.notifications.email.verified-department-routing.enabled=true",
 "app.notifications.email.managed-recipients.enabled=true",
 "app.notifications.email.detailed-department.enabled=true",
 "app.notifications.email.portal-origin=https://portal.example.test"})
@AutoConfigureTestDatabase(replace=AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("dev")
@Import({IncidentSecurityGate.class, IncidentReadSnapshot.class, IncidentAccessPolicy.class,
 VerifiedIncidentMailRouting.class, DepartmentHeadMailReceipt.class, DepartmentDetailMailReceipt.class,
 NotificationListenerMysqlProofTests.Config.class})
@Transactional(propagation=Propagation.NOT_SUPPORTED)
class NotificationListenerMysqlProofTests {
 @DynamicPropertySource static void datasource(DynamicPropertyRegistry registry) {
  registry.add("spring.datasource.url", () -> "jdbc:mysql://127.0.0.1:59455/incident_notification_proof?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC");
  registry.add("spring.datasource.username", () -> "notification_test");
  registry.add("spring.datasource.password", () -> System.getenv("INCIDENT_NOTIFICATION_MYSQL_PASSWORD"));
 }
 @TestConfiguration static class Config {
  @Bean JavaMailSender mailSender() {
   var sender=mock(JavaMailSender.class);
   when(sender.createMimeMessage()).thenAnswer(call -> new MimeMessage(Session.getInstance(new Properties())));
   return sender;
  }
  @Bean IncidentEmailNotifications notifications(ConfigurableEnvironment env, ObjectProvider<JavaMailSender> sender,
      VerifiedIncidentMailRouting routing) {
   return new IncidentEmailNotifications(new IncidentEmailNotifications.Settings(true,"sender@example.test","","","it@example.test,perioperative@example.test"),
      env,sender,(Executor) Runnable::run,new IncidentEmailDetailPolicy(env,Stream::empty),routing);
  }
 }
 @Autowired JdbcTemplate jdbc;
 @Autowired PlatformTransactionManager manager;
 @Autowired ApplicationEventPublisher events;
 @Autowired JavaMailSender sender;
 @Autowired ConfigurableEnvironment env;
 @Test void commitRollbackAndDuplicateUseRealMysqlAndAuthorizedListener() throws Exception {
  assertThat(jdbc.queryForObject("select @@server_uuid",String.class)).isEqualTo("a6563759-ddb5-11f1-9b7c-6e0023da6ea2");
  assertThat(jdbc.queryForObject("select database()",String.class)).isEqualTo("incident_notification_proof");
  assertThat(jdbc.queryForObject("select current_user()",String.class)).isEqualTo("notification_test@172.22.0.1");
  assertThat(jdbc.queryForObject("select count(*) from incident_department_detail_email_receipt where incident_id=1 and recipient_user_id=2",Integer.class)).isZero();
  String number="INC-20261111-100001-ABCDEF01";
  assertThat(jdbc.queryForObject("select count(*) from incidents where id=1 and incident_number=?",Integer.class,number)).isEqualTo(1);
  var tx=new TransactionTemplate(manager);
  tx.executeWithoutResult(status -> {events.publishEvent(new IncidentMailReady(number)); status.setRollbackOnly();});
  verify(sender,never()).send(any(MimeMessage.class));
  assertThat(jdbc.queryForObject("select count(*) from incident_department_detail_email_receipt where incident_id=1 and recipient_user_id=2",Integer.class)).isZero();
  var disabled=new MapPropertySource("notification-proof-flags",new java.util.HashMap<>(Map.of("app.notifications.email.enabled","false")));
  env.getPropertySources().addFirst(disabled);
  tx.executeWithoutResult(status -> events.publishEvent(new IncidentMailReady(number)));
  verify(sender,never()).send(any(MimeMessage.class));
  assertThat(jdbc.queryForObject("select count(*) from incident_department_detail_email_receipt where incident_id=1 and recipient_user_id=2",Integer.class)).isZero();
  env.getPropertySources().remove(disabled.getName());
  tx.executeWithoutResult(status -> events.publishEvent(new IncidentMailReady(number)));
  var captured=org.mockito.ArgumentCaptor.forClass(MimeMessage.class);
  verify(sender,times(1)).send(captured.capture());
  var output=new ByteArrayOutputStream(); captured.getValue().writeTo(output);
  assertThat(output.toString(java.nio.charset.StandardCharsets.UTF_8)).contains("https://portal.example.test/incidents/1");
  assertThat(jdbc.queryForObject("select status from incident_department_detail_email_receipt where incident_id=1 and recipient_user_id=2",String.class)).isEqualTo("SENT");
  tx.executeWithoutResult(status -> events.publishEvent(new IncidentMailReady(number)));
  verify(sender,times(1)).send(any(MimeMessage.class));
 }
 @Test void viewGrantEventRequiresEnabledDetailAndCurrentEligibleRecipient() throws Exception {
  assertThat(jdbc.queryForObject("select @@server_uuid",String.class)).isEqualTo("a6563759-ddb5-11f1-9b7c-6e0023da6ea2");
  assertThat(jdbc.queryForObject("select database()",String.class)).isEqualTo("incident_notification_proof");
  assertThat(jdbc.queryForObject("select current_user()",String.class)).isEqualTo("notification_test@172.22.0.1");
  assertThat(jdbc.queryForObject("select count(*) from incident_department_detail_email_receipt where incident_id=4 and recipient_user_id=5",Integer.class)).isZero();
  String number="INC-20261111-100004-ABCDEF04";
  var tx=new TransactionTemplate(manager);
  tx.executeWithoutResult(status -> { events.publishEvent(new DepartmentHeadViewGranted(number,5)); status.setRollbackOnly(); });
  verify(sender,never()).send(any(MimeMessage.class));
  var disabled=new MapPropertySource("notification-proof-detail-off",new java.util.HashMap<>(Map.of("app.notifications.email.detailed-department.enabled","false")));
  env.getPropertySources().addFirst(disabled);
  tx.executeWithoutResult(status -> events.publishEvent(new DepartmentHeadViewGranted(number,5)));
  verify(sender,never()).send(any(MimeMessage.class));
  env.getPropertySources().remove(disabled.getName());
  tx.executeWithoutResult(status -> events.publishEvent(new DepartmentHeadViewGranted(number,6)));
  verify(sender,never()).send(any(MimeMessage.class));
  tx.executeWithoutResult(status -> events.publishEvent(new DepartmentHeadViewGranted(number,5)));
  var captured=org.mockito.ArgumentCaptor.forClass(MimeMessage.class);
  verify(sender,times(1)).send(captured.capture());
  var output=new ByteArrayOutputStream(); captured.getValue().writeTo(output);
  assertThat(output.toString(java.nio.charset.StandardCharsets.UTF_8)).contains("https://portal.example.test/incidents/4");
  assertThat(jdbc.queryForObject("select status from incident_department_detail_email_receipt where incident_id=4 and recipient_user_id=5",String.class)).isEqualTo("SENT");
 }
}