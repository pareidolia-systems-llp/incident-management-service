package com.pareidolia.incidentmanagement.notification;

import com.pareidolia.incidentmanagement.security.IncidentAccessPolicy;
import com.pareidolia.incidentmanagement.security.IncidentReadSnapshot;
import com.pareidolia.incidentmanagement.security.IncidentSecurityGate;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
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

/** Real MySQL listener and routing for a synthetic restricted HR incident. */
@EnabledIfEnvironmentVariable(named="INCIDENT_NOTIFICATION_MYSQL_PROOF", matches="true")
@DataJpaTest(properties={"spring.jpa.hibernate.ddl-auto=none", "spring.sql.init.mode=never",
 "app.incident-access.enabled=true", "app.incident-access.hr-account-ids=3",
 "app.notifications.email.enabled=true", "app.notifications.email.verified-department-routing.enabled=true",
 "app.notifications.email.verified-department-routing.hr-department-id=2",
 "app.notifications.email.verified-department-routing.restricted-recipients=2=hr@example.test",
 "app.notifications.email.managed-recipients.enabled=true", "app.notifications.email.global-hr-generic.enabled=true",
 "app.notifications.email.detailed-department.enabled=true", "app.notifications.email.portal-origin=https://portal.example.test"})
@AutoConfigureTestDatabase(replace=AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("dev")
@Import({IncidentSecurityGate.class, IncidentReadSnapshot.class, IncidentAccessPolicy.class,
 VerifiedIncidentMailRouting.class, DepartmentHeadMailReceipt.class, DepartmentDetailMailReceipt.class,
 HrNotificationMysqlProofTests.Config.class})
@Transactional(propagation=Propagation.NOT_SUPPORTED)
class HrNotificationMysqlProofTests {
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
   return new IncidentEmailNotifications(new IncidentEmailNotifications.Settings(true,"sender@example.test","","","hr@example.test"),
      env,sender,(Executor) Runnable::run,new IncidentEmailDetailPolicy(env,Stream::empty),routing);
  }
 }
 @Autowired JdbcTemplate jdbc;
 @Autowired PlatformTransactionManager manager;
 @Autowired ApplicationEventPublisher events;
 @Autowired JavaMailSender sender;
 @Test void genericAndAuthorizedDetailedNoticesStayIndependentAndProtectHrContent() throws Exception {
  assertThat(jdbc.queryForObject("select @@server_uuid",String.class)).isEqualTo("a6563759-ddb5-11f1-9b7c-6e0023da6ea2");
  assertThat(jdbc.queryForObject("select database()",String.class)).isEqualTo("incident_notification_proof");
  assertThat(jdbc.queryForObject("select current_user()",String.class)).isEqualTo("notification_test@172.22.0.1");
  assertThat(jdbc.queryForObject("select count(*) from incidents where id=910001 and incident_number='INC-20261111-195959-1234ABCD'",Integer.class)).isEqualTo(1);
  assertThat(jdbc.queryForObject("select count(*) from incident_department_head_email_receipt where incident_id=910001 and recipient_user_id=3",Integer.class)).isZero();
  assertThat(jdbc.queryForObject("select count(*) from incident_department_detail_email_receipt where incident_id=910001 and recipient_user_id=3",Integer.class)).isZero();
  String number="INC-20261111-195959-1234ABCD"; var tx=new TransactionTemplate(manager);
  tx.executeWithoutResult(status -> events.publishEvent(new IncidentCreated(number)));
  var captured=org.mockito.ArgumentCaptor.forClass(MimeMessage.class);
  verify(sender,times(1)).send(captured.capture());
  var generic=new ByteArrayOutputStream(); captured.getValue().writeTo(generic);
  assertThat(generic.toString(StandardCharsets.UTF_8)).doesNotContain(number,"Synthetic HR authorization proof","Synthetic confidential content");
  tx.executeWithoutResult(status -> events.publishEvent(new IncidentMailReady(number)));
  captured=org.mockito.ArgumentCaptor.forClass(MimeMessage.class);
  verify(sender,times(2)).send(captured.capture());
  var detail=new ByteArrayOutputStream(); captured.getAllValues().get(1).writeTo(detail);
  assertThat(detail.toString(StandardCharsets.UTF_8)).contains("Synthetic HR authorization proof","https://portal.example.test/incidents/910001");
  assertThat(jdbc.queryForObject("select status from incident_department_head_email_receipt where incident_id=910001 and recipient_user_id=3",String.class)).isEqualTo("SENT");
  assertThat(jdbc.queryForObject("select status from incident_department_detail_email_receipt where incident_id=910001 and recipient_user_id=3",String.class)).isEqualTo("SENT");
  tx.executeWithoutResult(status -> { events.publishEvent(new IncidentCreated(number)); events.publishEvent(new IncidentMailReady(number)); });
  verify(sender,times(2)).send(any(MimeMessage.class));
 }
}
