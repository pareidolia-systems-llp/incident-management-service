package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.dto.CreateIncidentRequestDto;
import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.enums.*;
import com.pareidolia.incidentmanagement.mapper.IncidentMapper;
import com.pareidolia.incidentmanagement.notification.IncidentEmailConfiguration;
import com.pareidolia.incidentmanagement.notification.IncidentEmailTestSupport.TrustedItConfiguration;
import com.pareidolia.incidentmanagement.repository.*;
import com.pareidolia.incidentmanagement.service.*;
import com.pareidolia.incidentmanagement.service.impl.IncidentServiceImpl;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.test.context.*;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.*;
import org.springframework.transaction.support.TransactionTemplate;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@DataJpaTest(properties={"spring.datasource.url=jdbc:h2:mem:smtp_capture_test;DB_CLOSE_DELAY=-1","spring.datasource.username=sa","spring.datasource.password=",
 "spring.jpa.hibernate.ddl-auto=create-drop","spring.jpa.show-sql=false","app.department-routing.enabled=false","app.notifications.in-app.enabled=false",
 "app.notifications.email.v2.enabled=true","app.notifications.email.v2.details-enabled=true","app.notifications.email.portal-origin=https://portal.example.test","app.default-it-owner=owner@example.test","app.notifications.email.enabled=true","app.notifications.email.from=sender@example.test",
 "app.notifications.email.it-recipients=oversight@example.test,blocked@example.test","app.notifications.email.hr-recipients=oversight@example.test",
 "app.notifications.email.dev-allowlist=oversight@example.test,annotations@example.test,annotations02@example.test",
 "app.notifications.email.v2.department-recipients=Operations (Annotation)=annotations@example.test,annotations02@example.test",
 "app.notifications.email.smtp.host=127.0.0.1",
 "app.notifications.email.smtp.username=","app.notifications.email.smtp.password=","app.notifications.email.smtp.starttls=false"})
@org.springframework.test.context.event.RecordApplicationEvents
@ActiveProfiles("dev")
@Import({IncidentServiceImpl.class,IncidentMapper.class,IncidentEmailConfiguration.class,TrustedItConfiguration.class})
@Transactional(propagation=Propagation.NOT_SUPPORTED)
class IncidentEmailV2SmtpTests {
    static final Capture CAPTURE=new Capture();
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) { registry.add("app.notifications.email.smtp.port",CAPTURE::port); }
    @Autowired IncidentService incidents;
    @Autowired org.springframework.test.context.event.ApplicationEvents applicationEvents;
    @Autowired IncidentRepository repository;
    @Autowired IncidentHistoryRepository history;
    @Autowired jakarta.persistence.EntityManager em;
    @Autowired PlatformTransactionManager transactions;
    @Autowired ThreadPoolTaskExecutor incidentEmailExecutor;
    @Autowired org.springframework.mail.javamail.JavaMailSender mailSender;
    @MockitoBean AppUserService users;

    @BeforeEach void setup() { var sender=(org.springframework.mail.javamail.JavaMailSenderImpl)mailSender;
        assertThat(sender.getHost()).isEqualTo("127.0.0.1"); assertThat(sender.getPort()).isEqualTo(CAPTURE.port());
        assertThat(sender.getUsername()).isNullOrEmpty(); assertThat(sender.getPassword()).isNullOrEmpty();
        CAPTURE.messages.clear(); var u=new AppUser();u.setEmail("reporter@example.test");u.setDisplayName("Synthetic Reporter");u.setRole(AppUserRole.REPORTER);when(users.getAuthenticatedUser()).thenReturn(u); }
    @AfterEach void cleanup() throws Exception { drain();new TransactionTemplate(transactions).executeWithoutResult(s->{history.deleteAll();repository.findAll().forEach(em::remove);}); }
    @AfterAll static void stop() throws Exception { CAPTURE.close(); }
    void drain() throws Exception { incidentEmailExecutor.getThreadPoolExecutor().submit(()->{}).get(8,TimeUnit.SECONDS); }
    CreateIncidentRequestDto request() { var r=new CreateIncidentRequestDto();r.setTitle("private HR title");r.setDescription("confidential complaint");r.setReporterDepartment("private department");r.setAffectedSystem("private system");r.setIssueType(IssueType.IT_ISSUE);r.setSeverity(Severity.LOW);r.setPriority(Priority.LOW);return r; }
    @Test void committedCreationSendsOneGenericMessageToAllowlistedRecipient() throws Exception {
        assertThat(mailSender).isInstanceOf(org.springframework.mail.javamail.JavaMailSenderImpl.class);
        var result=new TransactionTemplate(transactions).execute(s->{var incident=incidents.createIncident(request());assertThat(CAPTURE.messages).isEmpty();return incident;});
        drain();assertThat(CAPTURE.messages).hasSize(1);String msg=CAPTURE.messages.get(0);
        assertThat(msg).contains("Subject: New incident created",result.getIncidentNumber(),"Sign in to the incident management portal","text/plain","text/html","https://portal.example.test/","Open Incident Management Portal");
        assertThat(msg).doesNotContain("private HR title","confidential complaint","reporter@example.test","private department","private system","SYNTHETIC-EMP","blocked@example.test","Content-Disposition: attachment");
    }
    @Test void creationPublishesSavedMetadataAndAuthenticatedReporter() throws Exception {
        var created=incidents.createIncident(request());drain();
        var events=applicationEvents.stream(com.pareidolia.incidentmanagement.notification.IncidentCreated.class).toList();
        assertThat(events).hasSize(1);
        var event=events.get(0);var saved=repository.findById(created.getId()).orElseThrow();
        assertThat(event.incidentNumber()).isEqualTo(saved.getIncidentNumber());
        assertThat(event.title()).isEqualTo(saved.getTitle());
        assertThat(event.description()).isEqualTo(saved.getDescription());
        assertThat(event.assignedHandler()).isEqualTo(saved.getAssignedOwner());
        assertThat(event.status()).isEqualTo(saved.getStatus());
        assertThat(event.createdAt()).isCloseTo(saved.getCreatedAt(), within(1, java.time.temporal.ChronoUnit.MILLIS));
        assertThat(event.reporterName()).isEqualTo("Synthetic Reporter");
        assertThat(event.reporterDepartment()).isEqualTo(saved.getReporterDepartment());
        assertThat(event.issueType()).isEqualTo(saved.getIssueType());
        assertThat(event.reportedAt()).isCloseTo(saved.getReportedAt(), within(1, java.time.temporal.ChronoUnit.MILLIS));
        assertThat(event.toString()).doesNotContain("private", "Synthetic Reporter");
    }
    @Test void departmentMessagesUseSeparateRecipientsAndRemainGeneric() throws Exception {
        var request=request();request.setReporterDepartment("Operations (Annotation)");
        incidents.createIncident(request);drain();
        assertThat(CAPTURE.messages).hasSize(3);
        assertThat(CAPTURE.messages).filteredOn(m -> m.contains("To: oversight@example.test")).hasSize(1);
        assertThat(CAPTURE.messages).filteredOn(m -> m.contains("To: annotations@example.test")).hasSize(1);
        assertThat(CAPTURE.messages).filteredOn(m -> m.contains("To: annotations02@example.test")).hasSize(1);
        for(String message:CAPTURE.messages) {
            assertThat(message).contains("text/plain","text/html","New incident created")
                    .doesNotContain("private HR title","confidential complaint","Synthetic Reporter", "Operations (Annotation)");
            assertThat(message.lines().filter(line -> line.startsWith("To: ")).count()).isEqualTo(1);
            assertThat(message).doesNotContain("\nCc:","\nBcc:");
        }
    }
    @Test void rollbackDoesNotSend() throws Exception {new TransactionTemplate(transactions).executeWithoutResult(s->{incidents.createIncident(request());s.setRollbackOnly();});drain();assertThat(CAPTURE.messages).isEmpty();assertThat(repository.count()).isZero();}
    @Test void transportFailureDoesNotRollbackIncident() throws Exception {
        CAPTURE.reject=true;try {var created=incidents.createIncident(request());drain();assertThat(repository.existsById(created.getId())).isTrue();assertThat(CAPTURE.messages).isEmpty();} finally {CAPTURE.reject=false;}
    }

    /** Minimal capture-only SMTP fixture. It never opens outbound sockets or relays mail. */
    static final class Capture implements AutoCloseable {
        final ServerSocket server; final Thread worker; final List<String> messages=new CopyOnWriteArrayList<>(); volatile boolean reject;
        Capture() {try {server=new ServerSocket(0,16,InetAddress.getByName("127.0.0.1"));worker=new Thread(this::serve,"loopback-smtp-capture");worker.setDaemon(true);worker.start();}catch(IOException e){throw new ExceptionInInitializerError(e);} }
        int port(){return server.getLocalPort();}
        void serve(){while(!server.isClosed())try(var socket=server.accept()){ socket.setSoTimeout(5000);handle(socket); }catch(IOException e){if(!server.isClosed()) throw new UncheckedIOException(e);} }
        void handle(Socket socket) throws IOException {
            var in=new BufferedReader(new InputStreamReader(socket.getInputStream(),StandardCharsets.UTF_8));
            var out=new PrintWriter(new OutputStreamWriter(socket.getOutputStream(),StandardCharsets.UTF_8),true);
            out.print("220 localhost capture\r\n");out.flush();String line;
            while((line=in.readLine())!=null){String cmd=line.toUpperCase(Locale.ROOT);
                if(cmd.startsWith("EHLO")||cmd.startsWith("HELO"))out.print("250 localhost\r\n");
                else if(cmd.startsWith("MAIL FROM"))out.print(reject?"451 synthetic failure\r\n":"250 OK\r\n");
                else if(cmd.startsWith("RCPT TO"))out.print("250 OK\r\n");
                else if(cmd.equals("DATA")){out.print("354 End data\r\n");out.flush();var data=new StringBuilder();while((line=in.readLine())!=null&&!line.equals("."))data.append(line).append('\n');messages.add(data.toString());out.print("250 OK\r\n");}
                else if(cmd.equals("QUIT")){out.print("221 Bye\r\n");out.flush();return;}else out.print("250 OK\r\n");out.flush();
            }
        }
        public void close() throws Exception {server.close();worker.join(5000);}
    }
}
