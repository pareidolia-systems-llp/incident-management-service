package com.pareidolia.incidentmanagement.notification;

import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.entity.Incident;
import com.pareidolia.incidentmanagement.enums.IssueType;
import com.pareidolia.incidentmanagement.repository.AppUserRepository;
import com.pareidolia.incidentmanagement.repository.IncidentRepository;
import com.pareidolia.incidentmanagement.security.IncidentAccessPolicy;
import com.pareidolia.incidentmanagement.security.IncidentConfidentiality;
import com.pareidolia.incidentmanagement.security.IncidentReadSnapshot;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import java.io.ByteArrayOutputStream;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mock.env.MockEnvironment;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class VerifiedIncidentMailRoutingTests {
    private static final String PREFIX = "app.notifications.email.verified-department-routing.";
    private final IncidentRepository incidents = mock(IncidentRepository.class);
    private final AppUserRepository accounts = mock(AppUserRepository.class);
    private final IncidentReadSnapshot snapshot = mock(IncidentReadSnapshot.class);
    private final IncidentAccessPolicy policy = mock(IncidentAccessPolicy.class);
    private final JdbcTemplate db = mock(JdbcTemplate.class);
    private final MockEnvironment env = new MockEnvironment()
            .withProperty(PREFIX + "it-department-id", "1").withProperty(PREFIX + "hr-department-id", "2")
            .withProperty(PREFIX + "department-recipients",
                    "1=it@example.test;2=hr@example.test,it@example.test;3=ops@example.test,OPS@example.test;4=rd@example.test")
            .withProperty(PREFIX + "restricted-recipients", "2=hr@example.test,it@example.test;3=ops@example.test");
    private final VerifiedIncidentMailRouting routing = new VerifiedIncidentMailRouting(incidents, accounts, snapshot, policy, db, env);
    private final Incident incident = new Incident();
    private final String number = IncidentEmailV2Tests.event(IssueType.IT_ISSUE).incidentNumber();

    VerifiedIncidentMailRoutingTests() {
        incident.setId(9L);
        incident.setIssueType(IssueType.IT_ISSUE);
        when(incidents.findByIncidentNumber(number)).thenReturn(Optional.of(incident));
        classification("STANDARD");
        when(snapshot.readForRollback(any())).thenAnswer(call -> ((Supplier<?>) call.getArgument(0)).get());
        when(policy.isHrCase(eq(incident), nullable(String.class))).thenAnswer(call ->
                IncidentConfidentiality.isHrCase(incident, call.getArgument(1)));
        when(policy.isHrDepartment(eq(2L), eq("Human Resources"))).thenReturn(true);
        when(incidents.findActiveResponsibleDepartmentName(1L)).thenReturn(Optional.of("IT"));
        when(incidents.findActiveResponsibleDepartmentName(2L)).thenReturn(Optional.of("Human Resources"));
        when(incidents.findActiveResponsibleDepartmentName(3L)).thenReturn(Optional.of("Operations"));
        when(incidents.findActiveResponsibleDepartmentName(4L)).thenReturn(Optional.of("R&D"));
        account(11L, "it@example.test", 1L, true);
        account(12L, "hr@example.test", 2L, true);
        account(13L, "ops@example.test", 3L, true);
        account(14L, "rd@example.test", 4L, true);
    }

    @Test void routesOnlyToTheCurrentDepartmentAndDeduplicates() {
        assertThat(routing.recipients(number)).containsExactly("it@example.test");
        incident.setResponsibleDepartmentId(3L);
        assertThat(routing.recipients(number)).containsExactly("ops@example.test");
        incident.setResponsibleDepartmentId(4L);
        assertThat(routing.recipients(number)).containsExactly("rd@example.test");
        incident.setResponsibleDepartmentId(99L);
        assertThat(routing.recipients(number)).isEmpty();
    }

    @Test void hrAndSecurityRequireExplicitCurrentCaseAuthorization() {
        incident.setIssueType(IssueType.HR_ISSUE);
        incident.setResponsibleDepartmentId(3L);
        classification("RESTRICTED");
        assertThat(routing.recipients(number)).isEmpty();
        when(incidents.countActiveCaseViewGrants(9L, 12L)).thenReturn(1L);
        assertThat(routing.recipients(number)).containsExactly("hr@example.test");
        incident.setIssueType(IssueType.INFORMATION_SECURITY_INCIDENT);
        assertThat(routing.recipients(number)).isEmpty();
        when(incidents.countActiveCaseViewGrants(9L, 13L)).thenReturn(1L);
        assertThat(routing.recipients(number)).containsExactly("ops@example.test");
        classification("UNCLASSIFIED");
        assertThat(routing.recipients(number)).isEmpty();
    }

    @Test void restrictedDepartmentHeadNeedsDesignationVerifiedLoginAndCaseGrant() {
        incident.setIssueType(IssueType.HR_ISSUE);
        incident.setResponsibleDepartmentId(2L);
        classification("RESTRICTED");
        env.setProperty(PREFIX + "department-head-notifications.enabled", "true");
        env.setProperty(PREFIX + "department-head-recipients", "2=head@example.test");
        env.setProperty(PREFIX + "restricted-recipients", "2=head@example.test");
        env.setProperty("app.notifications.email.portal-origin", "https://portal.example.test");
        when(policy.isEnabled()).thenReturn(true);
        when(snapshot.read(any())).thenAnswer(call -> ((Supplier<?>) call.getArgument(0)).get());
        account(22L, "head@example.test", 2L, false);
        AppUser head = accounts.findByEmail("head@example.test").orElseThrow();
        when(db.queryForObject(contains("department_head_designations"), eq(Integer.class), eq(2L), eq(22L))).thenReturn(1);
        when(incidents.countActiveCaseViewGrants(9L, 22L)).thenReturn(1L);
        assertThat(routing.recipients(number)).isEmpty();
        head.setLastLoginAt(java.time.LocalDateTime.now());
        assertThat(routing.recipients(number)).containsExactly("head@example.test");
        when(incidents.countActiveCaseViewGrants(9L, 22L)).thenReturn(0L);
        assertThat(routing.recipients(number)).isEmpty();
        when(incidents.countActiveCaseViewGrants(9L, 22L)).thenReturn(1L);
        when(policy.allowsHrOperations(head, incident)).thenReturn(false);
        assertThat(routing.recipients(number)).isEmpty();
    }

    @Test void referralMailIsMinimalAndRecordsTransportFailure() {
        @SuppressWarnings("unchecked") ObjectProvider<JavaMailSender> provider = mock(ObjectProvider.class);
        var sender = mock(JavaMailSender.class);
        when(provider.getIfUnique()).thenReturn(sender);
        var service = mock(com.pareidolia.incidentmanagement.service.HrReassignmentReferralService.class);
        var id = java.util.UUID.randomUUID();
        var allowed = java.util.Set.of("hr@example.test");
        when(service.notificationReviewerIds()).thenReturn(java.util.Set.of(12L));
        when(service.claimNotice(id, 12L, allowed)).thenReturn("hr@example.test", null);
        doThrow(new org.springframework.mail.MailSendException("Synthetic SMTP failure"))
                .when(sender).send(any(org.springframework.mail.SimpleMailMessage.class));
        env.setActiveProfiles("dev");
        env.setProperty("app.notifications.email.portal-origin", "https://portal.example.test");
        env.setProperty("app.notifications.email.enabled", "true");
        var settings = new IncidentEmailNotifications.Settings(true, "sender@example.test", "", "", "hr@example.test");
        var notifier = new IncidentEmailNotifications(settings, env, provider, Runnable::run,
                new IncidentEmailDetailPolicy(env, java.util.stream.Stream::empty), routing);
        notifier.hrReferrals(service);
        var event = new com.pareidolia.incidentmanagement.service.HrReassignmentReferralService.HrReferralQueued(id);
        notifier.hrReferralQueued(event);
        verifyNoInteractions(sender, service);
        env.setProperty("app.notifications.email.hr-referrals.enabled", "true");
        notifier.hrReferralQueued(event);
        notifier.hrReferralQueued(event);
        var sent = org.mockito.ArgumentCaptor.forClass(org.springframework.mail.SimpleMailMessage.class);
        verify(sender).send(sent.capture());
        assertThat(sent.getValue().getTo()).containsExactly("hr@example.test");
        assertThat(sent.getValue().getText()).isEqualTo("A review is pending. Sign in to the portal: https://portal.example.test/"
                + "\nReview reference: " + id);
        verify(service).recordNoticeResult(id, 12L, false);
    }

    @Test void queuedMailUsesCurrentMembershipAndCapturedContentIsMinimal() throws Exception {
        incident.setResponsibleDepartmentId(3L);
        var queue = new ArrayDeque<Runnable>();
        @SuppressWarnings("unchecked") ObjectProvider<JavaMailSender> provider = mock(ObjectProvider.class);
        var sender = mock(JavaMailSender.class);
        when(provider.getIfUnique()).thenReturn(sender);
        when(sender.createMimeMessage()).thenAnswer(call -> new MimeMessage(Session.getInstance(new Properties())));
        env.setActiveProfiles("dev");
        env.setProperty(PREFIX + "enabled", "true");
        var settings = new IncidentEmailNotifications.Settings(true, "sender@example.test", "", "", "ops@example.test");
        var notifier = new IncidentEmailNotifications(settings, env, provider, queue::add,
                new IncidentEmailDetailPolicy(env, java.util.stream.Stream::empty), routing);
        var event = IncidentEmailV2Tests.event(IssueType.IT_ISSUE);
        notifier.created(event);
        account(13L, "ops@example.test", 3L, false);
        queue.remove().run();
        verifyNoInteractions(sender);

        account(13L, "ops@example.test", 3L, true);
        notifier.created(event);
        env.setProperty("app.notifications.email.enabled", "false");
        queue.remove().run();
        verifyNoInteractions(sender);

        env.setProperty("app.notifications.email.enabled", "true");
        env.setProperty("app.incident-access.enabled", "true");
        notifier.created(event);
        assertThat(queue).isEmpty();
        notifier.classificationReady(new IncidentMailReady(number));
        queue.remove().run();
        var sent = org.mockito.ArgumentCaptor.forClass(MimeMessage.class);
        verify(sender).send(sent.capture());
        sent.getValue().saveChanges();
        var bytes = new ByteArrayOutputStream();
        sent.getValue().writeTo(bytes);
        assertThat(bytes.toString(java.nio.charset.StandardCharsets.UTF_8))
                .contains("To: ops@example.test").doesNotContain(number, "Printer", "Trusted");
    }

    private void classification(String status) {
        when(incidents.findSecurityClassifications(List.of(9L)))
                .thenReturn(List.<Object[]>of(new Object[]{9L, status, 1L}));
    }

    private void account(long id, String email, long department, boolean member) {
        var account = new AppUser();
        account.setId(id);
        account.setEmail(email);
        account.setActive(true);
        when(accounts.findByEmail(email)).thenReturn(Optional.of(account));
        when(policy.allowsHrOperations(account, incident)).thenReturn(true);
        when(db.queryForObject(anyString(), eq(Integer.class), eq(department), eq(id))).thenReturn(member ? 1 : 0);
    }
}
