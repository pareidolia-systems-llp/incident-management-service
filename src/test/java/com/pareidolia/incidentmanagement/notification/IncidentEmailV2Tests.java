package com.pareidolia.incidentmanagement.notification;

import com.pareidolia.incidentmanagement.enums.*;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mock.env.MockEnvironment;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class IncidentEmailV2Tests {
    static IncidentCreated event(IssueType type) {
        return new IncidentCreated("INC-2026-20261104-120000-ABCDEF12", "Printer <script>alert(1)</script>\r\nBcc: x@example.test",
            "Trusted <Reporter>", "Ops & Sales",type,Severity.LOW,Priority.HIGH,LocalDateTime.parse("2026-11-04T12:00:00"));
    }
    @Test void genericRestrictedContentNeverLeaksInSubjectOrEitherBody() {
        for (var issue : IssueType.values()) {
            var result=IncidentEmailTemplate.render(event(issue),false);
            assertThat(result.subject()).isEqualTo("New incident created");
            assertThat(result.plainText()).contains("INC-2026-20261104-120000-ABCDEF12","Sign in").doesNotContain("Printer", "Reporter", "Ops", issue.name());
            assertThat(result.html()).contains("Pareidolia Systems LLP","INC-2026-20261104-120000-ABCDEF12").doesNotContain("Printer", "Reporter", "Ops", issue.name());
        }
    }
    @Test void approvedRendererEscapesHtmlAndStripsUnsafeSubjectCharacters() {
        var result=IncidentEmailTemplate.render(event(IssueType.IT_ISSUE),true);
        assertThat(result.subject()).isEqualTo("New incident created");
        assertThat(result.html()).contains("&lt;script&gt;", "Trusted &lt;Reporter&gt;", "Ops &amp; Sales").doesNotContain("<script>");
        assertThat(result.plainText()).contains("Trusted <Reporter>","Reported department: Ops & Sales");
        assertThat(IncidentEmailTemplate.clean("x".repeat(1000)+"\u202e",120)).hasSize(120);
    }
    @SuppressWarnings("unchecked")
    @Test void onlyOrdinaryReportedTypesCanReachGlobalRecipients() throws Exception {
        var sender=mock(JavaMailSender.class);var provider=mock(ObjectProvider.class);when(provider.getIfUnique()).thenReturn(sender);
        when(sender.createMimeMessage()).thenAnswer(x -> new MimeMessage(Session.getInstance(new Properties())));
        var env=new MockEnvironment();env.setActiveProfiles("dev");env.setProperty("app.notifications.email.v2.enabled","true");
        var settings=new IncidentEmailNotifications.Settings(true,"sender@example.test","it@example.test","hr@example.test,it@example.test","it@example.test,hr@example.test");
        var notification=IncidentEmailTestSupport.trustedItNotifier(settings,env,provider,Runnable::run);
        for(var issue:IssueType.values()) notification.created(event(issue));
        var messages=org.mockito.ArgumentCaptor.forClass(MimeMessage.class);
        verify(sender,times(4)).send(messages.capture());
        for(var message:messages.getAllValues()) {
            assertThat(message.getAllRecipients()).hasSize(1);
            message.saveChanges();var bytes=new ByteArrayOutputStream();message.writeTo(bytes);String raw=bytes.toString(StandardCharsets.UTF_8);
            assertThat(raw).contains("text/plain","text/html","New incident created").doesNotContain("Printer", "Reporter", "Ops & Sales");
        }
        assertThat(messages.getAllValues()).extracting(IncidentEmailV2Tests::recipient)
                .containsOnly("it@example.test","hr@example.test");
    }

    @SuppressWarnings("unchecked")
    @Test void departmentMappingsAddConfiguredRecipientsAndDeduplicateCaseInsensitively() throws Exception {
        var sender=mock(JavaMailSender.class);var provider=mock(ObjectProvider.class);when(provider.getIfUnique()).thenReturn(sender);
        when(sender.createMimeMessage()).thenAnswer(x -> new MimeMessage(Session.getInstance(new Properties())));
        var env=new MockEnvironment();env.setActiveProfiles("dev");env.setProperty("app.notifications.email.v2.enabled","true");
        env.setProperty("app.notifications.email.v2.department-recipients",
            "Operations (Annotation)=annotator@pareidolia.in,annotator02@pareidolia.in;"
            +"Operations (Perioperative Flow Analysis)=annotator@pareidolia.in,annotator02@pareidolia.in;"
            +"R&D=debolina@pareidolia.in;HR=SCHAKRAVORTY@PAREIDOLIA.IN");
        var settings=new IncidentEmailNotifications.Settings(true,"sender@example.test","itadmin@pareidolia.in","schakravorty@pareidolia.in",
            "itadmin@pareidolia.in,schakravorty@pareidolia.in,annotator@pareidolia.in,annotator02@pareidolia.in,debolina@pareidolia.in");
        var notifier=IncidentEmailTestSupport.trustedItNotifier(settings,env,provider,Runnable::run);
        for(String department:new String[]{"Operations (Annotation)","Operations (Perioperative Flow Analysis)","R&D","Unmapped"}) {
            clearInvocations(sender);
            var original=event(IssueType.IT_ISSUE);
            notifier.created(new IncidentCreated(original.incidentNumber(),original.title(),original.reporterName(),department,
                original.issueType(),original.severity(),original.priority(),original.reportedAt()));
            var messages=org.mockito.ArgumentCaptor.forClass(MimeMessage.class);
            int expected=department.startsWith("Operations") ? 4 : department.equals("R&D") ? 3 : 2;
            verify(sender,times(expected)).send(messages.capture());
            var addresses=messages.getAllValues().stream().map(m -> {
                try {assertThat(m.getAllRecipients()).hasSize(1);return m.getAllRecipients()[0].toString();}
                catch(jakarta.mail.MessagingException e){throw new AssertionError(e);}
            }).toList();
            assertThat(addresses).contains("itadmin@pareidolia.in","schakravorty@pareidolia.in").doesNotHaveDuplicates();
            if(department.startsWith("Operations")) assertThat(addresses).contains("annotator@pareidolia.in","annotator02@pareidolia.in");
            if(department.equals("R&D")) assertThat(addresses).contains("debolina@pareidolia.in");
        }
        clearInvocations(sender);
        var original=event(IssueType.IT_ISSUE);
        notifier.created(new IncidentCreated(original.incidentNumber(),original.title(),original.reporterName(),
            "HR=attacker@example.test",original.issueType(),original.severity(),original.priority(),original.reportedAt()));
        verifyNoInteractions(sender);
        clearInvocations(sender);
        env.setProperty("app.notifications.email.v2.department-recipients","Ops & Sales=invalid address");
        notifier.created(event(IssueType.IT_ISSUE));
        verify(sender,times(2)).send(any(MimeMessage.class));
    }
    private static String recipient(MimeMessage message) {
        try {return message.getAllRecipients()[0].toString();}
        catch(jakarta.mail.MessagingException e){throw new AssertionError(e);}
    }
    @SuppressWarnings("unchecked")
    @Test void disabledV2PreservesLegacyGlobalRoutingAndIgnoresDepartmentMapping() {
        var sender=mock(JavaMailSender.class);var provider=mock(ObjectProvider.class);when(provider.getIfUnique()).thenReturn(sender);
        var env=new MockEnvironment();env.setActiveProfiles("dev");
        env.setProperty("app.notifications.email.v2.department-recipients","Ops & Sales=extra@example.test");
        var settings=new IncidentEmailNotifications.Settings(true,"sender@example.test","it@example.test","hr@example.test",
            "it@example.test,hr@example.test,extra@example.test");
        IncidentEmailTestSupport.trustedItNotifier(settings,env,provider,Runnable::run).created(event(IssueType.IT_ISSUE));
        var messages=org.mockito.ArgumentCaptor.forClass(org.springframework.mail.SimpleMailMessage.class);
        verify(sender,times(2)).send(messages.capture());
        assertThat(messages.getAllValues()).extracting(m -> m.getTo()[0]).containsExactly("it@example.test","hr@example.test");
        verify(sender,never()).send(any(MimeMessage.class));
    }
    @SuppressWarnings("unchecked")
    @Test void excludedByDevAllowlistIsNeverSentAndDisabledFeatureDoesNotSend() {
        var sender=mock(JavaMailSender.class);var provider=mock(ObjectProvider.class);when(provider.getIfUnique()).thenReturn(sender);
        when(sender.createMimeMessage()).thenAnswer(x -> new MimeMessage(Session.getInstance(new Properties())));
        var env=new MockEnvironment();env.setActiveProfiles("dev");env.setProperty("app.notifications.email.v2.enabled","true");
        var settings=new IncidentEmailNotifications.Settings(true,"sender@example.test","blocked@example.test","hr@example.test","hr@example.test");
        IncidentEmailTestSupport.trustedItNotifier(settings,env,provider,Runnable::run).created(event(IssueType.IT_ISSUE));verify(sender,times(1)).send(any(MimeMessage.class));
        clearInvocations(sender);settings=new IncidentEmailNotifications.Settings(false,"sender@example.test","blocked@example.test","hr@example.test","hr@example.test");
        IncidentEmailTestSupport.trustedItNotifier(settings,env,provider,Runnable::run).created(event(IssueType.IT_ISSUE));verifyNoInteractions(sender);
    }
}
