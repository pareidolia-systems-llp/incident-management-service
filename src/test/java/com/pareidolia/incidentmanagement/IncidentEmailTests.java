package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.notification.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.*;
import org.springframework.mail.*;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mock.env.MockEnvironment;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(OutputCaptureExtension.class)
class IncidentEmailTests {
    private final JavaMailSender sender=mock(JavaMailSender.class);
    private final String number="INC-2026-20261104-120000-ABCDEF12";
    private IncidentEmailNotifications notifier(boolean enabled,String it,String hr,String allowed,MockEnvironment env,java.util.concurrent.Executor executor) {
        @SuppressWarnings("unchecked") ObjectProvider<JavaMailSender> provider=mock(ObjectProvider.class);
        when(provider.getIfUnique()).thenReturn(sender);
        return new IncidentEmailNotifications(new IncidentEmailNotifications.Settings(enabled,"sender@example.test",it,hr,allowed),env,provider,executor);
    }
    private MockEnvironment dev() {var env=new MockEnvironment();env.setActiveProfiles("dev");return env;}
    @Test void disabledStartsWithoutSmtpConfigurationAndDoesNotQueue() {
        new ApplicationContextRunner().withUserConfiguration(IncidentEmailConfiguration.class).run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(IncidentEmailNotifications.class).doesNotHaveBean(JavaMailSender.class);
        });
        var executor=mock(java.util.concurrent.Executor.class);
        notifier(false,"allowed@example.test","","allowed@example.test",dev(),executor).created(new IncidentCreated(number));
        verifyNoInteractions(executor,sender);
    }
    @Test void finalAllowlistFiltersAndDeduplicatesRecipients() {
        notifier(true,"ALLOWED@example.test,blocked@example.test"," allowed@example.test ","allowed@example.test",dev(),Runnable::run)
            .created(new IncidentCreated(number));
        var capture=org.mockito.ArgumentCaptor.forClass(SimpleMailMessage.class);verify(sender).send(capture.capture());
        var message=capture.getValue();assertThat(message.getTo()).containsExactly("allowed@example.test");
        assertThat(message.getCc()).isNull();assertThat(message.getBcc()).isNull();
        assertThat(message.getSubject()).isEqualTo("New incident created");
        assertThat(message.getText()).isEqualTo("A new incident was created: "+number+".\nSign in to the incident management portal to review it.");
    }
    @Test void emptyRecipientsAndEmptyAllowlistSendNothing() {
        notifier(true,"","","allowed@example.test",dev(),Runnable::run).created(new IncidentCreated(number));
        notifier(true,"allowed@example.test","","",dev(),Runnable::run).created(new IncidentCreated(number));
        verifyNoInteractions(sender);
    }
    @Test void missingDevOrProductionProfilesFailClosed() {
        for(String[] profiles:new String[][]{{"test"},{"dev","prod"},{"dev","production"}}) {
            var env=new MockEnvironment();env.setActiveProfiles(profiles);
            notifier(true,"allowed@example.test","","allowed@example.test",env,Runnable::run).created(new IncidentCreated(number));
        }
        verifyNoInteractions(sender);
    }
    @Test void invalidAddressesAndTicketHeadersCannotSend() {
        notifier(true,"allowed@example.test\r\nBcc: other@example.test","","allowed@example.test",dev(),Runnable::run).created(new IncidentCreated(number));
        notifier(true,"allowed@example.test","","allowed@example.test",dev(),Runnable::run).created(new IncidentCreated(number+"\r\nsecret"));
        verifyNoInteractions(sender);
    }
    @Test void smtpFailureIsSanitized(CapturedOutput output) {
        doThrow(new MailSendException("SMTP_PASSWORD private-description reporter-identity")).when(sender).send(any(SimpleMailMessage.class));
        assertThatCode(() -> notifier(true,"allowed@example.test","","allowed@example.test",dev(),Runnable::run).created(new IncidentCreated(number))).doesNotThrowAnyException();
        assertThat(output.getAll()).contains("Incident email delivery failed.").doesNotContain("SMTP_PASSWORD","private-description","reporter-identity");
    }
    @Test void queueFailureCannotEscapeCommitCallback() {
        java.util.concurrent.Executor executor=task -> {throw new RejectedExecutionException("full");};
        assertThatCode(() -> notifier(true,"allowed@example.test","","allowed@example.test",dev(),executor).created(new IncidentCreated(number))).doesNotThrowAnyException();
        verifyNoInteractions(sender);
    }
}
