package com.pareidolia.incidentmanagement.notification;

import com.pareidolia.incidentmanagement.enums.IncidentStatus;
import com.pareidolia.incidentmanagement.enums.IssueType;
import com.pareidolia.incidentmanagement.enums.Priority;
import com.pareidolia.incidentmanagement.enums.Severity;
import jakarta.mail.internet.MimeMessage;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mock.env.MockEnvironment;

import static com.pareidolia.incidentmanagement.notification.IncidentEmailDetailAuthority.Classification.*;
import static org.assertj.core.api.Assertions.assertThat;

class IncidentEmailDetailTests {
    private static final String NUMBER = "INC-2026-20261107-120000-ABCDEF12";
    private static final String IT = "it@example.test";
    private static final String HR = "hr@example.test";
    private static final String OPS = "ops@example.test";

    @Test
    void sendsSeparateDetailedAndGenericMimeForTheSameCase() throws Exception {
        var fixture = new Fixture();
        fixture.authority("authority", (number, recipient) ->
                new IncidentEmailDetailAuthority.Decision(STANDARD, NUMBER.equals(number) && IT.equals(recipient)));
        fixture.send();
        assertThat(fixture.sender.messages).hasSize(3);
        String detailed = fixture.wire(IT);
        assertThat(detailed).contains("text/plain", "text/html", "multipart/alternative", "Synthetic title",
                "Synthetic description", "Synthetic reporter", "Synthetic handler", "Operations",
                "OPEN", "IT_ISSUE", "LOW", "HIGH", "Created at", "2026-11-07T12:01", "https://portal.example.test/");
        assertGeneric(fixture, HR);
        assertGeneric(fixture, OPS);
    }

    @Test
    void restrictedAndUnclassifiedCasesStayGenericEvenWithAnAffirmativeMailboxDecision() throws Exception {
        for (var classification : List.of(RESTRICTED, UNCLASSIFIED)) {
            for (String reportedDepartment : List.of("HR", "Security", "Operations")) {
                var fixture = new Fixture();
                fixture.env.setProperty("app.notifications.email.v2.department-recipients",
                        reportedDepartment + "=" + OPS + ",IT@example.test");
                fixture.authority("authority", (number, recipient) ->
                        new IncidentEmailDetailAuthority.Decision(classification, true));
                fixture.send(reportedDepartment);
                assertThat(fixture.sender.messages).hasSize(3);
                for (String recipient : List.of(IT, HR, OPS)) {
                    assertGeneric(fixture, recipient);
                }
            }
        }
    }

    @Test
    void absentAmbiguousUnknownOrFailingAuthorityPreservesGenericDelivery() throws Exception {
        var missing = new Fixture();
        var ambiguous = new Fixture();
        ambiguous.authority("first", (number, recipient) -> new IncidentEmailDetailAuthority.Decision(STANDARD, true));
        ambiguous.authority("second", (number, recipient) -> new IncidentEmailDetailAuthority.Decision(STANDARD, true));
        var unknown = new Fixture();
        unknown.authority("unknown", (number, recipient) -> null);
        var failing = new Fixture();
        failing.authority("failing", (number, recipient) -> { throw new IllegalStateException("synthetic lookup failure"); });
        for (var fixture : List.of(missing, ambiguous, unknown, failing)) {
            fixture.send();
            assertThat(fixture.sender.messages).hasSize(3);
            assertGeneric(fixture, IT);
        }
    }

    @Test
    void requiresExplicitOptInAndTrustedPortalLinkBeforeConsultingAuthority() throws Exception {
        var disabled = new Fixture();
        disabled.env.setProperty("app.notifications.email.v2.details-enabled", "false");
        var invalid = new Fixture();
        invalid.env.setProperty("app.notifications.email.v2.details-enabled", "yes");
        var noLink = new Fixture();
        noLink.env.setProperty("app.notifications.email.portal-origin", "");
        for (var fixture : List.of(disabled, invalid, noLink)) {
            fixture.authority("unused", (number, recipient) -> {
                throw new AssertionError("Authority must not be consulted");
            });
            fixture.send();
            assertGeneric(fixture, IT);
        }
    }

    @Test
    void escapesMarkupAndSanitizesControlCharactersInBothAlternatives() {
        var event = new IncidentCreated(NUMBER, "Title\r\nBcc: synthetic", "Reporter <name>", null,
                null, null, null, null, "<img src=x onerror=alert(1)>\u202e\u0000", " \t", null, null);
        var rendered = IncidentEmailTemplate.render(event, true, "https://portal.example.test");
        assertThat(rendered.subject()).isEqualTo("New incident created");
        assertThat(rendered.html()).contains("&lt;img", "Reporter &lt;name&gt;", "Pending assignment",
                "Not provided", "href=\"https://portal.example.test/\"")
                .doesNotContain("<img", "\u202e", "\u0000");
        assertThat(rendered.plainText()).contains("Incident title: Title Bcc: synthetic",
                "Description: <img src=x onerror=alert(1)>", "Assigned handler: Pending assignment",
                "Status: Not provided", "https://portal.example.test/")
                .doesNotContain("\r", "\u202e", "\u0000", "\nBcc:");
        assertThat(event.toString()).isEqualTo("IncidentCreated");
    }

    @Test
    void detailDeliveryFailureDoesNotStopOtherRecipients() throws Exception {
        var fixture = new Fixture();
        fixture.authority("authority", (number, recipient) ->
                new IncidentEmailDetailAuthority.Decision(STANDARD, IT.equals(recipient)));
        fixture.sender.failingRecipient = IT;
        fixture.send();
        assertThat(fixture.sender.messages).hasSize(2);
        assertGeneric(fixture, HR);
        assertGeneric(fixture, OPS);
    }

    private static void assertGeneric(Fixture fixture, String recipient) throws Exception {
        assertThat(fixture.wire(recipient)).contains("text/plain", "text/html", NUMBER)
                .doesNotContain("Synthetic title", "Synthetic description", "Synthetic reporter",
                        "Synthetic handler", "Reported department", "IT_ISSUE", "2026-11-07T12:01");
    }

    private static final class Fixture {
        final MockEnvironment env = new MockEnvironment()
                .withProperty("app.notifications.email.v2.enabled", "true")
                .withProperty("app.notifications.email.v2.details-enabled", "true")
                .withProperty("app.notifications.email.portal-origin", "https://portal.example.test")
                .withProperty("app.notifications.email.v2.department-recipients", "Operations=" + OPS + ",IT@example.test");
        final StaticListableBeanFactory beans = new StaticListableBeanFactory();
        final Capture sender = new Capture();

        Fixture() {
            env.setActiveProfiles("dev");
            beans.addBean("mail", sender);
        }

        void authority(String name, IncidentEmailDetailAuthority authority) {
            beans.addBean(name, authority);
        }

        void send() {
            send("Operations");
        }

        void send(String department) {
            var settings = new IncidentEmailNotifications.Settings(true, "sender@example.test",
                    IT, HR, String.join(",", IT, HR, OPS));
            new IncidentEmailConfiguration().incidentEmailNotifications(settings, env,
                    beans.getBeanProvider(JavaMailSender.class),
                    beans.getBeanProvider(IncidentEmailDetailAuthority.class), Runnable::run)
                    .created(new IncidentCreated(NUMBER, "Synthetic title", "Synthetic reporter", department,
                            IssueType.IT_ISSUE, Severity.LOW, Priority.HIGH, LocalDateTime.parse("2026-11-07T12:00:00"),
                            "Synthetic description", "Synthetic handler", IncidentStatus.OPEN,
                            LocalDateTime.parse("2026-11-07T12:01:00")));
        }

        String wire(String recipient) throws Exception {
            for (var message : sender.messages) {
                assertThat(message.getAllRecipients()).hasSize(1);
                assertThat(message.getSubject()).isEqualTo("New incident created");
                if (message.getAllRecipients()[0].toString().equals(recipient)) {
                    message.saveChanges();
                    var bytes = new ByteArrayOutputStream();
                    message.writeTo(bytes);
                    return bytes.toString(StandardCharsets.UTF_8);
                }
            }
            throw new AssertionError("No message captured for " + recipient);
        }
    }

    private static final class Capture extends JavaMailSenderImpl {
        final java.util.ArrayList<MimeMessage> messages = new java.util.ArrayList<>();
        String failingRecipient;

        @Override
        public void send(MimeMessage message) {
            try {
                if (message.getAllRecipients()[0].toString().equals(failingRecipient)) {
                    throw new MailSendException("synthetic delivery failure");
                }
                messages.add(message);
            } catch (jakarta.mail.MessagingException failure) {
                throw new AssertionError(failure);
            }
        }
    }
}
