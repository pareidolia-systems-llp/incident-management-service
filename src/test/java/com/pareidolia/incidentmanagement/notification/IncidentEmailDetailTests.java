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
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mock.env.MockEnvironment;

import static com.pareidolia.incidentmanagement.notification.IncidentEmailDetailAuthority.Classification.*;
import static com.pareidolia.incidentmanagement.notification.IncidentEmailDetailAuthority.Route.*;
import static org.assertj.core.api.Assertions.assertThat;

class IncidentEmailDetailTests {
    private static final String NUMBER = "INC-2026-20261107-120000-ABCDEF12";
    private static final String IT = "it@example.test";
    private static final String HR = "hr@example.test";
    private static final String HR_CASE = "schakravorty@pareidolia.in";
    private static final String OPS = "ops@example.test";

    @Test
    void sendsSeparateDetailedAndGenericMimeForTheSameCase() throws Exception {
        var fixture = new Fixture();
        fixture.authority("authority", number -> NUMBER.equals(number)
                ? new IncidentEmailDetailAuthority.Decision(ORDINARY_IT, STANDARD, Set.of(IT), false) : null);
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
    void trustedOrdinaryItCanSendDetailToEveryApprovedConfiguredRecipient() throws Exception {
        var fixture = new Fixture();
        fixture.authority("authority", number ->
                new IncidentEmailDetailAuthority.Decision(ORDINARY_IT, STANDARD, Set.of(IT, HR, OPS), false));
        fixture.send();
        assertThat(fixture.sender.messages).hasSize(3);
        for (String recipient : List.of(IT, HR, OPS)) {
            assertThat(fixture.wire(recipient)).contains("text/plain", "text/html", "Synthetic description");
        }
    }

    @Test
    void approvalsCannotTransferToAnotherCaseOrAddAnUnroutedRecipient() throws Exception {
        var fixture = new Fixture();
        fixture.authority("authority", number -> NUMBER.equals(number)
                ? new IncidentEmailDetailAuthority.Decision(ORDINARY_IT, STANDARD,
                        Set.of(IT, HR_CASE), false)
                : null);

        fixture.send();
        assertThat(fixture.sender.messages).hasSize(3);
        assertThat(fixture.wire(IT)).contains("Synthetic description");
        assertGeneric(fixture, HR);
        assertGeneric(fixture, OPS);

        fixture.sender.messages.clear();
        fixture.send("INC-2026-20261107-120000-ABCDEF13", "Operations", IssueType.IT_ISSUE);
        assertThat(fixture.sender.messages).isEmpty();
    }

    @Test
    void trustedHrRouteOverridesAllConfiguredRecipientsEvenWhenReporterSelectsIt() throws Exception {
        var fixture = new Fixture();
        fixture.authority("authority", number -> new IncidentEmailDetailAuthority.Decision(
                IncidentEmailDetailAuthority.Route.HR, STANDARD, Set.of(HR_CASE, IT, HR, OPS), false));
        fixture.send("Operations");
        assertThat(fixture.sender.messages).hasSize(1);
        assertThat(fixture.wire(HR_CASE)).contains("text/plain", "text/html", "Synthetic description", NUMBER);
    }

    @Test
    void hrMinimalRequiresExplicitApprovalAndOmitsIncidentNumber() throws Exception {
        for (var classification : List.of(STANDARD, RESTRICTED, UNCLASSIFIED)) {
            var fixture = new Fixture();
            fixture.authority("authority", number -> new IncidentEmailDetailAuthority.Decision(
                    IncidentEmailDetailAuthority.Route.HR, classification, Set.of(IT), true));
            fixture.send();
            assertThat(fixture.sender.messages).hasSize(1);
            assertThat(fixture.wire(HR_CASE)).contains("text/plain", "text/html", "https://portal.example.test/")
                    .doesNotContain(NUMBER, "Incident number", "Synthetic", "Operations");
        }
        var denied = new Fixture();
        denied.authority("authority", number -> new IncidentEmailDetailAuthority.Decision(
                IncidentEmailDetailAuthority.Route.HR, RESTRICTED, Set.of(HR_CASE), false));
        denied.send();
        assertThat(denied.sender.messages).isEmpty();
    }

    @Test
    void disablingV2CannotSendAnHrCaseToTheLegacyGlobalList() throws Exception {
        var fixture = new Fixture();
        fixture.env.setProperty("app.notifications.email.v2.enabled", "false");
        fixture.authority("authority", number -> new IncidentEmailDetailAuthority.Decision(
                IncidentEmailDetailAuthority.Route.HR, STANDARD, Set.of(HR_CASE), true));
        fixture.send();
        assertThat(fixture.sender.messages).hasSize(1);
        assertThat(fixture.wire(HR_CASE)).contains("text/plain", "text/html").doesNotContain(NUMBER, "Synthetic");
    }

    @Test
    void unknownRestrictedAndSecurityRoutesNeverFallBackToBroadDelivery() {
        for (var decision : List.of(
                new IncidentEmailDetailAuthority.Decision(ORDINARY_IT, UNCLASSIFIED, Set.of(IT), false),
                new IncidentEmailDetailAuthority.Decision(ORDINARY_IT, RESTRICTED, Set.of(IT), false),
                new IncidentEmailDetailAuthority.Decision(SECURITY, STANDARD, Set.of(IT), true),
                new IncidentEmailDetailAuthority.Decision(UNKNOWN, STANDARD, Set.of(IT), true))) {
            var fixture = new Fixture();
            fixture.authority("authority", number -> decision);
            fixture.send("HR");
            assertThat(fixture.sender.messages).isEmpty();
        }

        var conflicting = new Fixture();
        conflicting.authority("authority", IncidentEmailTestSupport::standardIt);
        conflicting.send("Operations", IssueType.INFORMATION_SECURITY_INCIDENT);
        assertThat(conflicting.sender.messages).isEmpty();
    }

    @Test
    void absentAmbiguousUnknownOrFailingAuthorityWithholdsEmail() {
        var missing = new Fixture();
        var ambiguous = new Fixture();
        ambiguous.authority("first", IncidentEmailTestSupport::standardIt);
        ambiguous.authority("second", IncidentEmailTestSupport::standardIt);
        var unknown = new Fixture();
        unknown.authority("unknown", number -> null);
        var failing = new Fixture();
        failing.authority("failing", number -> { throw new IllegalStateException("synthetic lookup failure"); });
        for (var fixture : List.of(missing, ambiguous, unknown, failing)) {
            fixture.send("HR");
            assertThat(fixture.sender.messages).isEmpty();
        }
    }

    @Test
    void detailsRequireExplicitOptInAndTrustedPortalLink() throws Exception {
        var disabled = new Fixture();
        disabled.env.setProperty("app.notifications.email.v2.details-enabled", "false");
        var invalid = new Fixture();
        invalid.env.setProperty("app.notifications.email.v2.details-enabled", "yes");
        var noLink = new Fixture();
        noLink.env.setProperty("app.notifications.email.portal-origin", "");
        for (var fixture : List.of(disabled, invalid, noLink)) {
            fixture.authority("authority", number ->
                    new IncidentEmailDetailAuthority.Decision(ORDINARY_IT, STANDARD, Set.of(IT), false));
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
        fixture.authority("authority", number ->
                new IncidentEmailDetailAuthority.Decision(ORDINARY_IT, STANDARD, Set.of(IT), false));
        fixture.sender.failingRecipient = IT;
        fixture.send();
        assertThat(fixture.sender.messages).hasSize(2);
        assertGeneric(fixture, HR);
        assertGeneric(fixture, OPS);
    }

    @Test
    void routineRoutingCoversEveryIssueType() throws Exception {
        for (IssueType type : IssueType.values()) {
            var fixture = new Fixture();
            fixture.enableRoutineRouting();
            fixture.send("Operations", type);
            switch (type) {
                case IT_ISSUE, SERVICE_REQUEST -> {
                    assertThat(fixture.sender.messages).hasSize(3);
                    for (String recipient : List.of(IT, HR, OPS)) {
                        assertThat(fixture.wire(recipient)).contains("text/plain", "text/html",
                                "Synthetic description", "https://portal.example.test/");
                    }
                }
                case HR_ISSUE -> {
                    assertThat(fixture.sender.messages).hasSize(1);
                    assertThat(fixture.wire(HR_CASE)).doesNotContain(NUMBER, "Synthetic");
                }
                case SUSPECTED_SECURITY_INCIDENT, INFORMATION_SECURITY_INCIDENT, MAJOR_CRITICAL_SECURITY_INCIDENT ->
                        assertThat(fixture.sender.messages).isEmpty();
            }
        }
    }

    @Test
    void hrHintsNarrowMislabeledRoutineIssuesAndSecurityVetoesBothRoutes() throws Exception {
        for (var event : List.of(
                hinted("Human Resources", null, null, null),
                hinted("Operations", "Routine HR Request", null, null),
                hinted("Operations", null, "Question about payroll", null),
                hinted("Operations", null, null, "HR"))) {
            var routine = new Fixture();
            routine.enableRoutineRouting();
            routine.send(event);
            assertThat(routine.sender.messages).hasSize(1);
            assertThat(routine.wire(HR_CASE)).doesNotContain(NUMBER, "payroll");

            var trustedIt = new Fixture();
            trustedIt.authority("authority", IncidentEmailTestSupport::standardIt);
            trustedIt.send(event);
            assertThat(trustedIt.sender.messages).isEmpty();
        }
        var security = new Fixture();
        security.enableRoutineRouting();
        security.send(hinted("HR", "Routine HR Request", "Suspicious login", null));
        assertThat(security.sender.messages).isEmpty();
    }

    @Test
    void routineOptInCannotOverrideAConfiguredAuthority() {
        var restricted = new Fixture();
        restricted.enableRoutineRouting();
        restricted.authority("authority", number ->
                new IncidentEmailDetailAuthority.Decision(ORDINARY_IT, RESTRICTED, Set.of(IT), false));
        var ambiguous = new Fixture();
        ambiguous.enableRoutineRouting();
        ambiguous.authority("first", IncidentEmailTestSupport::standardIt);
        ambiguous.authority("second", IncidentEmailTestSupport::standardIt);
        for (var fixture : List.of(restricted, ambiguous)) {
            fixture.send();
            assertThat(fixture.sender.messages).isEmpty();
        }
    }

    @Test
    void routineRoutingWithholdsUnknownTypeAndInvalidGlobalConfiguration() {
        var missing = new Fixture();
        missing.enableRoutineRouting();
        missing.send("Operations", null);
        assertThat(missing.sender.messages).isEmpty();

        var invalid = new Fixture();
        invalid.enableRoutineRouting();
        invalid.send(hinted("Operations", null, null, null), "invalid mailbox");
        assertThat(invalid.sender.messages).isEmpty();
    }

    @Test
    void routineDetailsRequireOptInAndSafePortalAndEscapeHtml() throws Exception {
        var event = hinted("Operations", null, "<script>example</script>", null);
        var detailed = new Fixture();
        detailed.enableRoutineRouting();
        detailed.send(event);
        assertThat(detailed.wire(IT).replace("=\r\n", "").replace("=\n", ""))
                .contains("&lt;script&gt;example&lt;/script&gt;");

        var disabled = new Fixture();
        disabled.enableRoutineRouting();
        disabled.env.setProperty("app.notifications.email.v2.details-enabled", "false");
        disabled.send(event);
        assertGeneric(disabled, IT);

        var badOrigin = new Fixture();
        badOrigin.enableRoutineRouting();
        badOrigin.env.setProperty("app.notifications.email.portal-origin", "http://portal.example.test");
        badOrigin.send(event);
        assertThat(badOrigin.sender.messages).isEmpty();
    }

    @Test
    void routineDeliveryFailureDoesNotStopOtherRecipients() throws Exception {
        var fixture = new Fixture();
        fixture.enableRoutineRouting();
        fixture.sender.failingRecipient = IT;
        fixture.send();
        assertThat(fixture.sender.messages).hasSize(2);
        assertThat(fixture.wire(HR)).contains("Synthetic description");
        assertThat(fixture.wire(OPS)).contains("Synthetic description");
    }

    private static IncidentCreated hinted(String department, String category, String description, String impact) {
        return new IncidentCreated(NUMBER, "Synthetic title", "Synthetic reporter", department,
                IssueType.IT_ISSUE, null, null, null, description, null, null, null,
                category, null, impact);
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
            send(department, IssueType.IT_ISSUE);
        }

        void send(String department, IssueType issueType) {
            send(NUMBER, department, issueType);
        }

        void send(String incidentNumber, String department, IssueType issueType) {
            send(new IncidentCreated(incidentNumber, "Synthetic title", "Synthetic reporter", department,
                    issueType, Severity.LOW, Priority.HIGH, LocalDateTime.parse("2026-11-07T12:00:00"),
                    "Synthetic description", "Synthetic handler", IncidentStatus.OPEN,
                    LocalDateTime.parse("2026-11-07T12:01:00")));
        }

        void enableRoutineRouting() {
            env.setProperty("app.notifications.email.v2.routine-routing-enabled", "true");
        }

        void send(IncidentCreated event) {
            send(event, IT);
        }

        void send(IncidentCreated event, String itRecipients) {
            var settings = new IncidentEmailNotifications.Settings(true, "sender@example.test",
                    itRecipients, HR, String.join(",", IT, HR, OPS, HR_CASE));
            new IncidentEmailConfiguration().incidentEmailNotifications(settings, env,
                    beans.getBeanProvider(JavaMailSender.class),
                    beans.getBeanProvider(IncidentEmailDetailAuthority.class), Runnable::run)
                    .created(event);
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
