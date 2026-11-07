package com.pareidolia.incidentmanagement.notification;

import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

class IncidentEmailPortalLinkTests {
    @Test void acceptsHttpsOriginAndNormalizesRoot() {
        assertThat(IncidentEmailPortalLink.url("https://Portal.example.test")).isEqualTo("https://portal.example.test/");
        assertThat(IncidentEmailPortalLink.url("https://portal.example.test:8443/")).isEqualTo("https://portal.example.test:8443/");
    }
    @Test void missingOriginPreservesPriorRendering() {
        assertThat(IncidentEmailPortalLink.url(null)).isNull();
        assertThat(IncidentEmailPortalLink.url("  ")).isNull();
        var event = new IncidentCreated("INC-2026-20261106-120000-ABCDEF12");
        assertThat(IncidentEmailTemplate.render(event,false,"")).isEqualTo(IncidentEmailTemplate.render(event,false));
    }
    @Test void rejectsUnsafeAndNonOriginConfigurationWithoutEchoingIt() {
        for (String value : List.of("http://portal.example.test", "//portal.example.test", "javascript:alert(1)",
                "https://user:private@portal.example.test", "https://portal.example.test/login",
                "https://portal.example.test?token=private", "https://portal.example.test/#fragment",
                "https://portal.example.test:0", "https://portal.example.test:65536",
                " https://portal.example.test", "https://portal.example.test/\r\nBcc:private",
                "https://portal.example.test/\" onclick=\"alert(1)", "https://")) {
            assertThatThrownBy(() -> IncidentEmailPortalLink.url(value))
                    .isInstanceOf(IllegalArgumentException.class).hasMessage("Incident email portal origin must be a plain HTTPS origin.");
        }
    }
    @Test void invalidConfigurationFailsAtSettingsCreation() {
        var env = new MockEnvironment().withProperty("app.notifications.email.portal-origin","http://private.example.test");
        assertThatThrownBy(() -> new IncidentEmailConfiguration().incidentEmailSettings(env))
                .isInstanceOf(IllegalArgumentException.class);
    }
    @Test void genericLinkContainsOnlyApprovedMetadataAndEscapesIncidentNumber() {
        var event = new IncidentCreated("<script>private</script>","private title","private reporter","private department",null,null,null,null);
        var result = IncidentEmailTemplate.render(event,false,"https://portal.example.test");
        assertThat(result.subject()).isEqualTo("New incident created");
        assertThat(result.html()).contains("href=\"https://portal.example.test/\"", "Open Incident Management Portal",
                "&lt;script&gt;private&lt;/script&gt;").doesNotContain("<script>", "private title","private reporter","private department","Status");
        assertThat(result.plainText()).contains("Open Incident Management Portal: https://portal.example.test/")
                .doesNotContain("private title","private reporter","private department");
        assertThat(IncidentEmailTemplate.render(new IncidentCreated(null),false,"https://portal.example.test").html()).contains("Not provided");
    }
    static class Capture extends JavaMailSenderImpl {
        final List<MimeMessage> messages = new ArrayList<>();
        @Override public void send(MimeMessage message) { messages.add(message); }
    }
    @Test void eachReviewedDepartmentRoutesGenericLinkedMimeWithCrossGroupDeduplication() throws Exception {
        var sender = new Capture();
        var beans = new StaticListableBeanFactory();
        beans.addBean("capture",sender);
        var env = new StandardEnvironment();
        env.setActiveProfiles("dev");
        env.getPropertySources().addFirst(new MapPropertySource("synthetic",Map.of(
                "app.notifications.email.v2.enabled","true",
                "app.notifications.email.portal-origin","https://portal.example.test",
                "app.notifications.email.v2.department-recipients",
                "Operations (Annotation)=ops1@example.test,ops2@example.test;Operations (Perioperative Flow Analysis)=ops1@example.test,ops2@example.test;R&D=research@example.test;HR=HR@example.test")));
        var settings = new IncidentEmailNotifications.Settings(true,"sender@example.test","it@example.test",
                "hr@example.test,IT@example.test","it@example.test,hr@example.test,ops1@example.test,ops2@example.test,research@example.test");
        var notifications = IncidentEmailTestSupport.trustedItNotifier(settings,env,beans.getBeanProvider(JavaMailSender.class),Runnable::run);
        for (String department : List.of("Operations (Annotation)","Operations (Perioperative Flow Analysis)","R&D","HR")) {
            sender.messages.clear();
            notifications.created(new IncidentCreated("INC-2026-20261106-120000-ABCDEF12","private title","private reporter",department,com.pareidolia.incidentmanagement.enums.IssueType.IT_ISSUE,null,null,null));
            var expected = new HashSet<>(Set.of("it@example.test","hr@example.test"));
            if (department.startsWith("Operations")) expected.addAll(Set.of("ops1@example.test","ops2@example.test"));
            if (department.equals("R&D")) expected.add("research@example.test");
            var actual = new HashSet<String>();
            for (var message : sender.messages) {
                assertThat(message.getAllRecipients()).hasSize(1);
                actual.add(message.getAllRecipients()[0].toString());
                message.saveChanges();
                var bytes = new ByteArrayOutputStream();
                message.writeTo(bytes);
                assertThat(bytes.toString(StandardCharsets.UTF_8)).contains("text/plain","text/html",
                        "https://portal.example.test/","Open Incident Management Portal")
                        .doesNotContain("private title","private reporter",department);
            }
            assertThat(actual).isEqualTo(expected);
            assertThat(sender.messages).hasSize(expected.size());
        }
    }
}
