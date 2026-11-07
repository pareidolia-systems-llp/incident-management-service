package com.pareidolia.incidentmanagement.notification;

import com.pareidolia.incidentmanagement.enums.IssueType;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.stream.Stream;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.mail.javamail.JavaMailSender;

public final class IncidentEmailTestSupport {
    private IncidentEmailTestSupport() { }

    public static IncidentEmailDetailAuthority.Decision standardIt(String incidentNumber) {
        return new IncidentEmailDetailAuthority.Decision(IncidentEmailDetailAuthority.Route.ORDINARY_IT,
                IncidentEmailDetailAuthority.Classification.STANDARD, Set.of(), false);
    }

    public static IncidentEmailNotifications trustedItNotifier(IncidentEmailNotifications.Settings settings,
            Environment environment, ObjectProvider<JavaMailSender> senders, Executor executor) {
        return new IncidentEmailNotifications(settings, environment, senders, executor,
                new IncidentEmailDetailPolicy(environment, () -> Stream.of(IncidentEmailTestSupport::standardIt)));
    }

    public static IncidentCreated itEvent(String number) {
        return new IncidentCreated(number, null, null, null, IssueType.IT_ISSUE, null, null, null);
    }

    @TestConfiguration(proxyBeanMethods = false)
    public static class TrustedItConfiguration {
        @Bean IncidentEmailDetailAuthority syntheticAuthority() {
            return IncidentEmailTestSupport::standardIt;
        }
    }
}
