package com.pareidolia.incidentmanagement.notification;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mock.env.MockEnvironment;
import static org.assertj.core.api.Assertions.assertThat;

class IncidentEmailReadinessChecksTests {
    MockEnvironment env; JavaMailSenderImpl sender;
    @BeforeEach void setup() {
        env=new MockEnvironment();
        for (String flag:List.of("app.incident-access.enabled","app.notifications.email.enabled",
                "app.notifications.email.verified-department-routing.enabled","app.notifications.email.managed-recipients.enabled",
                "app.notifications.email.detailed-department.enabled","app.notifications.email.global-hr-generic.enabled",
                "app.notifications.email.local-postfix-enabled")) env.setProperty(flag,"true");
        env.setProperty("app.notifications.email.verified-department-routing.hr-department-id","2");
        env.setProperty("app.notifications.email.portal-origin","https://portal.example.test");
        env.setProperty("app.notifications.email.from","alerts@pareidolia.in");
        sender=new JavaMailSenderImpl(); sender.setHost("localhost"); sender.setPort(25);
    }
    @Test void validConfigurationStillRequiresFurtherChecks() {
        assertThat(IncidentEmailReadinessChecks.inspect(env,sender)).isEqualTo(IncidentEmailReadinessChecks.Result.READY_FOR_FURTHER_CHECKS);
    }
    @Test void everyRoutingFlagIsRequired() {
        for (String flag:List.of("app.incident-access.enabled","app.notifications.email.enabled",
                "app.notifications.email.verified-department-routing.enabled","app.notifications.email.managed-recipients.enabled",
                "app.notifications.email.detailed-department.enabled","app.notifications.email.global-hr-generic.enabled",
                "app.notifications.email.local-postfix-enabled")) {
            env.setProperty(flag,"false");
            assertThat(IncidentEmailReadinessChecks.inspect(env,sender)).isEqualTo(IncidentEmailReadinessChecks.Result.UNSAFE_CONFIGURATION);
            env.setProperty(flag,"true");
        }
    }
    @Test void unsafeOriginHrDepartmentAndTransportAreRejected() {
        env.setProperty("app.notifications.email.portal-origin","https://portal.example.test/private");
        assertThat(IncidentEmailReadinessChecks.inspect(env,sender)).isEqualTo(IncidentEmailReadinessChecks.Result.UNSAFE_CONFIGURATION);
        env.setProperty("app.notifications.email.portal-origin","https://portal.example.test");
        env.setProperty("app.notifications.email.verified-department-routing.hr-department-id","invalid");
        assertThat(IncidentEmailReadinessChecks.inspect(env,sender)).isEqualTo(IncidentEmailReadinessChecks.Result.UNSAFE_CONFIGURATION);
        env.setProperty("app.notifications.email.verified-department-routing.hr-department-id","2");
        sender.setHost("mail.example.test");
        assertThat(IncidentEmailReadinessChecks.inspect(env,sender)).isEqualTo(IncidentEmailReadinessChecks.Result.UNSAFE_CONFIGURATION);
    }
    @Test void profilesWhichCannotDispatchProductionMailAreRejected() {
        env.setActiveProfiles("prod");
        assertThat(IncidentEmailReadinessChecks.inspect(env,sender)).isEqualTo(IncidentEmailReadinessChecks.Result.UNSAFE_CONFIGURATION);
    }
}
