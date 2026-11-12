package com.pareidolia.incidentmanagement.notification;

import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.mail.javamail.JavaMailSender;

/** Configuration-only checks: passing does not prove recipients or permit activation. */
public final class IncidentEmailReadinessChecks {
    private IncidentEmailReadinessChecks() { }
    public enum Result { READY_FOR_FURTHER_CHECKS, UNSAFE_CONFIGURATION }
    public static Result inspect(Environment environment, JavaMailSender sender) {
        if (environment == null) return Result.UNSAFE_CONFIGURATION;
        try {
            if (!environment.acceptsProfiles(Profiles.of("default & !dev & !prod & !production"))) return Result.UNSAFE_CONFIGURATION;
            for (String flag : new String[] {
                    "app.incident-access.enabled", "app.notifications.email.enabled",
                    "app.notifications.email.verified-department-routing.enabled",
                    "app.notifications.email.managed-recipients.enabled",
                    "app.notifications.email.detailed-department.enabled",
                    "app.notifications.email.global-hr-generic.enabled",
                    "app.notifications.email.local-postfix-enabled" }) {
                if (!environment.getProperty(flag,Boolean.class,false)) return Result.UNSAFE_CONFIGURATION;
            }
            Long hr=environment.getProperty("app.notifications.email.verified-department-routing.hr-department-id",Long.class);
            if (hr == null || hr <= 0 || IncidentEmailPortalLink.url(environment.getProperty("app.notifications.email.portal-origin", "")) == null
                    || !IncidentEmailNotifications.approvedProductionDelivery(sender,environment.getProperty("app.notifications.email.from", "")))
                return Result.UNSAFE_CONFIGURATION;
            return Result.READY_FOR_FURTHER_CHECKS;
        } catch (RuntimeException failure) {
            return Result.UNSAFE_CONFIGURATION;
        }
    }
}
