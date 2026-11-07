package com.pareidolia.incidentmanagement.notification;

import java.util.function.Supplier;
import java.util.stream.Stream;
import org.springframework.core.env.Environment;

import static com.pareidolia.incidentmanagement.notification.IncidentEmailDetailAuthority.Classification.STANDARD;

final class IncidentEmailDetailPolicy {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(IncidentEmailDetailPolicy.class);
    private final Environment environment;
    private final Supplier<Stream<IncidentEmailDetailAuthority>> authorities;

    IncidentEmailDetailPolicy(Environment environment, Supplier<Stream<IncidentEmailDetailAuthority>> authorities) {
        this.environment = environment;
        this.authorities = authorities;
    }

    record Assessment(boolean authorityConfigured, IncidentEmailDetailAuthority.Decision decision) { }

    Assessment assess(String incidentNumber) {
        try (var candidates = authorities.get()) {
            var sources = candidates.limit(2).toList();
            return new Assessment(!sources.isEmpty(),
                    sources.size() == 1 ? sources.get(0).assess(incidentNumber) : null);
        } catch (RuntimeException failure) {
            LOG.warn("Incident email authorization unavailable. Notification withheld.");
            return new Assessment(true, null);
        }
    }

    boolean allowsDetails(IncidentEmailDetailAuthority.Decision decision, String recipient, String portalUrl) {
        return detailsEnabled(portalUrl) && decision.classification() == STANDARD
                && decision.detailedRecipients().contains(recipient);
    }

    boolean detailsEnabled(String portalUrl) {
        return portalUrl != null
                && "true".equalsIgnoreCase(environment.getProperty("app.notifications.email.v2.details-enabled"));
    }
}
