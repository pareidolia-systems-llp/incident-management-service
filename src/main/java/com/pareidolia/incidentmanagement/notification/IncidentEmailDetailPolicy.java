package com.pareidolia.incidentmanagement.notification;

import java.util.Optional;
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

    Optional<IncidentEmailDetailAuthority.Decision> assess(String incidentNumber) {
        try (var candidates = authorities.get()) {
            var sources = candidates.limit(2).toList();
            return sources.size() == 1 ? Optional.ofNullable(sources.get(0).assess(incidentNumber)) : Optional.empty();
        } catch (RuntimeException failure) {
            LOG.warn("Incident email authorization unavailable. Notification withheld.");
            return Optional.empty();
        }
    }

    boolean allowsDetails(IncidentEmailDetailAuthority.Decision decision, String recipient, String portalUrl) {
        return portalUrl != null
                && "true".equalsIgnoreCase(environment.getProperty("app.notifications.email.v2.details-enabled"))
                && decision.classification() == STANDARD
                && decision.detailedRecipients().contains(recipient);
    }
}
