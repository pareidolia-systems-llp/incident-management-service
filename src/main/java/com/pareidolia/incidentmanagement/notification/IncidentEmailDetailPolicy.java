package com.pareidolia.incidentmanagement.notification;

import java.util.function.Supplier;
import java.util.stream.Stream;
import org.springframework.core.env.Environment;

final class IncidentEmailDetailPolicy {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(IncidentEmailDetailPolicy.class);
    private final Environment environment;
    private final Supplier<Stream<IncidentEmailDetailAuthority>> authorities;

    IncidentEmailDetailPolicy(Environment environment, Supplier<Stream<IncidentEmailDetailAuthority>> authorities) {
        this.environment = environment;
        this.authorities = authorities;
    }

    boolean allows(String incidentNumber, String recipient) {
        try {
            if (!"true".equalsIgnoreCase(environment.getProperty("app.notifications.email.v2.details-enabled"))) {
                return false;
            }
            try (var candidates = authorities.get()) {
                var sources = candidates.limit(2).toList();
                if (sources.size() != 1) {
                    return false;
                }
                var decision = sources.get(0).assess(incidentNumber, recipient);
                return decision != null
                        && decision.classification() == IncidentEmailDetailAuthority.Classification.STANDARD
                        && decision.fullEmailContentApproved();
            }
        } catch (RuntimeException failure) {
            LOG.warn("Incident email detail authorization unavailable. Using generic content.");
            return false;
        }
    }
}
