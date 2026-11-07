package com.pareidolia.incidentmanagement.notification;

import java.util.Objects;
import java.util.Set;

/**
 * Trusted case-specific email decision, read as one consistent snapshot at delivery time.
 * Routing and confidentiality must come from independently verified case data. Recipient
 * approvals must cover the exact mailbox and its audience. Reporter input and portal
 * access are insufficient. The email-only branch supplies no production implementation.
 */
@FunctionalInterface
public interface IncidentEmailDetailAuthority {
    enum Route { ORDINARY_IT, HR, SECURITY, UNKNOWN }
    enum Classification { STANDARD, RESTRICTED, UNCLASSIFIED }

    record Decision(Route route, Classification classification, Set<String> detailedRecipients,
                    boolean hrMinimalApproved) {
        public Decision {
            Objects.requireNonNull(route);
            Objects.requireNonNull(classification);
            // Exact, canonical addresses only, as used by the SMTP recipient boundary.
            detailedRecipients = Set.copyOf(detailedRecipients);
        }
    }

    Decision assess(String incidentNumber);
}
