package com.pareidolia.incidentmanagement.notification;

/**
 * Trusted server-side source of case-specific authorization for email disclosure.
 * Implementations must verify current classification and approval for full content at the exact
 * recipient address, including mailbox ownership and audience. Routing, user input and portal
 * access alone do not establish approval. No implementation is registered by the email-only release.
 */
@FunctionalInterface
public interface IncidentEmailDetailAuthority {
    enum Classification { STANDARD, RESTRICTED, UNCLASSIFIED }

    record Decision(Classification classification, boolean fullEmailContentApproved) { }

    Decision assess(String incidentNumber, String recipient);
}
