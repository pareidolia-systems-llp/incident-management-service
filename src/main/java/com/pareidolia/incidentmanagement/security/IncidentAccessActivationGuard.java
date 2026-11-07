package com.pareidolia.incidentmanagement.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Refuses activation until grant writers, aggregate coverage and MySQL races are verified. */
@Component
public class IncidentAccessActivationGuard {
    public IncidentAccessActivationGuard(@Value("${app.incident-access.enabled:false}") boolean enabled){
        if(enabled)throw new IllegalStateException("Incident access enforcement is not ready for activation: grant administration, all writers and MySQL locking must be verified.");
    }
}
