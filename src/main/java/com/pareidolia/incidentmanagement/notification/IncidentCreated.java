package com.pareidolia.incidentmanagement.notification;

import com.pareidolia.incidentmanagement.enums.IssueType;
import com.pareidolia.incidentmanagement.enums.Priority;
import com.pareidolia.incidentmanagement.enums.Severity;
import java.time.LocalDateTime;

/** Immutable snapshot captured from persisted incident and authenticated account. */
public record IncidentCreated(String incidentNumber, String title, String reporterName,
        String reporterDepartment, IssueType issueType, Severity severity, Priority priority, LocalDateTime reportedAt) {
    public IncidentCreated(String incidentNumber) { this(incidentNumber, null, null, null, null, null, null, null); }
    @Override public String toString() { return "IncidentCreated"; }
}
