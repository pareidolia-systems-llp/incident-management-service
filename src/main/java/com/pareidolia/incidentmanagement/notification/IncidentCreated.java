package com.pareidolia.incidentmanagement.notification;

import com.pareidolia.incidentmanagement.enums.IncidentStatus;
import com.pareidolia.incidentmanagement.enums.IssueType;
import com.pareidolia.incidentmanagement.enums.Priority;
import com.pareidolia.incidentmanagement.enums.Severity;
import java.time.LocalDateTime;

/** Immutable snapshot captured from persisted incident and authenticated account. */
public record IncidentCreated(String incidentNumber, String title, String reporterName,
        String reporterDepartment, IssueType issueType, Severity severity, Priority priority, LocalDateTime reportedAt,
        String description, String assignedHandler, IncidentStatus status, LocalDateTime createdAt,
        String category, String affectedSystem, String impactedUserOrDepartment, String responsibleDepartmentName) {
    public IncidentCreated(String incidentNumber, String title, String reporterName, String reporterDepartment,
            IssueType issueType, Severity severity, Priority priority, LocalDateTime reportedAt,
            String description, String assignedHandler, IncidentStatus status, LocalDateTime createdAt,
            String category, String affectedSystem, String impactedUserOrDepartment) {
        this(incidentNumber, title, reporterName, reporterDepartment, issueType, severity, priority, reportedAt,
                description, assignedHandler, status, createdAt, category, affectedSystem, impactedUserOrDepartment,
                null);
    }
    public IncidentCreated(String incidentNumber, String title, String reporterName, String reporterDepartment,
            IssueType issueType, Severity severity, Priority priority, LocalDateTime reportedAt,
            String description, String assignedHandler, IncidentStatus status, LocalDateTime createdAt) {
        this(incidentNumber, title, reporterName, reporterDepartment, issueType, severity, priority, reportedAt,
                description, assignedHandler, status, createdAt, null, null, null);
    }
    public IncidentCreated(String incidentNumber, String title, String reporterName, String reporterDepartment,
            IssueType issueType, Severity severity, Priority priority, LocalDateTime reportedAt) {
        this(incidentNumber, title, reporterName, reporterDepartment, issueType, severity, priority, reportedAt,
                null, null, null, null);
    }
    public IncidentCreated(String incidentNumber) { this(incidentNumber, null, null, null, null, null, null, null); }
    @Override public String toString() { return "IncidentCreated"; }
}
