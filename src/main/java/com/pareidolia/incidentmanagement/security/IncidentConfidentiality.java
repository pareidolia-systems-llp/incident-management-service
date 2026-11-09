package com.pareidolia.incidentmanagement.security;

import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.entity.Incident;
import com.pareidolia.incidentmanagement.enums.IssueType;
import com.pareidolia.incidentmanagement.repository.IncidentRepository;
import java.util.regex.Pattern;

/** Conservative restrictions for the legacy path. Intake hints can never grant access. */
public final class IncidentConfidentiality {
    private static final Pattern PROTECTED_HINT = Pattern.compile(
            "\\b(?:hr|human[\\s_-]+resources|payroll|salar(?:y|ies)|medical|grievance|harassment"
                    + "|benefits|compensation|discrimination|employee[\\s_-]+relations|leave[\\s_-]+request"
                    + "|confidential[\\s_-]+complaint|phishing|ransomware|malware|data[\\s_-]+breach"
                    + "|unauthorized[\\s_-]+access|account[\\s_-]+compromise|suspicious[\\s_-]+(?:login|email))\\b",
            Pattern.CASE_INSENSITIVE);

    private IncidentConfidentiality() { }

    public static boolean requiresRestriction(Incident incident, IncidentRepository repository) {
        String department = incident.getResponsibleDepartmentId() == null ? null
                : repository.findActiveResponsibleDepartmentName(incident.getResponsibleDepartmentId()).orElse(null);
        return requiresRestriction(incident, department);
    }

    public static boolean requiresRestriction(Incident incident, String responsibleDepartment) {
        IssueType type = incident.getIssueType();
        if (type == null || (type != IssueType.IT_ISSUE && type != IssueType.SERVICE_REQUEST)) return true;
        if (incident.getResponsibleDepartmentId() != null
                && (responsibleDepartment == null || responsibleDepartment.isBlank())) return true;
        return java.util.stream.Stream.of(responsibleDepartment, incident.getReporterDepartment(),
                        incident.getCategory(), incident.getTitle(), incident.getDescription(),
                        incident.getAffectedSystem(), incident.getImpactedUserOrDepartment())
                .anyMatch(value -> value != null && PROTECTED_HINT.matcher(value).find());
    }

    public static boolean isReporter(AppUser actor, Incident incident) {
        return actor.getEmail() != null && !actor.getEmail().isBlank() && incident.getReportedBy() != null
                && actor.getEmail().trim().equalsIgnoreCase(incident.getReportedBy().trim());
    }
}
