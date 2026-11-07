package com.pareidolia.incidentmanagement.notification;

import com.pareidolia.incidentmanagement.enums.IssueType;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static com.pareidolia.incidentmanagement.notification.IncidentEmailDetailAuthority.Route.*;

/** Conservative routing hints. A match can narrow delivery, but absence proves nothing about confidentiality. */
final class RoutineIncidentEmailRoute {
    private static final Pattern HR_HINT = Pattern.compile(
            "\\b(?:hr|human[\\s_-]+resources|payroll|salar(?:y|ies)|medical|grievance|harassment"
                    + "|benefits|compensation|discrimination|employee[\\s_-]+relations|leave[\\s_-]+request|confidential[\\s_-]+complaint)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern SECURITY_HINT = Pattern.compile(
            "\\b(?:phishing|ransomware|malware|data[\\s_-]+breach|unauthorized[\\s_-]+access"
                    + "|account[\\s_-]+compromise|suspicious[\\s_-]+(?:login|email))\\b",
            Pattern.CASE_INSENSITIVE);

    private RoutineIncidentEmailRoute() { }

    static IncidentEmailDetailAuthority.Route from(IncidentCreated event) {
        IssueType type = event.issueType();
        if (type == null) return UNKNOWN;
        return switch (type) {
            case SUSPECTED_SECURITY_INCIDENT, INFORMATION_SECURITY_INCIDENT, MAJOR_CRITICAL_SECURITY_INCIDENT -> SECURITY;
            case HR_ISSUE, IT_ISSUE, SERVICE_REQUEST -> {
                if (matches(SECURITY_HINT, event)) yield SECURITY;
                if (type == IssueType.HR_ISSUE || matches(HR_HINT, event)
                        || (event.responsibleDepartmentName() != null
                            && HR_HINT.matcher(event.responsibleDepartmentName()).find())) yield HR;
                yield ORDINARY_IT;
            }
        };
    }

    private static boolean matches(Pattern pattern, IncidentCreated event) {
        return Stream.of(event.reporterDepartment(), event.category(), event.title(), event.description(),
                        event.affectedSystem(), event.impactedUserOrDepartment())
                .anyMatch(value -> value != null && pattern.matcher(value).find());
    }
}
