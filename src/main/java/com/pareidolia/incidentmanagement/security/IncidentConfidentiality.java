package com.pareidolia.incidentmanagement.security;

import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.entity.Incident;
import com.pareidolia.incidentmanagement.enums.IssueType;
import com.pareidolia.incidentmanagement.repository.IncidentRepository;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.server.ResponseStatusException;

/** Conservative restrictions for the legacy path. Intake hints can never grant access. */
public final class IncidentConfidentiality {
    private static final Pattern PROTECTED_HINT = Pattern.compile(
            "\\b(?:hr|human[\\s_-]+resources|payroll|salar(?:y|ies)|medical|grievance|harassment"
                    + "|benefits|compensation|discrimination|employee[\\s_-]+relations|leave[\\s_-]+request"
                    + "|confidential[\\s_-]+complaint|phishing|ransomware|malware|data[\\s_-]+breach"
                    + "|unauthorized[\\s_-]+access|account[\\s_-]+compromise|suspicious[\\s_-]+(?:login|email))\\b",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern HR_HINT = Pattern.compile(
            "\\b(?:hr|human[\\s_-]+resources|payroll|salar(?:y|ies)|medical|grievance|harassment"
                    + "|benefits|compensation|discrimination|employee[\\s_-]+relations|leave[\\s_-]+request"
                    + "|confidential[\\s_-]+complaint)\\b", Pattern.CASE_INSENSITIVE);

    private static final Set<String> CLASSIFICATIONS = Set.of("UNCLASSIFIED", "STANDARD", "RESTRICTED");

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

    public static boolean isHrDepartment(String department) {
        return department != null && HR_HINT.matcher(department).find();
    }

    public static boolean isHrCase(Incident incident, String responsibleDepartment) {
        return incident.getIssueType() == IssueType.HR_ISSUE
                || java.util.stream.Stream.of(responsibleDepartment, incident.getReporterDepartment(), incident.getCategory(),
                        incident.getTitle(), incident.getDescription(), incident.getAffectedSystem(), incident.getImpactedUserOrDepartment())
                        .anyMatch(value -> value != null && HR_HINT.matcher(value).find());
    }

    /** A missing row is valid for a legacy incident, but an unreadable or invalid result is not. */
    public static Set<Long> persistedRestrictions(List<Incident> incidents, IncidentRepository repository) {
        List<Long> ids = incidents.stream().map(Incident::getId).distinct().toList();
        if (ids.contains(null)) throw unavailable(null);
        Set<Long> restricted = new HashSet<>();
        for (int start = 0; start < ids.size(); start += 250) {
            List<Long> batch = ids.subList(start, Math.min(start + 250, ids.size()));
            Set<Long> seen = new HashSet<>();
            try {
                for (Object[] row : repository.findSecurityClassifications(batch)) {
                    if (row.length != 3 || !(row[0] instanceof Number id) || !(row[1] instanceof String classification)
                            || !(row[2] instanceof Number version) || !batch.contains(id.longValue())
                            || !seen.add(id.longValue()) || !CLASSIFICATIONS.contains(classification)
                            || version.longValue() < 0 || (!"UNCLASSIFIED".equals(classification) && version.longValue() == 0)) {
                        throw unavailable(null);
                    }
                    if ("RESTRICTED".equals(classification)) restricted.add(id.longValue());
                }
            } catch (DataAccessException failure) {
                throw unavailable(failure);
            }
        }
        return restricted;
    }

    public static boolean reporterMayViewRestricted(AppUser actor, Incident incident, IncidentRepository repository) {
        if (actor.getId() == null || !Boolean.TRUE.equals(actor.getActive()) || !isReporter(actor, incident)) return false;
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || !(auth.getPrincipal() instanceof OidcUser oidc)
                || !Boolean.TRUE.equals(oidc.getEmailVerified()) || oidc.getEmail() == null
                || !actor.getEmail().trim().equalsIgnoreCase(oidc.getEmail().trim())) return false;
        try {
            return repository.countActiveCaseViewGrants(incident.getId(), actor.getId()) == 1;
        } catch (DataAccessException failure) {
            throw unavailable(failure);
        }
    }

    private static ResponseStatusException unavailable(Throwable cause) {
        return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Incident confidentiality could not be verified.", cause);
    }

    public static boolean isReporter(AppUser actor, Incident incident) {
        return actor.getEmail() != null && !actor.getEmail().isBlank() && incident.getReportedBy() != null
                && actor.getEmail().trim().equalsIgnoreCase(incident.getReportedBy().trim());
    }
}
