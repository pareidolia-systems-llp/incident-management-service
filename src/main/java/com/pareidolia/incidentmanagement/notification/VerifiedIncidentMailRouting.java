package com.pareidolia.incidentmanagement.notification;

import com.pareidolia.incidentmanagement.entity.Incident;
import com.pareidolia.incidentmanagement.repository.AppUserRepository;
import com.pareidolia.incidentmanagement.repository.IncidentRepository;
import com.pareidolia.incidentmanagement.security.IncidentAccessPolicy;
import com.pareidolia.incidentmanagement.security.IncidentConfidentiality;
import com.pareidolia.incidentmanagement.security.IncidentReadSnapshot;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.List;
import java.util.Set;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Resolves current case, department, membership and recipient permissions at dispatch. */
@Component
@ConditionalOnProperty(name = "app.notifications.email.verified-department-routing.enabled", havingValue = "true")
class VerifiedIncidentMailRouting {
    private static final String PREFIX = "app.notifications.email.verified-department-routing.";
    private final IncidentRepository incidents;
    private final AppUserRepository accounts;
    private final IncidentReadSnapshot snapshot;
    private final IncidentAccessPolicy policy;
    private final JdbcTemplate jdbc;
    private final Environment environment;

    VerifiedIncidentMailRouting(IncidentRepository incidents, AppUserRepository accounts, IncidentReadSnapshot snapshot,
            IncidentAccessPolicy policy, JdbcTemplate jdbc, Environment environment) {
        this.incidents = incidents;
        this.accounts = accounts;
        this.snapshot = snapshot;
        this.policy = policy;
        this.jdbc = jdbc;
        this.environment = environment;
    }

    record HeadRecipient(long incidentId, long userId, String email) { }
    private record Recipients(Set<String> department, Map<Long, HeadRecipient> heads) { }
    private static final Recipients NONE = new Recipients(Set.of(), Map.of());

    Set<String> recipients(String incidentNumber) {
        return resolveCurrent(incidentNumber).department();
    }

    Map<Long, HeadRecipient> headRecipients(String incidentNumber) {
        return resolveCurrent(incidentNumber).heads();
    }

    private Recipients resolveCurrent(String incidentNumber) {
        return policy.isEnabled() ? snapshot.read(() -> resolve(incidentNumber))
                : snapshot.readForRollback(() -> resolve(incidentNumber));
    }

    private Recipients resolve(String incidentNumber) {
        Incident incident = incidents.findByIncidentNumber(incidentNumber).orElse(null);
        if (incident == null) return NONE;
        var classifications = incidents.findSecurityClassifications(List.of(incident.getId()));
        if (classifications.size() != 1) return NONE;
        var row = classifications.get(0);
        if (row.length != 3 || !(row[0] instanceof Number id) || id.longValue() != incident.getId()
                || !(row[2] instanceof Number version) || version.longValue() <= 0
                || !("STANDARD".equals(row[1]) || "RESTRICTED".equals(row[1]))) return NONE;

        Long responsible = incident.getResponsibleDepartmentId();
        String responsibleName = responsible == null ? null : incidents.findActiveResponsibleDepartmentName(responsible).orElse(null);
        if (responsible != null && responsibleName == null) return NONE;
        boolean hr = policy.isHrCase(incident, responsibleName);
        boolean restricted = hr || "RESTRICTED".equals(row[1]) || IncidentConfidentiality.requiresRestriction(incident, responsibleName);
        Long department = hr ? environment.getProperty(PREFIX + "hr-department-id", Long.class)
                : responsible != null ? responsible
                : restricted ? null : environment.getProperty(PREFIX + "it-department-id", Long.class);
        if (department == null || department <= 0) return NONE;
        String destinationName = incidents.findActiveResponsibleDepartmentName(department).orElse(null);
        if (destinationName == null || hr != policy.isHrDepartment(department, destinationName)) return NONE;

        Set<String> addresses = matrix(department, "department-recipients");
        if (restricted) addresses.retainAll(matrix(department, "restricted-recipients"));
        var heads = new LinkedHashMap<Long, HeadRecipient>();
        if (policy.isEnabled() && department.equals(responsible)
                && environment.getProperty(PREFIX + "department-head-notifications.enabled", Boolean.class, false)
                && afterRollout(incident)
                && IncidentEmailPortalLink.url(environment.getProperty("app.notifications.email.portal-origin", "")) != null) {
            Set<String> approved = matrix(department, "department-head-recipients");
            if (restricted) approved.retainAll(matrix(department, "restricted-recipients"));
            for (String email : approved) {
                accounts.findByEmail(email).filter(account -> Boolean.TRUE.equals(account.getActive())
                        && account.getLastLoginAt() != null && email.equals(account.getEmail())
                        && activeHead(department, account.getId())).ifPresent(account -> {
                            // A mailbox designated for head delivery must not also receive the general notice.
                            addresses.remove(email);
                            if (policy.allowsHrOperations(account, incident)
                                    && incidents.countActiveCaseViewGrants(incident.getId(), account.getId()) == 1) {
                                heads.put(account.getId(), new HeadRecipient(incident.getId(), account.getId(), email));
                            }
                        });
            }
        }
        var authorized = new LinkedHashSet<String>();
        for (String address : addresses) {
            accounts.findByEmail(address).filter(account -> Boolean.TRUE.equals(account.getActive())
                    && activeMember(department, account.getId())
                    && policy.allowsHrOperations(account, incident)
                    && (!restricted || incidents.countActiveCaseViewGrants(incident.getId(), account.getId()) == 1))
                    .ifPresent(account -> authorized.add(address));
        }
        return new Recipients(authorized, heads);
    }

    private boolean afterRollout(Incident incident) {
        String cutoff = environment.getProperty(PREFIX + "department-head-notifications.rollout-cutoff", "");
        if (cutoff.isBlank() || incident.getCreatedAt() == null) return false;
        try {
            return incident.getCreatedAt().isAfter(LocalDateTime.parse(cutoff));
        } catch (java.time.format.DateTimeParseException invalidCutoff) {
            return false;
        }
    }

    private boolean activeHead(Long department, Long userId) {
        return Integer.valueOf(1).equals(jdbc.queryForObject("""
                select count(*) from department_head_designations
                where department_id=? and user_id=? and active=1
                """, Integer.class, department, userId));
    }

    private boolean activeMember(Long department, Long userId) {
        return Integer.valueOf(1).equals(jdbc.queryForObject("""
                select count(*) from employee_department_memberships
                where department_id=? and user_id=? and active=1
                """, Integer.class, department, userId));
    }

    private Set<String> matrix(Long department, String property) {
        var recipients = new LinkedHashSet<String>();
        for (String entry : environment.getProperty(PREFIX + property, "").split(";")) {
            String[] parts = entry.split("=", 2);
            if (parts.length == 2 && parts[0].trim().equals(department.toString())) {
                recipients.addAll(IncidentEmailNotifications.addresses(parts[1]));
            }
        }
        return recipients;
    }
}
