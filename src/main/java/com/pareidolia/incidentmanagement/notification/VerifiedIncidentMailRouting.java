package com.pareidolia.incidentmanagement.notification;

import com.pareidolia.incidentmanagement.entity.Incident;
import com.pareidolia.incidentmanagement.repository.AppUserRepository;
import com.pareidolia.incidentmanagement.repository.IncidentRepository;
import com.pareidolia.incidentmanagement.security.IncidentAccessPolicy;
import com.pareidolia.incidentmanagement.security.IncidentConfidentiality;
import com.pareidolia.incidentmanagement.security.IncidentReadSnapshot;
import java.util.LinkedHashSet;
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

    Set<String> recipients(String incidentNumber) {
        return policy.isEnabled() ? snapshot.read(() -> resolve(incidentNumber))
                : snapshot.readForRollback(() -> resolve(incidentNumber));
    }

    private Set<String> resolve(String incidentNumber) {
        Incident incident = incidents.findByIncidentNumber(incidentNumber).orElse(null);
        if (incident == null) return Set.of();
        var classifications = incidents.findSecurityClassifications(List.of(incident.getId()));
        if (classifications.size() != 1) return Set.of();
        var row = classifications.get(0);
        if (row.length != 3 || !(row[0] instanceof Number id) || id.longValue() != incident.getId()
                || !(row[2] instanceof Number version) || version.longValue() <= 0
                || !("STANDARD".equals(row[1]) || "RESTRICTED".equals(row[1]))) return Set.of();

        Long responsible = incident.getResponsibleDepartmentId();
        String responsibleName = responsible == null ? null : incidents.findActiveResponsibleDepartmentName(responsible).orElse(null);
        if (responsible != null && responsibleName == null) return Set.of();
        boolean hr = policy.isHrCase(incident, responsibleName);
        boolean restricted = hr || "RESTRICTED".equals(row[1]) || IncidentConfidentiality.requiresRestriction(incident, responsibleName);
        Long department = hr ? environment.getProperty(PREFIX + "hr-department-id", Long.class)
                : responsible != null ? responsible
                : restricted ? null : environment.getProperty(PREFIX + "it-department-id", Long.class);
        if (department == null || department <= 0) return Set.of();
        String destinationName = incidents.findActiveResponsibleDepartmentName(department).orElse(null);
        if (destinationName == null || hr != policy.isHrDepartment(department, destinationName)) return Set.of();

        Set<String> addresses = matrix(department, "department-recipients");
        if (restricted) addresses.retainAll(matrix(department, "restricted-recipients"));
        var authorized = new LinkedHashSet<String>();
        for (String address : addresses) {
            accounts.findByEmail(address).filter(account -> Boolean.TRUE.equals(account.getActive())
                    && activeMember(department, account.getId())
                    && policy.allowsHrOperations(account, incident)
                    && (!restricted || incidents.countActiveCaseViewGrants(incident.getId(), account.getId()) == 1))
                    .ifPresent(account -> authorized.add(address));
        }
        if (policy.isEnabled() && department.equals(responsible)
                && environment.getProperty(PREFIX + "department-head-notifications.enabled", Boolean.class, false)
                && IncidentEmailPortalLink.url(environment.getProperty("app.notifications.email.portal-origin", "")) != null) {
            Set<String> heads = matrix(department, "department-head-recipients");
            if (restricted) heads.retainAll(matrix(department, "restricted-recipients"));
            for (String address : heads) {
                accounts.findByEmail(address).filter(account -> Boolean.TRUE.equals(account.getActive())
                        && account.getLastLoginAt() != null && activeHead(department, account.getId())
                        && policy.allowsHrOperations(account, incident)
                        && incidents.countActiveCaseViewGrants(incident.getId(), account.getId()) == 1)
                        .ifPresent(account -> authorized.add(address));
            }
        }
        return authorized;
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
