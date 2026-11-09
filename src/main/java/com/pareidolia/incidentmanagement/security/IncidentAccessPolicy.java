package com.pareidolia.incidentmanagement.security;

import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.entity.Incident;
import jakarta.persistence.EntityManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

/** Fail-closed access decisions over stable account and incident IDs. */
@Component
public class IncidentAccessPolicy {
    public enum Permission { VIEW, HANDLE, MODIFY, REPORT, ASSIGN }
    public enum ReadOperation { DETAIL, NUMBER_LOOKUP, LIST, HISTORY, ATTACHMENT_LIST, ATTACHMENT_DOWNLOAD, REPORT, ASSIGNMENT_STATE, ASSIGNMENT_HISTORY }
    public static final String GLOBAL_INCIDENT_VIEW = "GLOBAL_INCIDENT_VIEW";

    /** Deliberately separate from case VIEW, which is a prerequisite for mutations. */
    public boolean hasGlobalView(AppUser actor) {
        if (!enabled || actor == null || actor.getId() == null || actor.getEmail() == null) return false;
        if (!securityGate.held()) throw new IllegalStateException("Global incident access requires a protected snapshot.");
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || !(auth.getPrincipal() instanceof OidcUser oidc)
                || !Boolean.TRUE.equals(oidc.getEmailVerified()) || oidc.getEmail() == null) return false;
        var rows = em.createNativeQuery("""
                select u.email, u.active, c.active from app_users u
                join assignment_admin_capabilities c on c.user_id = u.id
                where u.id = :actor and c.capability = :capability
                """ + securityGate.sharedClause())
                .setParameter("actor", actor.getId()).setParameter("capability", GLOBAL_INCIDENT_VIEW)
                .getResultList();
        if (rows.size() != 1) return false;
        Object[] row = (Object[]) rows.get(0);
        return row[0] instanceof String email && email.equalsIgnoreCase(actor.getEmail().trim())
                && email.equalsIgnoreCase(oidc.getEmail().trim()) && active(row[1]) && active(row[2]);
    }

    public boolean useGlobalView(AppUser actor, java.util.List<Incident> incidents, ReadOperation operation) {
        if (!hasGlobalView(actor) || globallyVisibleIncidents(incidents).size() != incidents.size()) return false;
        auditGlobalView(actor, incidents, operation);
        return true;
    }

    private void auditGlobalView(AppUser actor, java.util.List<Incident> incidents, ReadOperation operation) {
        // Write the audit in the same snapshot transaction. A failed audit fails the read.
        for (Incident incident : incidents) {
            if (em.createNativeQuery("""
                    insert into incident_global_view_audit (actor_user_id, incident_id, operation)
                    values (:actor, :incident, :operation)
                    """).setParameter("actor", actor.getId()).setParameter("incident", incident.getId())
                    .setParameter("operation", operation.name()).executeUpdate() != 1) {
                throw new IllegalStateException("Privileged incident access audit failed.");
            }
        }
    }

    public java.util.List<Incident> filterRead(AppUser actor, java.util.List<Incident> candidates,
            Permission permission, ReadOperation operation) {
        if (!hasGlobalView(actor)) return filter(actor, candidates, permission);
        var verified = globallyVisibleIncidents(candidates);
        auditGlobalView(actor, verified, operation);
        if (verified.size() == candidates.size()) return verified;
        var visible = new java.util.HashSet<>(verified);
        visible.addAll(filter(actor, candidates.stream().filter(incident -> !visible.contains(incident)).toList(), permission));
        return candidates.stream().filter(visible::contains).toList();
    }

    private java.util.List<Incident> globallyVisibleIncidents(java.util.List<Incident> incidents) {
        var verified = new java.util.ArrayList<Incident>();
        for (int offset = 0; offset < incidents.size(); offset += 250) {
            var batch = incidents.subList(offset, Math.min(offset + 250, incidents.size()));
            var classifications = classifications(batch.stream().map(Incident::getId).toList());
            var standard = batch.stream().filter(incident -> "STANDARD".equals(classifications.get(incident.getId()))).toList();
            var departmentNames = activeDepartmentNames(standard);
            standard.stream().filter(incident -> !isHrCase(incident, incident.getResponsibleDepartmentId() == null ? null : departmentNames.get(incident.getResponsibleDepartmentId()))
                    && !IncidentConfidentiality.requiresRestriction(incident,
                            incident.getResponsibleDepartmentId() == null ? null : departmentNames.get(incident.getResponsibleDepartmentId())))
                    .forEach(verified::add);
        }
        return verified;
    }

    private java.util.Map<Long, String> activeDepartmentNames(java.util.List<Incident> incidents) {
        var ids = incidents.stream().map(Incident::getResponsibleDepartmentId)
                .filter(java.util.Objects::nonNull).distinct().toList();
        var names = new java.util.HashMap<Long, String>();
        if (ids.isEmpty()) return names;
        @SuppressWarnings("unchecked") java.util.List<Object[]> rows = em.createNativeQuery(
                "select id,display_name from employee_departments where active=1 and id in (:ids)")
                .setParameter("ids", ids).getResultList();
        for (var row : rows) names.put(((Number) row[0]).longValue(), (String) row[1]);
        return names;
    }

    private java.util.Map<Long, String> classifications(java.util.List<Long> ids) {
        var classifications = new java.util.HashMap<Long, String>();
        @SuppressWarnings("unchecked") java.util.List<Object[]> rows = em.createNativeQuery(
                "select incident_id,classification from incident_security_classification where incident_id in (:ids)")
                .setParameter("ids", ids).getResultList();
        for (var row : rows) classifications.put(((Number) row[0]).longValue(), String.valueOf(row[1]));
        return classifications;
    }

    private static boolean validClassification(String classification) {
        return "STANDARD".equals(classification) || "RESTRICTED".equals(classification)
                || "UNCLASSIFIED".equals(classification);
    }
    private java.util.Set<Long> hrAccounts = java.util.Set.of();
    private java.util.Set<Long> hrDepartments = java.util.Set.of();

    @Value("${app.incident-access.hr-account-ids:}")
    void configureHrAccounts(String ids) {
        hrAccounts = parseIds(ids);
    }

    @Value("${app.incident-access.hr-department-ids:}")
    void configureHrDepartments(String ids) {
        hrDepartments = parseIds(ids);
    }

    private static java.util.Set<Long> parseIds(String ids) {
        return java.util.Arrays.stream(ids.split(",")).map(String::trim).filter(id -> !id.isEmpty())
                .map(Long::valueOf).peek(id -> {
                    if (id <= 0) throw new IllegalArgumentException("Invalid HR scope account ID.");
                }).collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    public boolean allowsHrScope(AppUser account, Incident incident) {
        if (account == null || incident == null || account.getId() == null
                || !Boolean.TRUE.equals(account.getActive())) return false;
        if (IncidentConfidentiality.isReporter(account, incident)) return true;
        return allowsHrScope(account, incident, activeDepartmentNames(java.util.List.of(incident)));
    }

    public boolean allowsHrOperations(AppUser account, Incident incident) {
        if (account == null || incident == null || account.getId() == null
                || !Boolean.TRUE.equals(account.getActive())) return false;
        return allowsHrOperations(account, incident, activeDepartmentNames(java.util.List.of(incident)));
    }

    public boolean isHrCase(Incident incident, String department) {
        return isHrCaseAtDepartment(incident, incident.getResponsibleDepartmentId(), department);
    }

    public boolean isHrCaseAtDepartment(Incident incident, Long id, String department) {
        return isHrDepartment(id, department) || IncidentConfidentiality.isHrCase(incident, department);
    }

    public boolean isHrDepartment(Long id, String department) {
        return (id != null && hrDepartments.contains(id)) || IncidentConfidentiality.isHrDepartment(department);
    }

    public boolean allowsHrDestination(AppUser account, Long destination, String department) {
        return account != null && department != null
                && (!isHrDepartment(destination, department)
                    || hrAccounts.contains(account.getId()));
    }

    private boolean allowsHrScope(AppUser account, Incident incident, java.util.Map<Long, String> departments) {
        return IncidentConfidentiality.isReporter(account, incident) || allowsHrOperations(account, incident, departments);
    }

    private boolean allowsHrOperations(AppUser account, Incident incident, java.util.Map<Long, String> departments) {
        Long departmentId = incident.getResponsibleDepartmentId();
        String department = departmentId == null ? null : departments.get(departmentId);
        if (departmentId != null && department == null) return false;
        return !isHrCase(incident, department) || hrAccounts.contains(account.getId());
    }

    private final EntityManager em;
    private final boolean enabled; private final IncidentSecurityGate securityGate;
    public IncidentAccessPolicy(EntityManager em,@Value("${app.incident-access.enabled:false}") boolean enabled){this.em=em;this.enabled=enabled;this.securityGate=new IncidentSecurityGate(em,enabled);}
    public boolean isEnabled(){return enabled;}
    public boolean can(AppUser actor,Incident incident,Permission permission){return evaluate(actor,incident,permission,false);}
    public boolean canForMutation(AppUser actor,Incident incident,Permission permission){return evaluate(actor,incident,permission,true);}
    private boolean evaluate(AppUser actor,Incident incident,Permission permission,boolean locking){
        if(!enabled)return true;
        if(locking)securityGate.write();else securityGate.read();
        if(actor==null || actor.getId()==null || incident==null || incident.getId()==null || permission==null)return false;
        var auth=SecurityContextHolder.getContext().getAuthentication();
        if(auth==null || !auth.isAuthenticated() || !(auth.getPrincipal() instanceof OidcUser oidc)
                || !Boolean.TRUE.equals(oidc.getEmailVerified()) || oidc.getEmail()==null)return false;
        if(locking){
            if(em.createNativeQuery("select id from app_users where id=?1 for update").setParameter(1,actor.getId()).getResultList().size()!=1)return false;
            em.refresh(actor,jakarta.persistence.LockModeType.PESSIMISTIC_WRITE);
            if(em.createNativeQuery("select id from incidents where id=?1 for update").setParameter(1,incident.getId()).getResultList().size()!=1)return false;
            em.refresh(incident,jakarta.persistence.LockModeType.PESSIMISTIC_WRITE);
        }
        String suffix=locking?" for update":securityGate.sharedClause();
        var accounts=em.createNativeQuery("select active,email from app_users where id=?1"+suffix).setParameter(1,actor.getId()).getResultList();
        if(accounts.size()!=1)return false;
        Object[] account=(Object[])accounts.get(0);
        if(!active(account[0]) || !(account[1] instanceof String email) || !email.equalsIgnoreCase(oidc.getEmail().trim())
                || actor.getEmail()==null || !email.equalsIgnoreCase(actor.getEmail().trim()))return false;
        var classes=em.createNativeQuery("select classification from incident_security_classification where incident_id=?1"+suffix).setParameter(1,incident.getId()).getResultList();
        if(classes.size()!=1)return false;
        String classification=String.valueOf(classes.get(0));
        if(!validClassification(classification))return false;
        if (!(permission == Permission.VIEW ? allowsHrScope(actor, incident) : allowsHrOperations(actor, incident))) return false;
        boolean reporter=incident.getReportedBy()!=null && email.equalsIgnoreCase(incident.getReportedBy().trim());
        if(!classification.equals("RESTRICTED") && reporter && permission==Permission.VIEW)return true;
        if(permission==Permission.ASSIGN)return false; // Legacy free-text assignment must never bypass the new workflow.
        if(!hasGrant(actor.getId(),incident.getId(),Permission.VIEW,locking))return false;
        return permission==Permission.VIEW || hasGrant(actor.getId(),incident.getId(),permission,locking);
    }
    private boolean hasGrant(Long userId,Long incidentId,Permission permission,boolean locking){
        var rows=em.createNativeQuery("select active from incident_security_grants where incident_id=?1 and user_id=?2 and permission=?3"+(locking?" for update":securityGate.sharedClause()))
            .setParameter(1,incidentId).setParameter(2,userId).setParameter(3,permission.name()).getResultList();
        return rows.size()==1 && active(rows.get(0));
    }
    /** Batched authorization within an already-held snapshot gate; no per-record queries. */
    public java.util.List<Incident> filter(AppUser actor,java.util.List<Incident> candidates,Permission permission){
        if(!enabled)return candidates;
        if(!securityGate.held())throw new IllegalStateException("Incident filtering requires a protected snapshot.");
        if(candidates.isEmpty())return java.util.List.of();
        var auth=SecurityContextHolder.getContext().getAuthentication();
        if(actor==null || actor.getId()==null || auth==null || !auth.isAuthenticated() || !(auth.getPrincipal() instanceof OidcUser oidc) || !Boolean.TRUE.equals(oidc.getEmailVerified()) || oidc.getEmail()==null)return java.util.List.of();
        var accounts=em.createNativeQuery("select active,email from app_users where id=?1"+securityGate.sharedClause()).setParameter(1,actor.getId()).getResultList();
        if(accounts.size()!=1)return java.util.List.of();Object[] account=(Object[])accounts.get(0);
        if(!active(account[0]) || !(account[1] instanceof String email) || !email.equalsIgnoreCase(oidc.getEmail().trim()) || actor.getEmail()==null || !email.equalsIgnoreCase(actor.getEmail().trim()))return java.util.List.of();
        var allowed=new java.util.HashSet<Long>();
        for(int offset=0;offset<candidates.size();offset+=250){
            var batch=candidates.subList(offset,Math.min(offset+250,candidates.size()));var ids=batch.stream().map(Incident::getId).toList();
            var classifications=classifications(ids);var grants=new java.util.HashMap<Long,java.util.Set<String>>();
            var departmentNames = activeDepartmentNames(batch);
            @SuppressWarnings("unchecked") java.util.List<Object[]> rows=em.createNativeQuery("select incident_id,permission from incident_security_grants where user_id=:user and active=1 and incident_id in (:ids)").setParameter("user",actor.getId()).setParameter("ids",ids).getResultList();
            for(var row:rows)grants.computeIfAbsent(((Number)row[0]).longValue(),id->new java.util.HashSet<>()).add(String.valueOf(row[1]));
            for(var incident:batch){String classification=classifications.get(incident.getId());if(!validClassification(classification) || !(permission == Permission.VIEW ? allowsHrScope(actor, incident, departmentNames) : allowsHrOperations(actor, incident, departmentNames)))continue;
        boolean reporter=incident.getReportedBy()!=null && email.equalsIgnoreCase(incident.getReportedBy().trim());
                var permissions=grants.getOrDefault(incident.getId(),java.util.Set.of());
                if(permission!=Permission.ASSIGN && ((!classification.equals("RESTRICTED") && reporter && permission==Permission.VIEW) || permissions.contains("VIEW") && (permission==Permission.VIEW || permissions.contains(permission.name()))))allowed.add(incident.getId());
            }
        }
        return candidates.stream().filter(i->allowed.contains(i.getId())).toList();
    }
    private static boolean active(Object value){return Boolean.TRUE.equals(value) || value instanceof Number n && n.intValue()==1;}
    public void require(AppUser actor,Incident incident,Permission permission){if(!can(actor,incident,permission))throw new AccessDeniedException("Access denied.");}
}
