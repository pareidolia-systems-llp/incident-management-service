package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.security.IncidentReadSnapshot;
import com.pareidolia.incidentmanagement.security.IncidentSecurityGate;
import jakarta.persistence.EntityManager;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@ConditionalOnProperty(name = "app.department-membership-admin.enabled", havingValue = "true")
public class DepartmentMembershipAdminService {
    public record Membership(long departmentId, long userId, String name, String email, boolean active, long version) { }
    public record Audit(long departmentId, long userId, long actorUserId, Boolean oldActive, boolean newActive,
                        long version, String reason, String changedAt) { }

    private final EntityManager em;
    private final AppUserService users;
    private final IncidentSecurityGate gate;
    private final IncidentReadSnapshot snapshot;
    private final Set<String> administrators;

    public DepartmentMembershipAdminService(EntityManager em, AppUserService users, IncidentSecurityGate gate,
            IncidentReadSnapshot snapshot, @Value("${app.department-membership-admin.allowed-emails:}") String configured) {
        this.em = em;
        this.users = users;
        this.gate = gate;
        this.snapshot = snapshot;
        this.administrators = Arrays.stream(configured.split(",")).map(AppUserService::normalizeEmail)
                .filter(email -> !email.isEmpty()).collect(Collectors.toUnmodifiableSet());
    }

    public List<Membership> list(Long departmentId) {
        requireId(departmentId);
        return snapshot.read(() -> {
            administrator();
            requireDepartment(departmentId, false);
            @SuppressWarnings("unchecked")
            List<Object[]> rows = em.createNativeQuery("""
                    select m.user_id, u.display_name, u.email, m.active, m.version
                    from employee_department_memberships m join app_users u on u.id = m.user_id
                    where m.department_id = :department order by u.email, u.id
                    """).setParameter("department", departmentId).setMaxResults(501).getResultList();
            if (rows.size() > 500) throw tooMany();
            return rows.stream().map(row -> new Membership(departmentId, number(row[0]), (String) row[1],
                    (String) row[2], active(row[3]), number(row[4]))).toList();
        });
    }

    public List<Audit> history(Long departmentId, Long userId) {
        requireId(departmentId);
        requireId(userId);
        return snapshot.read(() -> {
            administrator();
            @SuppressWarnings("unchecked")
            List<Object[]> rows = em.createNativeQuery("""
                    select actor_user_id, old_active, new_active, membership_version, reason, changed_at
                    from employee_department_membership_audit
                    where department_id = :department and user_id = :user order by membership_version desc
                    """).setParameter("department", departmentId).setParameter("user", userId)
                    .setMaxResults(201).getResultList();
            if (rows.size() > 200) throw tooMany();
            return rows.stream().map(row -> new Audit(departmentId, userId, number(row[0]),
                    row[1] == null ? null : active(row[1]), active(row[2]), number(row[3]),
                    (String) row[4], String.valueOf(row[5]))).toList();
        });
    }

    @Transactional
    public long change(Long departmentId, Long userId, boolean requestedActive, Long expectedVersion, String reason) {
        requireId(departmentId);
        requireId(userId);
        if (expectedVersion == null || expectedVersion < 0 || reason == null || reason.isBlank() || reason.length() > 500) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A version and a reason are required.");
        }
        AppUser actor = administrator();
        if (actor.getId().equals(userId)) throw denied();

        gate.write();
        // Share the assignment gate and lock accounts in ID order before department and membership rows.
        for (Long id : new TreeSet<>(List.of(actor.getId(), userId))) {
            var accounts = em.createNativeQuery("select active, email from app_users where id = :id for update")
                    .setParameter("id", id).getResultList();
            if (accounts.size() != 1) throw denied();
            Object[] account = (Object[]) accounts.get(0);
            if (!active(account[0]) || (id.equals(actor.getId())
                    && !AppUserService.normalizeEmail(actor.getEmail()).equals(AppUserService.normalizeEmail((String) account[1])))) {
                throw denied();
            }
        }
        requireDepartment(departmentId, true);

        var rows = em.createNativeQuery("""
                select active, version from employee_department_memberships
                where department_id = :department and user_id = :user for update
                """).setParameter("department", departmentId).setParameter("user", userId).getResultList();
        Object[] current = rows.isEmpty() ? null : (Object[]) rows.get(0);
        long version = current == null ? 0 : number(current[1]);
        Boolean previous = current == null ? null : active(current[0]);
        if (version != expectedVersion || (current == null && !requestedActive)) throw conflict();
        if (previous != null && previous == requestedActive) return version;

        long next = Math.addExact(version, 1);
        if (current == null) {
            em.createNativeQuery("""
                    insert into employee_department_memberships (department_id, user_id, active, version)
                    values (:department, :user, 1, :next)
                    """).setParameter("department", departmentId).setParameter("user", userId)
                    .setParameter("next", next).executeUpdate();
        } else if (em.createNativeQuery("""
                update employee_department_memberships set active = :active, version = :next
                where department_id = :department and user_id = :user and version = :expected
                """).setParameter("active", requestedActive ? 1 : 0).setParameter("next", next)
                .setParameter("department", departmentId).setParameter("user", userId)
                .setParameter("expected", version).executeUpdate() != 1) {
            throw conflict();
        }

        if (em.createNativeQuery("""
                insert into employee_department_membership_audit
                    (department_id, user_id, actor_user_id, old_active, new_active, membership_version, reason)
                values (:department, :user, :actor, :old, :active, :version, :reason)
                """).setParameter("department", departmentId).setParameter("user", userId)
                .setParameter("actor", actor.getId()).setParameter("old", previous == null ? null : previous ? 1 : 0)
                .setParameter("active", requestedActive ? 1 : 0).setParameter("version", next)
                .setParameter("reason", reason.trim()).executeUpdate() != 1) {
            throw new IllegalStateException("Department membership audit failed.");
        }
        return next;
    }

    private AppUser administrator() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()
                || !(authentication.getPrincipal() instanceof OidcUser oidc) || !Boolean.TRUE.equals(oidc.getEmailVerified())) {
            throw denied();
        }
        String email = AppUserService.normalizeEmail(oidc.getEmail());
        if (!administrators.contains(email)) throw denied();
        AppUser actor = users.getAuthenticatedUser();
        if (actor.getId() == null || !email.equals(AppUserService.normalizeEmail(actor.getEmail()))) throw denied();
        return actor;
    }

    private void requireDepartment(Long departmentId, boolean lock) {
        var rows = em.createNativeQuery("select active from employee_departments where id = :id" + (lock ? " for update" : ""))
                .setParameter("id", departmentId).getResultList();
        if (rows.size() != 1 || (lock && !active(rows.get(0)))) throw denied();
    }

    private static void requireId(Long id) {
        if (id == null || id <= 0) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A positive ID is required.");
    }

    private static boolean active(Object value) {
        return Boolean.TRUE.equals(value) || value instanceof Number number && number.intValue() == 1;
    }

    private static long number(Object value) {
        return ((Number) value).longValue();
    }

    private static AccessDeniedException denied() {
        return new AccessDeniedException("Access denied.");
    }

    private static ResponseStatusException conflict() {
        return new ResponseStatusException(HttpStatus.CONFLICT, "Membership changed. Reload and try again.");
    }

    private static ResponseStatusException tooMany() {
        return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Too many records to display safely.");
    }
}
