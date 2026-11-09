package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.dto.ActiveEmployeeEmailResponse;
import com.pareidolia.incidentmanagement.repository.AppUserRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import com.pareidolia.incidentmanagement.security.IncidentReadSnapshot;
import com.pareidolia.incidentmanagement.security.IncidentSecurityGate;
import jakarta.persistence.EntityManager;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import javax.sql.DataSource;
import org.springframework.beans.factory.ObjectProvider;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@Service
@ConditionalOnProperty(name = "app.department-membership-admin.enabled", havingValue = "true")
public class DepartmentMembershipAdminService {
    public record Membership(long departmentId, long userId, String name, String email, boolean active, long version) { }
    public record Audit(long departmentId, long userId, long actorUserId, Boolean oldActive, boolean newActive,
                        long version, String reason, String changedAt) { }

    private final EntityManager em;
    private final AppUserService users;
    private final AppUserRepository accounts;
    private final IncidentSecurityGate gate;
    private final IncidentReadSnapshot snapshot;
    private final Set<String> administrators;
    private final JdbcClient ordinaryJdbc;
    private final TransactionTemplate ordinaryTransaction;
    private final MembershipCommandConnection commandConnection;

    public DepartmentMembershipAdminService(EntityManager em, AppUserService users, AppUserRepository accounts, IncidentSecurityGate gate,
            IncidentReadSnapshot snapshot, DataSource ordinaryDataSource, PlatformTransactionManager transactionManager,
            ObjectProvider<MembershipCommandConnection> commandConnection,
            @Value("${app.department-membership-admin.allowed-emails:}") String configured) {
        this.em = em;
        this.users = users;
        this.accounts = accounts;
        this.gate = gate;
        this.snapshot = snapshot;
        this.ordinaryJdbc = JdbcClient.create(ordinaryDataSource);
        this.ordinaryTransaction = new TransactionTemplate(transactionManager);
        this.commandConnection = commandConnection.getIfAvailable();
        this.administrators = Arrays.stream(configured.split(",")).map(AppUserService::normalizeEmail)
                .filter(email -> !email.isEmpty()).collect(Collectors.toUnmodifiableSet());
    }

    public record Department(long id, String name) { }

    public List<Department> departments() {
        return snapshot.read(() -> {
            administrator();
            @SuppressWarnings("unchecked")
            List<Object[]> rows = em.createNativeQuery("""
                    select id, display_name from employee_departments
                    where active = 1 order by display_name, id
                    """).setMaxResults(501).getResultList();
            if (rows.size() > 500) throw tooMany();
            return rows.stream().map(row -> new Department(number(row[0]), (String) row[1])).toList();
        });
    }

    public List<ActiveEmployeeEmailResponse> searchEmployees(String search) {
        return snapshot.read(() -> {
            AppUser actor = administrator();
            String term = search == null ? "" : search.trim();
            if (term.length() < 2 || term.length() > 255) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Enter at least two email characters.");
            }
            return accounts.findByActiveTrueAndEmailContainingIgnoreCase(term,
                    PageRequest.of(0, 10, Sort.by("email", "id"))).getContent().stream()
                    .filter(user -> !actor.getId().equals(user.getId()))
                    .map(user -> new ActiveEmployeeEmailResponse(user.getId(), user.getDisplayName(), user.getEmail()))
                    .toList();
        });
    }

    public List<Membership> list(Long departmentId) {
        requireId(departmentId);
        return snapshot.read(() -> {
            administrator();
            requireDepartment(departmentId);
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

    public long change(Long departmentId, Long userId, boolean requestedActive, Long expectedVersion, String reason) {
        requireId(departmentId);
        requireId(userId);
        if (expectedVersion == null || expectedVersion < 0 || reason == null || reason.isBlank() || reason.length() > 500) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A version and a reason are required.");
        }
        String email = administratorEmail();
        if (commandConnection != null) {
            return commandConnection.execute(jdbc ->
                    change(jdbc, " for share", email, departmentId, userId, requestedActive, expectedVersion, reason.trim()));
        }
        return ordinaryTransaction.execute(status -> {
            gate.write();
            return change(ordinaryJdbc, gate.sharedClause(), email, departmentId, userId, requestedActive,
                    expectedVersion, reason.trim());
        });
    }

    private long change(JdbcClient jdbc, String sharedLock, String email, long departmentId, long userId,
            boolean requestedActive, long expectedVersion, String reason) {
        var actor = jdbc.sql("select id, email, active from app_users where email = :email" + sharedLock)
                .param("email", email)
                .query((row, index) -> new Account(row.getLong("id"), row.getString("email"), row.getBoolean("active")))
                .optional().orElseThrow(DepartmentMembershipAdminService::denied);
        if (!actor.active() || !email.equals(AppUserService.normalizeEmail(actor.email())) || actor.id() == userId) {
            throw denied();
        }

        requireActive(jdbc, "select active from app_users where id = :id" + sharedLock, userId);
        requireActive(jdbc, "select active from employee_departments where id = :id" + sharedLock, departmentId);
        var current = jdbc.sql("""
                select active, version from employee_department_memberships
                where department_id = :department and user_id = :user for update
                """).param("department", departmentId).param("user", userId)
                .query((row, index) -> new MembershipState(row.getBoolean("active"), row.getLong("version")))
                .optional().orElse(null);
        long version = current == null ? 0 : current.version();
        Boolean previous = current == null ? null : current.active();
        if (version != expectedVersion || (current == null && !requestedActive)) throw conflict();
        if (previous != null && previous == requestedActive) return version;

        long next = Math.addExact(version, 1);
        int changed = current == null
                ? jdbc.sql("""
                    insert into employee_department_memberships (department_id, user_id, active, version)
                    values (:department, :user, 1, :next)
                    """).param("department", departmentId).param("user", userId).param("next", next).update()
                : jdbc.sql("""
                    update employee_department_memberships set active = :active, version = :next
                    where department_id = :department and user_id = :user and version = :expected
                    """).param("active", requestedActive ? 1 : 0).param("next", next)
                        .param("department", departmentId).param("user", userId).param("expected", version).update();
        if (changed != 1) throw conflict();

        if (jdbc.sql("""
                insert into employee_department_membership_audit
                    (department_id, user_id, actor_user_id, old_active, new_active, membership_version, reason)
                values (:department, :user, :actor, :old, :active, :version, :reason)
                """).param("department", departmentId).param("user", userId)
                .param("actor", actor.id()).param("old", previous == null ? null : previous ? 1 : 0, java.sql.Types.TINYINT)
                .param("active", requestedActive ? 1 : 0).param("version", next).param("reason", reason).update() != 1) {
            throw new IllegalStateException("Department membership audit failed.");
        }
        return next;
    }

    private record Account(long id, String email, boolean active) { }
    private record MembershipState(boolean active, long version) { }

    private static void requireActive(JdbcClient jdbc, String sql, long id) {
        if (!jdbc.sql(sql).param("id", id).query((row, index) -> row.getBoolean("active")).optional().orElse(false)) {
            throw denied();
        }
    }

    private String administratorEmail() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()
                || !(authentication.getPrincipal() instanceof OidcUser oidc) || !Boolean.TRUE.equals(oidc.getEmailVerified())) {
            throw denied();
        }
        String email = AppUserService.normalizeEmail(oidc.getEmail());
        if (!administrators.contains(email)) throw denied();
        return email;
    }

    private AppUser administrator() {
        String email = administratorEmail();
        AppUser actor = users.getAuthenticatedUser();
        if (actor.getId() == null || !email.equals(AppUserService.normalizeEmail(actor.getEmail()))) throw denied();
        return actor;
    }

    private void requireDepartment(Long departmentId) {
        var rows = em.createNativeQuery("select id from employee_departments where id = :id")
                .setParameter("id", departmentId).getResultList();
        if (rows.size() != 1) throw denied();
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
