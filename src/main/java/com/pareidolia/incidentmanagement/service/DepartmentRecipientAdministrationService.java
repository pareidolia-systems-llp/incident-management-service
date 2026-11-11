package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.security.EmployeeManagementAccess;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@ConditionalOnProperty(name = "app.notifications.email.recipient-administration.enabled", havingValue = "true")
public class DepartmentRecipientAdministrationService {
    public record Department(long id, String name) { }
    public record Recipient(String id, long departmentId, String departmentName, String email, boolean active, long version) { }
    public record Directory(List<Department> departments, List<Recipient> recipients) { }
    public record Audit(long actorUserId, String oldEmail, String newEmail, Boolean oldActive, boolean newActive,
                        long version, String reason, LocalDateTime changedAt) { }

    private final JdbcTemplate jdbc;
    private final AppUserService users;
    private final EmployeeManagementAccess access;

    public DepartmentRecipientAdministrationService(JdbcTemplate jdbc, AppUserService users, EmployeeManagementAccess access) {
        this.jdbc = jdbc;
        this.users = users;
        this.access = access;
    }

    @Transactional(readOnly = true)
    public Directory list() {
        administrator(false);
        var departments = jdbc.query("select id, display_name from employee_departments where active=true order by display_name",
                (row, index) -> new Department(row.getLong(1), ResponsibleDepartments.displayName(row.getString(2)))).stream()
                .filter(department -> ResponsibleDepartments.includes(department.name())).toList();
        var recipients = jdbc.query("""
                select r.id, r.department_id, d.display_name, r.email, r.active, r.version
                from incident_department_mail_recipient r join employee_departments d on d.id=r.department_id
                order by d.display_name, r.email
                """, (row, index) -> new Recipient(row.getString(1), row.getLong(2), row.getString(3),
                        row.getString(4), row.getBoolean(5), row.getLong(6)));
        return new Directory(departments, recipients);
    }

    @Transactional(readOnly = true)
    public List<Audit> history(UUID id) {
        administrator(false);
        return jdbc.query("""
                select actor_user_id, old_email, new_email, old_active, new_active, version, reason, changed_at
                from incident_department_mail_recipient_audit where recipient_id=? order by version desc limit 200
                """, (row, index) -> new Audit(row.getLong(1), row.getString(2), row.getString(3),
                        row.getObject(4, Boolean.class), row.getBoolean(5), row.getLong(6), row.getString(7),
                        row.getObject(8, LocalDateTime.class)), id.toString());
    }

    @Transactional
    public UUID add(long departmentId, String email, String reason) {
        long actor = administrator(true);
        requireReason(reason);
        String address = validatedAddress(email);
        var names = jdbc.queryForList("select display_name from employee_departments where id=? and active=true for update",
                String.class, departmentId);
        if (names.size() != 1 || !ResponsibleDepartments.includes(names.get(0))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Select an active responsible department.");
        }
        UUID id = UUID.randomUUID();
        try {
            jdbc.update("""
                    insert into incident_department_mail_recipient(id,department_id,email,active,version) values (?,?,?,true,0)
                    """, id.toString(), departmentId, address);
        } catch (DuplicateKeyException duplicate) {
            throw conflict();
        }
        audit(id, actor, null, address, null, true, 0, reason);
        return id;
    }

    @Transactional
    public void update(UUID id, String email, boolean active, long expectedVersion, String reason) {
        long actor = administrator(true);
        requireReason(reason);
        String address = validatedAddress(email);
        var rows = jdbc.query("""
                select r.id, r.department_id, d.display_name, r.email, r.active, r.version
                from incident_department_mail_recipient r join employee_departments d on d.id=r.department_id
                where r.id=? for update
                """, (row, index) -> new Recipient(row.getString(1), row.getLong(2), row.getString(3),
                        row.getString(4), row.getBoolean(5), row.getLong(6)), id.toString());
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        var previous = rows.get(0);
        if (previous.version() != expectedVersion) throw conflict();
        if (previous.active() == active && previous.email().equals(address)) return;
        if (active && (!ResponsibleDepartments.includes(previous.departmentName())
                || !Boolean.TRUE.equals(jdbc.queryForObject("select active from employee_departments where id=?",
                        Boolean.class, previous.departmentId())))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Select an active responsible department.");
        }
        long version = Math.addExact(expectedVersion, 1);
        try {
            if (jdbc.update("""
                    update incident_department_mail_recipient set email=?,active=?,version=? where id=? and version=?
                    """, address, active, version, id.toString(), expectedVersion) != 1) throw conflict();
        } catch (DuplicateKeyException duplicate) {
            throw conflict();
        }
        audit(id, actor, previous.email(), address, previous.active(), active, version, reason);
    }

    private long administrator(boolean lock) {
        var actor = users.getAuthenticatedUser();
        if (actor == null || actor.getId() == null || !access.canManage(actor)) {
            throw new AccessDeniedException("Recipient administration is unavailable.");
        }
        var emails = jdbc.queryForList("""
                select u.email from app_users u join employee_mapping_admins a on a.user_id=u.id
                where u.id=? and u.active=true and a.active=true
                """ + (lock ? " for update" : ""), String.class, actor.getId());
        if (emails.size() != 1 || !AppUserService.normalizeEmail(emails.get(0)).equals(AppUserService.normalizeEmail(actor.getEmail()))) {
            throw new AccessDeniedException("Recipient administration is unavailable.");
        }
        return actor.getId();
    }

    private static void requireReason(String reason) {
        if (reason == null || reason.isBlank() || reason.length() > 500) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A change reason is required.");
        }
    }

    private void audit(UUID id, long actor, String oldEmail, String email, Boolean oldActive, boolean active, long version, String reason) {
        jdbc.update("""
                insert into incident_department_mail_recipient_audit
                    (recipient_id,actor_user_id,old_email,new_email,old_active,new_active,version,reason)
                values (?,?,?,?,?,?,?,?)
                """, id.toString(), actor, oldEmail, email, oldActive, active, version, reason.strip());
    }

    private static String validatedAddress(String input) {
        String email = AppUserService.normalizeEmail(input);
        try {
            var address = new InternetAddress(email, true);
            address.validate();
            if (email.length() <= 254 && email.equals(address.getAddress()) && !address.isGroup()) return email;
        } catch (AddressException invalid) {
            // Return the same response for any invalid mailbox.
        }
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Enter one valid recipient email address.");
    }

    private static ResponseStatusException conflict() {
        return new ResponseStatusException(HttpStatus.CONFLICT, "The recipient changed or the address is already configured.");
    }
}
