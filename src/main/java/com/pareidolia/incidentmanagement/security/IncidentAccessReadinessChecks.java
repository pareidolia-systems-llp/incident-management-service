package com.pareidolia.incidentmanagement.security;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.dao.DataAccessException;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/** Read-only diagnostics only. Passing these checks does not permit activation. */
public final class IncidentAccessReadinessChecks {
    static final Set<String> REQUIRED_TABLES = Set.of(
            "app_users", "incidents", "incident_attachments", "incident_history", "work_log_entries",
            "employee_departments", "employee_mapping_admins", "department_head_designations",
            "department_head_designation_audit", "employee_capability_administrators", "employee_mapping_admin_audit",
            "employee_management_audit", "handler_eligibility_grants", "handler_eligibility_audit",
            "employee_department_memberships", "employee_department_membership_audit",
            "incident_security_classification", "incident_classification_audit", "assignment_admin_capabilities",
            "assignment_admin_capability_audit", "incident_security_grants", "incident_security_grant_audit",
            "incident_global_view_audit", "incident_security_lock", "incident_assignment_state",
            "incident_assignment_audit", "incident_department_transfer_audit", "incident_transfer_handoff_approvals",
            "incident_transfer_handoff_audit", "hr_reassignment_referral_intake", "hr_reassignment_referral_decision",
            "hr_referral_email_receipt", "incident_department_head_email_receipt", "incident_oversight_notification",
            "incident_department_mail_recipient", "incident_department_mail_recipient_audit",
            "incident_department_detail_email_receipt");
    static final String TABLES_SQL = "select table_name from information_schema.tables where table_schema=database() and table_type='BASE TABLE' and engine='InnoDB'";
    static final String LOCK_SQL = "select count(*) from incident_security_lock where id=1";
    static final String LOCK_TOTAL_SQL = "select count(*) from incident_security_lock";
    static final String DEPARTMENTS_SQL = "select display_name from employee_departments where active=1";
    static final String CLASSIFICATION_SQL = """
            select count(*) from incidents i left join incident_security_classification c on c.incident_id=i.id
            where c.incident_id is null or c.version is null or c.classification is null
              or not ((binary c.classification='UNCLASSIFIED' and c.version=0)
                   or (binary c.classification in ('STANDARD','RESTRICTED') and c.version>0))
            """;
    static final String HR_HANDLER_SQL = """
            select count(*) from app_users u
            join handler_eligibility_grants h on h.user_id=u.id and h.active=1
            join employee_department_memberships m on m.user_id=u.id and m.active=1
            join employee_departments d on d.id=m.department_id and d.active=1
            where u.id=? and u.active=1 and u.role in ('IT_HANDLER','ADMIN')
              and u.employee_id is not null and trim(u.employee_id)<>''
              and binary d.display_name in ('HR','Human Resources')
              and locate('@',trim(u.email))>1
              and length(trim(u.email))-length(replace(trim(u.email),'@',''))=1
              and lower(substring_index(trim(u.email),'@',-1))=lower(?)
            """;
    private static final Set<String> DEPARTMENTS = Set.of("IT", "HR", "Operations (Annotation)",
            "Operations (Perioperative Flow Analysis)", "R&D");

    public enum Result { READY_FOR_FURTHER_CHECKS, UNSUPPORTED_DATABASE, MISSING_TABLES,
        INVALID_SECURITY_LOCK, INVALID_DEPARTMENTS, INVALID_CLASSIFICATIONS,
        HR_HANDLER_UNAVAILABLE, INVALID_TIMEOUT, UNSAFE_CONFIGURATION, UNAVAILABLE }

    private IncidentAccessReadinessChecks() { }

    /** Preliminary configuration checks only; does not verify OAuth or permit activation. */
    public static Result inspectConfiguration(Environment env) {
        if (!env.getProperty("app.incident-access.enabled", Boolean.class, false)
                || !env.getProperty("app.incident-assignment.enabled", Boolean.class, false)
                || !env.getProperty("app.employee-management.enabled", Boolean.class, false)
                || !"validate".equalsIgnoreCase(env.getProperty("spring.jpa.hibernate.ddl-auto", "").trim())
                || !"never".equalsIgnoreCase(env.getProperty("spring.sql.init.mode", "").trim())) {
            return Result.UNSAFE_CONFIGURATION;
        }
        return Result.READY_FOR_FURTHER_CHECKS;
    }

    /** Holds the same writer gate as security changes for one rollback-only diagnostic snapshot. */
    public static Result inspectCoordinated(JdbcTemplate jdbc, Set<Long> configuredHrAccountIds, String allowedDomain) {
        if (jdbc.getQueryTimeout() <= 0 || jdbc.getQueryTimeout() > 5) return Result.INVALID_TIMEOUT;
        if (jdbc.getDataSource() == null) return Result.UNAVAILABLE;
        try {
            var transaction = new TransactionTemplate(new DataSourceTransactionManager(jdbc.getDataSource()));
            transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
            transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
            transaction.setTimeout(10);
            Result result = transaction.execute(status -> {
                try {
                    Long row = jdbc.queryForObject("select id from incident_security_lock where id=1 for update", Long.class);
                    return Long.valueOf(1).equals(row) ? inspect(jdbc, configuredHrAccountIds, allowedDomain) : Result.INVALID_SECURITY_LOCK;
                } finally {
                    status.setRollbackOnly();
                }
            });
            return result == null ? Result.UNAVAILABLE : result;
        } catch (DataAccessException | TransactionException ex) {
            return Result.UNAVAILABLE;
        }
    }

    /** Diagnostic queries require a per-statement timeout; connection acquisition is not bounded here. */
    public static Result inspect(JdbcTemplate jdbc, Set<Long> configuredHrAccountIds, String allowedDomain) {
        try {
            if (jdbc.getQueryTimeout() <= 0 || jdbc.getQueryTimeout() > 5) return Result.INVALID_TIMEOUT;
            if (configuredHrAccountIds == null || configuredHrAccountIds.isEmpty()
                    || configuredHrAccountIds.stream().anyMatch(id -> id == null || id <= 0)
                    || allowedDomain == null || allowedDomain.isBlank()) return Result.HR_HANDLER_UNAVAILABLE;
            String product = jdbc.execute((org.springframework.jdbc.core.ConnectionCallback<String>)
                    connection -> connection.getMetaData().getDatabaseProductName());
            if (!"MySQL".equalsIgnoreCase(product)) return Result.UNSUPPORTED_DATABASE;
            List<String> tables = jdbc.queryForList(TABLES_SQL, String.class);
            if (!new HashSet<>(tables).containsAll(REQUIRED_TABLES)) return Result.MISSING_TABLES;
            if (!Long.valueOf(1).equals(jdbc.queryForObject(LOCK_SQL, Long.class))
                    || !Long.valueOf(1).equals(jdbc.queryForObject(LOCK_TOTAL_SQL, Long.class)))
                return Result.INVALID_SECURITY_LOCK;
            Set<String> departments = new HashSet<>();
            for (String value : jdbc.queryForList(DEPARTMENTS_SQL, String.class)) {
                String normalized = "Human Resources".equals(value) ? "HR" : value;
                if (DEPARTMENTS.contains(normalized) && !departments.add(normalized))
                    return Result.INVALID_DEPARTMENTS;
            }
            if (!departments.containsAll(DEPARTMENTS)) return Result.INVALID_DEPARTMENTS;
            if (!Long.valueOf(0).equals(jdbc.queryForObject(CLASSIFICATION_SQL, Long.class)))
                return Result.INVALID_CLASSIFICATIONS;
            boolean hrAvailable = false;
            for (Long id : configuredHrAccountIds) {
                if (Long.valueOf(1).equals(jdbc.queryForObject(HR_HANDLER_SQL, Long.class, id, allowedDomain.trim()))) {
                    hrAvailable = true;
                    break;
                }
            }
            if (!hrAvailable) return Result.HR_HANDLER_UNAVAILABLE;
            return Result.READY_FOR_FURTHER_CHECKS;
        } catch (DataAccessException ex) {
            return Result.UNAVAILABLE;
        }
    }
}
