package com.pareidolia.incidentmanagement.security;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

/** Preliminary V2 single-account privilege diagnostic. This alone cannot enable the guard. */
public final class IncidentRuntimePrivilegeChecks {
    private IncidentRuntimePrivilegeChecks() { }
    static final String ROLE_SQL = "select current_role()";
    private static final String GRANTEE = "concat(char(39),substring_index(current_user(),'@',1),char(39),'@',char(39),substring_index(current_user(),'@',-1),char(39))";
    static final String TABLE_SQL = "select concat(table_name,'|',privilege_type,'|*') from information_schema.table_privileges where table_schema=database() and grantee=" + GRANTEE;
    static final String COLUMN_SQL = "select concat(table_name,'|',privilege_type,'|',column_name) from information_schema.column_privileges where table_schema=database() and grantee=" + GRANTEE;
    // Approved synthetic proof scope: optional email, oversight, referral and transfer writers disabled.
    static final Set<String> REQUIRED = Set.of(
            "app_users|SELECT|*",
            "app_users|INSERT|*",
            "app_users|UPDATE|active",
            "app_users|UPDATE|display_name",
            "app_users|UPDATE|email",
            "app_users|UPDATE|last_login_at",
            "app_users|UPDATE|role",
            "app_users|UPDATE|employee_id",
            "app_users|UPDATE|account_version",
            "assignment_admin_capabilities|SELECT|*",
            "assignment_admin_capabilities|INSERT|*",
            "assignment_admin_capabilities|UPDATE|active",
            "assignment_admin_capabilities|UPDATE|version",
            "assignment_admin_capability_audit|SELECT|*",
            "assignment_admin_capability_audit|INSERT|*",
            "department_head_designation_audit|SELECT|*",
            "department_head_designation_audit|INSERT|*",
            "department_head_designations|SELECT|*",
            "department_head_designations|INSERT|*",
            "department_head_designations|UPDATE|active",
            "department_head_designations|UPDATE|version",
            "employee_capability_administrators|SELECT|*",
            "employee_capability_administrators|UPDATE|active",
            "employee_department_membership_audit|SELECT|*",
            "employee_department_membership_audit|INSERT|*",
            "employee_department_memberships|SELECT|*",
            "employee_department_memberships|INSERT|*",
            "employee_department_memberships|UPDATE|active",
            "employee_department_memberships|UPDATE|version",
            "employee_departments|SELECT|*",
            "employee_departments|UPDATE|id",
            "employee_management_audit|SELECT|*",
            "employee_management_audit|INSERT|*",
            "employee_mapping_admin_audit|INSERT|*",
            "employee_mapping_admins|SELECT|*",
            "employee_mapping_admins|INSERT|*",
            "employee_mapping_admins|UPDATE|active",
            "handler_eligibility_audit|SELECT|*",
            "handler_eligibility_audit|INSERT|*",
            "handler_eligibility_grants|SELECT|*",
            "handler_eligibility_grants|INSERT|*",
            "handler_eligibility_grants|UPDATE|active",
            "handler_eligibility_grants|UPDATE|version",
            "hr_reassignment_referral_decision|SELECT|referral_id",
            "hr_reassignment_referral_intake|SELECT|id",
            "hr_referral_email_receipt|SELECT|referral_id",
            "incident_assignment_audit|SELECT|*",
            "incident_assignment_audit|INSERT|*",
            "incident_assignment_state|SELECT|*",
            "incident_assignment_state|INSERT|*",
            "incident_assignment_state|UPDATE|handler_user_id",
            "incident_assignment_state|UPDATE|assignment_version",
            "incident_attachments|SELECT|*",
            "incident_attachments|INSERT|*",
            "incident_classification_audit|SELECT|*",
            "incident_classification_audit|INSERT|*",
            "incident_department_detail_email_receipt|SELECT|incident_id",
            "incident_department_head_email_receipt|SELECT|incident_id",
            "incident_department_mail_recipient|SELECT|id",
            "incident_department_mail_recipient_audit|SELECT|recipient_id",
            "incident_department_transfer_audit|SELECT|id",
            "incident_global_view_audit|SELECT|id",
            "incident_history|SELECT|*",
            "incident_history|INSERT|*",
            "incident_oversight_notification|SELECT|id",
            "incident_security_classification|SELECT|*",
            "incident_security_classification|INSERT|*",
            "incident_security_classification|UPDATE|classification",
            "incident_security_classification|UPDATE|version",
            "incident_security_grant_audit|SELECT|*",
            "incident_security_grant_audit|INSERT|*",
            "incident_security_grants|SELECT|*",
            "incident_security_grants|INSERT|*",
            "incident_security_grants|UPDATE|active",
            "incident_security_grants|UPDATE|version",
            "incident_security_lock|SELECT|*",
            "incident_security_lock|UPDATE|id",
            "incident_transfer_handoff_approvals|SELECT|approval_reference",
            "incident_transfer_handoff_audit|SELECT|approval_reference",
            "incidents|SELECT|*",
            "incidents|INSERT|*",
            "incidents|UPDATE|incident_number",
            "incidents|UPDATE|reported_at",
            "incidents|UPDATE|reported_by",
            "incidents|UPDATE|reporter_department",
            "incidents|UPDATE|responsible_department_id",
            "incidents|UPDATE|desk_number",
            "incidents|UPDATE|title",
            "incidents|UPDATE|description",
            "incidents|UPDATE|issue_type",
            "incidents|UPDATE|category",
            "incidents|UPDATE|affected_system",
            "incidents|UPDATE|impacted_user_or_department",
            "incidents|UPDATE|severity",
            "incidents|UPDATE|priority",
            "incidents|UPDATE|assigned_owner",
            "incidents|UPDATE|status",
            "incidents|UPDATE|investigation_details",
            "incidents|UPDATE|root_cause",
            "incidents|UPDATE|actions_taken",
            "incidents|UPDATE|containment_action",
            "incidents|UPDATE|corrective_action",
            "incidents|UPDATE|escalation_required",
            "incidents|UPDATE|escalation_details",
            "incidents|UPDATE|resolution_details",
            "incidents|UPDATE|resolved_at",
            "incidents|UPDATE|validation_details",
            "incidents|UPDATE|validated_by",
            "incidents|UPDATE|validated_at",
            "incidents|UPDATE|closure_confirmed_by",
            "incidents|UPDATE|closed_at",
            "incidents|UPDATE|review_details",
            "incidents|UPDATE|reviewed_by",
            "incidents|UPDATE|reviewed_at",
            "incidents|UPDATE|evidence_reference",
            "incidents|UPDATE|lessons_learned",
            "incidents|UPDATE|preventive_action",
            "incidents|UPDATE|updated_at",
            "work_log_entries|SELECT|*",
            "work_log_entries|INSERT|*");

    public enum Result { VERIFIED_FOR_FURTHER_CHECKS, MISSING_PRIVILEGE, UNSUPPORTED_ROLE, UNAVAILABLE }

    // Additional columns used by the approved managed-recipient email paths.
    static final Set<String> EMAIL_REQUIRED = Set.of(
            "incident_department_mail_recipient|SELECT|department_id", "incident_department_mail_recipient|SELECT|email", "incident_department_mail_recipient|SELECT|active", "incident_department_mail_recipient|SELECT|version",
            "incident_department_head_email_receipt|SELECT|incident_id", "incident_department_head_email_receipt|SELECT|recipient_user_id", "incident_department_head_email_receipt|SELECT|status",
            "incident_department_head_email_receipt|INSERT|incident_id", "incident_department_head_email_receipt|INSERT|recipient_user_id", "incident_department_head_email_receipt|INSERT|status",
            "incident_department_head_email_receipt|UPDATE|status", "incident_department_head_email_receipt|UPDATE|finished_at",
            "incident_department_detail_email_receipt|SELECT|incident_id", "incident_department_detail_email_receipt|SELECT|recipient_user_id", "incident_department_detail_email_receipt|SELECT|status",
            "incident_department_detail_email_receipt|INSERT|incident_id", "incident_department_detail_email_receipt|INSERT|recipient_user_id", "incident_department_detail_email_receipt|INSERT|status",
            "incident_department_detail_email_receipt|UPDATE|status", "incident_department_detail_email_receipt|UPDATE|finished_at");

    /** Conservative: accepts direct table/column grants only, and rejects active roles. */
    public static Result inspect(JdbcTemplate jdbc) {
        return inspect(jdbc,false);
    }
    public static Result inspect(JdbcTemplate jdbc, boolean managedEmailEnabled) {
        if (jdbc == null || jdbc.getQueryTimeout() <= 0 || jdbc.getQueryTimeout() > 5) return Result.UNAVAILABLE;
        try {
            Result result = jdbc.execute((ConnectionCallback<Result>) connection -> {
                JdbcTemplate scoped = new JdbcTemplate(new SingleConnectionDataSource(connection, true));
                scoped.setQueryTimeout(jdbc.getQueryTimeout());
                return inspectOnConnection(scoped,managedEmailEnabled);
            });
            return result == null ? Result.UNAVAILABLE : result;
        } catch (DataAccessException ex) {
            return Result.UNAVAILABLE;
        }
    }

    static Result inspectOnConnection(JdbcTemplate jdbc) {
        return inspectOnConnection(jdbc,false);
    }
    static Result inspectOnConnection(JdbcTemplate jdbc, boolean managedEmailEnabled) {
        try {
            if (!"NONE".equals(jdbc.queryForObject(ROLE_SQL, String.class))) return Result.UNSUPPORTED_ROLE;
            Set<String> privileges = new HashSet<>(jdbc.queryForList(TABLE_SQL, String.class));
            privileges.addAll(jdbc.queryForList(COLUMN_SQL, String.class));
            Set<String> requiredPrivileges=new HashSet<>(REQUIRED);
            if (managedEmailEnabled) requiredPrivileges.addAll(EMAIL_REQUIRED);
            for (String required : requiredPrivileges) {
                int separator = required.lastIndexOf('|');
                if (!privileges.contains(required) && !privileges.contains(required.substring(0, separator + 1) + "*"))
                    return Result.MISSING_PRIVILEGE;
            }
            return Result.VERIFIED_FOR_FURTHER_CHECKS;
        } catch (DataAccessException ex) {
            return Result.UNAVAILABLE;
        }
    }
}
