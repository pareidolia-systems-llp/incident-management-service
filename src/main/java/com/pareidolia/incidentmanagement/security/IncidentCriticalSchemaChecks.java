package com.pareidolia.incidentmanagement.security;

import java.util.HashSet;
import java.util.Set;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

/** Preliminary checks for migration-defined security structures; not activation authorization. */
public final class IncidentCriticalSchemaChecks {
    private IncidentCriticalSchemaChecks() { }
    static final String COLUMNS = "select concat(table_name,'|',column_name,'|',column_type,'|',is_nullable) from information_schema.columns where table_schema=database()";
    static final String INDEXES = "select concat(table_name,'|',index_name,'|',non_unique,'|',seq_in_index,'|',column_name,'|',coalesce(cast(sub_part as char),'FULL')) from information_schema.statistics where table_schema=database()";
    static final String FOREIGN_KEYS = "select concat(k.table_name,'|',k.constraint_name,'|',k.ordinal_position,'|',k.column_name,'|',k.referenced_table_name,'|',k.referenced_column_name,'|',r.delete_rule,'|',r.update_rule) from information_schema.key_column_usage k join information_schema.referential_constraints r on r.constraint_schema=k.constraint_schema and r.table_name=k.table_name and r.constraint_name=k.constraint_name where k.constraint_schema=database() and k.referenced_table_schema=database() and k.referenced_table_name is not null";
    static final String CHECKS = "select concat(t.table_name,'|',t.constraint_name,'|',t.enforced,'|',c.check_clause) from information_schema.table_constraints t join information_schema.check_constraints c on c.constraint_schema=t.constraint_schema and c.constraint_name=t.constraint_name where t.constraint_schema=database() and t.constraint_type='CHECK'";
    static final Set<String> REQUIRED_COLUMNS = Set.of(
        "app_users|id|bigint|NO", "app_users|active|bit(1)|NO", "app_users|email|varchar(255)|NO", "app_users|employee_id|varchar(64)|YES", "app_users|account_version|bigint|NO",
        "incident_security_lock|id|bigint|NO",
        "incident_security_classification|incident_id|bigint|NO", "incident_security_classification|classification|varchar(20)|NO", "incident_security_classification|version|bigint|NO",
        "incident_security_grants|incident_id|bigint|NO", "incident_security_grants|user_id|bigint|NO", "incident_security_grants|permission|varchar(20)|NO", "incident_security_grants|active|tinyint|NO", "incident_security_grants|version|bigint|NO",
        "incident_security_grant_audit|incident_id|bigint|NO", "incident_security_grant_audit|target_user_id|bigint|NO", "incident_security_grant_audit|permission|varchar(20)|NO", "incident_security_grant_audit|version|bigint|NO", "incident_security_grant_audit|reason|varchar(500)|NO",
        "incident_assignment_state|incident_id|bigint|NO", "incident_assignment_state|handler_user_id|bigint|YES", "incident_assignment_state|assignment_version|bigint|NO",
        "incident_assignment_audit|incident_id|bigint|NO", "incident_assignment_audit|assignment_version|bigint|NO", "incident_assignment_audit|reason|varchar(500)|NO",
        "employee_department_memberships|department_id|bigint|NO", "employee_department_memberships|user_id|bigint|NO", "employee_department_memberships|active|tinyint|NO", "employee_department_memberships|version|bigint|NO",
        "handler_eligibility_grants|user_id|bigint|NO", "handler_eligibility_grants|active|tinyint|NO", "handler_eligibility_grants|version|bigint|NO",
        "department_head_designations|department_id|bigint|NO", "department_head_designations|user_id|bigint|NO", "department_head_designations|active|tinyint|NO", "department_head_designations|version|bigint|NO",
        "assignment_admin_capabilities|user_id|bigint|NO", "assignment_admin_capabilities|capability|varchar(40)|NO", "assignment_admin_capabilities|active|tinyint|NO", "assignment_admin_capabilities|version|bigint|NO",
        "incident_department_mail_recipient|id|char(36)|NO", "incident_department_mail_recipient|department_id|bigint|NO", "incident_department_mail_recipient|email|varchar(254)|NO", "incident_department_mail_recipient|active|tinyint(1)|NO", "incident_department_mail_recipient|version|bigint|NO",
        "incident_department_head_email_receipt|incident_id|bigint|NO", "incident_department_head_email_receipt|recipient_user_id|bigint|NO", "incident_department_head_email_receipt|status|varchar(10)|NO",
        "incident_department_detail_email_receipt|incident_id|bigint|NO", "incident_department_detail_email_receipt|recipient_user_id|bigint|NO", "incident_department_detail_email_receipt|status|varchar(10)|NO");
    static final Set<String> REQUIRED_INDEXES = Set.of(
        "incident_security_lock|PRIMARY|0|1|id|FULL", "incident_security_classification|PRIMARY|0|1|incident_id|FULL",
        "incident_security_grants|PRIMARY|0|1|incident_id|FULL", "incident_security_grants|PRIMARY|0|2|user_id|FULL", "incident_security_grants|PRIMARY|0|3|permission|FULL",
        "incident_security_grant_audit|uk_isga_version|0|1|incident_id|FULL", "incident_security_grant_audit|uk_isga_version|0|2|target_user_id|FULL", "incident_security_grant_audit|uk_isga_version|0|3|permission|FULL", "incident_security_grant_audit|uk_isga_version|0|4|version|FULL",
        "incident_assignment_state|PRIMARY|0|1|incident_id|FULL", "incident_assignment_state|idx_assignment_handler|1|1|handler_user_id|FULL",
        "incident_assignment_audit|uk_assignment_audit_version|0|1|incident_id|FULL", "incident_assignment_audit|uk_assignment_audit_version|0|2|assignment_version|FULL",
        "incidents|idx_incidents_security_created|1|1|created_at|FULL", "incidents|idx_incidents_security_created|1|2|id|FULL",
        "employee_department_memberships|PRIMARY|0|1|department_id|FULL", "employee_department_memberships|PRIMARY|0|2|user_id|FULL",
        "handler_eligibility_grants|PRIMARY|0|1|user_id|FULL", "department_head_designations|PRIMARY|0|1|department_id|FULL", "department_head_designations|PRIMARY|0|2|user_id|FULL",
        "assignment_admin_capabilities|PRIMARY|0|1|user_id|FULL", "assignment_admin_capabilities|PRIMARY|0|2|capability|FULL",
        "incident_department_mail_recipient|PRIMARY|0|1|id|FULL", "incident_department_mail_recipient|uk_department_mail_address|0|1|department_id|FULL", "incident_department_mail_recipient|uk_department_mail_address|0|2|email|FULL",
        "incident_department_head_email_receipt|PRIMARY|0|1|incident_id|FULL", "incident_department_head_email_receipt|PRIMARY|0|2|recipient_user_id|FULL",
        "incident_department_detail_email_receipt|PRIMARY|0|1|incident_id|FULL", "incident_department_detail_email_receipt|PRIMARY|0|2|recipient_user_id|FULL",
        "employee_department_membership_audit|uk_membership_audit_version|0|1|department_id|FULL", "employee_department_membership_audit|uk_membership_audit_version|0|2|user_id|FULL", "employee_department_membership_audit|uk_membership_audit_version|0|3|membership_version|FULL",
        "incident_classification_audit|uk_ica_version|0|1|incident_id|FULL", "incident_classification_audit|uk_ica_version|0|2|version|FULL",
        "assignment_admin_capability_audit|uk_aaca_version|0|1|target_user_id|FULL", "assignment_admin_capability_audit|uk_aaca_version|0|2|capability|FULL", "assignment_admin_capability_audit|uk_aaca_version|0|3|version|FULL");
    static final Set<String> REQUIRED_FKS = Set.of(
        "incident_security_classification|fk_isc_incident|1|incident_id|incidents|id|RESTRICT|RESTRICT",
        "incident_security_grants|fk_isg_incident|1|incident_id|incidents|id|RESTRICT|RESTRICT", "incident_security_grants|fk_isg_user|1|user_id|app_users|id|RESTRICT|RESTRICT",
        "incident_security_grant_audit|fk_isga_grant|1|incident_id|incident_security_grants|incident_id|RESTRICT|RESTRICT", "incident_security_grant_audit|fk_isga_grant|2|target_user_id|incident_security_grants|user_id|RESTRICT|RESTRICT", "incident_security_grant_audit|fk_isga_grant|3|permission|incident_security_grants|permission|RESTRICT|RESTRICT",
        "incident_assignment_state|fk_assignment_incident|1|incident_id|incidents|id|RESTRICT|RESTRICT", "incident_assignment_state|fk_assignment_handler|1|handler_user_id|app_users|id|RESTRICT|RESTRICT",
        "employee_department_memberships|fk_membership_department|1|department_id|employee_departments|id|RESTRICT|RESTRICT", "employee_department_memberships|fk_membership_user|1|user_id|app_users|id|RESTRICT|RESTRICT",
        "handler_eligibility_grants|fk_handler_eligibility_user|1|user_id|app_users|id|RESTRICT|RESTRICT", "department_head_designations|fk_head_designations_department|1|department_id|employee_departments|id|RESTRICT|RESTRICT", "department_head_designations|fk_head_designations_user|1|user_id|app_users|id|RESTRICT|RESTRICT",
        "assignment_admin_capabilities|fk_aac_user|1|user_id|app_users|id|RESTRICT|RESTRICT",
        "incident_department_mail_recipient|fk_department_mail_department|1|department_id|employee_departments|id|NO ACTION|NO ACTION",
        "incident_department_head_email_receipt|fk_head_email_incident|1|incident_id|incidents|id|NO ACTION|NO ACTION", "incident_department_head_email_receipt|fk_head_email_recipient|1|recipient_user_id|app_users|id|NO ACTION|NO ACTION",
        "incident_department_detail_email_receipt|fk_detail_email_incident|1|incident_id|incidents|id|NO ACTION|NO ACTION", "incident_department_detail_email_receipt|fk_detail_email_recipient|1|recipient_user_id|app_users|id|NO ACTION|NO ACTION",
        "employee_department_membership_audit|fk_membership_audit_membership|1|department_id|employee_department_memberships|department_id|RESTRICT|RESTRICT", "employee_department_membership_audit|fk_membership_audit_membership|2|user_id|employee_department_memberships|user_id|RESTRICT|RESTRICT",
        "incident_classification_audit|fk_ica_classification|1|incident_id|incident_security_classification|incident_id|RESTRICT|RESTRICT",
        "assignment_admin_capability_audit|fk_aaca_capability|1|target_user_id|assignment_admin_capabilities|user_id|RESTRICT|RESTRICT", "assignment_admin_capability_audit|fk_aaca_capability|2|capability|assignment_admin_capabilities|capability|RESTRICT|RESTRICT");
    // Canonicalized expressions from the reviewed MySQL migrations; unsupported equivalents fail closed.
    static final Set<String> REQUIRED_CHECKS = Set.of(
        "incident_security_lock|ck_incident_security_lock_singleton|yes|id=1",
        "incident_security_classification|ck_isc_value|yes|classificationin('UNCLASSIFIED','STANDARD','RESTRICTED')", "incident_security_classification|ck_isc_version|yes|version>=0",
        "incident_security_grants|ck_isg_permission|yes|permissionin('VIEW','HANDLE','MODIFY','REPORT','ASSIGN')", "incident_security_grants|ck_isg_active|yes|activein(0,1)", "incident_security_grants|ck_isg_version|yes|version>=0",
        "incident_assignment_state|ck_assignment_version|yes|assignment_version>=0",
        "incident_assignment_audit|ck_assignment_action|yes|action_typein('INITIAL','REASSIGN')", "incident_assignment_audit|ck_assignment_reason|yes|char_length(trim(reason))>0",
        "employee_department_memberships|ck_department_membership_active|yes|activein(0,1)", "employee_department_memberships|ck_department_membership_version|yes|version>=0",
        "handler_eligibility_grants|ck_handler_eligibility_active|yes|activein(0,1)", "handler_eligibility_grants|ck_handler_eligibility_version|yes|version>=0",
        "department_head_designations|ck_head_designations_active|yes|activein(0,1)", "department_head_designations|ck_head_designations_version|yes|version>=0",
        "assignment_admin_capabilities|ck_aac_active|yes|activein(0,1)", "assignment_admin_capabilities|ck_aac_version|yes|version>=0",
        "incident_department_head_email_receipt|ck_head_email_status|yes|statusin('CLAIMED','SENT','UNCERTAIN')", "incident_department_detail_email_receipt|ck_detail_email_status|yes|statusin('CLAIMED','SENT','UNCERTAIN')");
    public enum Result { VERIFIED_FOR_FURTHER_CHECKS, INVALID_SCHEMA, UNAVAILABLE }
    public static Result inspect(JdbcTemplate jdbc) {
        if (jdbc == null || jdbc.getQueryTimeout() <= 0 || jdbc.getQueryTimeout() > 5) return Result.UNAVAILABLE;
        try {
            Result result=jdbc.execute((ConnectionCallback<Result>) connection -> {
                var scoped=new JdbcTemplate(new SingleConnectionDataSource(connection,true));
                scoped.setQueryTimeout(jdbc.getQueryTimeout());
                return inspectOnConnection(scoped);
            });
            return result == null ? Result.UNAVAILABLE : result;
        } catch (DataAccessException ex) { return Result.UNAVAILABLE; }
    }
    static Result inspectOnConnection(JdbcTemplate jdbc) {
        try {
            Set<String> indexes=new HashSet<>(jdbc.queryForList(INDEXES,String.class));
            Set<String> foreignKeys=new HashSet<>(jdbc.queryForList(FOREIGN_KEYS,String.class));
            if (!new HashSet<>(jdbc.queryForList(COLUMNS,String.class)).containsAll(REQUIRED_COLUMNS)
                    || !indexes.containsAll(REQUIRED_INDEXES) || !foreignKeys.containsAll(REQUIRED_FKS) || !hasUniqueEmail(indexes)
                    || hasExtraUniqueColumns(indexes) || hasExtraForeignKeyColumns(foreignKeys)) return Result.INVALID_SCHEMA;
            Set<String> checks=new HashSet<>();
            for (String check:jdbc.queryForList(CHECKS,String.class)) checks.add(canonical(check));
            return checks.containsAll(REQUIRED_CHECKS) ? Result.VERIFIED_FOR_FURTHER_CHECKS : Result.INVALID_SCHEMA;
        } catch (DataAccessException ex) { return Result.UNAVAILABLE; }
    }
    private static boolean hasUniqueEmail(Set<String> actual) {
        for (String row:actual) {
            String[] parts=row.split("\\|",-1);
            if (parts.length!=6 || !"app_users".equals(parts[0]) || !"0".equals(parts[2])
                    || !"1".equals(parts[3]) || !"email".equals(parts[4]) || !"FULL".equals(parts[5])) continue;
            String prefix=parts[0]+"|"+parts[1]+"|";
            if (actual.stream().filter(item->item.startsWith(prefix)).count()==1) return true;
        }
        return false;
    }
    private static boolean hasExtraUniqueColumns(Set<String> actual) {
        for (String expected : REQUIRED_INDEXES) {
            String[] parts=expected.split("\\|",4);
            if (!"0".equals(parts[2])) continue;
            String prefix=parts[0]+"|"+parts[1]+"|";
            if (actual.stream().anyMatch(row -> row.startsWith(prefix) && !REQUIRED_INDEXES.contains(row))) return true;
        }
        return false;
    }
    private static boolean hasExtraForeignKeyColumns(Set<String> actual) {
        for (String expected : REQUIRED_FKS) {
            String[] parts=expected.split("\\|",3);
            String prefix=parts[0]+"|"+parts[1]+"|";
            if (actual.stream().anyMatch(row -> row.startsWith(prefix) && !REQUIRED_FKS.contains(row))) return true;
        }
        return false;
    }
    static String canonical(String value) {
        String[] parts=value.split("\\|",4);
        if (parts.length != 4) return "";
        String expression=parts[3].replace("\\'", "'");
        StringBuilder normalized=new StringBuilder();
        boolean quoted=false;
        for (int i=0; i<expression.length(); i++) {
            char ch=expression.charAt(i);
            if (ch=='\'') { quoted=!quoted; normalized.append(ch); continue; }
            if (!quoted && expression.regionMatches(true,i,"_latin1'",0,8)) { i+=6; continue; }
            if (!quoted && (Character.isWhitespace(ch) || ch=='`')) continue;
            normalized.append(quoted ? ch : Character.toLowerCase(ch));
        }
        if (quoted) return "";
        String clause=normalized.toString();
        while (outerParentheses(clause)) clause=clause.substring(1,clause.length()-1);
        return (parts[0]+"|"+parts[1]+"|"+parts[2]+"|").toLowerCase(java.util.Locale.ROOT)+clause;
    }
    private static boolean outerParentheses(String value) {
        if (value.length()<2 || value.charAt(0)!='(' || value.charAt(value.length()-1)!=')') return false;
        int depth=0; boolean quoted=false;
        for (int i=0;i<value.length();i++) {
            char ch=value.charAt(i);
            if (ch=='\'') quoted=!quoted;
            else if (!quoted && ch=='(') depth++;
            else if (!quoted && ch==')' && --depth==0 && i!=value.length()-1) return false;
            if (depth<0) return false;
        }
        return !quoted && depth==0;
    }
}
