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
    static final String FOREIGN_KEYS = "select concat(k.table_name,'|',k.constraint_name,'|',k.ordinal_position,'|',k.column_name,'|',k.referenced_table_name,'|',k.referenced_column_name,'|',r.delete_rule,'|',r.update_rule) from information_schema.key_column_usage k join information_schema.referential_constraints r on r.constraint_schema=k.constraint_schema and r.table_name=k.table_name and r.constraint_name=k.constraint_name where k.constraint_schema=database() and k.referenced_table_name is not null";
    static final String CHECKS = "select concat(t.table_name,'|',t.constraint_name,'|',t.enforced,'|',c.check_clause) from information_schema.table_constraints t join information_schema.check_constraints c on c.constraint_schema=t.constraint_schema and c.constraint_name=t.constraint_name where t.constraint_schema=database() and t.constraint_type='CHECK'";
    static final Set<String> REQUIRED_COLUMNS = Set.of(
        "incident_security_lock|id|bigint|NO",
        "incident_security_classification|incident_id|bigint|NO", "incident_security_classification|classification|varchar(20)|NO", "incident_security_classification|version|bigint|NO",
        "incident_security_grants|incident_id|bigint|NO", "incident_security_grants|user_id|bigint|NO", "incident_security_grants|permission|varchar(20)|NO", "incident_security_grants|active|tinyint|NO", "incident_security_grants|version|bigint|NO",
        "incident_security_grant_audit|incident_id|bigint|NO", "incident_security_grant_audit|target_user_id|bigint|NO", "incident_security_grant_audit|permission|varchar(20)|NO", "incident_security_grant_audit|version|bigint|NO", "incident_security_grant_audit|reason|varchar(500)|NO",
        "incident_assignment_state|incident_id|bigint|NO", "incident_assignment_state|handler_user_id|bigint|YES", "incident_assignment_state|assignment_version|bigint|NO",
        "incident_assignment_audit|incident_id|bigint|NO", "incident_assignment_audit|assignment_version|bigint|NO", "incident_assignment_audit|reason|varchar(500)|NO");
    static final Set<String> REQUIRED_INDEXES = Set.of(
        "incident_security_lock|PRIMARY|0|1|id|FULL", "incident_security_classification|PRIMARY|0|1|incident_id|FULL",
        "incident_security_grants|PRIMARY|0|1|incident_id|FULL", "incident_security_grants|PRIMARY|0|2|user_id|FULL", "incident_security_grants|PRIMARY|0|3|permission|FULL",
        "incident_security_grant_audit|uk_isga_version|0|1|incident_id|FULL", "incident_security_grant_audit|uk_isga_version|0|2|target_user_id|FULL", "incident_security_grant_audit|uk_isga_version|0|3|permission|FULL", "incident_security_grant_audit|uk_isga_version|0|4|version|FULL",
        "incident_assignment_state|PRIMARY|0|1|incident_id|FULL", "incident_assignment_state|idx_assignment_handler|1|1|handler_user_id|FULL",
        "incident_assignment_audit|uk_assignment_audit_version|0|1|incident_id|FULL", "incident_assignment_audit|uk_assignment_audit_version|0|2|assignment_version|FULL",
        "incidents|idx_incidents_security_created|1|1|created_at|FULL", "incidents|idx_incidents_security_created|1|2|id|FULL");
    static final Set<String> REQUIRED_FKS = Set.of(
        "incident_security_classification|fk_isc_incident|1|incident_id|incidents|id|RESTRICT|RESTRICT",
        "incident_security_grants|fk_isg_incident|1|incident_id|incidents|id|RESTRICT|RESTRICT", "incident_security_grants|fk_isg_user|1|user_id|app_users|id|RESTRICT|RESTRICT",
        "incident_security_grant_audit|fk_isga_grant|1|incident_id|incident_security_grants|incident_id|RESTRICT|RESTRICT", "incident_security_grant_audit|fk_isga_grant|2|target_user_id|incident_security_grants|user_id|RESTRICT|RESTRICT", "incident_security_grant_audit|fk_isga_grant|3|permission|incident_security_grants|permission|RESTRICT|RESTRICT",
        "incident_assignment_state|fk_assignment_incident|1|incident_id|incidents|id|RESTRICT|RESTRICT", "incident_assignment_state|fk_assignment_handler|1|handler_user_id|app_users|id|RESTRICT|RESTRICT");
    // Canonicalized expressions from the reviewed MySQL migrations; unsupported equivalents fail closed.
    static final Set<String> REQUIRED_CHECKS = Set.of(
        "incident_security_lock|ck_incident_security_lock_singleton|yes|id=1",
        "incident_security_classification|ck_isc_value|yes|classificationin('UNCLASSIFIED','STANDARD','RESTRICTED')", "incident_security_classification|ck_isc_version|yes|version>=0",
        "incident_security_grants|ck_isg_permission|yes|permissionin('VIEW','HANDLE','MODIFY','REPORT','ASSIGN')", "incident_security_grants|ck_isg_active|yes|activein(0,1)", "incident_security_grants|ck_isg_version|yes|version>=0",
        "incident_assignment_state|ck_assignment_version|yes|assignment_version>=0",
        "incident_assignment_audit|ck_assignment_action|yes|action_typein('INITIAL','REASSIGN')", "incident_assignment_audit|ck_assignment_reason|yes|char_length(trim(reason))>0");
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
                    || !indexes.containsAll(REQUIRED_INDEXES) || !foreignKeys.containsAll(REQUIRED_FKS)
                    || hasExtraUniqueColumns(indexes) || hasExtraForeignKeyColumns(foreignKeys)) return Result.INVALID_SCHEMA;
            Set<String> checks=new HashSet<>();
            for (String check:jdbc.queryForList(CHECKS,String.class)) checks.add(canonical(check));
            return checks.containsAll(REQUIRED_CHECKS) ? Result.VERIFIED_FOR_FURTHER_CHECKS : Result.INVALID_SCHEMA;
        } catch (DataAccessException ex) { return Result.UNAVAILABLE; }
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
