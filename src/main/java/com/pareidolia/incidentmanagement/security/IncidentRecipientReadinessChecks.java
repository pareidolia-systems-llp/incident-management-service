package com.pareidolia.incidentmanagement.security;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.springframework.core.env.Environment;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

/** Read-only check against an explicit deployment-approved routing list; never grants case access. */
public final class IncidentRecipientReadinessChecks {
    private IncidentRecipientReadinessChecks() { }
    private static final Set<String> DEPARTMENTS=Set.of("IT","HR","Operations (Annotation)","Operations (Perioperative Flow Analysis)","R&D");
    static final String ACTIVE_SQL="""
            select concat(d.display_name,'|',r.email) from employee_departments d
            join incident_department_mail_recipient r on r.department_id=d.id
            where d.active=1 and r.active=1
            """;
    static final String ELIGIBLE_SQL="""
            select concat(d.display_name,'|',r.email) from employee_departments d
            join incident_department_mail_recipient r on r.department_id=d.id
            join app_users u on binary u.email=binary r.email
            join employee_department_memberships m on m.department_id=d.id and m.user_id=u.id
            where d.active=1 and r.active=1 and u.active=1 and m.active=1
            """;
    static final String DEPARTMENT_IDS_SQL="select concat(id,'|',display_name) from employee_departments where active=1";
    public enum Result { READY_FOR_FURTHER_CHECKS, INVALID_CONFIGURATION, INVALID_RECIPIENTS, UNAVAILABLE }
    static Result inspectOnConnection(JdbcTemplate jdbc, Environment env) {
        if (jdbc == null || env == null || jdbc.getQueryTimeout() <= 0 || jdbc.getQueryTimeout() > 5) return Result.UNAVAILABLE;
        try {
            var approved=parse(env.getProperty("app.notifications.email.readiness.approved-recipients", ""),env.getProperty("app.auth.allowed-domain", ""));
            if (!approved.keySet().equals(DEPARTMENTS)) return Result.INVALID_CONFIGURATION;
            var active=entries(jdbc.queryForList(ACTIVE_SQL,String.class));
            var eligible=entries(jdbc.queryForList(ELIGIBLE_SQL,String.class));
            for (String department:DEPARTMENTS) {
                Set<String> activeEmails=active.getOrDefault(department,Set.of());
                Set<String> eligibleEmails=eligible.getOrDefault(department,Set.of());
                if (activeEmails.isEmpty() || !approved.get(department).containsAll(activeEmails)
                        || java.util.Collections.disjoint(approved.get(department),eligibleEmails)) return Result.INVALID_RECIPIENTS;
            }
            var departmentIds=new HashMap<Long,String>();
            for (String row:jdbc.queryForList(DEPARTMENT_IDS_SQL,String.class)) {
                String[] pair=row.split("\\|",-1);
                if (pair.length!=2) return Result.INVALID_CONFIGURATION;
                String name="Human Resources".equals(pair[1]) ? "HR" : pair[1];
                if (DEPARTMENTS.contains(name) && departmentIds.put(Long.valueOf(pair[0]),name)!=null) return Result.INVALID_CONFIGURATION;
            }
            Long hr=env.getProperty("app.notifications.email.verified-department-routing.hr-department-id",Long.class);
            if (hr==null || !"HR".equals(departmentIds.get(hr))) return Result.INVALID_CONFIGURATION;
            String matrix=env.getProperty("app.notifications.email.verified-department-routing.restricted-recipients","");
            if (matrix.isBlank()) return Result.INVALID_CONFIGURATION;
            var seen=new HashSet<Long>(); boolean hrReady=false;
            for (String row:matrix.split(";",-1)) {
                String[] pair=row.split("=",-1);
                if (pair.length!=2 || !pair[0].trim().matches("[1-9][0-9]*")) return Result.INVALID_CONFIGURATION;
                Long id=Long.valueOf(pair[0].trim()); String department=departmentIds.get(id);
                if (department==null || !seen.add(id)) return Result.INVALID_CONFIGURATION;
                Set<String> allowed=approved.get(department);
                Set<String> entries=new HashSet<>();
                for (String address:pair[1].split(",",-1)) {
                    String email=address.trim().toLowerCase(Locale.ROOT);
                    if (!allowed.contains(email) || !entries.add(email) || !active.getOrDefault(department,Set.of()).contains(email)) return Result.INVALID_CONFIGURATION;
                }
                if (id.equals(hr) && !java.util.Collections.disjoint(entries,eligible.getOrDefault(department,Set.of()))) hrReady=true;
            }
            if (!hrReady) return Result.INVALID_RECIPIENTS;
            return Result.READY_FOR_FURTHER_CHECKS;
        } catch (DataAccessException failure) { return Result.UNAVAILABLE; }
        catch (RuntimeException failure) { return Result.INVALID_CONFIGURATION; }
    }
    private static Map<String,Set<String>> parse(String text,String domain) {
        if (text == null || text.isBlank() || domain == null || domain.isBlank()) throw new IllegalArgumentException();
        Map<String,Set<String>> result=new HashMap<>();
        for (String row:text.split(";",-1)) {
            String[] pair=row.split("=",-1); if (pair.length!=2) throw new IllegalArgumentException();
            String department=pair[0].trim();
            if (!DEPARTMENTS.contains(department) || result.containsKey(department)) throw new IllegalArgumentException();
            Set<String> emails=new HashSet<>();
            for (String value:pair[1].split(",",-1)) {
                String email=value.trim().toLowerCase(Locale.ROOT);
                if (email.length()>254 || !email.matches("[a-z0-9.!#$%&'*+/?^_`{}~-]+@[a-z0-9.-]+")
                        || !email.substring(email.lastIndexOf('@')+1).equals(domain.trim().toLowerCase(Locale.ROOT))
                        || !emails.add(email)) throw new IllegalArgumentException();
                try { var parsed=new jakarta.mail.internet.InternetAddress(email,true); parsed.validate();
                    if (!email.equals(parsed.getAddress())) throw new IllegalArgumentException();
                } catch (jakarta.mail.internet.AddressException failure) { throw new IllegalArgumentException(); }
            }
            result.put(department,Set.copyOf(emails));
        }
        return result;
    }
    private static Map<String,Set<String>> entries(java.util.List<String> rows) {
        Map<String,Set<String>> result=new HashMap<>();
        for (String row:rows) {
            if (row == null) throw new IllegalArgumentException();
            String[] pair=row.split("\\|",-1); if(pair.length!=2) throw new IllegalArgumentException();
            String department="Human Resources".equals(pair[0]) ? "HR" : pair[0];
            if (DEPARTMENTS.contains(department)) result.computeIfAbsent(department,key->new HashSet<>()).add(pair[1]);
        }
        return result;
    }
}
