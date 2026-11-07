package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.security.EmployeeManagementAccess;

import jakarta.persistence.EntityManager;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Personnel designations only. These records never confer incident permissions. */
@Service
@ConditionalOnProperty(name="app.department-head-designations.enabled",havingValue="true")
public class DepartmentHeadDesignationService {
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.pareidolia.incidentmanagement.security.IncidentSecurityGate securityGate;
    @org.springframework.beans.factory.annotation.Value("${app.incident-access.enabled:false}") private boolean securityGateEnabled;
    private void securityWrite(){
        if(securityGateEnabled){if(securityGate==null)throw new IllegalStateException("Security gate unavailable.");securityGate.write();}
    }
public record Department(Long id,String name,boolean active) { }
    public record Designation(Long departmentId,String departmentName,Long userId,String name,String email,boolean active,long version) { }
    public record AuditEntry(Long actorUserId,Boolean oldActive,boolean newActive,long version,String reason,String changedAt) { }
    private final AppUserService users;
    private final EmployeeManagementAccess access;
    private final EntityManager em;
    public DepartmentHeadDesignationService(AppUserService users,EmployeeManagementAccess access,EntityManager em) {
        this.users=users;this.access=access;this.em=em;
    }
    private Long trustedActor() {
        var actor=users.getAuthenticatedUser();
        if(actor==null || actor.getId()==null || !access.canManage(actor)) throw denied();
        return actor.getId();
    }
    private void requireMappingAdmin(Long actor, boolean locked) {
        String lock=locked ? " for update" : "";
        var accounts=em.createNativeQuery("select active,email from app_users where id=?1"+lock).setParameter(1,actor).getResultList();
        var caps=em.createNativeQuery("select active from employee_mapping_admins where user_id=?1"+lock)
                .setParameter(1,actor).getResultList();
        if(accounts.size()!=1 || caps.size()!=1 || !enabled(caps.get(0))) throw denied();
        Object[] row=(Object[])accounts.get(0);
        var current=users.getAuthenticatedUser();
        if(!enabled(row[0]) || !(row[1] instanceof String email) || current==null || !actor.equals(current.getId())
                || !access.canManage(current) || !AppUserService.normalizeEmail(email).equals(AppUserService.normalizeEmail(current.getEmail()))) throw denied();
    }
    @Transactional(readOnly=true)
    public List<Department> departments() {
        Long actor=trustedActor();requireMappingAdmin(actor,false);
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select id,display_name,active from employee_departments order by display_name,id").setMaxResults(501).getResultList();
        if(rows.size()>500) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Too many departments to display safely.");
        return rows.stream().map(row->new Department(id(row[0]),(String)row[1],enabled(row[2]))).toList();
    }
    @Transactional(readOnly=true)
    public List<Designation> list() {
        Long actor=trustedActor();requireMappingAdmin(actor,false);
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select h.department_id,d.display_name,h.user_id,u.display_name,u.email,h.active,h.version from department_head_designations h join employee_departments d on d.id=h.department_id join app_users u on u.id=h.user_id order by d.display_name,u.display_name,h.user_id").setMaxResults(501).getResultList();
        if(rows.size()>500) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Too many designations to display safely.");
        return rows.stream().map(row->new Designation(id(row[0]),(String)row[1],id(row[2]),(String)row[3],(String)row[4],enabled(row[5]),id(row[6]))).toList();
    }
    @Transactional(readOnly=true)
    public List<AuditEntry> history(Long department,Long user) {
        if(department==null || department<=0 || user==null || user<=0) throw denied();
        Long actor=trustedActor();requireMappingAdmin(actor,false);
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select actor_user_id,old_active,new_active,designation_version,reason,changed_at from department_head_designation_audit where department_id=?1 and user_id=?2 order by changed_at desc,id desc")
                .setParameter(1,department).setParameter(2,user).setMaxResults(201).getResultList();
        if(rows.size()>200)throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Too many audit entries to display safely.");
        return rows.stream().map(row->new AuditEntry(id(row[0]),row[1]==null?null:enabled(row[1]),enabled(row[2]),id(row[3]),(String)row[4],timestamp(row[5]))).toList();
    }
    private static String timestamp(Object value) {
        if(value instanceof java.sql.Timestamp t)return t.toLocalDateTime().toString();
        if(value instanceof java.time.LocalDateTime t)return t.toString();
        throw denied();
    }
    @Transactional(isolation=Isolation.REPEATABLE_READ)
    public long set(Long department,Long user,boolean active,Long expectedVersion,String reason) {
        securityWrite();
        if(department==null || department<=0 || user==null || user<=0 || reason==null || reason.isBlank() || reason.length()>500 || (expectedVersion!=null && expectedVersion<0))
            throw new com.pareidolia.incidentmanagement.exception.InvalidRequestException("Invalid designation request.");
        Long actor=trustedActor();
        // Stable account parents serialize cooperating account and entitlement writers.
        for (Long account : new java.util.TreeSet<>(List.of(actor,user))) {
            if (em.createNativeQuery("select id from app_users where id=?1 for update").setParameter(1,account).getResultList().size()!=1) throw denied();
        }
        if(!actor.equals(trustedActor())) throw denied();
        requireMappingAdmin(actor,true);
        var targets=em.createNativeQuery("select active from app_users where id=?1 for update").setParameter(1,user).getResultList();
        var departments=em.createNativeQuery("select active from employee_departments where id=?1 for update").setParameter(1,department).getResultList();
        if(targets.size()!=1 || departments.size()!=1) throw denied();
        boolean targetActive=enabled(targets.get(0)), departmentActive=enabled(departments.get(0));
        // Removing a stale designation remains possible after deactivation.
        if(active && (!targetActive || !departmentActive)) throw denied();
        var rows=em.createNativeQuery("select active,version from department_head_designations where department_id=?1 and user_id=?2 for update")
                .setParameter(1,department).setParameter(2,user).getResultList();
        if(rows.size()>1)throw denied();
        Integer oldActive=null;long version;
        if(rows.isEmpty()) {
            if(expectedVersion!=null || !active) throw conflict();
            version=0;
            if(em.createNativeQuery("insert into department_head_designations(department_id,user_id,active,version) values (?1,?2,1,0)")
                    .setParameter(1,department).setParameter(2,user).executeUpdate()!=1) throw conflict();
        } else {
            Object[] row=(Object[])rows.get(0);oldActive=enabled(row[0])?1:0;long oldVersion=id(row[1]);
            if(expectedVersion==null || expectedVersion!=oldVersion)throw conflict();
            if((oldActive==1)==active)return oldVersion;
            version=Math.addExact(oldVersion,1);
            if(em.createNativeQuery("update department_head_designations set active=?3,version=?4 where department_id=?1 and user_id=?2 and version=?5")
                    .setParameter(1,department).setParameter(2,user).setParameter(3,active?1:0).setParameter(4,version).setParameter(5,oldVersion).executeUpdate()!=1)throw conflict();
        }
        if(em.createNativeQuery("insert into department_head_designation_audit(department_id,user_id,actor_user_id,old_active,new_active,designation_version,reason) values (?1,?2,?3,?4,?5,?6,?7)")
            .setParameter(1,department).setParameter(2,user).setParameter(3,actor).setParameter(4,oldActive).setParameter(5,active?1:0).setParameter(6,version).setParameter(7,reason.trim()).executeUpdate()!=1) throw new IllegalStateException("Designation audit failed.");
        return version;
    }
    private static long id(Object value) { if(value instanceof Number n)return n.longValue();throw denied(); }
    private static boolean enabled(Object value) {
        if(value instanceof Boolean b)return b;
        if(value instanceof Number n && (n.intValue()==0 || n.intValue()==1))return n.intValue()==1;
        throw denied();
    }
    private static AccessDeniedException denied() { return new AccessDeniedException("Access denied."); }
    private static ResponseStatusException conflict() { return new ResponseStatusException(HttpStatus.CONFLICT,"Designation changed. Refresh and try again."); }
}
