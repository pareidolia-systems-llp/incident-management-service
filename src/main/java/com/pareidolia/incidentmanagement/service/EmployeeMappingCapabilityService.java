package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.security.EmployeeManagementAccess;
import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.TreeSet;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

/** Separately authorized mapping capability management. No HTTP endpoint or automatic bootstrap. */
@Service
@ConditionalOnProperty(name="app.employee-capability-management.enabled", havingValue="true")
public class EmployeeMappingCapabilityService {
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.pareidolia.incidentmanagement.security.IncidentSecurityGate securityGate;
    @org.springframework.beans.factory.annotation.Value("${app.incident-access.enabled:false}") private boolean securityGateEnabled;
    private void securityWrite(){
        if(securityGateEnabled){if(securityGate==null)throw new IllegalStateException("Security gate unavailable.");securityGate.write();}
    }
    private final AppUserService users;
    private final EmployeeManagementAccess access;
    private final EntityManager em;
    public EmployeeMappingCapabilityService(AppUserService users, EmployeeManagementAccess access, EntityManager em) {
        this.users=users; this.access=access; this.em=em;
    }
    @Transactional(isolation=Isolation.REPEATABLE_READ)
    public boolean setMappingAdmin(Long target, boolean grant, String reason) {
        securityWrite();
        if (target==null || target<=0 || reason==null || reason.isBlank() || reason.length()>500) throw new IllegalArgumentException("Invalid capability request.");
        var actor=users.getAuthenticatedUser();
        if (actor==null || actor.getId()==null || actor.getId()<=0 || !access.canManage(actor)) throw denied();
        Long actorId=actor.getId();
        if (grant && actorId.equals(target)) throw denied();
        for (Long id : new TreeSet<>(List.of(actorId,target))) {
            if (em.createNativeQuery("select id from app_users where id=?1 for update").setParameter(1,id).getResultList().size()!=1) throw denied();
        }
        var accounts=em.createNativeQuery("select active,email from app_users where id=?1 for update").setParameter(1,actorId).getResultList();
        var authority=em.createNativeQuery("select active from employee_capability_administrators where user_id=?1 for update").setParameter(1,actorId).getResultList();
        if(accounts.size()!=1 || authority.size()!=1 || !enabled(authority.get(0))) throw denied();
        Object[] current=(Object[])accounts.get(0);
        var again=users.getAuthenticatedUser();
        if(!enabled(current[0]) || !(current[1] instanceof String email) || again==null || !actorId.equals(again.getId()) || !access.canManage(again)
                || !AppUserService.normalizeEmail(email).equals(AppUserService.normalizeEmail(again.getEmail()))) throw denied();
        var targets=em.createNativeQuery("select active from app_users where id=?1 for update").setParameter(1,target).getResultList();
        if(targets.size()!=1 || (grant && !enabled(targets.get(0)))) throw denied();
        var rows=em.createNativeQuery("select active from employee_mapping_admins where user_id=?1 for update").setParameter(1,target).getResultList();
        if(rows.size()>1) throw denied();
        Integer old=rows.isEmpty()?null:(enabled(rows.get(0))?1:0);
        if(old!=null && (old==1)==grant) return false;
        if(old==null && !grant) return false;
        int changed;
        if(old==null) changed=em.createNativeQuery("insert into employee_mapping_admins(user_id,active) values (?1,1)").setParameter(1,target).executeUpdate();
        else changed=em.createNativeQuery("update employee_mapping_admins set active=?2 where user_id=?1 and active=?3").setParameter(1,target).setParameter(2,grant?1:0).setParameter(3,old).executeUpdate();
        if(changed!=1) throw new IllegalStateException("Capability update failed.");
        if(em.createNativeQuery("insert into employee_mapping_admin_audit(actor_user_id,target_user_id,old_active,new_active,reason) values (?1,?2,?3,?4,?5)")
                .setParameter(1,actorId).setParameter(2,target).setParameter(3,old).setParameter(4,grant?1:0).setParameter(5,reason.trim()).executeUpdate()!=1) throw new IllegalStateException("Capability audit failed.");
        return true;
    }
    private static boolean enabled(Object value) {
        if(value instanceof Boolean b)return b;
        if(value instanceof Number n && (n.intValue()==0 || n.intValue()==1))return n.intValue()==1;
        throw denied();
    }
    private static AccessDeniedException denied(){return new AccessDeniedException("Access denied.");}
}
