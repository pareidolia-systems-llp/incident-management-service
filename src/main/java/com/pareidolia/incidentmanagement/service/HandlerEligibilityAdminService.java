package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.security.EmployeeManagementAccess;
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
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Eligibility is not incident access. Bootstrap authority is separately configured. */
@Service
@ConditionalOnProperty(name="app.handler-eligibility-admin.enabled",havingValue="true")
public class HandlerEligibilityAdminService {
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.pareidolia.incidentmanagement.security.IncidentSecurityGate securityGate;
    @org.springframework.beans.factory.annotation.Value("${app.incident-access.enabled:false}") private boolean securityGateEnabled;
    private void securityWrite(){
        if(securityGateEnabled){if(securityGate==null)throw new IllegalStateException("Security gate unavailable.");securityGate.write();}
    }
    private final AppUserService users;
    private final EmployeeManagementAccess access;
    private final EntityManager em;
    private final Set<String> administrators;
    public HandlerEligibilityAdminService(AppUserService users, EmployeeManagementAccess access, EntityManager em,
            @Value("${app.handler-eligibility-admin.allowed-emails:}") String configured) {
        this.users=users; this.access=access; this.em=em;
        this.administrators=Arrays.stream(configured.split(",")).map(AppUserService::normalizeEmail)
            .filter(s -> !s.isEmpty()).collect(Collectors.toUnmodifiableSet());
    }
    private com.pareidolia.incidentmanagement.entity.AppUser trusted() {
        var actor=users.getAuthenticatedUser();
        if(actor==null || actor.getId()==null || !access.canManage(actor)
                || !administrators.contains(AppUserService.normalizeEmail(actor.getEmail()))) throw denied();
        return actor;
    }
    @Transactional(isolation=Isolation.REPEATABLE_READ)
    public long change(Long target, boolean active, Long expectedVersion, String reason) {
        securityWrite();
        if(target==null || target<=0 || reason==null || reason.isBlank() || reason.length()>500
                || (expectedVersion!=null && expectedVersion<0)) throw new IllegalArgumentException("Invalid eligibility request.");
        var actor=trusted(); Long actorId=actor.getId();
        if(actorId.equals(target)) throw denied();
        for(Long id:new TreeSet<>(List.of(actorId,target)))
            if(em.createNativeQuery("select id from app_users where id=?1 for update").setParameter(1,id).getResultList().size()!=1) throw denied();
        var current=em.createNativeQuery("select active,email from app_users where id=?1 for update").setParameter(1,actorId).getResultList();
        var targetRows=em.createNativeQuery("select active from app_users where id=?1 for update").setParameter(1,target).getResultList();
        if(current.size()!=1 || targetRows.size()!=1) throw denied();
        Object[] currentActor=(Object[])current.get(0); var again=trusted();
        if(!enabled(currentActor[0]) || !(currentActor[1] instanceof String email) || !actorId.equals(again.getId())
                || !AppUserService.normalizeEmail(email).equals(AppUserService.normalizeEmail(again.getEmail()))) throw denied();
        if(active && !enabled(targetRows.get(0))) throw denied();
        var rows=em.createNativeQuery("select active,version from handler_eligibility_grants where user_id=?1 for update").setParameter(1,target).getResultList();
        if(rows.size()>1) throw denied();
        Integer old=null; long version;
        if(rows.isEmpty()) {
            if(expectedVersion!=null || !active) throw conflict();
            version=0;
            em.createNativeQuery("insert into handler_eligibility_grants(user_id,active,version) values (?1,1,0)").setParameter(1,target).executeUpdate();
        } else {
            Object[] row=(Object[])rows.get(0); old=enabled(row[0])?1:0;
            long previous=((Number)row[1]).longValue();
            if(expectedVersion==null || expectedVersion.longValue()!=previous) throw conflict();
            if((old==1)==active) return previous;
            version=Math.addExact(previous,1);
            if(em.createNativeQuery("update handler_eligibility_grants set active=?2,version=?3 where user_id=?1 and version=?4")
                    .setParameter(1,target).setParameter(2,active?1:0).setParameter(3,version).setParameter(4,previous).executeUpdate()!=1) throw conflict();
        }
        if(em.createNativeQuery("insert into handler_eligibility_audit(actor_user_id,target_user_id,old_active,new_active,grant_version,reason) values (?1,?2,?3,?4,?5,?6)")
                .setParameter(1,actorId).setParameter(2,target).setParameter(3,old).setParameter(4,active?1:0).setParameter(5,version).setParameter(6,reason.trim()).executeUpdate()!=1)
            throw new IllegalStateException("Eligibility audit failed.");
        return version;
    }
    public record Grant(long userId,String name,String email,boolean active,long version) { }
    public record Audit(long actorUserId,Boolean oldActive,boolean newActive,long version,String reason,String changedAt) { }
    @Transactional(readOnly=true)
    public List<Grant> list() {
        trusted();
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select g.user_id,u.display_name,u.email,g.active,g.version from handler_eligibility_grants g join app_users u on u.id=g.user_id order by u.email,u.id").setMaxResults(501).getResultList();
        if(rows.size()>500) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Too many grants to display safely.");
        return rows.stream().map(r -> new Grant(((Number)r[0]).longValue(),(String)r[1],(String)r[2],enabled(r[3]),((Number)r[4]).longValue())).toList();
    }
    @Transactional(readOnly=true)
    public List<Audit> history(Long target) {
        trusted(); if(target==null || target<=0) throw denied();
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select actor_user_id,old_active,new_active,grant_version,reason,changed_at from handler_eligibility_audit where target_user_id=?1 order by changed_at desc,id desc").setParameter(1,target).setMaxResults(201).getResultList();
        if(rows.size()>200) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Too many audit entries to display safely.");
        return rows.stream().map(r -> new Audit(((Number)r[0]).longValue(),r[1]==null?null:enabled(r[1]),enabled(r[2]),((Number)r[3]).longValue(),(String)r[4],String.valueOf(r[5]))).toList();
    }
    private static boolean enabled(Object value) {
        if(value instanceof Boolean b)return b;
        if(value instanceof Number n && (n.intValue()==0 || n.intValue()==1))return n.intValue()==1;
        throw denied();
    }
    private static AccessDeniedException denied(){return new AccessDeniedException("Access denied.");}
    private static ResponseStatusException conflict(){return new ResponseStatusException(HttpStatus.CONFLICT,"Eligibility changed. Refresh and try again.");}
}
