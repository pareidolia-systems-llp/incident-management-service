package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.entity.AppUser;
import jakarta.persistence.EntityManager;
import java.util.*;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Separately configured capability administrators; no implicit or automatic grants. */
@Service
@ConditionalOnProperty(name={"app.incident-security-admin.enabled","app.incident-access.enabled"},havingValue="true")
public class IncidentCapabilityAdministrationService {
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.pareidolia.incidentmanagement.security.IncidentSecurityGate securityGate;
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.pareidolia.incidentmanagement.security.IncidentReadSnapshot readSnapshot;
    @org.springframework.beans.factory.annotation.Value("${app.incident-access.enabled:false}") private boolean securityGateEnabled;
    private void securityWrite(){
        if(securityGateEnabled){if(securityGate==null)throw new IllegalStateException("Security gate unavailable.");securityGate.write();}
    }
    private <T> T secureRead(java.util.function.Supplier<T> work){
        if(!securityGateEnabled)return work.get();
        if(readSnapshot==null)throw new IllegalStateException("Security snapshot unavailable.");
        return readSnapshot.read(work);
    }
    private static final String GLOBAL_VIEW = com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.GLOBAL_INCIDENT_VIEW;
    private static final Set<String> CAPS=Set.of("INCIDENT_CLASSIFIER","RESTRICTED_DOWNGRADE","ASSIGNMENT_ADMIN","CASE_ACCESS_ADMIN", GLOBAL_VIEW);

    @Value("${app.incident-capability-admin.global-view-approver-emails:}")
    private String globalViewApprovers = "";
    public record Capability(long userId,String name,String email,String capability,boolean active,long version) { }
    public record Target(long id,String name,String email) { }
    public record Audit(long actorId,Boolean oldActive,boolean newActive,long version,String reason,String changedAt) { }
    private final AppUserService users;private final EntityManager em;private final Set<String> admins;
    public IncidentCapabilityAdministrationService(AppUserService users,EntityManager em,@Value("${app.incident-capability-admin.allowed-emails:}") String configured){
        this.users=users;this.em=em;this.admins=Arrays.stream(configured.split(",")).map(AppUserService::normalizeEmail).filter(s->!s.isEmpty()).collect(Collectors.toUnmodifiableSet());
    }
    private AppUser actor(){
        var auth=SecurityContextHolder.getContext().getAuthentication();
        if(auth==null || !auth.isAuthenticated() || !(auth.getPrincipal() instanceof OidcUser oidc) || !Boolean.TRUE.equals(oidc.getEmailVerified()) || oidc.getEmail()==null)throw denied();
        var user=users.getAuthenticatedUser();
        if(user==null || user.getId()==null || user.getId()<=0 || !Boolean.TRUE.equals(user.getActive()) || user.getEmail()==null
                || !admins.contains(AppUserService.normalizeEmail(user.getEmail())) || !AppUserService.normalizeEmail(user.getEmail()).equals(AppUserService.normalizeEmail(oidc.getEmail())))throw denied();
        return user;
    }
    private void current(AppUser actor,boolean lock){
        var rows=em.createNativeQuery("select active,email from app_users where id=?1"+(lock?" for update":"")).setParameter(1,actor.getId()).getResultList();
        if(rows.size()!=1)throw denied();Object[] row=(Object[])rows.get(0);var again=actor();
        if(!active(row[0]) || !(row[1] instanceof String email) || !actor.getId().equals(again.getId()) || !AppUserService.normalizeEmail(email).equals(AppUserService.normalizeEmail(again.getEmail())))throw denied();
    }
    @Transactional(readOnly=true)
    public List<Target> search(String search){
        return secureRead(() -> {
        var actor=actor();current(actor,false);if(search==null || search.trim().length()<2 || search.length()>255)throw bad();
        String q="%"+search.trim().toLowerCase(Locale.ROOT).replace("!","!!").replace("%","!%").replace("_","!_")+"%";
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select id,display_name,email from app_users where active=true and (lower(email) like ?1 escape '!' or lower(display_name) like ?1 escape '!') order by email,id").setParameter(1,q).setMaxResults(10).getResultList();
        return rows.stream().map(r->new Target(number(r[0]),(String)r[1],(String)r[2])).toList();

        });
    }
    @Transactional(readOnly=true)
    public List<Capability> list(){
        return secureRead(() -> {
        var actor=actor();current(actor,false);
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select c.user_id,u.display_name,u.email,c.capability,c.active,c.version from assignment_admin_capabilities c join app_users u on u.id=c.user_id order by u.email,c.capability").setMaxResults(501).getResultList();
        if(rows.size()>500)throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Too many capabilities to display safely.");
        return rows.stream().map(r->new Capability(number(r[0]),(String)r[1],(String)r[2],(String)r[3],active(r[4]),number(r[5]))).toList();

        });
    }
    @Transactional(readOnly=true)
    public List<Audit> history(Long target,String capability){
        return secureRead(() -> {
        var actor=actor();current(actor,false);if(target==null || target<=0 || capability==null || !CAPS.contains(capability))throw bad();
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select actor_user_id,old_active,new_active,version,reason,changed_at from assignment_admin_capability_audit where target_user_id=?1 and capability=?2 order by version desc").setParameter(1,target).setParameter(2,capability).setMaxResults(201).getResultList();
        if(rows.size()>200)throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Too many audit entries.");
        return rows.stream().map(r->new Audit(number(r[0]),r[1]==null?null:active(r[1]),active(r[2]),number(r[3]),(String)r[4],String.valueOf(r[5]))).toList();

        });
    }
    @Transactional(isolation=Isolation.REPEATABLE_READ)
    public long change(Long target,String capability,boolean grant,Long expected,String reason){
        securityWrite();
        if(target==null || target<=0 || capability==null || !CAPS.contains(capability) || expected==null || expected<0 || reason==null || reason.isBlank() || reason.length()>500)throw bad();
        var actor=actor();if(actor.getId().equals(target))throw denied();
        if (GLOBAL_VIEW.equals(capability) && Arrays.stream(globalViewApprovers.split(","))
                .map(AppUserService::normalizeEmail).noneMatch(AppUserService.normalizeEmail(actor.getEmail())::equals)) {
            throw denied();
        }
        for(Long id:new TreeSet<>(List.of(actor.getId(),target)))if(em.createNativeQuery("select id from app_users where id=?1 for update").setParameter(1,id).getResultList().size()!=1)throw denied();
        current(actor,true);var targetRows=em.createNativeQuery("select active from app_users where id=?1 for update").setParameter(1,target).getResultList();
        if(targetRows.size()!=1 || grant && !active(targetRows.get(0)))throw denied();
        var rows=em.createNativeQuery("select active,version from assignment_admin_capabilities where user_id=?1 and capability=?2 for update").setParameter(1,target).setParameter(2,capability).getResultList();
        if(rows.size()>1)throw denied();Integer old=null;long version=0;
        if(!rows.isEmpty()){Object[] row=(Object[])rows.get(0);old=active(row[0])?1:0;version=number(row[1]);}
        if(expected.longValue()!=version || rows.isEmpty() && !grant)throw conflict();
        if(old!=null && (old==1)==grant)return version;long next=Math.addExact(version,1);
        if(rows.isEmpty())em.createNativeQuery("insert into assignment_admin_capabilities(user_id,capability,active,version) values (?1,?2,1,?3)").setParameter(1,target).setParameter(2,capability).setParameter(3,next).executeUpdate();
        else if(em.createNativeQuery("update assignment_admin_capabilities set active=?3,version=?4 where user_id=?1 and capability=?2 and version=?5").setParameter(1,target).setParameter(2,capability).setParameter(3,grant?1:0).setParameter(4,next).setParameter(5,version).executeUpdate()!=1)throw conflict();
        if(em.createNativeQuery("insert into assignment_admin_capability_audit(actor_user_id,target_user_id,capability,old_active,new_active,version,reason) values (?1,?2,?3,?4,?5,?6,?7)").setParameter(1,actor.getId()).setParameter(2,target).setParameter(3,capability).setParameter(4,old).setParameter(5,grant?1:0).setParameter(6,next).setParameter(7,reason.trim()).executeUpdate()!=1)throw new IllegalStateException("Capability audit failed.");
        return next;
    }
    private static boolean active(Object v){if(v instanceof Boolean b)return b;if(v instanceof Number n && (n.intValue()==0 || n.intValue()==1))return n.intValue()==1;throw denied();}
    private static long number(Object v){if(v instanceof Number n)return n.longValue();throw denied();}
    private static AccessDeniedException denied(){return new AccessDeniedException("Access denied.");}
    private static ResponseStatusException bad(){return new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid request.");}
    private static ResponseStatusException conflict(){return new ResponseStatusException(HttpStatus.CONFLICT,"Capability changed. Refresh and try again.");}
}
