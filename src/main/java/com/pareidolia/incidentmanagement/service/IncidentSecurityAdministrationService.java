package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.entity.Incident;
import com.pareidolia.incidentmanagement.security.IncidentAccessPolicy;
import jakarta.persistence.EntityManager;
import java.util.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Administrative writes never grant incident access except via an explicit case grant. */
@Service
@ConditionalOnProperty(name={"app.incident-security-admin.enabled","app.incident-access.enabled"},havingValue="true")
public class IncidentSecurityAdministrationService {
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
    public record Triage(long incidentId,String incidentNumber,String classification,long version) { }
    public record ClassificationResult(String classification,long version) { }
    public record CaseGrant(long userId,String name,String email,String permission,boolean active,long version) { }
    public record CaseTarget(long id,String name,String email) { }
    public record GrantHistory(long actorId,Boolean oldActive,boolean newActive,long version,String reason,String changedAt) { }
    public record ClassificationHistory(long actorId,String previous,String next,long version,String reason,String changedAt) { }
    private static final Set<String> CLASSIFICATIONS=Set.of("STANDARD","RESTRICTED");
    private static final Set<String> PERMISSIONS=Set.of("VIEW","HANDLE","MODIFY","REPORT","ASSIGN");
    private static final org.slf4j.Logger SECURITY_AUDIT = org.slf4j.LoggerFactory.getLogger("incident.security.audit");
    private final AppUserService users;private final EntityManager em;
    private final IncidentAccessPolicy access;
    private final org.springframework.context.ApplicationEventPublisher events;
    private boolean withinScope(AppUser actor, Long incident) {
        return incident != null && incident > 0 && access.allowsHrOperations(actor, em.find(Incident.class, incident));
    }
    private void requireScope(AppUser actor, Long incident) {
        if (!withinScope(actor, incident)) throw missing();
    }
    public IncidentSecurityAdministrationService(AppUserService users,EntityManager em,IncidentAccessPolicy access,org.springframework.context.ApplicationEventPublisher events){this.users=users;this.em=em;this.access=access;this.events=events;}
    private AppUser identity(){
        var auth=SecurityContextHolder.getContext().getAuthentication();
        if(auth==null || !auth.isAuthenticated() || !(auth.getPrincipal() instanceof OidcUser oidc)
                || !Boolean.TRUE.equals(oidc.getEmailVerified()) || oidc.getEmail()==null)throw denied();
        var actor=users.getAuthenticatedUser();
        if(actor==null || actor.getId()==null || actor.getId()<=0 || !Boolean.TRUE.equals(actor.getActive())
                || actor.getEmail()==null || !AppUserService.normalizeEmail(actor.getEmail()).equals(AppUserService.normalizeEmail(oidc.getEmail())))throw denied();
        return actor;
    }
    private void lockAccounts(Long... ids){for(Long id:new TreeSet<>(Arrays.asList(ids)))
        if(em.createNativeQuery("select id from app_users where id=?1 for update").setParameter(1,id).getResultList().size()!=1)throw missing();}
    private void lockIncident(Long id){if(id==null || id<=0 || em.createNativeQuery("select id from incidents where id=?1 for update").setParameter(1,id).getResultList().size()!=1)throw missing();}
    private void requireCapability(AppUser actor,String capability,boolean locked){
        String suffix=locked?" for update":"";
        var accounts=em.createNativeQuery("select active,email from app_users where id=?1"+suffix).setParameter(1,actor.getId()).getResultList();
        var caps=em.createNativeQuery("select active from assignment_admin_capabilities where user_id=?1 and capability=?2"+suffix).setParameter(1,actor.getId()).setParameter(2,capability).getResultList();
        if(accounts.size()!=1 || caps.size()!=1 || !active(caps.get(0)))throw denied();
        Object[] account=(Object[])accounts.get(0);var again=identity();
        if(!active(account[0]) || !(account[1] instanceof String email) || !actor.getId().equals(again.getId())
                || !AppUserService.normalizeEmail(email).equals(AppUserService.normalizeEmail(again.getEmail())))throw denied();
    }
    @Transactional(readOnly=true)
    public List<Triage> triage(){
        return secureRead(() -> {
        var actor=identity();requireCapability(actor,"INCIDENT_CLASSIFIER",false);
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select i.id,i.incident_number,coalesce(c.classification,'UNCLASSIFIED'),coalesce(c.version,0) from incidents i left join incident_security_classification c on c.incident_id=i.id where c.incident_id is null or c.classification='UNCLASSIFIED' order by i.id").setMaxResults(501).getResultList();
        if(rows.size()>500)throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Too many incidents to display safely.");
        return rows.stream().filter(r -> withinScope(actor, number(r[0]))).map(r->new Triage(number(r[0]),(String)r[1],(String)r[2],number(r[3]))).toList();

        });
    }
    @Transactional(readOnly=true)
    public Triage classification(Long incident){
        return secureRead(() -> {
        var actor=identity();requireCapability(actor,"INCIDENT_CLASSIFIER",false);requireScope(actor, incident);
        var rows=em.createNativeQuery("select i.id,i.incident_number,coalesce(c.classification,'UNCLASSIFIED'),coalesce(c.version,0) from incidents i left join incident_security_classification c on c.incident_id=i.id where i.id=?1").setParameter(1,incident).getResultList();
        if(rows.size()!=1)throw denied();Object[] r=(Object[])rows.get(0);
        return new Triage(number(r[0]),(String)r[1],(String)r[2],number(r[3]));

        });
    }
    @Transactional(isolation=Isolation.REPEATABLE_READ)
    public ClassificationResult classify(Long incident,String requested,Long expected,String reason){
        securityWrite();
        validateReason(reason);if(!CLASSIFICATIONS.contains(requested) || expected==null || expected<0)throw bad();
        var actor=identity();lockAccounts(actor.getId());lockIncident(incident);requireCapability(actor,"INCIDENT_CLASSIFIER",true);requireScope(actor, incident);
        var rows=em.createNativeQuery("select classification,version from incident_security_classification where incident_id=?1 for update").setParameter(1,incident).getResultList();
        if(rows.size()>1)throw denied();String old="UNCLASSIFIED";long version=0;
        if(!rows.isEmpty()){Object[] r=(Object[])rows.get(0);old=(String)r[0];version=number(r[1]);}
        if(!Set.of("UNCLASSIFIED","STANDARD","RESTRICTED").contains(old) || expected.longValue()!=version)throw conflict();
        if(old.equals(requested))return new ClassificationResult(old,version);
        if(old.equals("RESTRICTED") && requested.equals("STANDARD"))requireCapability(actor,"RESTRICTED_DOWNGRADE",true);
        long next=Math.addExact(version,1);
        if(rows.isEmpty()) em.createNativeQuery("insert into incident_security_classification(incident_id,classification,version) values (?1,?2,?3)").setParameter(1,incident).setParameter(2,requested).setParameter(3,next).executeUpdate();
        else if(em.createNativeQuery("update incident_security_classification set classification=?2,version=?3 where incident_id=?1 and version=?4").setParameter(1,incident).setParameter(2,requested).setParameter(3,next).setParameter(4,version).executeUpdate()!=1)throw conflict();
        if(em.createNativeQuery("insert into incident_classification_audit(incident_id,actor_user_id,previous_classification,new_classification,version,reason) values (?1,?2,?3,?4,?5,?6)").setParameter(1,incident).setParameter(2,actor.getId()).setParameter(3,old).setParameter(4,requested).setParameter(5,next).setParameter(6,reason.trim()).executeUpdate()!=1)throw new IllegalStateException("Classification audit failed.");
        if ("UNCLASSIFIED".equals(old)) {
            events.publishEvent(new com.pareidolia.incidentmanagement.notification.IncidentMailReady(em.find(Incident.class, incident).getIncidentNumber()));
        }
        return new ClassificationResult(requested,next);
    }
    @Transactional(isolation=Isolation.REPEATABLE_READ)
    public long setGrant(Long incident,Long target,String permission,boolean grant,Long expected,String reason){
        securityWrite();
        validateReason(reason);if(target==null || target<=0 || !PERMISSIONS.contains(permission) || expected==null || expected<0)throw bad();
        var actor=identity();if(actor.getId().equals(target))throw denied();
        lockAccounts(actor.getId(),target);requireCapability(actor,"CASE_ACCESS_ADMIN",true);
        if (!withinScope(actor, incident)) {
            SECURITY_AUDIT.warn("case_grant_denied actor_id={} target_id={} operation={}",
                    actor.getId(), target, grant ? "grant" : "revoke");
            throw missing();
        }
        lockIncident(incident);
        var targetRows=em.createNativeQuery("select active from app_users where id=?1 for update").setParameter(1,target).getResultList();
        if(targetRows.size()!=1 || (grant && !active(targetRows.get(0))))throw denied();
        if (grant && !access.allowsHrScope(em.find(AppUser.class, target), em.find(Incident.class, incident))) {
            SECURITY_AUDIT.warn("case_grant_denied actor_id={} target_id={} operation=grant", actor.getId(), target);
            throw missing();
        }
        var rows=em.createNativeQuery("select active,version from incident_security_grants where incident_id=?1 and user_id=?2 and permission=?3 for update").setParameter(1,incident).setParameter(2,target).setParameter(3,permission).getResultList();
        if(rows.size()>1)throw denied();Integer old=null;long version=0;
        if(!rows.isEmpty()){Object[] r=(Object[])rows.get(0);old=active(r[0])?1:0;version=number(r[1]);}
        if(expected.longValue()!=version || rows.isEmpty() && !grant)throw conflict();
        if(old!=null && (old==1)==grant)return version;
        long next=Math.addExact(version,1);
        if(rows.isEmpty())em.createNativeQuery("insert into incident_security_grants(incident_id,user_id,permission,active,version) values (?1,?2,?3,1,?4)").setParameter(1,incident).setParameter(2,target).setParameter(3,permission).setParameter(4,next).executeUpdate();
        else if(em.createNativeQuery("update incident_security_grants set active=?4,version=?5 where incident_id=?1 and user_id=?2 and permission=?3 and version=?6").setParameter(1,incident).setParameter(2,target).setParameter(3,permission).setParameter(4,grant?1:0).setParameter(5,next).setParameter(6,version).executeUpdate()!=1)throw conflict();
        if(em.createNativeQuery("insert into incident_security_grant_audit(incident_id,target_user_id,permission,actor_user_id,old_active,new_active,version,reason) values (?1,?2,?3,?4,?5,?6,?7,?8)").setParameter(1,incident).setParameter(2,target).setParameter(3,permission).setParameter(4,actor.getId()).setParameter(5,old).setParameter(6,grant?1:0).setParameter(7,next).setParameter(8,reason.trim()).executeUpdate()!=1)throw new IllegalStateException("Grant audit failed.");
        if (grant && "VIEW".equals(permission)) {
            events.publishEvent(new com.pareidolia.incidentmanagement.notification.DepartmentHeadViewGranted(
                    em.find(Incident.class, incident).getIncidentNumber(), target));
        }
        return next;
    }
    @Transactional(readOnly=true)
    public List<CaseTarget> searchTargets(String search){
        return secureRead(() -> {
        var actor=identity();requireCapability(actor,"CASE_ACCESS_ADMIN",false);
        if(search==null || search.trim().length()<2 || search.length()>255)throw bad();
        String pattern="%"+search.trim().toLowerCase(Locale.ROOT).replace("!","!!").replace("%","!%").replace("_","!_")+"%";
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select id,display_name,email from app_users where active=true and (lower(email) like ?1 escape '!' or lower(display_name) like ?1 escape '!') order by email,id").setParameter(1,pattern).setMaxResults(10).getResultList();
        return rows.stream().map(r->new CaseTarget(number(r[0]),(String)r[1],(String)r[2])).toList();

        });
    }
    @Transactional(readOnly=true)
    public List<CaseGrant> grants(Long incident){
        return secureRead(() -> {
        var actor=identity();requireCapability(actor,"CASE_ACCESS_ADMIN",false);requireScope(actor, incident);
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select g.user_id,u.display_name,u.email,g.permission,g.active,g.version from incident_security_grants g join app_users u on u.id=g.user_id where g.incident_id=?1 order by u.email,g.permission").setParameter(1,incident).setMaxResults(501).getResultList();
        if(rows.size()>500)throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Too many grants to display safely.");
        return rows.stream().map(r->new CaseGrant(number(r[0]),(String)r[1],(String)r[2],(String)r[3],active(r[4]),number(r[5]))).toList();

        });
    }
    @Transactional(readOnly=true)
    public List<GrantHistory> grantHistory(Long incident,Long target,String permission){
        return secureRead(() -> {
        var actor=identity();requireCapability(actor,"CASE_ACCESS_ADMIN",false);if(incident==null || incident<=0 || target==null || target<=0 || !PERMISSIONS.contains(permission))throw bad();
        requireScope(actor, incident);
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select actor_user_id,old_active,new_active,version,reason,changed_at from incident_security_grant_audit where incident_id=?1 and target_user_id=?2 and permission=?3 order by version desc").setParameter(1,incident).setParameter(2,target).setParameter(3,permission).setMaxResults(201).getResultList();
        if(rows.size()>200)throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Too many audit entries.");
        return rows.stream().map(r->new GrantHistory(number(r[0]),r[1]==null?null:active(r[1]),active(r[2]),number(r[3]),(String)r[4],String.valueOf(r[5]))).toList();

        });
    }
    @Transactional(readOnly=true)
    public List<ClassificationHistory> classificationHistory(Long incident){
        return secureRead(() -> {
        var actor=identity();requireCapability(actor,"INCIDENT_CLASSIFIER",false);requireScope(actor, incident);
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select actor_user_id,previous_classification,new_classification,version,reason,changed_at from incident_classification_audit where incident_id=?1 order by version desc").setParameter(1,incident).setMaxResults(201).getResultList();
        if(rows.size()>200)throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Too many audit entries.");
        return rows.stream().map(r->new ClassificationHistory(number(r[0]),(String)r[1],(String)r[2],number(r[3]),(String)r[4],String.valueOf(r[5]))).toList();

        });
    }
    private static void validateReason(String s){if(s==null || s.isBlank() || s.length()>500)throw bad();}
    private static boolean active(Object v){if(v instanceof Boolean b)return b;if(v instanceof Number n && (n.intValue()==0 || n.intValue()==1))return n.intValue()==1;throw denied();}
    private static long number(Object v){if(v instanceof Number n)return n.longValue();throw denied();}
    private static AccessDeniedException denied(){return new AccessDeniedException("Access denied.");}
    private static ResponseStatusException missing(){return new ResponseStatusException(HttpStatus.NOT_FOUND,"Incident not found.");}
    private static ResponseStatusException bad(){return new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid request.");}
    private static ResponseStatusException conflict(){return new ResponseStatusException(HttpStatus.CONFLICT,"Record changed. Refresh and try again.");}
}
