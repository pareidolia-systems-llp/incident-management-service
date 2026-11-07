package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.dto.*;
import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.repository.AppUserRepository;
import com.pareidolia.incidentmanagement.security.EmployeeManagementAccess;
import jakarta.persistence.EntityManager;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Opt-in employee administration over existing app_users; no duplicate directory. */
@Service
@ConditionalOnProperty(name="app.employee-management.enabled",havingValue="true")
public class EmployeeDirectoryService {
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.pareidolia.incidentmanagement.security.IncidentSecurityGate securityGate;
    @org.springframework.beans.factory.annotation.Value("${app.incident-access.enabled:false}") private boolean securityGateEnabled;
    private void securityWrite(){
        if(securityGateEnabled){if(securityGate==null)throw new IllegalStateException("Security gate unavailable.");securityGate.write();}
    }
    private final AppUserService users; private final AppUserRepository repository;
    private final EmployeeManagementAccess access; private final EntityManager em; private final String allowedDomain;
    public EmployeeDirectoryService(AppUserService users,AppUserRepository repository,EmployeeManagementAccess access,EntityManager em,@org.springframework.beans.factory.annotation.Value("${app.auth.allowed-domain}") String allowedDomain){
        this.users=users;this.repository=repository;this.access=access;this.em=em;this.allowedDomain=allowedDomain.trim().toLowerCase(java.util.Locale.ROOT);
    }
    private AppUser actor(){var a=users.getAuthenticatedUser();if(a==null || a.getId()==null || !access.canManage(a))throw denied();return a;}
    private void lockActorAndTarget(Long actorId,Long targetId){
        for(Long id:new TreeSet<>(List.of(actorId,targetId)))
            if(em.createNativeQuery("select id from app_users where id=?1 for update").setParameter(1,id).getResultList().size()!=1)throw denied();
        var rows=em.createNativeQuery("select active,email from app_users where id=?1 for update").setParameter(1,actorId).getResultList();
        if(rows.size()!=1)throw denied(); Object[] r=(Object[])rows.get(0); var current=actor();
        if(!bool(r[0]) || !(r[1] instanceof String email) || !actorId.equals(current.getId())
                || !AppUserService.normalizeEmail(email).equals(AppUserService.normalizeEmail(current.getEmail())))throw denied();
    }
    @Transactional(readOnly=true)
    public EmployeePageResponse list(String search,int page,int size){
        actor(); if(search==null || search.length()>255 || page<0 || size<1 || size>100 || page>10000)throw invalid("Invalid search.");
        String literal = search.trim().toLowerCase(java.util.Locale.ROOT);
        String q = "%" + literal.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%";
        String where=" where lower(display_name) like ?1 escape '!' or lower(email) like ?1 escape '!' or lower(employee_id) like ?1 escape '!'";
        Number count=(Number)em.createNativeQuery("select count(*) from app_users"+where).setParameter(1,q).getSingleResult();
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select id,employee_id,display_name,email,active,account_version,last_login_at from app_users"+where+" order by display_name,id")
            .setParameter(1,q).setFirstResult(Math.multiplyExact(page,size)).setMaxResults(size).getResultList();
        long total=count.longValue();return new EmployeePageResponse(rows.stream().map(EmployeeDirectoryService::response).toList(),page,size,total,(int)Math.min(Integer.MAX_VALUE,(total+size-1)/size));
    }
    @Transactional(readOnly=true)
    public EmployeeResponse view(Long id){actor();return find(id,false);}
    @Transactional(readOnly=true)
    public EmployeeEditPreview preview(Long id,UpdateEmployeeRequest request){
        actor(); var employee=find(id,false);check(employee,request.expectedVersion());
        if(request.employeeId()==null && employee.employeeId()!=null)throw invalid("An assigned Employee ID cannot be cleared.");
        Number count=(Number)em.createNativeQuery("select count(*) from app_users where lower(display_name)=lower(?1) and id<>?2").setParameter(1,request.employeeName()).setParameter(2,id).getSingleResult();
        return new EmployeeEditPreview(employee,request,count.longValue()>0);
    }
    @Transactional(isolation=Isolation.REPEATABLE_READ)
    public EmployeeResponse create(CreateEmployeeRequest request){
        securityWrite();
        var a=actor();lockActorAndTarget(a.getId(),a.getId());
        String email=request.officialEmail(); int at=email==null?-1:email.lastIndexOf('@');
        if(allowedDomain.isEmpty() || at<=0 || at!=email.indexOf('@') || !allowedDomain.equals(email.substring(at+1)))throw invalid("Use an official company email.");
        var employee=new AppUser();employee.setDisplayName(request.employeeName());employee.setEmail(request.officialEmail());
        try {repository.saveAndFlush(employee);
            if(em.createNativeQuery("update app_users set employee_id=?2 where id=?1").setParameter(1,employee.getId()).setParameter(2,request.employeeId()).executeUpdate()!=1)throw new IllegalStateException("Employee creation failed.");
            var created=find(employee.getId(),true); audit(a.getId(),null,created,"CREATE","Employee created");return created;
        } catch(DataIntegrityViolationException | jakarta.persistence.PersistenceException ex){throw conflict("Employee ID or email already exists.");}
    }
    @Transactional(isolation=Isolation.REPEATABLE_READ)
    public EmployeeResponse update(Long id,UpdateEmployeeRequest request){
        securityWrite();
        if (request.reason() == null || request.reason().isBlank() || request.reason().length() > 500) {
            throw invalid("An edit reason is required.");
        }
        var a=actor();lockActorAndTarget(a.getId(),id);var before=find(id,true);check(before,request.expectedVersion());
        if(request.employeeId()==null && before.employeeId()!=null)throw invalid("An assigned Employee ID cannot be cleared.");
        if(Objects.equals(before.employeeId(),request.employeeId()) && Objects.equals(before.employeeName(),request.employeeName()))return before;
        try {int changed=em.createNativeQuery("update app_users set employee_id=?2,display_name=?3,account_version=account_version+1 where id=?1 and account_version=?4")
            .setParameter(1,id).setParameter(2,request.employeeId()).setParameter(3,request.employeeName()).setParameter(4,request.expectedVersion()).executeUpdate();
            if(changed!=1)throw conflict("Employee changed. Refresh and try again.");
            var after=find(id,true);audit(a.getId(),before,after,"UPDATE",request.reason());return after;
        }catch(DataIntegrityViolationException | jakarta.persistence.PersistenceException ex){throw conflict("Employee ID already exists.");}
    }
    @Transactional(isolation=Isolation.REPEATABLE_READ)
    public EmployeeResponse status(Long id,boolean active,Long expectedVersion,String reason){
        securityWrite();
        if(expectedVersion==null || expectedVersion<0 || reason==null || reason.isBlank() || reason.length()>500)throw invalid("Reason and current version are required.");
        var a=actor();if(a.getId().equals(id))throw denied();lockActorAndTarget(a.getId(),id);var before=find(id,true);check(before,expectedVersion);
        if(before.active()==active)return before;
        if(em.createNativeQuery("update app_users set active=?2,account_version=account_version+1 where id=?1 and account_version=?3")
            .setParameter(1,id).setParameter(2,active?1:0).setParameter(3,expectedVersion).executeUpdate()!=1)throw conflict("Employee changed. Refresh and try again.");
        var after=find(id,true);audit(a.getId(),before,after,"STATUS",reason.trim());return after;
    }
    public record Audit(Long actorId,String action,String oldEmployeeId,String newEmployeeId,String oldName,String newName,Boolean oldActive,boolean newActive,long version,String reason,String changedAt) { }
    @Transactional(readOnly=true)
    public List<Audit> history(Long id){
        actor(); if(id==null || id<=0)throw invalid("Invalid employee.");
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select actor_id,action,old_employee_id,new_employee_id,old_name,new_name,old_active,new_active,version,reason,changed_at from employee_management_audit where target_id=?1 order by version desc").setParameter(1,id).setMaxResults(201).getResultList();
        if(rows.size()>200)throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Too many audit entries to display safely.");
        return rows.stream().map(r->new Audit(((Number)r[0]).longValue(),(String)r[1],(String)r[2],(String)r[3],(String)r[4],(String)r[5],r[6]==null?null:bool(r[6]),bool(r[7]),((Number)r[8]).longValue(),(String)r[9],String.valueOf(r[10]))).toList();
    }
    private EmployeeResponse find(Long id,boolean lock){
        if(id==null || id<=0)throw invalid("Invalid employee.");
        var rows=em.createNativeQuery("select id,employee_id,display_name,email,active,account_version,last_login_at from app_users where id=?1"+(lock?" for update":"")).setParameter(1,id).getResultList();
        if(rows.size()!=1)throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Employee not found.");return response((Object[])rows.get(0));
    }
    private static EmployeeResponse response(Object[] r){
        LocalDateTime last=r[6] instanceof java.sql.Timestamp t?t.toLocalDateTime():(LocalDateTime)r[6];
        return new EmployeeResponse(((Number)r[0]).longValue(),(String)r[1],(String)r[2],(String)r[3],bool(r[4]),last!=null,((Number)r[5]).longValue(),last);
    }
    private void audit(Long actor,EmployeeResponse before,EmployeeResponse after,String action,String reason){
        if(em.createNativeQuery("insert into employee_management_audit(actor_id,target_id,action,old_employee_id,new_employee_id,old_name,new_name,old_active,new_active,version,reason) values (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)")
            .setParameter(1,actor).setParameter(2,after.id()).setParameter(3,action).setParameter(4,before==null?null:before.employeeId()).setParameter(5,after.employeeId())
            .setParameter(6,before==null?null:before.employeeName()).setParameter(7,after.employeeName()).setParameter(8,before==null?null:(before.active()?1:0)).setParameter(9,after.active()?1:0)
            .setParameter(10,after.version()).setParameter(11,reason).executeUpdate()!=1)throw new IllegalStateException("Employee audit failed.");
    }
    private static void check(EmployeeResponse e,Long version){if(version==null || !version.equals(e.version()))throw conflict("Employee changed. Refresh and try again.");}
    private static boolean bool(Object v){if(v instanceof Boolean b)return b;if(v instanceof Number n && (n.intValue()==0 || n.intValue()==1))return n.intValue()==1;throw denied();}
    private static AccessDeniedException denied(){return new AccessDeniedException("Access denied.");}
    private static ResponseStatusException invalid(String message){return new ResponseStatusException(HttpStatus.BAD_REQUEST,message);}
    private static ResponseStatusException conflict(String message){return new ResponseStatusException(HttpStatus.CONFLICT,message);}
}
