package com.pareidolia.incidentmanagement.service;

import jakarta.persistence.EntityManager;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Read projection of the HR directory, never a second employee directory. Caller holds security gate. */
@Component
public class EligibleHandlerDirectory {
    public record Employee(long id,String name,String email) { }
    private final EntityManager em;
    private final String domain;
    public EligibleHandlerDirectory(EntityManager em,@Value("${app.auth.allowed-domain}") String domain){this.em=em;this.domain=domain.trim().toLowerCase(Locale.ROOT);}
    public static String searchPattern(String search){
        return "%"+search.trim().toLowerCase(Locale.ROOT).replace("!","!!").replace("%","!%").replace("_","!_")+"%";
    }
    private static final String ELIGIBLE=" from app_users u join handler_eligibility_grants g on g.user_id=u.id where u.active=true and g.active=1 and u.employee_id is not null and trim(u.employee_id)<>'' and u.role in ('IT_HANDLER','ADMIN')";
    public List<Employee> search(String search){
        if(search==null || search.trim().length()<2 || search.length()>255)throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST,"Enter 2 to 255 characters.");
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select u.id,u.display_name,u.email"+ELIGIBLE+" and (lower(u.email) like ?1 escape '!' or lower(u.display_name) like ?1 escape '!') order by u.email,u.id")
            .setParameter(1,searchPattern(search)).setMaxResults(100).getResultList();
        return rows.stream().map(EligibleHandlerDirectory::employee).filter(this::official).toList();
    }
    public Employee requireEligible(Long id){
        if(id==null || id<=0)throw new org.springframework.security.access.AccessDeniedException("Handler is unavailable.");
        var rows=em.createNativeQuery("select u.id,u.display_name,u.email"+ELIGIBLE+" and u.id=?1").setParameter(1,id).getResultList();
        if(rows.size()!=1)throw new org.springframework.security.access.AccessDeniedException("Handler is unavailable.");
        var employee=employee((Object[])rows.get(0));
        if(!official(employee))throw new org.springframework.security.access.AccessDeniedException("Handler is unavailable.");
        return employee;
    }
    public boolean activeDepartment(Long departmentId) {
        return departmentId != null && em.createNativeQuery(
                "select id from employee_departments where id=?1 and active=1")
                .setParameter(1, departmentId).getResultList().size() == 1;
    }

    public boolean activeMember(Long departmentId, Long userId) {
        return departmentId != null && em.createNativeQuery("""
                select m.user_id from employee_department_memberships m
                join employee_departments d on d.id=m.department_id
                where m.department_id=?1 and m.user_id=?2 and m.active=1 and d.active=1
                """).setParameter(1, departmentId).setParameter(2, userId).getResultList().size() == 1;
    }

    public Employee identity(Long id){
        if(id==null)return null;
        var rows=em.createNativeQuery("select id,display_name,email from app_users where id=?1").setParameter(1,id).getResultList();
        if(rows.size()!=1)throw new IllegalStateException("Missing employee identity.");return employee((Object[])rows.get(0));
    }
    private boolean official(Employee employee){String email=employee.email().trim().toLowerCase(Locale.ROOT);int at=email.indexOf('@');return !domain.isBlank() && at>0 && at==email.lastIndexOf('@') && email.substring(at+1).equals(domain);}
    private static Employee employee(Object[] r){return new Employee(((Number)r[0]).longValue(),(String)r[1],(String)r[2]);}
}
