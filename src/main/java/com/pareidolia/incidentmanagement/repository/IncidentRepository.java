package com.pareidolia.incidentmanagement.repository;

import com.pareidolia.incidentmanagement.entity.Incident;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.List;

public interface IncidentRepository extends JpaRepository<Incident, Long> {

    interface ResponsibleDepartmentOption {
        Long getId();
        String getDisplayName();
    }

    @Query(value = """
            select id, display_name as displayName from employee_departments
            where active = 1 order by display_name, id
            """, nativeQuery = true)
    List<ResponsibleDepartmentOption> findActiveResponsibleDepartments();

    @Query(value = "select display_name from employee_departments where id = :id and active = 1 for update",
            nativeQuery = true)
    Optional<String> lockActiveResponsibleDepartmentName(@Param("id") Long id);

    @org.springframework.data.jpa.repository.Query("select i from Incident i where i.reportedAt >= :start "
            + "and (i.reportedAt < :end or (:includeEnd = true and i.reportedAt = :end)) "
            + "order by i.reportedAt, i.id")
    List<Incident> findForReport(java.time.LocalDateTime start, java.time.LocalDateTime end, boolean includeEnd);

    List<Incident> findByReportedAtGreaterThanEqualAndReportedAtLessThanOrderByReportedAtAscIdAsc(
            java.time.LocalDateTime start, java.time.LocalDateTime end);

    Optional<Incident> findByIncidentNumber(String incidentNumber);

    List<Incident> findByReportedByIgnoreCaseOrderByCreatedAtDescIdDesc(String reportedBy);

    List<Incident> findAllByOrderByCreatedAtDescIdDesc();
}
