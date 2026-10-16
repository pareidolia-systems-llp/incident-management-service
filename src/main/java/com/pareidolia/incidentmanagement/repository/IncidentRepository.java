package com.pareidolia.incidentmanagement.repository;

import com.pareidolia.incidentmanagement.entity.Incident;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.List;

public interface IncidentRepository extends JpaRepository<Incident, Long> {

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
