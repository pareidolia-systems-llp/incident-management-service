package com.pareidolia.incidentmanagement.repository;

import com.pareidolia.incidentmanagement.entity.IncidentHistory;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IncidentHistoryRepository extends JpaRepository<IncidentHistory, Long> {

    @org.springframework.data.jpa.repository.Query("select h from IncidentHistory h join fetch h.incident i "
            + "where i.reportedAt >= :start and i.reportedAt < :end order by i.reportedAt, i.id, h.changedAt, h.id")
    List<IncidentHistory> findForReport(java.time.LocalDateTime start, java.time.LocalDateTime end);

    List<IncidentHistory> findByIncidentIdOrderByChangedAtDesc(Long incidentId);
}
