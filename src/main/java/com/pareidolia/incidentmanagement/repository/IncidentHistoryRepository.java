package com.pareidolia.incidentmanagement.repository;

import com.pareidolia.incidentmanagement.entity.IncidentHistory;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IncidentHistoryRepository extends JpaRepository<IncidentHistory, Long> {

    @org.springframework.data.jpa.repository.Query("select h from IncidentHistory h join fetch h.incident i "
            + "where i.reportedAt >= :start and (i.reportedAt < :end or (:includeEnd = true and i.reportedAt = :end)) "
            + "order by i.reportedAt, i.id, h.changedAt, h.id")
    List<IncidentHistory> findForReport(java.time.LocalDateTime start, java.time.LocalDateTime end, boolean includeEnd);

    @org.springframework.data.jpa.repository.Query("select h from IncidentHistory h join fetch h.incident i "
            + "where i.reportedAt >= :start and i.reportedAt < :end order by i.reportedAt, i.id, h.changedAt, h.id")
    List<IncidentHistory> findForReport(java.time.LocalDateTime start, java.time.LocalDateTime end);

    @org.springframework.data.jpa.repository.Query("select h from IncidentHistory h join fetch h.incident i where i.reportedAt >= :start and (i.reportedAt < :end or (:includeEnd = true and i.reportedAt = :end)) order by i.reportedAt,i.id,h.changedAt,h.id")
    List<IncidentHistory> findForReport(java.time.LocalDateTime start,java.time.LocalDateTime end,boolean includeEnd,org.springframework.data.domain.Pageable page);
    List<IncidentHistory> findByIncidentIdOrderByChangedAtDesc(Long incidentId);

    List<IncidentHistory> findByIncidentIdOrderByChangedAtAscIdAsc(Long incidentId);

    // One batch query for list/dashboard; unrelated work entries do not clear attention.
    @org.springframework.data.jpa.repository.Query("select h from IncidentHistory h where h.incident.id in :ids "
            + "and h.actionType in :actions and not exists (select later.id from IncidentHistory later "
            + "where later.incident = h.incident and later.actionType in :actions "
            + "and (later.changedAt > h.changedAt or (later.changedAt = h.changedAt and later.id > h.id)))")
    List<IncidentHistory> findLatestAttentionEvents(List<Long> ids,
            List<com.pareidolia.incidentmanagement.enums.HistoryActionType> actions);
}
