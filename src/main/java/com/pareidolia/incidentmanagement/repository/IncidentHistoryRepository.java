package com.pareidolia.incidentmanagement.repository;

import com.pareidolia.incidentmanagement.entity.IncidentHistory;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IncidentHistoryRepository extends JpaRepository<IncidentHistory, Long> {

    List<IncidentHistory> findByIncidentIdOrderByChangedAtDesc(Long incidentId);
}
