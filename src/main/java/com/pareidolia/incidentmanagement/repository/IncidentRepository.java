package com.pareidolia.incidentmanagement.repository;

import com.pareidolia.incidentmanagement.entity.Incident;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.List;

public interface IncidentRepository extends JpaRepository<Incident, Long> {

    Optional<Incident> findByIncidentNumber(String incidentNumber);

    List<Incident> findByReportedByIgnoreCase(String reportedBy);
}
