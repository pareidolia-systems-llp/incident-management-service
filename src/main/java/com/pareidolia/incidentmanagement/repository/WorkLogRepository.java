package com.pareidolia.incidentmanagement.repository;

import com.pareidolia.incidentmanagement.entity.WorkLogEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface WorkLogRepository extends JpaRepository<WorkLogEntry, Long> {
    List<WorkLogEntry> findByOwnerIdOrderByWorkedAtDescIdDesc(Long ownerId);
}
