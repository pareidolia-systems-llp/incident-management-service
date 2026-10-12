package com.pareidolia.incidentmanagement.repository;

import com.pareidolia.incidentmanagement.entity.IncidentAttachment;
import com.pareidolia.incidentmanagement.dto.IncidentAttachmentResponseDto;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import java.util.List;
import java.util.Optional;

public interface IncidentAttachmentRepository extends JpaRepository<IncidentAttachment, Long> {
    @Query("select new com.pareidolia.incidentmanagement.dto.IncidentAttachmentResponseDto("
            + "a.id, a.originalFilename, a.contentType, a.fileSize, a.uploadedBy, a.uploadedAt) "
            + "from IncidentAttachment a where a.incident.id = :incidentId order by a.uploadedAt, a.id")
    List<IncidentAttachmentResponseDto> findMetadataByIncidentId(Long incidentId);

    Optional<IncidentAttachment> findByIdAndIncidentId(Long id, Long incidentId);
}
