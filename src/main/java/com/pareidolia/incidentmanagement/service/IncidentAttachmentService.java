package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.dto.AttachmentContentDto;
import com.pareidolia.incidentmanagement.dto.IncidentAttachmentResponseDto;
import org.springframework.web.multipart.MultipartFile;
import java.util.List;

public interface IncidentAttachmentService {
    List<IncidentAttachmentResponseDto> list(Long incidentId);
    List<IncidentAttachmentResponseDto> upload(Long incidentId, List<MultipartFile> files);
    AttachmentContentDto content(Long incidentId, Long attachmentId);
}
