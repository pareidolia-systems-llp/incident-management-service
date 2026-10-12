package com.pareidolia.incidentmanagement.dto;

import java.time.LocalDateTime;

public record IncidentAttachmentResponseDto(Long id, String originalFilename, String contentType,
        long fileSize, String uploadedBy, LocalDateTime uploadedAt) { }
