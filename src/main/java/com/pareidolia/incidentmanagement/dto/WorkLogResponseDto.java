package com.pareidolia.incidentmanagement.dto;

import java.time.LocalDateTime;

public record WorkLogResponseDto(Long id, LocalDateTime workedAt, String category,
                                 String summary, String details, Integer durationMinutes,
                                 LocalDateTime createdAt) {}
